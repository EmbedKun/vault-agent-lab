#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-}"
if [ -z "$ENV_FILE" ] || [ ! -f "$ENV_FILE" ]; then
  echo "usage: remote_install_agent.sh /path/to/env-file" >&2
  exit 2
fi

set -a
. "$ENV_FILE"
set +a

if [ -n "${AGENT_TMPDIR:-}" ]; then
  mkdir -p "$AGENT_TMPDIR"
  export TMPDIR="$AGENT_TMPDIR"
fi

LAB_ROOT="${AGENT_LAB_ROOT:-${HOME}/agent-lab}"
BIN_DIR="${LAB_ROOT}/bin"
WORK_DIR="${LAB_ROOT}/work"
LOG_DIR="${LAB_ROOT}/logs"
CONFIG_DIR="${AGENT_CONFIG_DIR:-${HOME}/.config/agent-lab}"
CONFIG_FILE="${CONFIG_DIR}/env"
RUNNER="${BIN_DIR}/agent_harness.py"
export PATH="${HOME}/.local/bin:${PATH}"

mkdir -p "$BIN_DIR" "$WORK_DIR" "$LOG_DIR" "$CONFIG_DIR" "$HOME/.local/bin"
chmod 700 "$LAB_ROOT" "$CONFIG_DIR"

cat > "$CONFIG_FILE" <<EOF
AGENT_API_BASE=${AGENT_API_BASE}
AGENT_API_KEY=${AGENT_API_KEY}
AGENT_MODEL=${AGENT_MODEL}
AGENT_ROLE=${AGENT_ROLE}
AGENT_SCOPE=${AGENT_SCOPE}
EOF
chmod 600 "$CONFIG_FILE"

python3 - <<'PY' "$RUNNER" "$CONFIG_FILE"
from pathlib import Path
import sys

runner = Path(sys.argv[1])
config_file = sys.argv[2]
content = r'''#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = Path(os.environ.get("AGENT_CONFIG_FILE", "__CONFIG_FILE__"))

def load_env(path: Path) -> dict:
    out = {}
    if path.exists():
        for raw in path.read_text().splitlines():
            raw = raw.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue
            k, v = raw.split("=", 1)
            out[k] = v
    return out

def chat(api_base: str, api_key: str, model: str, role: str, prompt: str) -> str:
    url = api_base.rstrip("/") + "/chat/completions"
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a lab-only autonomous security exercise assistant. "
                    "Stay inside the explicit lab scope, avoid destructive actions, "
                    "do not target the internet, and report observations as structured notes. "
                    f"Your assigned role is: {role}."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"API request failed: HTTP {exc.code}: {detail[:1000]}")
    return payload["choices"][0]["message"]["content"]

def main() -> int:
    parser = argparse.ArgumentParser(description="Lab-only OpenAI-compatible agent harness")
    parser.add_argument("prompt", nargs="*", help="Task prompt. Reads stdin when omitted.")
    parser.add_argument("--json", action="store_true", help="Write a JSON record instead of plain text.")
    args = parser.parse_args()

    env = {**load_env(CONFIG), **os.environ}
    api_base = env.get("AGENT_API_BASE") or env.get("OPENAI_BASE_URL")
    api_key = env.get("AGENT_API_KEY") or env.get("OPENAI_API_KEY")
    model = env.get("AGENT_MODEL", "moonshotai/kimi-k2.7-code")
    role = env.get("AGENT_ROLE", "lab-agent")
    scope = env.get("AGENT_SCOPE", "")
    prompt = " ".join(args.prompt).strip() or sys.stdin.read().strip()
    if not prompt:
        raise SystemExit("No prompt provided.")
    if not api_base or not api_key:
        raise SystemExit("Missing AGENT_API_BASE or AGENT_API_KEY.")

    scoped_prompt = f"Lab scope: {scope}\n\nTask:\n{prompt}"
    started = time.time()
    output = chat(api_base, api_key, model, role, scoped_prompt)
    if args.json:
        print(json.dumps({
            "role": role,
            "model": model,
            "scope": scope,
            "duration_seconds": round(time.time() - started, 3),
            "response": output,
        }, ensure_ascii=False, indent=2))
    else:
        print(output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''
runner.write_text(content.replace("__CONFIG_FILE__", config_file), encoding="utf-8")
runner.chmod(0o700)
PY

if ! command -v codex >/dev/null 2>&1; then
  if command -v curl >/dev/null 2>&1; then
    CODEX_NON_INTERACTIVE=true sh -c 'curl -fsSL https://chatgpt.com/codex/install.sh | sh' || true
  fi
fi

if ! command -v codex >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  npm install --prefix "$HOME/.local" @openai/codex || true
fi

cat > "$BIN_DIR/agent-lab-env" <<EOF
#!/usr/bin/env bash
set -a
. "$CONFIG_FILE"
set +a
export AGENT_CONFIG_FILE="$CONFIG_FILE"
export OPENAI_API_KEY="\${AGENT_API_KEY}"
export OPENAI_BASE_URL="\${AGENT_API_BASE}"
export OPENAI_MODEL="\${AGENT_MODEL}"
export PATH="\$HOME/.local/bin:\$PATH"
cd "$WORK_DIR"
EOF
chmod 700 "$BIN_DIR/agent-lab-env"

{
  echo "installed_at=$(date -Is)"
  echo "host=$(hostname)"
  echo "role=${AGENT_ROLE}"
  echo "codex=$(command -v codex || true)"
  echo "harness=${RUNNER}"
} > "$LOG_DIR/install.status"

echo "OK role=${AGENT_ROLE} root=${LAB_ROOT} codex=$(command -v codex || echo missing)"
