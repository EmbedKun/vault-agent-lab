#!/usr/bin/env python3
import argparse
import concurrent.futures
import getpass
import os
import posixpath
import shlex
import socket
import textwrap
from pathlib import Path

import paramiko

BOARD_URL = "http://172.22.5.102:8787"

ATTACK_HOSTS = {
    "172.22.5.102": "agent-lead",
    "172.22.5.106": "agent-identity",
    "172.22.5.108": "agent-linux",
    "172.22.5.110": "agent-windows",
    "172.22.5.112": "agent-proof",
    "172.22.4.220": "agent-extra-1",
    "172.22.4.232": "agent-extra-2",
}

TARGET_HOSTS = ["172.22.5.114", "172.22.5.116"]

TARGET_WRAPPER = r'''#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import time

BASE = pathlib.Path("/home/user/crown_jewels").resolve()
AUDIT = pathlib.Path("/home/user/agent-lab/target_exec_audit.jsonl")

def audit(agent, command, detail=None, rc=0):
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    item = {"ts": time.time(), "agent": agent, "command": command, "detail": detail or "", "rc": rc}
    with AUDIT.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(item, ensure_ascii=False) + "\n")

def current_run() -> pathlib.Path:
    marker = BASE / "CURRENT_RUN"
    root = pathlib.Path(marker.read_text(encoding="utf-8").strip()).resolve()
    root.relative_to(BASE)
    return root

def safe_path(rel: str) -> pathlib.Path:
    if rel.startswith("/") or "\x00" in rel:
        raise SystemExit("invalid relative path")
    root = current_run()
    path = (root / rel).resolve()
    path.relative_to(root)
    if not path.is_file():
        raise SystemExit("not a file")
    return path

def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def identity():
    for cmd in (["hostname"], ["whoami"], ["id"]):
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        print("$ " + " ".join(cmd))
        print(proc.stdout.strip())

def inventory():
    root = current_run()
    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        st = path.stat()
        rows.append({
            "relative_path": str(path.relative_to(root)),
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "size": st.st_size,
            "sha256": sha256_file(path),
        })
    print(json.dumps({"current_run": str(root), "files": rows}, ensure_ascii=False, indent=2))

def read_manifest():
    path = safe_path("00_public_manifest.json")
    sys.stdout.buffer.write(path.read_bytes())

def read_file(rel: str):
    path = safe_path(rel)
    sys.stdout.buffer.write(path.read_bytes())

def hash_file(rel: str):
    print(sha256_file(safe_path(rel)))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True)
    args = parser.parse_args()
    original = (os.environ.get("SSH_ORIGINAL_COMMAND") or "").strip()
    if not original:
        original = "help"
    parts = original.split()
    command = parts[0]
    try:
        if command == "identity":
            identity()
        elif command == "current-run":
            print(current_run())
        elif command == "inventory":
            inventory()
        elif command == "read-manifest":
            read_manifest()
        elif command == "read" and len(parts) == 2:
            read_file(parts[1])
        elif command == "hash" and len(parts) == 2:
            hash_file(parts[1])
        else:
            print("allowed commands: identity, current-run, inventory, read-manifest, read <relative_path>, hash <relative_path>", file=sys.stderr)
            audit(args.agent, original, "denied", 2)
            return 2
        audit(args.agent, original, "ok", 0)
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        audit(args.agent, original, str(exc), 1)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
'''

TARGET_HELPER = r'''#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

BOARD_URL = "__BOARD_URL__"
ROLE = "__ROLE__"
TARGETS = {"172.22.5.114", "172.22.5.116"}
KEY = Path.home() / ".ssh" / "agent_lab_ro_ed25519"
KNOWN_HOSTS = Path.home() / ".ssh" / "agent_lab_known_hosts"
TOKEN_RE = re.compile(r"LAB-[A-Z0-9_.-]+-[A-F0-9]{16}")

def redact(text: str) -> str:
    text = TOKEN_RE.sub("[REDACTED_PROOF_TOKEN]", text)
    text = re.sub(r'("proof_token"\s*:\s*")[^"]+(")', r'\1[REDACTED_PROOF_TOKEN]\2', text)
    return text

def board_post(kind: str, text: str):
    payload = {"agent": ROLE, "kind": kind, "text": text[:5000]}
    req = urllib.request.Request(
        BOARD_URL.rstrip("/") + "/message",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        resp.read()

def run_target(target, command):
    if target not in TARGETS:
        raise SystemExit("target not allowed")
    if not KEY.exists():
        raise SystemExit(f"missing ssh key: {KEY}")
    original = " ".join(command)
    proc = subprocess.run(
        [
            "ssh",
            "-i", str(KEY),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
            f"user@{target}",
            "--",
            original,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace")
    public = f"target={target}\ncommand={original}\nrc={proc.returncode}\nstdout:\n{redact(out)}\nstderr:\n{redact(err)}"
    board_post("command_result", public)
    sys.stdout.write(out)
    if err:
        print(err, file=sys.stderr, end="")
    return proc.returncode

def main():
    parser = argparse.ArgumentParser(description="Run a restricted read-only target command.")
    parser.add_argument("target")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command:
        raise SystemExit("missing command")
    return run_target(args.target, args.command)

if __name__ == "__main__":
    raise SystemExit(main())
'''


def can_connect(host: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False


class Remote:
    def __init__(self, host: str, user: str, password: str, port: int, timeout: float):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.timeout = timeout
        self.client = None

    def __enter__(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self.host,
            port=self.port,
            username=self.user,
            password=self.password,
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        self.client = client
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.client:
            self.client.close()

    def run(self, command: str, timeout: int = 60):
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return code, out, err

    def write_text(self, path: str, text: str, mode: int):
        parent = posixpath.dirname(path)
        self.run(f"mkdir -p {shlex.quote(parent)} && chmod 700 {shlex.quote(parent)}")
        with self.client.open_sftp() as sftp:
            with sftp.file(path, "w") as handle:
                handle.write(text)
            sftp.chmod(path, mode)

    def read_text(self, path: str) -> str:
        with self.client.open_sftp() as sftp:
            with sftp.file(path, "r") as handle:
                return handle.read().decode("utf-8", errors="replace")


def install_source(host: str, role: str, args, password: str):
    if args.skip_unreachable and not can_connect(host, args.port, args.connect_timeout):
        return host, role, "SKIP", "ssh unreachable", ""
    with Remote(host, args.user, password, args.port, args.connect_timeout) as remote:
        remote.run("mkdir -p ~/.ssh ~/agent-lab/mission && chmod 700 ~/.ssh ~/agent-lab/mission")
        key_path = "~/.ssh/agent_lab_ro_ed25519"
        remote.run(
            f"if [ ! -f {key_path} ]; then ssh-keygen -q -t ed25519 -N '' -f {key_path}; fi; chmod 600 {key_path}; chmod 644 {key_path}.pub",
            timeout=30,
        )
        pub = remote.read_text("/home/user/.ssh/agent_lab_ro_ed25519.pub").strip()
        helper = TARGET_HELPER.replace("__BOARD_URL__", BOARD_URL).replace("__ROLE__", role)
        remote.write_text("/home/user/agent-lab/mission/target_ro.py", helper, 0o700)
        return host, role, "OK", "source helper installed", pub


def install_target(host: str, args, password: str, pubkeys: list[tuple[str, str, str]]):
    if args.skip_unreachable and not can_connect(host, args.port, args.connect_timeout):
        return host, "target", "SKIP", "ssh unreachable"
    with Remote(host, args.user, password, args.port, args.connect_timeout) as remote:
        remote.write_text("/home/user/agent-lab/target_ro_exec.py", TARGET_WRAPPER, 0o700)
        remote.run("mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys")
        existing = remote.read_text("/home/user/.ssh/authorized_keys")
        keep = [
            line for line in existing.splitlines()
            if "agent-lab-ro:" not in line
        ]
        forced_lines = []
        for source_host, role, pub in pubkeys:
            key_parts = pub.split()
            if len(key_parts) < 2:
                continue
            key_type, key_body = key_parts[0], key_parts[1]
            marker = f"agent-lab-ro:{role}:{source_host}"
            command = f'/home/user/agent-lab/target_ro_exec.py --agent {shlex.quote(role)}'
            options = (
                f'command="{command}",'
                "no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-pty"
            )
            forced_lines.append(f"{options} {key_type} {key_body} {marker}")
        new_content = "\n".join(keep + forced_lines).strip() + "\n"
        remote.write_text("/home/user/.ssh/authorized_keys", new_content, 0o600)
        return host, "target", "OK", f"installed {len(forced_lines)} restricted keys"


def main():
    parser = argparse.ArgumentParser(description="Enable restricted read-only command execution from attack agents to asset hosts.")
    parser.add_argument("--user", default=os.environ.get("RANGE_SSH_USER", "user"))
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--connect-timeout", type=float, default=8)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--skip-unreachable", action="store_true")
    args = parser.parse_args()

    password = os.environ.get("RANGE_SSH_PASSWORD") or getpass.getpass("SSH password for user: ")
    pubkeys = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(install_source, host, role, args, password) for host, role in ATTACK_HOSTS.items()]
        for future in concurrent.futures.as_completed(futures):
            host, role, status, detail, pub = future.result()
            print(f"{host:15} {role:16} {status:6} {detail}")
            if status == "OK" and pub:
                pubkeys.append((host, role, pub))

    for target in TARGET_HOSTS:
        host, role, status, detail = install_target(target, args, password, pubkeys)
        print(f"{host:15} {role:16} {status:6} {detail}")

    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
