#!/usr/bin/env python3
import argparse
import concurrent.futures
import os
import shlex
import socket
import sys
import tempfile
import time
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parent
DEFAULT_HOSTS = ROOT / "hosts.txt"
REMOTE_INSTALL = ROOT / "remote_install_agent.sh"
DEFAULT_SCOPE = ",".join(
    [
        "172.22.5.102",
        "172.22.5.104",
        "172.22.5.106",
        "172.22.5.108",
        "172.22.5.110",
        "172.22.5.112",
        "172.22.5.114",
        "172.22.5.116",
        "172.22.4.103",
        "172.22.4.220",
        "172.22.4.232",
    ]
)


def parse_hosts(path: Path):
    hosts = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        host = parts[0]
        meta = {"role": "lab-agent"}
        for item in parts[1:]:
            if "=" in item:
                k, v = item.split("=", 1)
                meta[k] = v
        hosts.append((host, meta, line_no))
    return hosts


def shell_env_line(values: dict[str, str]) -> str:
    return "\n".join(f"{k}={shlex.quote(v)}" for k, v in values.items()) + "\n"


def can_connect(host: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False


def run_remote(client: paramiko.SSHClient, command: str, timeout: int):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return code, out, err


def upload_bytes_via_exec(client: paramiko.SSHClient, remote_path: str, data: bytes, mode: str, timeout: int):
    quoted = shlex.quote(remote_path)
    command = f"umask 077; cat > {quoted}; chmod {mode} {quoted}"
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    stdin.write(data.decode("utf-8"))
    stdin.flush()
    stdin.channel.shutdown_write()
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if code != 0:
        raise RuntimeError(f"stdin upload failed for {remote_path}: rc={code} out={out!r} err={err!r}")


def deploy_one(host: str, meta: dict[str, str], args, api_key: str, password: str):
    role = meta["role"]
    started = time.time()
    if args.skip_unreachable and not can_connect(host, args.port, args.connect_timeout):
        return host, role, "SKIP", "ssh port unreachable", time.time() - started

    if args.dry_run:
        return host, role, "DRY", "would deploy", time.time() - started

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=args.port,
            username=args.user,
            password=password,
            timeout=args.connect_timeout,
            banner_timeout=args.connect_timeout,
            auth_timeout=args.connect_timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        stamp = f"{os.getpid()}-{int(time.time())}"
        remote_tmp = meta.get("tmp", "/tmp").rstrip("/") or "/tmp"
        remote_script = f"{remote_tmp}/agent-lab-install-{stamp}.sh"
        remote_env = f"{remote_tmp}/agent-lab-env-{stamp}"
        upload_notes = []
        env_values = {
            "AGENT_API_BASE": args.api_base,
            "AGENT_API_KEY": api_key,
            "AGENT_MODEL": args.model,
            "AGENT_ROLE": role,
            "AGENT_SCOPE": args.scope,
        }
        if meta.get("root"):
            env_values["AGENT_LAB_ROOT"] = meta["root"]
        if meta.get("config"):
            env_values["AGENT_CONFIG_DIR"] = meta["config"]
        if meta.get("tmp"):
            env_values["AGENT_TMPDIR"] = meta["tmp"]
        env_data = shell_env_line(env_values)
        script_data = REMOTE_INSTALL.read_bytes()
        env_bytes = env_data.encode("utf-8")
        try:
            with client.open_sftp() as sftp:
                sftp.put(str(REMOTE_INSTALL), remote_script)
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", delete=False) as tmp:
                    tmp.write(env_data)
                    tmp_path = tmp.name
                try:
                    sftp.put(tmp_path, remote_env)
                finally:
                    Path(tmp_path).unlink(missing_ok=True)
        except Exception as exc:
            upload_notes.append(f"sftp fallback used: {exc!r}")
            upload_bytes_via_exec(client, remote_script, script_data, "700", args.remote_timeout)
            upload_bytes_via_exec(client, remote_env, env_bytes, "600", args.remote_timeout)
        command = (
            f"chmod 700 {shlex.quote(remote_script)} && "
            f"chmod 600 {shlex.quote(remote_env)} && "
            f"bash {shlex.quote(remote_script)} {shlex.quote(remote_env)}; "
            f"rc=$?; rm -f {shlex.quote(remote_script)} {shlex.quote(remote_env)}; exit $rc"
        )
        code, out, err = run_remote(client, command, args.remote_timeout)
        detail = ("\n".join(upload_notes) + "\n" + out + err).replace(api_key, "[REDACTED]").strip()
        status = "OK" if code == 0 else f"FAIL({code})"
        return host, role, status, detail[-1500:], time.time() - started
    except Exception as exc:
        return host, role, "FAIL", repr(exc), time.time() - started
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description="Deploy lab agent tooling over SSH.")
    parser.add_argument("--hosts", default=str(DEFAULT_HOSTS), help="Host inventory file.")
    parser.add_argument("--user", default=os.environ.get("RANGE_SSH_USER", "user"))
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--api-base", default=os.environ.get("RANGE_API_BASE", "https://api.hpc-ai.com/inference/v1"))
    parser.add_argument("--model", default=os.environ.get("RANGE_MODEL", "moonshotai/kimi-k2.7-code"))
    parser.add_argument("--scope", default=os.environ.get("RANGE_SCOPE", DEFAULT_SCOPE))
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--connect-timeout", type=float, default=8)
    parser.add_argument("--remote-timeout", type=int, default=900)
    parser.add_argument("--skip-unreachable", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--only", action="append", default=[], help="Deploy only the specified host. Can be repeated.")
    args = parser.parse_args()

    password = os.environ.get("RANGE_SSH_PASSWORD")
    api_key = os.environ.get("RANGE_API_KEY")
    if not args.dry_run and (not password or not api_key):
        print("Missing RANGE_SSH_PASSWORD or RANGE_API_KEY.", file=sys.stderr)
        print("Set them in the current shell, then rerun. The script does not store local secrets.", file=sys.stderr)
        return 2

    hosts = parse_hosts(Path(args.hosts))
    if args.only:
        wanted = set(args.only)
        hosts = [(host, meta, line_no) for host, meta, line_no in hosts if host in wanted]
    if not hosts:
        print("No hosts found.", file=sys.stderr)
        return 2

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(deploy_one, host, meta, args, api_key or "", password or "")
            for host, meta, _ in hosts
        ]
        for fut in concurrent.futures.as_completed(futures):
            host, role, status, detail, duration = fut.result()
            print(f"{host:15} {role:18} {status:8} {duration:6.1f}s {detail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
