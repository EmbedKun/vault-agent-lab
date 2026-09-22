#!/usr/bin/env python3
import argparse
import concurrent.futures
import os
import shlex
import socket
import time
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parent
DEFAULT_HOSTS = ROOT / "hosts.txt"


def parse_hosts(path: Path):
    hosts = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        meta = {"role": "lab-agent"}
        for item in parts[1:]:
            if "=" in item:
                k, v = item.split("=", 1)
                meta[k] = v
        hosts.append((parts[0], meta))
    return hosts


def can_connect(host: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False


def remote_command(meta: dict[str, str], probe_api: bool) -> str:
    if meta.get("root"):
        quoted_harness = shlex.quote(f"{meta['root']}/bin/agent_harness.py")
    else:
        quoted_harness = '"$HOME/agent-lab/bin/agent_harness.py"'
    if meta.get("config"):
        quoted_env = shlex.quote(f"{meta['config']}/env")
    else:
        quoted_env = '"$HOME/.config/agent-lab/env"'
    checks = [
        "printf 'host='; hostname",
        "printf 'user='; whoami",
        f"printf 'harness='; test -x {quoted_harness} && echo yes || echo no",
        f"printf 'env_perm='; stat -c %a {quoted_env} 2>/dev/null || echo missing",
        "printf 'codex='; command -v codex || echo missing",
        "printf 'python3='; command -v python3 || echo missing",
    ]
    if probe_api:
        checks.append(
            f"AGENT_CONFIG_FILE={quoted_env} {quoted_harness} --json "
            + shlex.quote("Reply with exactly: LAB_AGENT_READY")
            + " 2>&1"
        )
    return "set -e; " + "; ".join(checks)


def check_one(host: str, meta: dict[str, str], args, password: str):
    role = meta["role"]
    started = time.time()
    if args.skip_unreachable and not can_connect(host, args.port, args.connect_timeout):
        return host, role, "SKIP", "ssh port unreachable", time.time() - started

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
        _, stdout, stderr = client.exec_command(remote_command(meta, args.probe_api), timeout=args.remote_timeout)
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        status = "OK" if code == 0 else f"FAIL({code})"
        detail = "\n".join(x for x in [out, err] if x)
        return host, role, status, detail[-2000:], time.time() - started
    except Exception as exc:
        return host, role, "FAIL", repr(exc), time.time() - started
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description="Check lab agent deployments over SSH.")
    parser.add_argument("--hosts", default=str(DEFAULT_HOSTS))
    parser.add_argument("--user", default=os.environ.get("RANGE_SSH_USER", "user"))
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--connect-timeout", type=float, default=8)
    parser.add_argument("--remote-timeout", type=int, default=180)
    parser.add_argument("--skip-unreachable", action="store_true")
    parser.add_argument("--probe-api", action="store_true")
    parser.add_argument("--only", action="append", default=[])
    args = parser.parse_args()

    password = os.environ.get("RANGE_SSH_PASSWORD")
    if not password:
        print("Missing RANGE_SSH_PASSWORD.", flush=True)
        return 2

    hosts = parse_hosts(Path(args.hosts))
    if args.only:
        wanted = set(args.only)
        hosts = [(host, meta) for host, meta in hosts if host in wanted]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(check_one, host, meta, args, password) for host, meta in hosts]
        for fut in concurrent.futures.as_completed(futures):
            host, role, status, detail, duration = fut.result()
            flat = detail.replace("\n", " | ")
            print(f"{host:15} {role:18} {status:8} {duration:6.1f}s {flat}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
