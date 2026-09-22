#!/usr/bin/env python3
import argparse
import concurrent.futures
import getpass
import os
import socket
import time

import paramiko

ATTACK_HOSTS = {
    "172.22.5.102": "agent-lead",
    "172.22.5.106": "agent-identity",
    "172.22.5.108": "agent-linux",
    "172.22.5.110": "agent-windows",
    "172.22.5.112": "agent-proof",
    "172.22.4.220": "agent-extra-1",
    "172.22.4.232": "agent-extra-2",
}


def can_connect(host, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False


def remote(host, role, args, password):
    if args.skip_unreachable and not can_connect(host, args.port, args.connect_timeout):
        return host, role, "SKIP", "ssh unreachable"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=args.port, username=args.user, password=password,
                       timeout=args.connect_timeout, banner_timeout=args.connect_timeout,
                       auth_timeout=args.connect_timeout, look_for_keys=False, allow_agent=False)
        if args.action == "start":
            cmd = (
                "rm -f /home/user/agent-lab/mission/STOP_VAULT_LOOP; "
                "if [ -f /home/user/agent-lab/mission/vault_agent_loop.pid ]; then "
                "oldpid=$(cat /home/user/agent-lab/mission/vault_agent_loop.pid 2>/dev/null || true); "
                "if [ -n \"$oldpid\" ]; then kill \"$oldpid\" 2>/dev/null || true; fi; fi; "
                "nohup python3 /home/user/agent-lab/mission/vault_agent_loop.py "
                "> /home/user/agent-lab/mission/vault_agent_loop.out 2>&1 & "
                "echo $! > /home/user/agent-lab/mission/vault_agent_loop.pid; "
                "sleep 1; if kill -0 $(cat /home/user/agent-lab/mission/vault_agent_loop.pid) 2>/dev/null; then echo running; else echo not_running; fi"
            )
        elif args.action == "stop":
            cmd = (
                "touch /home/user/agent-lab/mission/STOP_VAULT_LOOP; "
                "if [ -f /home/user/agent-lab/mission/vault_agent_loop.pid ]; then "
                "oldpid=$(cat /home/user/agent-lab/mission/vault_agent_loop.pid 2>/dev/null || true); "
                "if [ -n \"$oldpid\" ]; then kill \"$oldpid\" 2>/dev/null || true; fi; fi; "
                "rm -f /home/user/agent-lab/mission/vault_agent_loop.pid; echo stopped"
            )
        else:
            cmd = (
                "if [ -f /home/user/agent-lab/mission/vault_agent_loop.pid ] && "
                "kill -0 $(cat /home/user/agent-lab/mission/vault_agent_loop.pid) 2>/dev/null; "
                "then echo running pid=$(cat /home/user/agent-lab/mission/vault_agent_loop.pid); else echo stopped; fi; "
                "tail -n 1 /home/user/agent-lab/mission/vault_agent_loop.log 2>/dev/null || true"
            )
        _, stdout, stderr = client.exec_command(cmd, timeout=30)
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return host, role, "OK" if code == 0 else "FAIL", (out + err).strip()
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["start", "stop", "status"])
    parser.add_argument("--user", default=os.environ.get("RANGE_SSH_USER", "user"))
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--connect-timeout", type=float, default=8)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--skip-unreachable", action="store_true")
    args = parser.parse_args()
    password = os.environ.get("RANGE_SSH_PASSWORD") or getpass.getpass("SSH password for user: ")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(remote, h, r, args, password) for h, r in ATTACK_HOSTS.items()]
        for f in concurrent.futures.as_completed(futures):
            host, role, status, detail = f.result()
            print("%-15s %-16s %-6s %s" % (host, role, status, detail))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
