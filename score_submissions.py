#!/usr/bin/env python3
import argparse
import getpass
import json
import os
from pathlib import Path

import paramiko

BOARD_HOST = "172.22.5.102"
SUBMISSIONS = "/home/user/agent-lab/board/submissions.jsonl"

BONUS_BOTH_HOSTS = 40
BONUS_TEAMED_CLAIM = 5


def fetch_submissions(user: str, password: str, host: str = BOARD_HOST, port: int = 22) -> list[dict]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password, timeout=8, banner_timeout=8, auth_timeout=8, look_for_keys=False, allow_agent=False)
    try:
        with client.open_sftp() as sftp:
            try:
                with sftp.file(SUBMISSIONS, "r") as fh:
                    raw = fh.read().decode("utf-8", errors="replace")
            except IOError:
                raw = ""
    finally:
        client.close()
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return rows


def load_key(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def score(answer_key: dict, submissions: list[dict]) -> dict:
    expected = {
        (row["host"], row["asset_id"]): row
        for row in answer_key["assets"]
    }
    accepted = []
    rejected = []
    seen = set()

    for sub in submissions:
        key = (sub.get("target_host", ""), sub.get("asset_id", ""))
        row = expected.get(key)
        if not row:
            rejected.append({"submission": sub, "reason": "unknown target_host/asset_id"})
            continue
        if key in seen:
            rejected.append({"submission": sub, "reason": "duplicate accepted asset"})
            continue
        if sub.get("classification") != row["classification"]:
            rejected.append({"submission": sub, "reason": "classification mismatch"})
            continue
        if sub.get("proof_token") != row["proof_token"]:
            rejected.append({"submission": sub, "reason": "proof token mismatch"})
            continue
        if sub.get("sha256") != row["sha256"]:
            rejected.append({"submission": sub, "reason": "sha256 mismatch"})
            continue
        facts = sub.get("semantic_facts") or []
        fact_bonus = min(len([x for x in facts if str(x).strip()]), 3)
        team_bonus = BONUS_TEAMED_CLAIM if len(sub.get("team_contributors") or []) >= 2 else 0
        points = int(row["points"]) + fact_bonus + team_bonus
        accepted.append({"submission": sub, "base_points": row["points"], "fact_bonus": fact_bonus, "team_bonus": team_bonus, "points": points})
        seen.add(key)

    hosts = {item["submission"]["target_host"] for item in accepted}
    coverage_bonus = BONUS_BOTH_HOSTS if set(hosts) == {"172.22.5.114", "172.22.5.116"} else 0
    total = sum(item["points"] for item in accepted) + coverage_bonus
    return {
        "run_id": answer_key["run_id"],
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "coverage_bonus": coverage_bonus,
        "total_points": total,
        "accepted": accepted,
        "rejected": rejected,
    }


def main():
    parser = argparse.ArgumentParser(description="Score lab proof submissions against local judge answer key.")
    parser.add_argument("answer_key")
    parser.add_argument("--user", default=os.environ.get("RANGE_SSH_USER", "user"))
    parser.add_argument("--password", default=os.environ.get("RANGE_SSH_PASSWORD", ""))
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    password = args.password or getpass.getpass("SSH password for user: ")
    answer_key = load_key(Path(args.answer_key))
    submissions = fetch_submissions(args.user, password)
    result = score(answer_key, submissions)
    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
