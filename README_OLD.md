# Agent Lab Deployment

This folder installs lab-only agent tooling on the listed Linux hosts:

- OpenAI Codex CLI, using the official Linux installer when possible.
- A minimal OpenAI-compatible harness at `~/agent-lab/bin/agent_harness.py`.
- Per-host configuration at `~/.config/agent-lab/env` with mode `0600`.

The deployer reads secrets from environment variables and does not write them to local files.

## 1. Review the inventory

Edit `hosts.txt` if you want to change host roles before deployment.

`172.22.4.103` did not respond on SSH port 22 during the first connectivity check, so deployment may skip or fail there unless SSH is opened or the address/port is corrected.

## 2. Set secrets in the current PowerShell session

Use a fresh, temporary API key if possible. The key already pasted into the chat should be rotated after the lab.

```powershell
$env:RANGE_SSH_USER = "user"
$env:RANGE_SSH_PASSWORD = "<ssh password>"
$env:RANGE_API_BASE = "https://api.hpc-ai.com/inference/v1"
$env:RANGE_API_KEY = "<api key>"
$env:RANGE_MODEL = "moonshotai/kimi-k2.7-code"
```

## 3. Dry run

```powershell
python .\agent_lab_deploy\deploy_agents.py --dry-run --skip-unreachable
```

## 4. Deploy

```powershell
python .\agent_lab_deploy\deploy_agents.py --skip-unreachable
```

## 5. Test one remote host

```bash
source ~/agent-lab/bin/agent-lab-env
~/agent-lab/bin/agent_harness.py "Return a one paragraph readiness check for this lab role."
codex --version
```

## Guardrails

Keep the agents inside the private lab scope. Do not target internet hosts, production networks, or real third-party accounts. Treat `~/agent-lab/work` as the working directory for any local experiments.
