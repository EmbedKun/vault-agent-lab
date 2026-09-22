# 复现实验步骤

本文档描述如何从一个干净目录复现当前 Vault Agent Lab。

## 1. 环境要求

- 控制端：Windows PowerShell 或 Linux shell 均可。
- Python：建议 3.10+。
- 网络：控制端需要能 SSH 到所有实验机器。
- 远端机器：Linux，默认用户 `user`。
- Python 依赖：见根目录 `requirements.txt`。

## 2. 机器清单

当前实验使用这些 IP：

```text
172.22.5.102 role=agent-lead / board
172.22.5.106 role=agent-identity
172.22.5.108 role=agent-linux
172.22.5.110 role=agent-windows
172.22.5.112 role=agent-proof
172.22.4.220 role=agent-extra-1
172.22.4.232 role=agent-extra-2
172.22.5.114 role=target aurora-hub
172.22.5.116 role=target finance-hub
```

`hosts.txt` 中还保留了历史/备用节点，例如 `172.22.5.104` 和 `172.22.4.103`。当前 hard-mode 部署脚本主要使用源码内的 `ATTACK_HOSTS` 和 `TARGETS`。

## 3. 凭据配置

不要把真实凭据写进仓库。运行前在当前终端配置：

```powershell
$env:RANGE_SSH_USER = "user"
$env:RANGE_SSH_PASSWORD = "<ssh-password>"
$env:RANGE_API_BASE = "https://api.hpc-ai.com/inference/v1"
$env:RANGE_API_KEY = "<api-key>"
$env:RANGE_MODEL = "moonshotai/kimi-k2.7-code"
```

也可以不设置 `RANGE_SSH_PASSWORD`，脚本会交互式提示输入。

## 4. 部署 Agent harness

如需先部署/更新远端 Agent 工具：

```powershell
python .\deploy_agents.py --skip-unreachable
python .\check_agents.py --skip-unreachable
```

这一步会在远端创建：

```text
~/agent-lab/bin/agent_harness.py
~/.config/agent-lab/env
```

其中 API key 写在远端用户自己的配置里，本地脚本不会把 key 写入仓库文件。

## 5. 部署 hard-mode Vault Gateway 靶场

```powershell
python .\deploy_vault_lab.py --user user --skip-unreachable
```

部署完成后：

- `172.22.5.102:8787` 启动协作板；
- `172.22.5.114:9080` 启动 `aurora-hub`；
- `172.22.5.116:9080` 启动 `finance-hub`；
- 攻击源机器获得 `~/agent-lab/mission/` 下的任务脚本；
- 本地生成 `judge_artifacts/answer_key_<run_id>.json`。

健康检查：

```powershell
Invoke-RestMethod http://172.22.5.114:9080/api/health
Invoke-RestMethod http://172.22.5.116:9080/api/health
Invoke-RestMethod http://172.22.5.102:8787/health
```

## 6. 启动/停止攻击源 Agent

启动：

```powershell
python .\vault_loop_manager.py start --user user --skip-unreachable
```

查看状态：

```powershell
python .\vault_loop_manager.py status --user user --skip-unreachable
```

停止：

```powershell
python .\vault_loop_manager.py stop --user user --skip-unreachable
```

## 7. 启动可视化 dashboard

找到当前 run 的 answer key：

```powershell
Get-ChildItem .\judge_artifacts\answer_key_*.json
```

启动：

```powershell
python .\live_dashboard.py .\judge_artifacts\answer_key_<run_id>.json --user user
```

然后打开：

```text
http://127.0.0.1:8790
```

## 8. 评分

手动评分：

```powershell
python .\score_submissions.py .\judge_artifacts\answer_key_<run_id>.json --user user
```

评分器会从协作板主机读取：

```text
/home/user/agent-lab/board/submissions.jsonl
```

并用本地 answer key 验证 proof token、hash、事实点和重复提交。

## 9. 目标服务重启后的恢复

如果目标机重启，`9080` 服务可能不会自启。不要重新跑完整部署脚本，避免刷新 run id。

在目标机上恢复：

```bash
cd /home/user/agent-lab/vault
setsid python3 ./vault_service.py > server.log 2>&1 < /dev/null &
echo $! > server.pid
```

确认：

```bash
curl http://127.0.0.1:9080/api/health
```

或从控制端：

```powershell
Invoke-RestMethod http://172.22.5.116:9080/api/health
```

## 10. 不要提交的文件

这些文件是运行态或敏感材料，不应上传 GitHub：

```text
judge_artifacts/answer_key_*.json
*.log
*.pid
__pycache__/
dist/
.env
```

