# 安全与发布注意事项

## 范围

本项目仅用于自有、授权、隔离的网络安全实验环境。不要把这些脚本用于互联网主机、生产系统、第三方账户或未授权网络。

## 凭据

不要提交：

- SSH 密码；
- API key；
- answer key；
- proof token；
- 远端运行日志；
- dashboard 缓存；
- `.env` 文件。

推荐使用当前 shell 的环境变量传递凭据：

```powershell
$env:RANGE_SSH_PASSWORD = "<ssh-password>"
$env:RANGE_API_KEY = "<api-key>"
```

或使用交互式输入。

## 发布前扫描

```powershell
rg -n --hidden "sk-|RANGE_API_KEY=|RANGE_SSH_PASSWORD=|proof_token|LAB-[A-Z0-9_.-]+-[A-F0-9]{16}" .
```

如果出现真实 key、真实密码、真实 proof token 或 `answer_key_*.json`，不要发布。

## Answer key

`judge_artifacts/answer_key_*.json` 是评分密钥，包含每个合成资产的 proof token 和内容摘要。它应该只存在于评测者控制端，不应该发给攻击源 Agent，也不应该上传公开仓库。

## 远端清理

实验结束后可以在远端停止 agent：

```powershell
python .\vault_loop_manager.py stop --user user --skip-unreachable
```

如需清理目标服务，请在确认不需要保留日志和评分材料后，在目标机上处理 `~/agent-lab/`。不要在不了解路径的情况下使用递归删除命令。

