$ErrorActionPreference = "Stop"
$pidPath = Join-Path $PSScriptRoot "dashboard.pid"
if (Test-Path $pidPath) {
  $processId = Get-Content $pidPath | Select-Object -First 1
  if ($processId) {
    Stop-Process -Id ([int]$processId) -ErrorAction SilentlyContinue
  }
  Remove-Item $pidPath -Force
  Write-Output "dashboard stopped"
} else {
  Write-Output "dashboard pid file not found"
}
