param(
  [string]$AnswerKey = "",
  [int]$Port = 8790
)

$ErrorActionPreference = "Stop"

function ConvertFrom-SecureStringPlain {
  param([Parameter(Mandatory = $true)][Security.SecureString]$Secure)
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try {
    [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  }
  finally {
    if ($ptr -ne [IntPtr]::Zero) {
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
  }
}

if (-not $AnswerKey) {
  $latest = Get-ChildItem "$PSScriptRoot\judge_artifacts\answer_key_*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $latest) {
    throw "No answer key found under $PSScriptRoot\judge_artifacts"
  }
  $AnswerKey = $latest.FullName
}

$sshSecure = Read-Host "SSH password for dashboard observer" -AsSecureString
$oldUser = $env:RANGE_SSH_USER
$oldPassword = $env:RANGE_SSH_PASSWORD

try {
  $env:RANGE_SSH_USER = "user"
  $env:RANGE_SSH_PASSWORD = ConvertFrom-SecureStringPlain $sshSecure
  $log = Join-Path $PSScriptRoot "dashboard.out.log"
  $errLog = Join-Path $PSScriptRoot "dashboard.err.log"
  $pidPath = Join-Path $PSScriptRoot "dashboard.pid"
  $argsList = @(
    "$PSScriptRoot\live_dashboard.py",
    "--answer-key", $AnswerKey,
    "--host", "127.0.0.1",
    "--port", "$Port"
  )
  $proc = Start-Process -FilePath "python" -ArgumentList $argsList -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError $errLog -PassThru
  Set-Content -Path $pidPath -Value $proc.Id
  Start-Sleep -Seconds 1
  Write-Output "dashboard=http://127.0.0.1:$Port"
  Write-Output "pid=$($proc.Id)"
  Write-Output "log=$log"
  Write-Output "err=$errLog"
}
finally {
  if ($null -eq $oldUser) { Remove-Item Env:RANGE_SSH_USER -ErrorAction SilentlyContinue } else { $env:RANGE_SSH_USER = $oldUser }
  if ($null -eq $oldPassword) { Remove-Item Env:RANGE_SSH_PASSWORD -ErrorAction SilentlyContinue } else { $env:RANGE_SSH_PASSWORD = $oldPassword }
}
