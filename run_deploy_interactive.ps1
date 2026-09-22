param(
  [switch]$DryRun,
  [switch]$IncludeUnreachable,
  [string[]]$Only = @()
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

$sshSecure = Read-Host "SSH password for user" -AsSecureString
$apiSecure = Read-Host "API key" -AsSecureString

$oldSshUser = $env:RANGE_SSH_USER
$oldSshPassword = $env:RANGE_SSH_PASSWORD
$oldApiBase = $env:RANGE_API_BASE
$oldApiKey = $env:RANGE_API_KEY
$oldModel = $env:RANGE_MODEL

try {
  $env:RANGE_SSH_USER = "user"
  $env:RANGE_SSH_PASSWORD = ConvertFrom-SecureStringPlain $sshSecure
  $env:RANGE_API_BASE = "https://api.hpc-ai.com/inference/v1"
  $env:RANGE_API_KEY = ConvertFrom-SecureStringPlain $apiSecure
  $env:RANGE_MODEL = "moonshotai/kimi-k2.7-code"

  $argsList = @()
  if (-not $IncludeUnreachable) {
    $argsList += "--skip-unreachable"
  }
  if ($DryRun) {
    $argsList += "--dry-run"
  }
  foreach ($hostName in $Only) {
    $argsList += "--only"
    $argsList += $hostName
  }

  python "$PSScriptRoot\deploy_agents.py" @argsList
}
finally {
  if ($null -eq $oldSshUser) { Remove-Item Env:RANGE_SSH_USER -ErrorAction SilentlyContinue } else { $env:RANGE_SSH_USER = $oldSshUser }
  if ($null -eq $oldSshPassword) { Remove-Item Env:RANGE_SSH_PASSWORD -ErrorAction SilentlyContinue } else { $env:RANGE_SSH_PASSWORD = $oldSshPassword }
  if ($null -eq $oldApiBase) { Remove-Item Env:RANGE_API_BASE -ErrorAction SilentlyContinue } else { $env:RANGE_API_BASE = $oldApiBase }
  if ($null -eq $oldApiKey) { Remove-Item Env:RANGE_API_KEY -ErrorAction SilentlyContinue } else { $env:RANGE_API_KEY = $oldApiKey }
  if ($null -eq $oldModel) { Remove-Item Env:RANGE_MODEL -ErrorAction SilentlyContinue } else { $env:RANGE_MODEL = $oldModel }
}
