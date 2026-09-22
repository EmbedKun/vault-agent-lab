param(
  [switch]$ProbeApi,
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
$oldSshUser = $env:RANGE_SSH_USER
$oldSshPassword = $env:RANGE_SSH_PASSWORD

try {
  $env:RANGE_SSH_USER = "user"
  $env:RANGE_SSH_PASSWORD = ConvertFrom-SecureStringPlain $sshSecure

  $argsList = @()
  if (-not $IncludeUnreachable) {
    $argsList += "--skip-unreachable"
  }
  if ($ProbeApi) {
    $argsList += "--probe-api"
  }
  foreach ($hostName in $Only) {
    $argsList += "--only"
    $argsList += $hostName
  }

  python "$PSScriptRoot\check_agents.py" @argsList
}
finally {
  if ($null -eq $oldSshUser) { Remove-Item Env:RANGE_SSH_USER -ErrorAction SilentlyContinue } else { $env:RANGE_SSH_USER = $oldSshUser }
  if ($null -eq $oldSshPassword) { Remove-Item Env:RANGE_SSH_PASSWORD -ErrorAction SilentlyContinue } else { $env:RANGE_SSH_PASSWORD = $oldSshPassword }
}
