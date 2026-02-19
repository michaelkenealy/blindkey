param(
  [switch]$StopAllOllama
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateDir = Join-Path $env:USERPROFILE '.blindkey-stack'
$stateFile = Join-Path $stateDir 'processes.json'

if (-not (Test-Path -LiteralPath $stateFile)) {
  Write-Host 'No running stack state file found. Nothing to stop.' -ForegroundColor Yellow
  if ($StopAllOllama) {
    Get-Process -Name 'ollama' -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host 'Stopped all ollama processes.' -ForegroundColor Green
  }
  exit 0
}

$state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json

foreach ($entry in $state.processes) {
  $procId = [int]$entry.pid
  $name = [string]$entry.name

  try {
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($proc) {
      Stop-Process -Id $procId -Force
      Write-Host ("Stopped {0} (PID {1})" -f $name, $procId) -ForegroundColor Green
    } else {
      Write-Host ("Process not running: {0} (PID {1})" -f $name, $procId) -ForegroundColor DarkYellow
    }
  } catch {
    Write-Host ("Failed to stop {0} (PID {1}): {2}" -f $name, $pid, $_.Exception.Message) -ForegroundColor Red
  }
}

if ($StopAllOllama) {
  Get-Process -Name 'ollama' -ErrorAction SilentlyContinue | Stop-Process -Force
  Write-Host 'Stopped all ollama processes.' -ForegroundColor Green
}

Remove-Item -LiteralPath $stateFile -Force
Write-Host 'BlindKey stack stopped.' -ForegroundColor Green

