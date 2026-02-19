param(
  [string]$BlindKeyPath = 'C:\Users\mkene\Code\BlindKey',
  [string]$ConductorPath = 'C:\Users\mkene\Code\Conductor',
  [switch]$NoModelPrompt,
  [string]$Model,
  [switch]$StartTunnel
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateDir = Join-Path $env:USERPROFILE '.blindkey-stack'
$stateFile = Join-Path $stateDir 'processes.json'

function Assert-PathExists([string]$path, [string]$label) {
  if (-not (Test-Path -LiteralPath $path)) {
    throw "$label path not found: $path"
  }
}

function Test-CommandExists([string]$commandName) {
  return [bool](Get-Command $commandName -ErrorAction SilentlyContinue)
}

function New-RandomSecret([int]$bytes = 32) {
  $buffer = New-Object byte[] $bytes
  (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($buffer)
  return [Convert]::ToBase64String($buffer)
}

function Get-OllamaModels {
  if (-not (Test-CommandExists 'ollama')) {
    throw 'Ollama is not installed or not on PATH.'
  }

  $ollamaPath = (Get-Command ollama -ErrorAction Stop).Source
  $lines = @(& $ollamaPath list) | Where-Object { $_ -and $_.Trim().Length -gt 0 }
  if ($lines.Count -le 1) {
    return @()
  }

  $models = @()
  foreach ($line in $lines | Select-Object -Skip 1) {
    $parts = $line -split '\s{2,}'
    if ($parts.Count -gt 0 -and $parts[0].Trim().Length -gt 0) {
      $models += $parts[0].Trim()
    }
  }

  return $models | Select-Object -Unique
}

function Select-Model([string[]]$models, [string]$defaultModel) {
  if ($models.Count -eq 0) {
    throw 'No local Ollama models found. Pull one first (example: ollama pull llama3.1:8b).'
  }

  if ($defaultModel -and ($models -contains $defaultModel)) {
    return $defaultModel
  }

  Write-Host ''
  Write-Host 'Select an Ollama model for BlindKey local chat:' -ForegroundColor Cyan
  for ($i = 0; $i -lt $models.Count; $i++) {
    Write-Host ("[{0}] {1}" -f ($i + 1), $models[$i])
  }

  while ($true) {
    $choice = Read-Host ("Enter model number (1-{0})" -f $models.Count)
    $idx = 0
    if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 1 -and $idx -le $models.Count) {
      return $models[$idx - 1]
    }
    Write-Host 'Invalid selection. Try again.' -ForegroundColor Yellow
  }
}

function Start-PowershellProcess([string]$name, [string]$workingDirectory, [string]$command) {
  $ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
  $proc = Start-Process -FilePath $ps -ArgumentList @(
    '-NoLogo',
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-Command', $command
  ) -WorkingDirectory $workingDirectory -WindowStyle Minimized -PassThru

  return [pscustomobject]@{
    name = $name
    pid = $proc.Id
    command = $command
    workingDirectory = $workingDirectory
    startedAt = (Get-Date).ToString('o')
  }
}

function Start-OllamaServe {
  if (Get-Process -Name 'ollama' -ErrorAction SilentlyContinue) {
    Write-Host 'Ollama already running. Reusing existing process.' -ForegroundColor Green
    return $null
  }

  $proc = Start-Process -FilePath 'ollama' -ArgumentList @('serve') -WindowStyle Minimized -PassThru
  Start-Sleep -Seconds 2

  return [pscustomobject]@{
    name = 'ollama'
    pid = $proc.Id
    command = 'ollama serve'
    workingDirectory = ''
    startedAt = (Get-Date).ToString('o')
  }
}

Assert-PathExists $BlindKeyPath 'BlindKey'
Assert-PathExists $ConductorPath 'Conductor'

if (-not (Test-Path -LiteralPath $stateDir)) {
  New-Item -ItemType Directory -Path $stateDir | Out-Null
}

if (Test-Path -LiteralPath $stateFile) {
  Write-Host 'Existing stack state found. Run Stop-BlindKeyStack.ps1 first if you want a clean restart.' -ForegroundColor Yellow
}

$selectedModel = $Model
if (-not $selectedModel) {
  $models = Get-OllamaModels
  if ($NoModelPrompt) {
    $selectedModel = $models[0]
  } else {
    $selectedModel = Select-Model -models $models -defaultModel $env:LOCAL_LLM_MODEL
  }
}

$chatBridgeSecret = if ($env:CHAT_BRIDGE_SHARED_SECRET) {
  $env:CHAT_BRIDGE_SHARED_SECRET
} else {
  New-RandomSecret
}

$localLlmUrl = if ($env:LOCAL_LLM_URL) {
  $env:LOCAL_LLM_URL
} else {
  'http://127.0.0.1:11434/api/chat'
}

$llmProvider = if ($env:LLM_PROVIDER) {
  $env:LLM_PROVIDER
} else {
  'ollama'
}

$localChatUrl = if ($env:BLINDKEY_LOCAL_CHAT_URL) {
  $env:BLINDKEY_LOCAL_CHAT_URL
} elseif ($env:BLINDKEY_CHAT_URL) {
  $env:BLINDKEY_CHAT_URL
} else {
  'http://127.0.0.1:3601/v1/chat'
}

$localToken = if ($env:BLINDKEY_LOCAL_CHAT_TOKEN) {
  $env:BLINDKEY_LOCAL_CHAT_TOKEN
} elseif ($env:BLINDKEY_CHAT_TOKEN) {
  $env:BLINDKEY_CHAT_TOKEN
} else {
  $chatBridgeSecret
}

$processes = @()

$ollamaEntry = Start-OllamaServe
if ($ollamaEntry) {
  $processes += $ollamaEntry
}

$bridgeCmd = "`$env:LOCAL_LLM_MODEL='$selectedModel'; `$env:LOCAL_LLM_URL='$localLlmUrl'; `$env:LLM_PROVIDER='$llmProvider'; `$env:CHAT_BRIDGE_SHARED_SECRET='$chatBridgeSecret'; npm run dev --workspace=@blindkey/chat-bridge"
$processes += Start-PowershellProcess -name 'blindkey-chat-bridge' -workingDirectory $BlindKeyPath -command $bridgeCmd

$conductorCmd = "`$env:BLINDKEY_LOCAL_CHAT_URL='$localChatUrl'; `$env:BLINDKEY_LOCAL_CHAT_TOKEN='$localToken'; `$env:BLINDKEY_CHAT_URL='$localChatUrl'; `$env:BLINDKEY_CHAT_TOKEN='$localToken'; npm run dev"
$processes += Start-PowershellProcess -name 'conductor' -workingDirectory $ConductorPath -command $conductorCmd

if ($StartTunnel -or ($env:BLINDKEY_STACK_START_TUNNEL -eq 'true')) {
  if (-not [string]::IsNullOrWhiteSpace($env:BLINDKEY_TUNNEL_COMMAND)) {
    $processes += Start-PowershellProcess -name 'tunnel' -workingDirectory $BlindKeyPath -command $env:BLINDKEY_TUNNEL_COMMAND
  } else {
    Write-Host 'Tunnel requested but BLINDKEY_TUNNEL_COMMAND is not set. Skipping.' -ForegroundColor Yellow
  }
}

$state = [pscustomobject]@{
  selectedModel = $selectedModel
  startedAt = (Get-Date).ToString('o')
  blindKeyPath = $BlindKeyPath
  conductorPath = $ConductorPath
  bridgeSecretHint = if ($env:CHAT_BRIDGE_SHARED_SECRET) { 'from-env' } else { 'auto-generated-for-session' }
  localChatUrl = $localChatUrl
  localLlmUrl = $localLlmUrl
  llmProvider = $llmProvider
  processes = $processes
}

$state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $stateFile

Write-Host ''
Write-Host 'BlindKey stack started.' -ForegroundColor Green
Write-Host ("Model: {0}" -f $selectedModel)
Write-Host ("State: {0}" -f $stateFile)
Write-Host 'Use scripts\Stop-BlindKeyStack.ps1 to stop it.'
