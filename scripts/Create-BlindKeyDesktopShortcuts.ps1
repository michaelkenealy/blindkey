param(
  [string]$DesktopPath = [Environment]::GetFolderPath('Desktop'),
  [string]$RepoPath = 'C:\Users\mkene\Code\BlindKey'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$startScript = Join-Path $RepoPath 'scripts\Start-BlindKeyStack.ps1'
$stopScript = Join-Path $RepoPath 'scripts\Stop-BlindKeyStack.ps1'

if (-not (Test-Path -LiteralPath $startScript)) {
  throw "Start script not found: $startScript"
}
if (-not (Test-Path -LiteralPath $stopScript)) {
  throw "Stop script not found: $stopScript"
}

$shell = New-Object -ComObject WScript.Shell

$startShortcutPath = Join-Path $DesktopPath 'BlindKey Stack - Start.lnk'
$startShortcut = $shell.CreateShortcut($startShortcutPath)
$startShortcut.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$startShortcut.Arguments = "-ExecutionPolicy Bypass -File `"$startScript`""
$startShortcut.WorkingDirectory = $RepoPath
$startShortcut.IconLocation = 'shell32.dll,25'
$startShortcut.Save()

$stopShortcutPath = Join-Path $DesktopPath 'BlindKey Stack - Stop.lnk'
$stopShortcut = $shell.CreateShortcut($stopShortcutPath)
$stopShortcut.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$stopShortcut.Arguments = "-ExecutionPolicy Bypass -File `"$stopScript`""
$stopShortcut.WorkingDirectory = $RepoPath
$stopShortcut.IconLocation = 'shell32.dll,27'
$stopShortcut.Save()

Write-Host "Created shortcuts:" -ForegroundColor Green
Write-Host "- $startShortcutPath"
Write-Host "- $stopShortcutPath"
