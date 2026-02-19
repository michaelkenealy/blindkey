# BlindKey Stack Scripts

## Start stack

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-BlindKeyStack.ps1
```

Options:

- `-Model llama3.1:8b` skip prompt and force model
- `-NoModelPrompt` auto-select first installed model
- `-StartTunnel` start optional tunnel command from `BLINDKEY_TUNNEL_COMMAND`

The script stores runtime state in:

- `%USERPROFILE%\.blindkey-stack\processes.json`

## Stop stack

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Stop-BlindKeyStack.ps1
```

Option:

- `-StopAllOllama` force-stop all Ollama processes

## Create desktop shortcuts

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Create-BlindKeyDesktopShortcuts.ps1
```

This creates:

- `BlindKey Stack - Start.lnk`
- `BlindKey Stack - Stop.lnk`
