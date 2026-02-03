# JumpCloud Deployment

JumpCloud Commands execute scripts on managed devices through the agent. Output and exit codes are retained for 30 days.

## Console Setup

1. Navigate to **DEVICE MANAGEMENT > Commands > +**
2. Configure the command:
   - **Name:** OpenClaw Detection
   - **Command Type:** Shell (macOS/Linux) or PowerShell (Windows)
   - **Run as:** root (scans all users) or current user
   - **Schedule:** Manual, scheduled, or event-triggered
3. Enter the command:

```bash
curl -sL https://raw.githubusercontent.com/sun-security/openclaw-detector/main/macos-linux/openclaw-detector.sh | bash
```

## API Setup

### macOS/Linux

```bash
curl -X POST https://console.jumpcloud.com/api/commands/ \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: YOUR_API_KEY' \
  -d '{
    "name": "OpenClaw Detection",
    "command": "curl -sL https://raw.githubusercontent.com/sun-security/openclaw-detector/main/macos-linux/openclaw-detector.sh | bash",
    "commandType": "mac",
    "sudo": true,
    "timeout": "120"
  }'
```

### Windows

```bash
curl -X POST https://console.jumpcloud.com/api/commands/ \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: YOUR_API_KEY' \
  -d '{
    "name": "OpenClaw Detection (Windows)",
    "command": "iwr -useb https://raw.githubusercontent.com/sun-security/openclaw-detector/main/windows/openclaw-detector.ps1 | iex",
    "commandType": "windows",
    "shell": "powershell",
    "timeout": "120"
  }'
```

## Reviewing Results

1. Open **DEVICE MANAGEMENT > Commands**
2. Select the command
3. Go to the **Results** tab
4. Filter by exit code:
   - **Exit 0:** Clean - OpenClaw not found
   - **Exit 1:** Found - OpenClaw detected, review
   - **Exit 2:** Error - script failed

## Alerting

Set up JumpCloud alerts to notify on exit code 1 for shadow IT detection workflows.
