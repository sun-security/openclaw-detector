# VMware Workspace ONE UEM Deployment

Workspace ONE UEM provides script execution for macOS through the Scripts feature.

[VMware Docs](https://docs.vmware.com/en/VMware-Workspace-ONE-UEM/2206/macOS_Platform/GUID-AutomateScriptsmacOSDevices.html)

## Adding the Script

1. Go to **Resources > Scripts**
2. Click **Add > macOS**
3. Configure settings:
   - **Name:** OpenClaw Detection
   - **Language:** Bash
   - **Execution Context:** System (scans all users)
   - **Timeout:** 120 seconds
4. Enter the script:

```bash
#!/bin/bash
curl -sL https://raw.githubusercontent.com/sun-security/openclaw-detector/main/macos-linux/openclaw-detector.sh | bash
```

5. Save

## Supported Script Languages

- Bash
- Python 3
- Zsh

## Exit Code Reference

| Code     | Workspace ONE Status | Description             |
| -------- | -------------------- | ----------------------- |
| 0        | Success              | OpenClaw not present    |
| Non-zero | Failed               | OpenClaw found or error |

## Assigning to Devices

1. Open **Resources > Scripts**
2. Select **OpenClaw Detection**
3. Click **Assignment**
4. Add Smart Groups to target
5. Set execution schedule
6. Save

## Checking Results

1. Go to **Resources > Scripts**
2. Select **OpenClaw Detection**
3. Open the **Devices** tab
4. Review execution status and output per device
5. Filter by **Status: Failed** to find affected devices

## Compliance Tracking

Create a Smart Group based on script execution status to monitor devices where OpenClaw was detected.
