# Microsoft Intune Deployment

Deploy the OpenClaw detection script using Intune's Remediations feature. Only a detection script is required—no remediation action needed.

## Configuration Steps

1. Go to **Devices > Manage devices > Scripts and remediations**
2. Select **Create script package**
3. Enter these settings:
   - **Name:** OpenClaw Detection
   - **Detection script:** Upload the script below
   - **Remediation script:** Leave blank
   - **Run script in 64-bit PowerShell:** Yes
   - **Run this script using the logged-on credentials:** No (executes as SYSTEM)

## Detection Script

Save as `detect-openclaw.ps1`:

```powershell
iwr -useb https://raw.githubusercontent.com/sun-security/openclaw-detector/main/windows/openclaw-detector.ps1 | iex
```

Alternatively, copy the full script contents for environments without internet access.

## Exit Code Reference

| Code | Intune Status | Description |
|------|---------------|-------------|
| 0 | Compliant | OpenClaw not present |
| 1 | Non-compliant | OpenClaw found |
| 2 | Error | Execution failed |

## Targeting Devices

1. Open **Assignments**
2. Select device groups to include
3. Configure run frequency (default is every 8 hours)

## Monitoring Results

1. Go to **Devices > Manage devices > Scripts and remediations**
2. Click on **OpenClaw Detection**
3. Check **Device status** for individual results
4. Use **Detection status: With issues** filter to locate affected devices

## Documentation

[Microsoft Learn - Remediations](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/remediations)
