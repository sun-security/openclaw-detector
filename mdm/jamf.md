# Jamf Pro Deployment

Use Jamf Pro Policies to run the OpenClaw detection script on managed macOS devices.

## Adding the Script

1. Open **Settings > Computer Management > Scripts**
2. Click **New**
3. Set **Display Name:** OpenClaw Detection
4. Paste this into the **Script** field:

```bash
#!/bin/bash
curl -sL https://raw.githubusercontent.com/sun-security/openclaw-detector/main/macos-linux/openclaw-detector.sh | bash
```

5. Save the script

## Creating the Policy

1. Navigate to **Computers > Policies**
2. Click **New**
3. Configure general settings:
   - **Display Name:** OpenClaw Detection
   - **Trigger:** Recurring Check-in
   - **Execution Frequency:** Once per day or Once per week
4. Under **Scripts** payload, click **Configure**
5. Add the **OpenClaw Detection** script
6. Set the **Scope** to target computers or groups
7. Save the policy

## Exit Code Reference

| Code | Description |
|------|-------------|
| 0 | OpenClaw not present |
| 1 | OpenClaw found |
| 2 | Execution failed |

## Checking Results

1. Open **Computers > Policies**
2. Select **OpenClaw Detection**
3. View the **Logs** tab for script output and exit codes

## Creating a Smart Group

Build a Smart Group to track devices where OpenClaw was detected:

1. Go to **Computers > Smart Computer Groups**
2. Click **New**
3. Set **Display Name:** OpenClaw Detected
4. Add criteria: **Policy Failed** is **OpenClaw Detection**

## Documentation

[Jamf Pro - Scripts](https://docs.jamf.com/10.27.0/jamf-pro/administrator-guide/Scripts.html)
