# Kandji Deployment

Kandji's Custom Scripts library item enables running detection scripts on managed Macs.

[Kandji - Custom Scripts](https://support.kandji.io/kb/custom-scripts-overview)

## Adding the Script

1. Go to **Library > Add New > Custom Scripts**
2. Configure settings:
   - **Name:** OpenClaw Detection
   - **Audit Script:** Enter the script below
   - **Remediation Script:** Leave empty
3. Save

## Audit Script

```bash
#!/bin/bash
curl -sL https://raw.githubusercontent.com/sun-security/openclaw-detector/main/macos-linux/openclaw-detector.sh | bash
```

For offline environments, paste the full script contents instead.

## Exit Code Reference

| Code     | Kandji Status | Description             |
| -------- | ------------- | ----------------------- |
| 0        | Pass          | OpenClaw not present    |
| Non-zero | Fail          | OpenClaw found or error |

## Assigning to Devices

1. Open **Blueprints**
2. Select your target Blueprint
3. Click **Add Library Item**
4. Choose **OpenClaw Detection**
5. Save changes

## Checking Results

1. Go to **Devices**
2. Select a device
3. Open the **Library Items** tab
4. Review **OpenClaw Detection** status:
   - **Pass:** OpenClaw not present
   - **Fail:** OpenClaw detected

## Finding Affected Devices

1. Navigate to **Devices**
2. Apply filter: **Library Item Status: Fail**
3. Select **OpenClaw Detection** from the dropdown
