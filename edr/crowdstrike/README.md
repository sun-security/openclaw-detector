# CrowdStrike Falcon - OpenClaw Detection

Detect OpenClaw installations across your fleet using CrowdStrike Falcon's API.

## How It Works

Unlike MDM scripts that run directly on endpoints, this script queries CrowdStrike's cloud APIs to find OpenClaw presence using telemetry already collected by Falcon sensors.

**Detection Methods:**
1. **Discover API** - Queries the installed applications inventory for apps matching OpenClaw patterns
2. **Host Tags** (thorough mode) - Checks host metadata for OpenClaw references

## Prerequisites

- CrowdStrike Falcon subscription with API access
- Python 3.8+
- API credentials with required scopes

## Setup

### 1. Create API Credentials

1. Go to [Falcon Console](https://falcon.crowdstrike.com) > **Support and Resources** > **API Clients and Keys**
2. Click **Create API Client**
3. Configure:
   - **Name**: `OpenClaw Scanner` (or your preference)
   - **Scopes**:
     - **Discover**: Read (required - for application inventory queries)
     - **Hosts**: Read (required - for host details)
4. Save the **Client ID** and **Client Secret**

### 2. Install Dependencies

```bash
pip install crowdstrike-falconpy
```

### 3. Configure Environment

```bash
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
```

For non-US-1 clouds:

```bash
# US-2
export FALCON_BASE_URL="https://api.us-2.crowdstrike.com"

# EU-1
export FALCON_BASE_URL="https://api.eu-1.crowdstrike.com"

# US-GOV-1
export FALCON_BASE_URL="https://api.laggar.gcw.crowdstrike.com"
```

For MSSP/parent-child CID scenarios:

```bash
export FALCON_MEMBER_CID="child-cid-here"
```

## Usage

### Basic Scan

```bash
python openclaw-detector.py
```

Output:
```
summary: detected
scan-time: 2024-01-15T10:30:00Z
total-hosts: 1247
hosts-with-openclaw: 3

# detections
host: dev-workstation-01
  installed_app: Application 'OpenClaw' found via Discover API (v2024.1.5)
host: eng-laptop-42
  installed_app: Application 'openclaw' found via Discover API (v2024.1.3)
host: contractor-mac-7
  installed_app: Application 'OpenClaw' found via Discover API (v2024.1.5)
```

### JSON Output

```bash
python openclaw-detector.py --json
```

### With Host Details

```bash
python openclaw-detector.py --host-details
```

Includes platform, OS version, last seen time, and host IDs.

### Thorough Scan

Includes additional checks via host tags (slower):

```bash
python openclaw-detector.py --thorough
```

### Save to File

```bash
python openclaw-detector.py --json --output report.json
```

## Exit Codes

| Code | Result | Interpretation |
|:----:|--------|----------------|
| 0 | Not detected | No OpenClaw found on any host |
| 1 | Detected | OpenClaw found on one or more hosts |
| 2 | Failure | API error or script failure |

## API Details

This script uses the following CrowdStrike Falcon APIs:

| API | Endpoint | Purpose |
|-----|----------|---------|
| Discover | `GET /discover/queries/applications/v1` | Query application IDs by name filter |
| Discover | `GET /discover/entities/applications/v1` | Get application details (name, version, vendor, host) |
| Hosts | `GET /devices/queries/devices/v1` | Query host IDs, get total count |
| Hosts | `GET /devices/entities/devices/v2` | Get host details (hostname, platform, OS) |

**FQL Filter Used:** `name:*'openclaw'*` (case variations searched separately)

## Automation

### Cron Job

```bash
# /etc/cron.d/openclaw-scan
0 6 * * * security /opt/scripts/openclaw-scan.sh >> /var/log/openclaw-scan.log 2>&1
```

`/opt/scripts/openclaw-scan.sh`:
```bash
#!/bin/bash
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
python3 /opt/openclaw-detector/openclaw-detector.py --json \
  --output "/var/log/openclaw-$(date +%Y%m%d).json"
```

### GitHub Actions

```yaml
name: OpenClaw Fleet Scan
on:
  schedule:
    - cron: '0 6 * * *'
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - run: pip install crowdstrike-falconpy

      - name: Run scan
        env:
          FALCON_CLIENT_ID: ${{ secrets.FALCON_CLIENT_ID }}
          FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
        run: python edr/crowdstrike/openclaw-detector.py --json --output report.json

      - uses: actions/upload-artifact@v4
        with:
          name: openclaw-report
          path: report.json
```

### SIEM Integration

```bash
python openclaw-detector.py --json | curl -X POST \
  -H "Content-Type: application/json" \
  -d @- \
  https://your-siem.example.com/api/events
```

## Limitations

| Limitation | Details |
|------------|---------|
| Sensor dependency | Only hosts with active Falcon sensors are scanned |
| Discover module required | Application inventory requires Falcon Discover module |
| Telemetry lag | Recently installed apps may not appear immediately |
| No live file scanning | Queries existing telemetry, not real-time file checks |
| API rate limits | Large fleets may hit limits (pagination built-in) |

## Comparison: MDM vs EDR

| Aspect | MDM Script | Falcon API |
|--------|-----------|------------|
| Runs on | Each endpoint | Central server |
| Data source | Live file system | Falcon telemetry |
| Scheduling | MDM platform | Your automation |
| Coverage | MDM-enrolled devices | Falcon-protected devices |
| Depth | Full file/process/service scan | Application inventory |
| Real-time | Yes | Near real-time (telemetry sync) |

For maximum coverage, use both if you have MDM and EDR deployed.

## Troubleshooting

### "401 Unauthorized"

- Verify credentials are correct
- Check API client hasn't been revoked
- Confirm correct `FALCON_BASE_URL` for your cloud

### "403 Forbidden"

- Ensure **Discover: Read** scope is enabled
- Ensure **Hosts: Read** scope is enabled

### No detections found

- Falcon Discover module may not be enabled
- Application inventory may not have synced
- Try `--thorough` for tag-based detection

### Rate limiting

- Script handles pagination automatically
- For very large fleets, add delays or contact CrowdStrike
