<h1 align="center">☀️ OpenClaw Detector</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Sun-Security-FF6B35?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PGNpcmNsZSBjeD0iMTIiIGN5PSIxMiIgcj0iNSIgZmlsbD0iI0ZGRDkzRCIvPjxwYXRoIGQ9Ik0xMiAxdjJtMCAxOHYybTExLTExaC0ybS0xOCAwSDFtMTYuOTUtNy4wNy0xLjQxIDEuNDFNNi4zNCAxNy42Nmw0LjI0LTQuMjRNMTcuNjYgMTcuNjZsLTEuNDEtMS40MU02LjM0IDYuMzRsMS40MSAxLjQxIiBzdHJva2U9IiNGRkQ5M0QiIHN0cm9rZS13aWR0aD0iMiIvPjwvc3ZnPg==&logoColor=FFD93D" alt="Sun Security">
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-FFD93D?style=for-the-badge" alt="Platforms">
  <img src="https://img.shields.io/badge/License-MIT-FF8C42?style=for-the-badge" alt="License">
</p>

<p align="center">
  <b>Identify OpenClaw installations across your managed fleet.</b><br>
  Lightweight scanning scripts for macOS, Linux, and Windows — built for MDM platforms.
</p>

---

## Overview

OpenClaw Detector provides ready-to-deploy scripts that scan endpoints for OpenClaw presence. The scripts examine CLI binaries, application bundles, configuration directories, background services, and container artifacts.

**Built by [Sun Security](https://github.com/sun-security)** — securing AI agents across your organization.

---

## What Gets Scanned

### Core Detection (affects exit code)

| Item | macOS | Linux | Windows |
|------|:-----:|:-----:|:-------:|
| State folder (`~/.openclaw`) | ✓ | ✓ | ✓ |
| CLI executable | ✓ | ✓ | ✓ |
| Version info | ✓ | ✓ | ✓ |
| Config files | ✓ | ✓ | ✓ |
| App bundle (`.app`) | ✓ | — | — |
| Gateway service | ✓ | ✓ | ✓ |
| Gateway port | ✓ | ✓ | ✓ |
| Docker images | ✓ | ✓ | ✓ |
| Docker containers | ✓ | ✓ | ✓ |

### Supplementary Checks (informational only)

| Item | macOS | Linux | Windows |
|------|:-----:|:-----:|:-------:|
| Active processes | ✓ | ✓ | ✓ |
| Environment variables | ✓ | ✓ | — |
| Shell RC files | ✓ | ✓ | — |
| Homebrew packages | ✓ | — | — |
| Launchd agents/daemons | ✓ | — | — |
| Login items | ✓ | — | — |
| Systemd units | — | ✓ | — |
| Init.d scripts | — | ✓ | — |
| Cron jobs | — | ✓ | — |
| Package managers (dpkg, rpm, pacman, snap, flatpak, nix) | — | ✓ | — |
| Windows services | — | — | ✓ |
| Registry entries | — | — | ✓ |
| WSL instances | — | — | ✓ |

---

## Quick Start

### macOS / Linux

```bash
curl -sL https://raw.githubusercontent.com/sun-security/openclaw-detector/main/macos-linux/openclaw-detector.sh | bash
```

### Windows (PowerShell)

```powershell
iwr -useb https://raw.githubusercontent.com/sun-security/openclaw-detector/main/windows/openclaw-detector.ps1 | iex
```

### Scan All Users (requires elevated privileges)

```bash
curl -sL https://raw.githubusercontent.com/sun-security/openclaw-detector/main/macos-linux/openclaw-detector.sh | sudo bash
```

---

## Exit Codes

| Code | Result | MDM Interpretation |
|:----:|--------|-------------------|
| 0 | Not found | Compliant |
| 1 | Detected | Non-compliant |
| 2 | Scan failed | Requires investigation |

---

## Configuration

| Environment Variable | Default | Purpose |
|---------------------|---------|---------|
| `OPENCLAW_PROFILE` | — | Target a specific profile in multi-instance setups |
| `OPENCLAW_GATEWAY_PORT` | 18789 | Custom gateway port to probe |

---

## Sample Output

```
summary: installed-and-running
platform: darwin
cli: /usr/local/bin/openclaw
cli-version: 2026.1.15
app: /Applications/OpenClaw.app
state-dir: /Users/developer/.openclaw
config: /Users/developer/.openclaw/openclaw.json
gateway-service: gui/501/bot.molt.gateway
gateway-port: 18789
docker-container: not-found
docker-image: not-found
```

---

## MDM Deployment Guides

| Platform | Documentation |
|----------|---------------|
| Jamf Pro | [mdm/jamf.md](mdm/jamf.md) |
| Microsoft Intune | [mdm/intune.md](mdm/intune.md) |
| JumpCloud | [mdm/jumpcloud.md](mdm/jumpcloud.md) |
| Kandji | [mdm/kandji.md](mdm/kandji.md) |
| VMware Workspace ONE | [mdm/workspace-one.md](mdm/workspace-one.md) |

---

## Project Structure

```
openclaw-detector/
├── macos-linux/
│   └── openclaw-detector.sh    # Bash script for macOS and Linux
├── windows/
│   └── openclaw-detector.ps1   # PowerShell script for Windows
└── mdm/
    ├── intune.md               # Microsoft Intune guide
    ├── jamf.md                 # Jamf Pro guide
    ├── jumpcloud.md            # JumpCloud guide
    ├── kandji.md               # Kandji guide
    └── workspace-one.md        # Workspace ONE guide
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Made with ☀️ by <a href="https://github.com/sun-security">Sun Security</a></sub>
</p>
