# OpenClaw Detection Script for MDM deployment (Windows)
# Exit codes: 0=not-installed (clean), 1=found (non-compliant), 2=error

$ErrorActionPreference = "Stop"

$script:Profile = $env:OPENCLAW_PROFILE
$Port = if ($env:OPENCLAW_GATEWAY_PORT) { $env:OPENCLAW_GATEWAY_PORT } else { 18789 }
$script:Output = [System.Collections.ArrayList]::new()

function Write-DetectionOutput {
    param([string]$Line)
    [void]$script:Output.Add($Line)
}

# --- Path & Directory Helpers ---

function Resolve-OpenClawStateDir {
    param([string]$HomeDir)
    if ($script:Profile) {
        return Join-Path $HomeDir ".openclaw-$($script:Profile)"
    }
    return Join-Path $HomeDir ".openclaw"
}

function Resolve-OpenClawHomeDir {
    param([string]$User)
    return "C:\Users\$User"
}

function Get-OpenClawTargetUsers {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544') {
        Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } | ForEach-Object { $_.Name }
    } else {
        $env:USERNAME
    }
}

# --- CLI Detection ---

function Find-OpenClawCliInPath {
    try {
        $cmd = Get-Command openclaw -ErrorAction SilentlyContinue
        if ($cmd) {
            return $cmd.Source
        }
    } catch {}
    return $null
}

function Find-OpenClawCliGlobal {
    $locations = @(
        "C:\Program Files\openclaw\openclaw.exe",
        "C:\Program Files (x86)\openclaw\openclaw.exe"
    )
    foreach ($loc in $locations) {
        if (Test-Path $loc) {
            return $loc
        }
    }
    return $null
}

function Find-OpenClawCliForUser {
    param([string]$HomeDir)
    $locations = @(
        (Join-Path $HomeDir "AppData\Local\Programs\openclaw\openclaw.exe"),
        (Join-Path $HomeDir "AppData\Roaming\npm\openclaw.cmd"),
        (Join-Path $HomeDir "AppData\Local\pnpm\openclaw.cmd"),
        (Join-Path $HomeDir ".volta\bin\openclaw.exe"),
        (Join-Path $HomeDir "scoop\shims\openclaw.exe")
    )
    foreach ($loc in $locations) {
        if (Test-Path $loc) {
            return $loc
        }
    }
    return $null
}

function Get-OpenClawCliVersion {
    param([string]$CliPath)
    try {
        $version = & $CliPath --version 2>$null | Select-Object -First 1
        if ($version) { return $version }
    } catch {}
    return "unknown"
}

# --- State & Config Detection ---

function Test-OpenClawStateDir {
    param([string]$Path)
    return Test-Path $Path -PathType Container
}

function Test-OpenClawConfig {
    param([string]$StateDir)
    return Test-Path (Join-Path $StateDir "openclaw.json") -PathType Leaf
}

function Get-OpenClawConfiguredPort {
    param([string]$ConfigFile)
    if (Test-Path $ConfigFile) {
        try {
            $content = Get-Content $ConfigFile -Raw
            if ($content -match '"port"\s*:\s*(\d+)') {
                return $matches[1]
            }
        } catch {}
    }
    return $null
}

# --- Service & Runtime Detection ---

function Find-OpenClawScheduledTask {
    $taskName = if ($script:Profile) { "OpenClaw Gateway $($script:Profile)" } else { "OpenClaw Gateway" }
    try {
        $null = schtasks /Query /TN $taskName 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $taskName
        }
    } catch {}
    return $null
}

function Test-OpenClawGatewayPort {
    param([int]$PortNum)
    try {
        $result = Test-NetConnection -ComputerName localhost -Port $PortNum -WarningAction SilentlyContinue
        return $result.TcpTestSucceeded
    } catch {
        return $false
    }
}

# --- Docker Detection ---

function Find-OpenClawDockerContainers {
    try {
        $cmd = Get-Command docker -ErrorAction SilentlyContinue
        if (-not $cmd) { return $null }
        $containers = docker ps --format '{{.Names}} ({{.Image}})' 2>$null | Select-String -Pattern "openclaw" -SimpleMatch
        if ($containers) {
            return ($containers -join ", ")
        }
    } catch {}
    return $null
}

function Find-OpenClawDockerImages {
    try {
        $cmd = Get-Command docker -ErrorAction SilentlyContinue
        if (-not $cmd) { return $null }
        $images = docker images --format '{{.Repository}}:{{.Tag}}' 2>$null | Select-String -Pattern "openclaw" -SimpleMatch
        if ($images) {
            return ($images -join ", ")
        }
    } catch {}
    return $null
}

# --- Supplementary Checks (informational only, do not affect exit code) ---

function Find-OpenClawRunningProcesses {
    try {
        $procs = Get-Process -Name "*openclaw*" -ErrorAction SilentlyContinue
        if ($procs) {
            return ($procs | ForEach-Object { "$($_.Name) (PID: $($_.Id))" }) -join ", "
        }
    } catch {}
    return $null
}

function Find-OpenClawWindowsServices {
    try {
        $services = Get-Service -Name "*openclaw*" -ErrorAction SilentlyContinue
        if ($services) {
            return ($services | ForEach-Object { "$($_.Name) ($($_.Status))" }) -join ", "
        }
    } catch {}
    return $null
}

function Find-OpenClawRegistryEntries {
    $found = @()
    # Check dedicated registry paths
    $registryPaths = @(
        "HKLM:\SOFTWARE\OpenClaw",
        "HKLM:\SOFTWARE\WOW6432Node\OpenClaw",
        "HKCU:\SOFTWARE\OpenClaw"
    )
    foreach ($path in $registryPaths) {
        try {
            if (Test-Path $path) {
                $found += $path
            }
        } catch {}
    }
    # Check uninstall entries for installed programs
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($basePath in $uninstallPaths) {
        try {
            if (Test-Path $basePath) {
                $keys = Get-ChildItem $basePath -ErrorAction SilentlyContinue
                foreach ($key in $keys) {
                    try {
                        $displayName = (Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue).DisplayName
                        if ($displayName -and $displayName -match "openclaw") {
                            $found += "$($key.PSChildName) ($displayName)"
                        }
                    } catch {}
                }
            }
        } catch {}
    }
    if ($found.Count -gt 0) {
        return $found -join ", "
    }
    return $null
}

function Find-OpenClawInWsl {
    try {
        $cmd = Get-Command wsl -ErrorAction SilentlyContinue
        if (-not $cmd) { return $null }

        # Check if WSL is available and has distros
        $distros = wsl --list --quiet 2>$null
        if (-not $distros -or $LASTEXITCODE -ne 0) { return $null }

        $found = @()
        foreach ($distro in $distros) {
            $distro = $distro.Trim()
            if (-not $distro) { continue }
            try {
                # Check for openclaw CLI in WSL
                $cliResult = wsl -d $distro -- command -v openclaw 2>$null
                if ($cliResult -and $LASTEXITCODE -eq 0) {
                    $found += "${distro}: cli at $cliResult"
                }
                # Check for state directory in WSL
                $stateResult = wsl -d $distro -- bash -c 'test -d ~/.openclaw && echo "found"' 2>$null
                if ($stateResult -eq "found" -and $LASTEXITCODE -eq 0) {
                    $found += "${distro}: state-dir"
                }
            } catch {}
        }
        if ($found.Count -gt 0) {
            return $found -join ", "
        }
    } catch {}
    return $null
}

# --- Main Detection Logic ---

function Invoke-OpenClawDetection {
    $cliFound = $false
    $stateFound = $false
    $serviceRunning = $false
    $portListening = $false

    Write-DetectionOutput "platform: windows"

    # Check global CLI locations first
    $cliPath = Find-OpenClawCliInPath
    if (-not $cliPath) { $cliPath = Find-OpenClawCliGlobal }
    if ($cliPath) {
        $cliFound = $true
        Write-DetectionOutput "cli: $cliPath"
        Write-DetectionOutput "cli-version: $(Get-OpenClawCliVersion $cliPath)"
    }

    $users = @(Get-OpenClawTargetUsers)
    $multiUser = $users.Count -gt 1
    $portsToCheck = @($Port)

    foreach ($user in $users) {
        $homeDir = Resolve-OpenClawHomeDir $user
        $stateDir = Resolve-OpenClawStateDir $homeDir
        $configFile = Join-Path $stateDir "openclaw.json"

        if ($multiUser) {
            Write-DetectionOutput "user: $user"
            # Check user-specific CLI if not already found
            if (-not $cliFound) {
                $userCli = Find-OpenClawCliForUser $homeDir
                if ($userCli) {
                    $cliFound = $true
                    Write-DetectionOutput "  cli: $userCli"
                    Write-DetectionOutput "  cli-version: $(Get-OpenClawCliVersion $userCli)"
                }
            }
            if (Test-OpenClawStateDir $stateDir) {
                Write-DetectionOutput "  state-dir: $stateDir"
                $stateFound = $true
            } else {
                Write-DetectionOutput "  state-dir: not-found"
            }
            if (Test-OpenClawConfig $stateDir) {
                Write-DetectionOutput "  config: $configFile"
            } else {
                Write-DetectionOutput "  config: not-found"
            }
            $configPort = Get-OpenClawConfiguredPort $configFile
            if ($configPort) {
                Write-DetectionOutput "  config-port: $configPort"
                $portsToCheck += [int]$configPort
            }
        } else {
            # Single user mode - check user CLI
            if (-not $cliFound) {
                $userCli = Find-OpenClawCliForUser $homeDir
                if ($userCli) {
                    $cliFound = $true
                    Write-DetectionOutput "cli: $userCli"
                    Write-DetectionOutput "cli-version: $(Get-OpenClawCliVersion $userCli)"
                }
            }
            if (-not $cliFound) {
                Write-DetectionOutput "cli: not-found"
                Write-DetectionOutput "cli-version: n/a"
            }
            if (Test-OpenClawStateDir $stateDir) {
                Write-DetectionOutput "state-dir: $stateDir"
                $stateFound = $true
            } else {
                Write-DetectionOutput "state-dir: not-found"
            }
            if (Test-OpenClawConfig $stateDir) {
                Write-DetectionOutput "config: $configFile"
            } else {
                Write-DetectionOutput "config: not-found"
            }
            $configPort = Get-OpenClawConfiguredPort $configFile
            if ($configPort) {
                Write-DetectionOutput "config-port: $configPort"
                $portsToCheck += [int]$configPort
            }
        }
    }

    # Print cli not-found for multi-user if none found
    if ($multiUser -and -not $cliFound) {
        Write-DetectionOutput "cli: not-found"
        Write-DetectionOutput "cli-version: n/a"
    }

    $taskResult = Find-OpenClawScheduledTask
    if ($taskResult) {
        Write-DetectionOutput "gateway-service: $taskResult"
        $serviceRunning = $true
    } else {
        Write-DetectionOutput "gateway-service: not-scheduled"
    }

    $uniquePorts = $portsToCheck | Sort-Object -Unique
    $listeningPort = $null
    foreach ($p in $uniquePorts) {
        if (Test-OpenClawGatewayPort $p) {
            $portListening = $true
            $listeningPort = $p
            break
        }
    }
    if ($portListening) {
        Write-DetectionOutput "gateway-port: $listeningPort"
    } else {
        Write-DetectionOutput "gateway-port: not-listening"
    }

    $dockerContainers = Find-OpenClawDockerContainers
    $dockerRunning = $false
    if ($dockerContainers) {
        $dockerRunning = $true
        Write-DetectionOutput "docker-container: $dockerContainers"
    } else {
        Write-DetectionOutput "docker-container: not-found"
    }

    $dockerImages = Find-OpenClawDockerImages
    $dockerInstalled = $false
    if ($dockerImages) {
        $dockerInstalled = $true
        Write-DetectionOutput "docker-image: $dockerImages"
    } else {
        Write-DetectionOutput "docker-image: not-found"
    }

    # --- Supplementary checks (informational only, do not affect exit code) ---
    Write-DetectionOutput "# supplementary-checks (informational only)"

    $processResult = Find-OpenClawRunningProcesses
    if ($processResult) {
        Write-DetectionOutput "info-process: $processResult"
    } else {
        Write-DetectionOutput "info-process: none-found"
    }

    $serviceResult = Find-OpenClawWindowsServices
    if ($serviceResult) {
        Write-DetectionOutput "info-windows-service: $serviceResult"
    } else {
        Write-DetectionOutput "info-windows-service: none-found"
    }

    $registryResult = Find-OpenClawRegistryEntries
    if ($registryResult) {
        Write-DetectionOutput "info-registry: $registryResult"
    } else {
        Write-DetectionOutput "info-registry: none-found"
    }

    $wslResult = Find-OpenClawInWsl
    if ($wslResult) {
        Write-DetectionOutput "info-wsl: $wslResult"
    } else {
        Write-DetectionOutput "info-wsl: none-found"
    }

    $installed = $cliFound -or $stateFound -or $dockerInstalled
    $running = $serviceRunning -or $portListening -or $dockerRunning

    # Exit codes: 0=not-installed (clean), 1=found (non-compliant), 2=error
    if (-not $installed) {
        Write-Output "summary: not-installed"
        $script:Output | ForEach-Object { Write-Output $_ }
        exit 0
    } elseif ($running) {
        Write-Output "summary: installed-and-running"
        $script:Output | ForEach-Object { Write-Output $_ }
        exit 1
    } else {
        Write-Output "summary: installed-not-running"
        $script:Output | ForEach-Object { Write-Output $_ }
        exit 1
    }
}

try {
    Invoke-OpenClawDetection
} catch {
    Write-Output "summary: error"
    Write-Output "error: $_"
    exit 2
}
