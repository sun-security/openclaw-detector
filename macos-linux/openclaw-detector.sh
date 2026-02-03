#!/usr/bin/env bash
# OpenClaw Presence Scanner - MDM Deployment Edition (macOS/Linux)
# Returns: 0=clean (compliant), 1=detected (action needed), 2=failure

set -euo pipefail

ACTIVE_PROFILE="${OPENCLAW_PROFILE:-}"
GATEWAY_PORT="${OPENCLAW_GATEWAY_PORT:-18789}"

# --- OS Identification ---

identify_os() {
  case "$(uname -s)" in
    Darwin) printf "darwin" ;;
    Linux) printf "linux" ;;
    *) printf "unknown" ;;
  esac
}

# --- Directory Resolution ---

build_state_path() {
  local base_home="$1"
  if [[ -n "$ACTIVE_PROFILE" ]]; then
    printf "%s/.openclaw-%s" "$base_home" "$ACTIVE_PROFILE"
  else
    printf "%s/.openclaw" "$base_home"
  fi
}

derive_home_path() {
  local username="$1"
  local os_type="$2"
  case "$os_type" in
    darwin) printf "/Users/%s" "$username" ;;
    linux) printf "/home/%s" "$username" ;;
  esac
}

enumerate_users() {
  local os_type="$1"
  if [[ $EUID -eq 0 ]]; then
    case "$os_type" in
      darwin)
        for entry in /Users/*; do
          [[ -d "$entry" && "$(basename "$entry")" != "Shared" ]] && basename "$entry"
        done
        ;;
      linux)
        for entry in /home/*; do
          [[ -d "$entry" ]] && basename "$entry"
        done
        ;;
    esac
  else
    whoami
  fi
}

# --- Binary Location ---

locate_in_system_path() {
  local binary_path
  binary_path=$(command -v openclaw 2>/dev/null) || true
  if [[ -n "$binary_path" ]]; then
    printf "%s" "$binary_path"
    return 0
  fi
  return 1
}

locate_in_user_dirs() {
  local user_home="$1"
  local search_paths=(
    "${user_home}/.volta/bin/openclaw"
    "${user_home}/.local/bin/openclaw"
    "${user_home}/.nvm/current/bin/openclaw"
    "${user_home}/bin/openclaw"
    "${user_home}/.cargo/bin/openclaw"
    "${user_home}/.asdf/shims/openclaw"
    "${user_home}/.mise/shims/openclaw"
    "${user_home}/.nix-profile/bin/openclaw"
  )
  for candidate in "${search_paths[@]}"; do
    if [[ -x "$candidate" ]]; then
      printf "%s" "$candidate"
      return 0
    fi
  done
  return 1
}

locate_in_system_dirs() {
  local search_paths=(
    "/usr/local/bin/openclaw"
    "/opt/homebrew/bin/openclaw"
    "/usr/bin/openclaw"
    "/opt/openclaw/bin/openclaw"
    "/snap/bin/openclaw"
    "/nix/var/nix/profiles/default/bin/openclaw"
  )
  for candidate in "${search_paths[@]}"; do
    if [[ -x "$candidate" ]]; then
      printf "%s" "$candidate"
      return 0
    fi
  done
  return 1
}

# --- macOS Application Bundle ---

locate_macos_application() {
  local bundle_paths=(
    "/Applications/OpenClaw.app"
    "$HOME/Applications/OpenClaw.app"
  )
  for bundle in "${bundle_paths[@]}"; do
    if [[ -d "$bundle" ]]; then
      printf "%s" "$bundle"
      return 0
    fi
  done
  printf "not-found"
  return 1
}

# --- Configuration & State ---

verify_state_directory() {
  local dir_path="$1"
  if [[ -d "$dir_path" ]]; then
    printf "%s" "$dir_path"
    return 0
  else
    printf "not-found"
    return 1
  fi
}

verify_config_file() {
  local cfg_path="${1}/openclaw.json"
  if [[ -f "$cfg_path" ]]; then
    printf "%s" "$cfg_path"
  else
    printf "not-found"
  fi
}

extract_port_from_config() {
  local cfg_file="$1"
  if [[ -f "$cfg_file" ]]; then
    grep -o '"port"[[:space:]]*:[[:space:]]*[0-9]*' "$cfg_file" 2>/dev/null | head -1 | grep -o '[0-9]*$' || true
  fi
}

# --- Service Detection ---

check_launchd_agent() {
  local svc_label uid
  uid=$(id -u)
  if [[ -n "$ACTIVE_PROFILE" ]]; then
    svc_label="bot.molt.${ACTIVE_PROFILE}"
  else
    svc_label="bot.molt.gateway"
  fi
  if launchctl print "gui/${uid}/${svc_label}" &>/dev/null; then
    printf "gui/%s/%s" "$uid" "$svc_label"
    return 0
  else
    printf "not-loaded"
    return 1
  fi
}

check_systemd_unit() {
  local unit_name
  if [[ -n "$ACTIVE_PROFILE" ]]; then
    unit_name="openclaw-gateway-${ACTIVE_PROFILE}.service"
  else
    unit_name="openclaw-gateway.service"
  fi
  if systemctl --user is-active "$unit_name" &>/dev/null; then
    printf "%s" "$unit_name"
    return 0
  else
    printf "inactive"
    return 1
  fi
}

probe_gateway_port() {
  local port_num="$1"
  if nc -z localhost "$port_num" &>/dev/null; then
    printf "listening"
    return 0
  else
    printf "not-listening"
    return 1
  fi
}

# --- Container Detection ---

scan_docker_containers() {
  if ! command -v docker &>/dev/null; then
    return 0
  fi
  docker ps --format '{{.Names}} ({{.Image}})' 2>/dev/null | grep -i openclaw || true
}

scan_docker_images() {
  if ! command -v docker &>/dev/null; then
    return 0
  fi
  docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -i openclaw || true
}

# --- Supplementary Scans (informational, no impact on result) ---

scan_active_processes() {
  local matches=""
  if command -v pgrep &>/dev/null; then
    matches=$(pgrep -l -i openclaw 2>/dev/null | tr '\n' ', ' | sed 's/, $//') || true
  fi
  if [[ -z "$matches" ]]; then
    matches=$(ps aux 2>/dev/null | grep -i '[o]penclaw' | awk '{print $11 " (PID:" $2 ")"}' | tr '\n' ', ' | sed 's/, $//') || true
  fi
  printf "%s" "$matches"
}

scan_homebrew_installations() {
  if ! command -v brew &>/dev/null; then
    return 0
  fi
  local matches=""
  local formula_list
  formula_list=$(brew list --formula 2>/dev/null | grep -i openclaw) || true
  if [[ -n "$formula_list" ]]; then
    matches="formula: $formula_list"
  fi
  local cask_list
  cask_list=$(brew list --cask 2>/dev/null | grep -i openclaw) || true
  if [[ -n "$cask_list" ]]; then
    [[ -n "$matches" ]] && matches+=", "
    matches+="cask: $cask_list"
  fi
  printf "%s" "$matches"
}

scan_linux_package_managers() {
  local matches=""

  if command -v dpkg &>/dev/null; then
    local dpkg_hits
    dpkg_hits=$(dpkg -l 2>/dev/null | grep -i openclaw | awk '{print $2}') || true
    if [[ -n "$dpkg_hits" ]]; then
      matches+="dpkg: $dpkg_hits, "
    fi
  fi

  if command -v rpm &>/dev/null; then
    local rpm_hits
    rpm_hits=$(rpm -qa 2>/dev/null | grep -i openclaw) || true
    if [[ -n "$rpm_hits" ]]; then
      matches+="rpm: $rpm_hits, "
    fi
  fi

  if command -v pacman &>/dev/null; then
    local pacman_hits
    pacman_hits=$(pacman -Q 2>/dev/null | grep -i openclaw | awk '{print $1}') || true
    if [[ -n "$pacman_hits" ]]; then
      matches+="pacman: $pacman_hits, "
    fi
  fi

  if command -v snap &>/dev/null; then
    local snap_hits
    snap_hits=$(snap list 2>/dev/null | grep -i openclaw | awk '{print $1}') || true
    if [[ -n "$snap_hits" ]]; then
      matches+="snap: $snap_hits, "
    fi
  fi

  if command -v flatpak &>/dev/null; then
    local flatpak_hits
    flatpak_hits=$(flatpak list 2>/dev/null | grep -i openclaw | awk '{print $1}') || true
    if [[ -n "$flatpak_hits" ]]; then
      matches+="flatpak: $flatpak_hits, "
    fi
  fi

  if command -v nix-env &>/dev/null; then
    local nix_hits
    nix_hits=$(nix-env -q 2>/dev/null | grep -i openclaw) || true
    if [[ -n "$nix_hits" ]]; then
      matches+="nix: $nix_hits, "
    fi
  fi

  printf "%s" "${matches%, }"
}

scan_all_launchd_items() {
  local matches=""
  local uid
  uid=$(id -u)

  local agent_list
  agent_list=$(launchctl list 2>/dev/null | grep -i openclaw | awk '{print $3}') || true
  if [[ -n "$agent_list" ]]; then
    matches+="user: $agent_list, "
  fi

  local plist_dirs=(
    "$HOME/Library/LaunchAgents"
    "/Library/LaunchAgents"
    "/Library/LaunchDaemons"
    "/System/Library/LaunchAgents"
    "/System/Library/LaunchDaemons"
  )
  for dir in "${plist_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
      local found_plists
      found_plists=$(find "$dir" -name "*openclaw*" -o -name "*OpenClaw*" 2>/dev/null | xargs -I{} basename {} 2>/dev/null | tr '\n' ' ') || true
      if [[ -n "$found_plists" ]]; then
        matches+="$(basename "$dir"): $found_plists, "
      fi
    fi
  done

  printf "%s" "${matches%, }"
}

scan_all_systemd_units() {
  local matches=""

  local user_units
  user_units=$(systemctl --user list-units --all 2>/dev/null | grep -i openclaw | awk '{print $1}') || true
  if [[ -n "$user_units" ]]; then
    matches+="user: $user_units, "
  fi

  local system_units
  system_units=$(systemctl list-units --all 2>/dev/null | grep -i openclaw | awk '{print $1}') || true
  if [[ -n "$system_units" ]]; then
    matches+="system: $system_units, "
  fi

  local unit_dirs=(
    "$HOME/.config/systemd/user"
    "/etc/systemd/system"
    "/etc/systemd/user"
    "/usr/lib/systemd/system"
    "/usr/lib/systemd/user"
  )
  for dir in "${unit_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
      local found_units
      found_units=$(find "$dir" -name "*openclaw*" 2>/dev/null | xargs -I{} basename {} 2>/dev/null | tr '\n' ' ') || true
      if [[ -n "$found_units" ]]; then
        matches+="$(basename "$dir"): $found_units, "
      fi
    fi
  done

  printf "%s" "${matches%, }"
}

scan_initd_entries() {
  local matches=""
  local initd_dirs=(
    "/etc/init.d"
    "/etc/rc.d"
  )
  for dir in "${initd_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
      local found_scripts
      found_scripts=$(find "$dir" -name "*openclaw*" 2>/dev/null | xargs -I{} basename {} 2>/dev/null | tr '\n' ' ') || true
      if [[ -n "$found_scripts" ]]; then
        matches+="$dir: $found_scripts, "
      fi
    fi
  done
  printf "%s" "${matches%, }"
}

scan_cron_entries() {
  local matches=""

  local user_cron
  user_cron=$(crontab -l 2>/dev/null | grep -i openclaw) || true
  if [[ -n "$user_cron" ]]; then
    matches+="user-crontab: found, "
  fi

  local cron_dirs=(
    "/etc/cron.d"
    "/etc/cron.daily"
    "/etc/cron.hourly"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
  )
  for dir in "${cron_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
      local found_cron
      found_cron=$(find "$dir" -name "*openclaw*" 2>/dev/null | xargs -I{} basename {} 2>/dev/null | tr '\n' ' ') || true
      if [[ -n "$found_cron" ]]; then
        matches+="$(basename "$dir"): $found_cron, "
      fi
    fi
  done

  printf "%s" "${matches%, }"
}

scan_macos_login_items() {
  local matches=""

  local login_item_list
  login_item_list=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | tr ',' '\n' | grep -i openclaw | tr '\n' ', ' | sed 's/, $//') || true
  if [[ -n "$login_item_list" ]]; then
    matches+="login-items: $login_item_list, "
  fi

  local autostart_agents
  autostart_agents=$(find "$HOME/Library/LaunchAgents" /Library/LaunchAgents -name "*.plist" 2>/dev/null | while read -r plist; do
    if grep -qi "openclaw" "$plist" 2>/dev/null; then
      basename "$plist"
    fi
  done | tr '\n' ', ' | sed 's/, $//') || true
  if [[ -n "$autostart_agents" ]]; then
    matches+="launch-agents: $autostart_agents, "
  fi

  printf "%s" "${matches%, }"
}

scan_environment_vars() {
  local matches=""
  local env_list
  env_list=$(env 2>/dev/null | grep -i "^OPENCLAW" | tr '\n' ', ' | sed 's/, $//') || true
  if [[ -n "$env_list" ]]; then
    matches="$env_list"
  fi
  printf "%s" "$matches"
}

scan_shell_rc_files() {
  local matches=""
  local rc_files=(
    "$HOME/.bashrc"
    "$HOME/.bash_profile"
    "$HOME/.zshrc"
    "$HOME/.zprofile"
    "$HOME/.profile"
    "$HOME/.config/fish/config.fish"
  )
  for rcfile in "${rc_files[@]}"; do
    if [[ -f "$rcfile" ]]; then
      if grep -qi "openclaw" "$rcfile" 2>/dev/null; then
        matches+="$(basename "$rcfile"), "
      fi
    fi
  done
  printf "%s" "${matches%, }"
}

# --- Primary Scan Routine ---

execute_scan() {
  local os_type binary_located=false app_located=false state_exists=false svc_active=false port_open=false
  local report=""

  append() { report+="$1"$'\n'; }

  os_type=$(identify_os)
  append "platform: $os_type"

  if [[ "$os_type" == "unknown" ]]; then
    echo "summary: error"
    printf "%s" "$report"
    exit 2
  fi

  local binary_path=""
  binary_path=$(locate_in_system_path) || binary_path=$(locate_in_system_dirs) || true
  if [[ -n "$binary_path" ]]; then
    binary_located=true
    append "cli: $binary_path"
    append "cli-version: $("$binary_path" --version 2>/dev/null | head -1 || echo "unknown")"
  fi

  if [[ "$os_type" == "darwin" ]]; then
    local app_path
    app_path=$(locate_macos_application) && app_located=true || app_located=false
    append "app: $app_path"
  fi

  local user_list
  user_list=$(enumerate_users "$os_type")
  local multi_user_mode=false
  local total_users
  total_users=$(echo "$user_list" | wc -l | tr -d ' ')
  [[ $total_users -gt 1 ]] && multi_user_mode=true

  local ports_to_scan="$GATEWAY_PORT"

  for acct in $user_list; do
    local home_path state_path
    home_path=$(derive_home_path "$acct" "$os_type")
    state_path=$(build_state_path "$home_path")

    if $multi_user_mode; then
      append "user: $acct"
      if ! $binary_located; then
        local user_binary
        user_binary=$(locate_in_user_dirs "$home_path") || true
        if [[ -n "$user_binary" ]]; then
          binary_located=true
          append "  cli: $user_binary"
          append "  cli-version: $("$user_binary" --version 2>/dev/null | head -1 || echo "unknown")"
        fi
      fi
      local state_check
      state_check=$(verify_state_directory "$state_path") && state_exists=true
      append "  state-dir: $state_check"
      local config_check
      config_check=$(verify_config_file "$state_path")
      append "  config: $config_check"
      local cfg_port
      cfg_port=$(extract_port_from_config "${state_path}/openclaw.json")
      if [[ -n "$cfg_port" ]]; then
        append "  config-port: $cfg_port"
        ports_to_scan="$ports_to_scan $cfg_port"
      fi
    else
      if ! $binary_located; then
        local user_binary
        user_binary=$(locate_in_user_dirs "$home_path") || true
        if [[ -n "$user_binary" ]]; then
          binary_located=true
          append "cli: $user_binary"
          append "cli-version: $("$user_binary" --version 2>/dev/null | head -1 || echo "unknown")"
        fi
      fi
      if ! $binary_located; then
        append "cli: not-found"
        append "cli-version: n/a"
      fi
      local state_check
      state_check=$(verify_state_directory "$state_path") && state_exists=true
      append "state-dir: $state_check"
      append "config: $(verify_config_file "$state_path")"
      local cfg_port
      cfg_port=$(extract_port_from_config "${state_path}/openclaw.json")
      if [[ -n "$cfg_port" ]]; then
        append "config-port: $cfg_port"
        ports_to_scan="$ports_to_scan $cfg_port"
      fi
    fi
  done

  if $multi_user_mode && ! $binary_located; then
    append "cli: not-found"
    append "cli-version: n/a"
  fi

  case "$os_type" in
    darwin)
      local svc_check
      svc_check=$(check_launchd_agent) && svc_active=true || svc_active=false
      append "gateway-service: $svc_check"
      ;;
    linux)
      local svc_check
      svc_check=$(check_systemd_unit) && svc_active=true || svc_active=false
      append "gateway-service: $svc_check"
      ;;
  esac

  local dedupe_ports active_port=""
  dedupe_ports=$(echo "$ports_to_scan" | tr ' ' '\n' | sort -u | tr '\n' ' ')
  for p in $dedupe_ports; do
    if probe_gateway_port "$p" >/dev/null; then
      port_open=true
      active_port="$p"
      break
    fi
  done
  if $port_open; then
    append "gateway-port: $active_port"
  else
    append "gateway-port: not-listening"
  fi

  local running_containers found_images container_active=false images_present=false
  running_containers=$(scan_docker_containers)
  if [[ -n "$running_containers" ]]; then
    container_active=true
    append "docker-container: $running_containers"
  else
    append "docker-container: not-found"
  fi

  found_images=$(scan_docker_images)
  if [[ -n "$found_images" ]]; then
    images_present=true
    append "docker-image: $found_images"
  else
    append "docker-image: not-found"
  fi

  # --- Extra checks (informational, no exit code impact) ---
  append "# supplementary-checks (informational only)"

  local proc_scan
  proc_scan=$(scan_active_processes) || true
  if [[ -n "$proc_scan" ]]; then
    append "info-process: $proc_scan"
  else
    append "info-process: none-found"
  fi

  case "$os_type" in
    darwin)
      local brew_scan
      brew_scan=$(scan_homebrew_installations) || true
      if [[ -n "$brew_scan" ]]; then
        append "info-homebrew: $brew_scan"
      else
        append "info-homebrew: none-found"
      fi

      local launchd_scan
      launchd_scan=$(scan_all_launchd_items) || true
      if [[ -n "$launchd_scan" ]]; then
        append "info-launchd: $launchd_scan"
      else
        append "info-launchd: none-found"
      fi

      local login_scan
      login_scan=$(scan_macos_login_items) || true
      if [[ -n "$login_scan" ]]; then
        append "info-login-items: $login_scan"
      else
        append "info-login-items: none-found"
      fi
      ;;
    linux)
      local pkg_scan
      pkg_scan=$(scan_linux_package_managers) || true
      if [[ -n "$pkg_scan" ]]; then
        append "info-packages: $pkg_scan"
      else
        append "info-packages: none-found"
      fi

      local systemd_scan
      systemd_scan=$(scan_all_systemd_units) || true
      if [[ -n "$systemd_scan" ]]; then
        append "info-systemd: $systemd_scan"
      else
        append "info-systemd: none-found"
      fi

      local initd_scan
      initd_scan=$(scan_initd_entries) || true
      if [[ -n "$initd_scan" ]]; then
        append "info-initd: $initd_scan"
      else
        append "info-initd: none-found"
      fi

      local cron_scan
      cron_scan=$(scan_cron_entries) || true
      if [[ -n "$cron_scan" ]]; then
        append "info-cron: $cron_scan"
      else
        append "info-cron: none-found"
      fi
      ;;
  esac

  local env_scan
  env_scan=$(scan_environment_vars) || true
  if [[ -n "$env_scan" ]]; then
    append "info-env-vars: $env_scan"
  else
    append "info-env-vars: none-found"
  fi

  local shell_scan
  shell_scan=$(scan_shell_rc_files) || true
  if [[ -n "$shell_scan" ]]; then
    append "info-shell-config: $shell_scan"
  else
    append "info-shell-config: none-found"
  fi

  local is_installed=false is_running=false

  if $binary_located || $app_located || $state_exists || $images_present; then
    is_installed=true
  fi

  if $svc_active || $port_open || $container_active; then
    is_running=true
  fi

  # Returns: 0=clean (compliant), 1=detected (action needed), 2=failure
  if ! $is_installed; then
    echo "summary: not-installed"
    printf "%s" "$report"
    exit 0
  elif $is_running; then
    echo "summary: installed-and-running"
    printf "%s" "$report"
    exit 1
  else
    echo "summary: installed-not-running"
    printf "%s" "$report"
    exit 1
  fi
}

execute_scan
