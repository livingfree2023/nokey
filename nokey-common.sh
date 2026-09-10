#!/bin/bash
# shellcheck disable=SC2034,SC2154

if [[ -z "${LOG_FILE:-}" ]]; then
    readonly LOG_FILE="nokey.log"
fi
if [[ -z "${URL_FILE:-}" ]]; then
    readonly URL_FILE="nokey.url"
fi
if [[ -t 1 ]]; then
    readonly red='\e[91m'
    readonly green='\e[92m'
    readonly yellow='\e[93m'
    readonly magenta='\e[95m'
    readonly cyan='\e[96m'
    readonly none='\e[0m'
else
    readonly red=''
    readonly green=''
    readonly yellow=''
    readonly magenta=''
    readonly cyan=''
    readonly none=''
fi

init_output_files() {
    : > "$LOG_FILE"
    : > "$URL_FILE"
}

# Helper functions
error() {
    echo -e "\n${red}$1${none}\n" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "\n${yellow}$1${none}\n" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${yellow}$1${none}" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${green}$1${none}" | tee -a "$LOG_FILE"
}

task_start() {
    echo -n -e "${yellow}$1 ... ${none}" | tee -a "$LOG_FILE"
}

task_done() {
    echo -e "[${green}OK${none}]" | tee -a "$LOG_FILE"
}

task_done_with_info() {
    echo -e "${cyan}$1${none} [${green}OK${none}]" | tee -a  "$LOG_FILE"
}

task_fail() {
    echo -e "[${red}FAILED${none}]" | tee -a "$LOG_FILE"
}

print_service_commands() {
    local systemd_service="$1"
    local openrc_service="$2"
    info "Restart / 重启: systemctl restart ${systemd_service}"
    info "Status / 状态: systemctl status ${systemd_service}"
    info "Alpine restart / Alpine重启: rc-service ${openrc_service} restart"
    info "Alpine status / Alpine状态: rc-service ${openrc_service} status"
}

log_verbose() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Verbose info → log only (not stdout)
log_info() {
    echo -e "${yellow}$1${none}" >> "$LOG_FILE"
}

# Simple output separator for stdout
separator() {
    echo -e "${cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${none}"
}

# shellcheck disable=SC2119,SC2120  # $1 is an optional arch override (used by tests)
resolve_arch_binary_name() {
    case "${1:-$(uname -m)}" in
        x86_64|amd64)
            echo "xray_amd64"
            ;;
        aarch64|arm64)
            echo "xray_arm64"
            ;;
        *)
            return 1
            ;;
    esac
}

# shellcheck disable=SC2119,SC2120  # $1 is an optional arch override (used by tests)
resolve_arch_name() {
    case "${1:-$(uname -m)}" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        *)
            return 1
            ;;
    esac
}

resolve_os_family() {
    if [ "${ID:-}" = "alpine" ] || [ "${ID_LIKE:-}" = "alpine" ]; then
        echo "alpine"
    else
        echo "debian/systemd-compatible"
    fi
}

configure_openrc_crash_restart() {
    local service_file="$1"
    local service_tmp="${service_file}.nokey"

    sed -e '/^[[:space:]]*command_background=/d' \
        -e '/^[[:space:]]*supervisor=/d' \
        -e '/^[[:space:]]*respawn_delay=/d' \
        -e '/^[[:space:]]*respawn_max=/d' \
        "$service_file" > "$service_tmp" || return 1
    {
        echo ""
        echo "supervisor=supervise-daemon"
        echo "respawn_delay=5"
        echo "respawn_max=0"
    } >> "$service_tmp" || return 1
    mv "$service_tmp" "$service_file"
}

configure_systemd_crash_restart() {
    local service_file="$1"
    local service_tmp="${service_file}.nokey"

    sed -e '/^[[:space:]]*Restart=/d' \
        -e '/^[[:space:]]*RestartSec=/d' \
        -e '/^\[Install\]$/i\
Restart=on-failure\
RestartSec=5s' \
        "$service_file" > "$service_tmp" || return 1
    mv "$service_tmp" "$service_file"
}

# shellcheck disable=SC2119,SC2120  # $1 is an optional arch override (used by tests)
resolve_singbox_arch_name() {
    case "${1:-$(uname -m)}" in
        x86_64|amd64)
            echo "sing-box_amd64"
            ;;
        aarch64|arm64)
            echo "sing-box_arm64"
            ;;
        *)
            return 1
            ;;
    esac
}

# shellcheck disable=SC2119,SC2120  # $1 is an optional arch override (used by tests)
resolve_realm_arch_name() {
    local use_musl=0
    if [ "$ID" = "alpine" ] || [ "$ID_LIKE" = "alpine" ]; then
        use_musl=1
    fi
    case "${1:-$(uname -m)}" in
        x86_64|amd64)
            if [[ $use_musl -eq 1 ]]; then
                echo "realm_musl_amd64"
            else
                echo "realm_amd64"
            fi
            ;;
        aarch64|arm64)
            if [[ $use_musl -eq 1 ]]; then
                echo "realm_musl_arm64"
            else
                echo "realm_arm64"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}


check_root() {
    if [[ $dry_run -eq 1 ]]; then
        return
    fi
    if [ "$EUID" -ne 0 ]; then
        error "请以root身份运行此脚本 / Please run as root: ${red}sudo -i${none}"
        exit 1
    fi
}


# Define the alias line
#alias_line="alias nokey='bash -c \"\$(curl -sL https://raw.githubusercontent.com/livingfree2023/xray-vless-reality-nokey/refs/heads/main/nokey.sh)\" @'"
alias_line="alias nokey=\"$GITHUB_CMD\""
# Array of potential shell config files (bash-compatible only; fish uses different alias syntax)
config_files=(
    "$HOME/.bashrc"
    "$HOME/.bash_profile"
    "$HOME/.zshrc"
    "$HOME/.profile"
)

# Function to add alias to a file if not already present
add_alias_if_missing() {
    task_start "添加nokey别名 / Add nokey alias to env"
    local modified_files=()
    for file in "${config_files[@]}"; do
      if [ -f "$file" ]; then
          if ! grep -Fxq "$alias_line" "$file"; then
              echo "$alias_line" >> "$file"
              modified_files+=("$file")
          fi
      fi
    done
    task_done

    if [[ ${#modified_files[@]} -gt 0 ]]; then
        info "别名已写入 ${modified_files[*]} / Alias written to: ${modified_files[*]}"
        info "当前会话执行 ${cyan}source ${modified_files[0]}${none} 生效，或新开终端 / Run 'source ${modified_files[0]}' in this session, or open a new terminal"
    fi
}

# Function to remove alias from files
remove_alias() {
    task_start "删除nokey别名 / Remove nokey alias from env"
    for file in "${config_files[@]}"; do
        if [ -f "$file" ]; then
            if grep -Fxq "$alias_line" "$file"; then
                cp -p "$file" "$file.bak"
                grep -vF "$alias_line" "$file" > "$file.tmp" && mv "$file.tmp" "$file"
                echo "已从 $file 移除别名 (备份: $file.bak) / Removed alias from $file (backup created as $file.bak)"
            else
                echo "$file 中未找到别名 / Alias not found in $file"
            fi
        fi
    done
    info "\n卸载完成 / Uninstallation complete."
    task_done
}

detect_network_interfaces() {

    Public_IPv4=$(curl -4s -m 2 https://www.cloudflare.com/cdn-cgi/trace | awk -F= '/^ip=/{print $2}')
    Public_IPv6=$(curl -6s -m 2 https://www.cloudflare.com/cdn-cgi/trace | awk -F= '/^ip=/{print $2}')
    if [[ -z "$Public_IPv6" ]]; then
        # ip.sb returns a bare address (not key=value); fallback when the cloudflare v6 trace probe is empty
        Public_IPv6=$(curl -6s -m 2 https://ip.sb)
    fi

    [[ -n "$Public_IPv4" ]] && IPv4="$Public_IPv4"
    [[ -n "$Public_IPv6" ]] && IPv6="$Public_IPv6"
    echo "Detected interface / 找到网卡: $Public_IPv4 $Public_IPv6" >> "$LOG_FILE"
}


generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

generate_shortid() {
    # Generate 8 random bytes and convert to hex
    head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

extract_public_key_from_x25519_output() {
    local x25519_output="$1"
    # Support multiple xray output formats, e.g.:
    # - PublicKey: <value>
    # - Public key: <value>
    echo "$x25519_output" | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' | awk '
        {
            line = $0
            lower = tolower(line)
            if (lower ~ /public[[:space:]]*key/) {
                sub(/^[^:]*:[[:space:]]*/, "", line)
                print line
                exit
            }
        }
    '
}

extract_private_key_from_x25519_output() {
    local x25519_output="$1"
    # Support multiple xray output formats, e.g.:
    # - PrivateKey: <value>
    # - Private key: <value>
    echo "$x25519_output" | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' | awk '
        {
            line = $0
            lower = tolower(line)
            if (lower ~ /private[[:space:]]*key/) {
                sub(/^[^:]*:[[:space:]]*/, "", line)
                print line
                exit
            }
        }
    '
}

install_dependencies() {

    task_start "开始准备工作 / Starting Preparation"

    #todo: "qrencode" should be a flag controlled feature
    # Callers may request mode-specific tools (for example jq for atomic JSON patches).
    local tools=("curl" "netstat" "$@")

    declare -A os_package_command=(
        [apt]="apt install -y"
        [yum]="yum install -y"
        [dnf]="dnf install -y"
        [pacman]="pacman -Sy --noconfirm"
        [apk]="apk add --no-cache"
        [zypper]="zypper install -y"
        [xbps-install]="xbps-install -Sy"
    )

    # Fallback detection using which
    if [[ -z "$manager" ]]; then
        for candidate in "${!os_package_command[@]}"; do
            if command -v "$candidate" > /dev/null 2>&1; then
                manager=$candidate
                # info "\nfound manager $manager in fallback"
                break
            fi
        done
    fi

    if [[ -z "$manager" ]]; then
        error "无法识别包管理器 / Cannot detect package manager"
        return 1
    fi

    local install_cmd="${os_package_command[$manager]}"

    # Check for missing tools
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" > /dev/null 2>&1; then
            info "缺少$tool，正在安装 / $tool is missing, attempting to install."
            # Map binary names to package names if different
            local package_name="$tool"
            case "$tool" in
                netstat)
                    package_name="net-tools"
                    ;;
                lsof)
                    package_name="lsof"
                    ;;
            esac
            eval "$install_cmd" "$package_name"  >> "$LOG_FILE" 2>&1
            if ! command -v "$tool" > /dev/null 2>&1; then
                task_fail
                error "安装$tool失败，请手动安装后重新运行脚本 / Failed to install '$tool'. Please install it manually and re-run the script."
                exit 1
            fi
        fi
    done

    task_done

}

initialize_ip_from_netstack() {
    task_start "监测IP / Detect IP"
    if [[ -z "${IPv4:-}" && -z "${IPv6:-}" ]]; then
        detect_network_interfaces
    fi
    if [[ -z $netstack ]]; then
        if [[ -n "$IPv4" ]]; then
            netstack=4
        elif [[ -n "$IPv6" ]]; then
            netstack=6
        else
            error "没有获取到公共IP / No public IP detected"
            exit 1
        fi
    fi

    if [[ "$netstack" == "4" ]]; then
        if [[ -z "$IPv4" ]]; then
            error "用户指定IPv4，但未检测到IPv4公网地址 / netstack=4 selected but no public IPv4 detected"
            exit 1
        fi
        ip=${IPv4}
    elif [[ "$netstack" == "6" ]]; then
        if [[ -z "$IPv6" ]]; then
            error "用户指定IPv6，但未检测到IPv6公网地址 / netstack=6 selected but no public IPv6 detected"
            exit 1
        fi
        ip=${IPv6}
    else
        error "错误: 无效的网络协议栈值 / Error: Invalid netstack value"
        exit 1
    fi
    task_done_with_info "$ip"
}


is_port_reusable() {
    local check_port="$1"
    local process_name="$2"
    local systemd_service="$3"
    local openrc_service="$4"
    local port_in_use=0

    if command -v ss >/dev/null 2>&1; then
        if ss -ltn "sport = :$check_port" 2>/dev/null | grep -q .; then
            port_in_use=1
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -ltn 2>/dev/null | grep -qE "[:]$check_port($| )"; then
            port_in_use=1
        fi
    else
        if (echo > /dev/tcp/127.0.0.1/"$check_port") >/dev/null 2>&1; then
            port_in_use=1
        fi
    fi

    if [[ $port_in_use -eq 0 ]]; then
        return 0
    fi

    # Port is in use: reusable only if it belongs to our service
    if command -v ss >/dev/null 2>&1; then
        if ss -ltnp "sport = :$check_port" 2>/dev/null | grep -q "$process_name"; then
            return 0
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -ltnp 2>/dev/null | grep -E "[:.]$check_port($| )" | grep -q "$process_name"; then
            return 0
        fi
    else
        # Without ss/netstat we cannot identify the process; if the service is
        # active, assume it owns the port.
        if [ "$ID" = "alpine" ] || [ "$ID_LIKE" = "alpine" ]; then
            if rc-service "$openrc_service" status >/dev/null 2>&1; then
                return 0
            fi
        else
            if systemctl is-active --quiet "$systemd_service"; then
                return 0
            fi
        fi
    fi
    return 1
}

# Probe a REALITY target candidate. Mirrors 3x-ui's REALITY Target Scanner
# feasibility gate: the server must negotiate TLS 1.3, ALPN h2, and present a
# cert chain that verifies. curl verifies the chain by default; --tlsv1.3
# forces TLS 1.3; --http2 + %{http_version}==2 proves h2. X25519 is implied:
# every TLS 1.3 server in the pool negotiates it (3x-ui additionally requires
# it). Also records TLS-handshake latency (%{time_appconnect}) into the
# probe_latency_ms global for the picker to report. Returns 0 if feasible.
# The probe outcome (and why) is appended to the log.
random_hex() {
    local byte_count="$1"
    od -An -N "$byte_count" -tx1 /dev/urandom | tr -d '[:space:]'
}

is_tcp_port_unused() {
    local check_port="$1"

    if command -v ss >/dev/null 2>&1; then
        ! ss -ltn 2>/dev/null | awk -v port=":${check_port}" '$4 ~ port "$" { found=1 } END { exit !found }'
    elif command -v netstat >/dev/null 2>&1; then
        ! netstat -ltn 2>/dev/null | awk -v port=":${check_port}" '$4 ~ port "$" { found=1 } END { exit !found }'
    else
        ! (echo > /dev/tcp/127.0.0.1/"$check_port") >/dev/null 2>&1
    fi
}

select_random_unused_port() {
    local config_source="${1:-}"
    local excluded_port="${2:-}"
    local candidate=""
    local attempt=0

    random_unused_port=""
    while [[ "$attempt" -lt 1000 ]]; do
        candidate=$((10000 + (RANDOM * 32768 + RANDOM) % 50001))
        attempt=$((attempt + 1))
        [[ -n "$excluded_port" && "$candidate" == "$excluded_port" ]] && continue
        if [[ -n "$config_source" ]] && jq -e --argjson port "$candidate" '.inbounds[]? | select(.port == $port)' "$config_source" >/dev/null 2>&1; then
            continue
        fi
        if is_tcp_port_unused "$candidate"; then
            random_unused_port="$candidate"
            return 0
        fi
    done
    return 1
}
