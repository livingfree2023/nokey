#!/bin/bash
# shellcheck disable=SC2034,SC2154

readonly GITHUB_RELEASE_BASE_URL="https://github.com/livingfree2023/nokey/releases/latest/download"
readonly SINGBOX_SERVICE_NAME="sing-box.service"
readonly SINGBOX_SERVICE_NAME_ALPINE="sing-box"
readonly GITHUB_SINGBOX_SERVICE_URL="https://raw.githubusercontent.com/livingfree2023/nokey/refs/heads/main/sing-box.service"
readonly GITHUB_SINGBOX_RC_URL="https://raw.githubusercontent.com/livingfree2023/nokey/refs/heads/main/sing-box.rc"
readonly SINGBOX_CONFIG_DIR="/etc/sing-box"
readonly DEFAULT_DOMAIN="www.amd.com"
readonly REALITY_SCAN_TIMEOUT=5
readonly REALITY_TARGET_CANDIDATES=(
    "www.amazon.com"
    "aws.amazon.com"
    "www.samsung.com"
    "www.nvidia.com"
    "www.amd.com"
    "www.intel.com"
    "www.sony.com"
)

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${script_dir}/nokey-common.sh" ]]; then
    # shellcheck source=/dev/null
    . "${script_dir}/nokey-common.sh"
else
    common_url="${NOKEY_COMMON_URL:-https://raw.githubusercontent.com/livingfree2023/nokey/refs/heads/main/nokey-common.sh}"
    if ! command -v curl >/dev/null 2>&1; then
        echo "curl is required to load nokey-common.sh" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    . <(curl -fsSL "$common_url")
fi

force_reinstall=0
dry_run=0
remove_mode=0
netstack=""
IPv4=""
IPv6=""
ip=""
port=""
domain=""
uuid=""
shortid=""
private_key=""
public_key=""
current_hostname="$(hostname)"
fingerprint="random"
random_unused_port=""
probe_latency_ms=""
manager=""

. /etc/os-release

uninstall_singbox() {
    task_start "卸载 Sing-box / Uninstall Sing-box"
    {
        if [ "$ID" = "alpine" ] || [ "$ID_LIKE" = "alpine" ]; then
            rc-service "$SINGBOX_SERVICE_NAME_ALPINE" stop 2>/dev/null || true
            rc-update del "$SINGBOX_SERVICE_NAME_ALPINE" 2>/dev/null || true
            rm -f "/etc/init.d/$SINGBOX_SERVICE_NAME_ALPINE"
        else
            systemctl stop "$SINGBOX_SERVICE_NAME" 2>/dev/null || true
            systemctl disable "$SINGBOX_SERVICE_NAME" 2>/dev/null || true
            rm -f "/etc/systemd/system/$SINGBOX_SERVICE_NAME" 2>/dev/null || true
            systemctl daemon-reload 2>/dev/null || true
        fi
        rm -f /usr/local/bin/sing-box
        rm -rf "$SINGBOX_CONFIG_DIR"
    } >> "$LOG_FILE" 2>&1
    task_done
}

probe_reality_target() {
    local candidate="$1"
    local probe_out=""
    local curl_rc=0
    probe_latency_ms=""
    probe_out="$(curl -sSI --max-time "$REALITY_SCAN_TIMEOUT" --tlsv1.3 --http2 -o /dev/null -w '%{http_version}|%{time_appconnect}' "https://$candidate/" 2>/dev/null)" || curl_rc=$?
    local http_version="${probe_out%%|*}"
    local latency_sec="${probe_out#*|}"
    if [[ -n "$latency_sec" && "$latency_sec" != "$http_version" ]]; then
        probe_latency_ms="$(awk -v t="$latency_sec" 'BEGIN { printf "%.0f", t * 1000 }')"
    fi
    if [[ "$http_version" == "2" ]]; then
        log_info "REALITY probe: $candidate -> feasible (TLS 1.3 + h2 verified, ${probe_latency_ms}ms)"
        return 0
    fi
    if [[ $curl_rc -ne 0 ]]; then
        log_info "REALITY probe: $candidate -> rejected (curl rc=$curl_rc: connect/TLS/cert failure)"
    else
        log_info "REALITY probe: $candidate -> rejected (negotiated HTTP/$http_version, need h2)"
    fi
    return 1
}

# Auto-pick an SNI when the user did not pass --domain: probe the candidate
# pool and use the first feasible one; fall back to DEFAULT_DOMAIN if none
# responds. Skips the scan entirely when a domain is already set. Each probe
# step and the reason for the pick are reported to stdout and the log.
pick_default_domain() {
    [[ -n $domain ]] && return 0
    local candidate
    local shuffled=("${REALITY_TARGET_CANDIDATES[@]}")
    local i j tmp
    # Fisher-Yates shuffle so no two installs probe the same first SNI
    # (avoid a fixed scan-order fingerprint across one-click deployments).
    for ((i = ${#shuffled[@]} - 1; i > 0; i--)); do
        j=$((RANDOM % (i + 1)))
        tmp="${shuffled[i]}"
        shuffled[i]="${shuffled[j]}"
        shuffled[j]="$tmp"
    done
    info "自动探测REALITY目标SNI / Auto-probing REALITY target SNI:"
    for candidate in "${shuffled[@]}"; do
        if probe_reality_target "$candidate"; then
            domain="$candidate"
            info "  ${candidate} -> ${green}可用 / feasible${none} (TLS 1.3 + h2 验证通过 / verified, ${probe_latency_ms}ms)"
            info "自动选择REALITY目标 / Auto-selected REALITY target: ${cyan}${domain}${none}"
            return 0
        fi
        info "  ${candidate} -> 不可用 / not feasible (原因见日志 / reason in log)"
    done
    domain="$DEFAULT_DOMAIN"
    warn "所有候选均不可用，使用默认SNI / No feasible target probed; using default SNI: ${cyan}${domain}${none}"
    return 1
}



install_singbox() {
    if [[ $force_reinstall == 1 ]]; then
      uninstall_singbox
    fi

    task_start "开始，安装或升级Sing-box / Install or upgrade Sing-box"

    # Detect OS type (similar to install-singbox.sh)
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_ID_LIKE="${ID_LIKE:-}"
    else
        OS_ID=""
        OS_ID_LIKE=""
    fi

    if echo "$OS_ID $OS_ID_LIKE" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "$OS_ID $OS_ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "$OS_ID $OS_ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then
        OS="redhat"
    else
        OS="unknown"
    fi

    log_info "检测到系统 / Detected OS: $OS (${OS_ID:-unknown})"

    # Check root privileges
    if [[ $dry_run -eq 1 ]]; then
        return
    fi
    if [ "$EUID" -ne 0 ]; then
        error "请以root身份运行此脚本 / Please run as root: ${red}sudo -i${none}"
        exit 1
    fi

    # Install dependencies based on OS
    task_start "安装系统依赖 / Installing system dependencies"

    case "$OS" in
        alpine)
            apk update >> "$LOG_FILE" 2>&1 || { task_fail; error "apk update 失败"; exit 1; }
            apk add --no-cache bash curl ca-certificates openssl openrc >> "$LOG_FILE" 2>&1 || {
                task_fail; error "依赖安装失败"; exit 1
            }

            # 确保 OpenRC 运行
            if ! rc-service --list 2>/dev/null | grep -q "^openrc"; then
                rc-update add openrc boot >/dev/null 2>&1 || true
                rc-service openrc start >/dev/null 2>&1 || true
            fi
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y >> "$LOG_FILE" 2>&1 || { task_fail; error "apt update 失败"; exit 1; }
            apt-get install -y curl ca-certificates openssl >> "$LOG_FILE" 2>&1 || {
                task_fail; error "依赖安装失败"; exit 1
            }
            ;;
        redhat)
            yum install -y curl ca-certificates openssl >> "$LOG_FILE" 2>&1 || {
                task_fail; error "依赖安装失败"; exit 1
            }
            ;;
        *)
            warn "未识别的系统类型，尝试继续..."
            ;;
    esac

    task_done

    # For sing-box, we'll use default values similar to install-singbox.sh
    # Generate random port if not set (prefer 443 when free or owned by sing-box)
    if [[ -z $port ]]; then
        if is_port_reusable 443 sing-box "$SINGBOX_SERVICE_NAME" "$SINGBOX_SERVICE_NAME_ALPINE"; then
            port=443
        else
            if ! select_random_unused_port; then
                task_fail
                error "没有找到可用的Sing-box端口 / Could not find an unused Sing-box port."
                exit 1
            fi
            port="$random_unused_port"
        fi
        log_info "使用端口: $port"
    fi

    # Generate UUID if not set (sing-box VLESS uses standard UUID format)
    if [[ -z $uuid ]]; then
        uuid=$(generate_uuid)
        log_info "自动生成UUID / Auto-generated UUID"
    fi

    # Default domain if not set
    if [[ -z $domain ]]; then
        pick_default_domain || true
    fi

    # Install sing-box binary
    log_info "正在从GitHub Releases下载sing-box二进制文件 / Downloading sing-box binary from GitHub Releases"

    # Determine architecture and download appropriate sing-box binary
    local arch_binary_name=""
    local arch_name=""
    arch_binary_name="$(resolve_singbox_arch_name)" || { task_fail; error "不支持的架构: $(uname -m)，仅支持amd64和arm64 / Unsupported architecture: $(uname -m). Only amd64 and arm64 are supported."; exit 1; }
    arch_name="$(resolve_arch_name)" || { task_fail; error "不支持的架构: $(uname -m)，仅支持amd64和arm64 / Unsupported architecture: $(uname -m). Only amd64 and arm64 are supported."; exit 1; }

    log_info "检测到系统 / Detected OS: $(resolve_os_family) | 架构 / Architecture: ${arch_name}"

    mkdir -p /usr/local/bin || { task_fail; error "创建sing-box目录失败 / Failed to create sing-box directories"; exit 1; }
    log_verbose "Created install directories under /usr/local"

    local download_url="${GITHUB_RELEASE_BASE_URL}/${arch_binary_name}"
    log_verbose "Downloading: ${download_url} -> /usr/local/bin/sing-box"
    if curl -fSL "$download_url" -o /usr/local/bin/sing-box >> "$LOG_FILE" 2>&1; then
        chmod 755 /usr/local/bin/sing-box
        log_verbose "Set executable permissions on /usr/local/bin/sing-box"
        if ! /usr/local/bin/sing-box version >/dev/null 2>&1; then
            warn "下载的二进制无法执行(glibc/musl不兼容)，回退到apk安装 / Downloaded binary cannot execute (glibc/musl mismatch); fallback to apk"
            rm -f /usr/local/bin/sing-box
            if [[ "$OS" == "alpine" ]]; then
                apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community sing-box >> "$LOG_FILE" 2>&1 || {
                    task_fail; error "通过apk安装sing-box失败 / Failed to install sing-box via apk"; exit 1;
                }
            else
                task_fail; error "下载的sing-box二进制文件无法执行 / Downloaded sing-box binary cannot execute"; exit 1;
            fi
        fi
    else
        warn "从Release下载sing-box失败，回退到官方安装脚本 / Failed to download sing-box from Release; fallback to official installer"
        # Fallback to official sing-box installer
        if [[ "$OS" == "alpine" ]]; then
            apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community sing-box >> "$LOG_FILE" 2>&1 || {
                task_fail; error "通过apk安装sing-box失败 / Failed to install sing-box via apk"; exit 1;
            }
        else
            bash <(curl -fsSL https://sing-box.app/install.sh) >> "$LOG_FILE" 2>&1 || {
                task_fail; error "通过官方脚本安装sing-box失败 / Failed to install sing-box via official script"; exit 1;
            }
        fi
    fi

    # Create configuration directory and file
    mkdir -p "$SINGBOX_CONFIG_DIR" || { task_fail; error "创建sing-box配置目录失败 / Failed to create sing-box config directory"; exit 1; }

    # Generate Reality keypair using sing-box
    task_start "生成Reality密钥对 / Generate Reality Key Pair"
    keys=$(sing-box generate reality-keypair 2>>"$LOG_FILE")
    if [[ -z "$keys" ]]; then
        task_fail
        error "生成Reality密钥失败，sing-box是否安装正确？ / Failed to generate Reality keys. Is sing-box installed correctly?"
        exit 1
    fi
    private_key=$(extract_private_key_from_x25519_output "$keys")
    public_key=$(extract_public_key_from_x25519_output "$keys")
    if [[ -z "$private_key" || -z "$public_key" ]]; then
        task_fail
        error "无法解析Reality密钥 / Failed to parse Reality keys"
        exit 1
    fi
    task_done_with_info "${public_key}"

    # Generate shortid if not set
    task_start "生成shortid / Generate shortid"
    if [[ -z $shortid ]]; then
        shortid=$(generate_shortid)
    fi
    task_done_with_info "${shortid}"

    # Generate sing-box config (VLESS Reality Vision)
    local config_path="${SINGBOX_CONFIG_DIR}/config.json"
    cat > "$config_path" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen_port": $port,
      "users": [
        {
          "name": "nokey",
          "uuid": "$uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$domain",
        "alpn": ["h2", "http/1.1"],
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$domain",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": ["$shortid"],
          "max_time_difference": "1m"
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ]
}
EOF

    # Validate configuration if sing-box is available
    if command -v sing-box >/dev/null 2>&1; then
        if sing-box check -c "$config_path" >/dev/null 2>&1; then
            info "配置文件验证通过 / Config file validation passed"
        else
            warn "配置文件验证失败，但将继续... / Config file validation failed, but continuing..."
        fi
    fi

    # Setup service (if not already installed by package manager)
    if [[ ! -f "/etc/init.d/$SINGBOX_SERVICE_NAME_ALPINE" && ! -f "/etc/systemd/system/$SINGBOX_SERVICE_NAME" ]]; then
        local service_tmp
        service_tmp="$(mktemp /tmp/nokey.sing-box.service.XXXXXX)" || { task_fail; error "创建sing-box.service临时文件失败 / Failed to create temporary file for sing-box.service"; exit 1; }

        if [ "$ID" = "alpine" ] || [ "$ID_LIKE" = "alpine" ]; then
            log_info "安装OpenRC服务 / Installing OpenRC service: /etc/init.d/${SINGBOX_SERVICE_NAME_ALPINE}"
            log_verbose "Downloading service file: ${GITHUB_SINGBOX_RC_URL} -> ${service_tmp}"
            if curl -fSL "${GITHUB_SINGBOX_RC_URL}" -o "${service_tmp}" >> "$LOG_FILE" 2>&1; then
                if ! install -m 755 "${service_tmp}" /etc/init.d/"$SINGBOX_SERVICE_NAME_ALPINE" >> "$LOG_FILE" 2>&1; then
                    task_fail
                    error "安装sing-box OpenRC服务失败 / Failed to install sing-box OpenRC service"
                    exit 1
                fi
                rm -f "${service_tmp}" >> "$LOG_FILE" 2>&1
                log_verbose "Installed OpenRC service file from sing-box.rc"
                rc-update add "$SINGBOX_SERVICE_NAME_ALPINE" >> "$LOG_FILE" 2>&1 || warn "添加sing-box开机自启失败 / Failed to add sing-box to startup"
            else
                warn "下载sing-box.rc失败，服务可能已被包管理器安装 / Failed to download sing-box.rc; service may already be installed by package manager"
                rm -f "${service_tmp}" >> "$LOG_FILE" 2>&1
            fi
        else
            log_info "安装systemd服务 / Installing systemd service: /etc/systemd/system/${SINGBOX_SERVICE_NAME}"
            log_verbose "Downloading service file: ${GITHUB_SINGBOX_SERVICE_URL} -> ${service_tmp}"
            if curl -fSL "${GITHUB_SINGBOX_SERVICE_URL}" -o "${service_tmp}" >> "$LOG_FILE" 2>&1; then
                if ! cp "${service_tmp}" /etc/systemd/system/"$SINGBOX_SERVICE_NAME" >> "$LOG_FILE" 2>&1; then
                    task_fail
                    error "安装sing-box systemd服务失败 / Failed to install sing-box systemd service"
                    exit 1
                fi
                rm -f "${service_tmp}" >> "$LOG_FILE" 2>&1
                log_verbose "Installed systemd service file from sing-box.service"
                systemctl daemon-reload >> "$LOG_FILE" 2>&1 || true
                systemctl enable "$SINGBOX_SERVICE_NAME" >> "$LOG_FILE" 2>&1 || warn "启用sing-box服务失败 / Failed to enable sing-box service"
            else
                warn "下载sing-box.service失败，服务可能已被包管理器安装 / Failed to download sing-box.service; service may already be installed by package manager"
                rm -f "${service_tmp}" >> "$LOG_FILE" 2>&1
            fi
        fi
    else
        info "服务文件已存在，跳过服务安装 / Service file already exists, skipping service setup"
    fi

    if [ "$ID" = "alpine" ] || [ "$ID_LIKE" = "alpine" ]; then
        configure_openrc_crash_restart /etc/init.d/"$SINGBOX_SERVICE_NAME_ALPINE" >> "$LOG_FILE" 2>&1 || { task_fail; error "配置sing-box崩溃自动重启失败 / Failed to configure sing-box crash restart"; exit 1; }
    else
        configure_systemd_crash_restart /etc/systemd/system/"$SINGBOX_SERVICE_NAME" >> "$LOG_FILE" 2>&1 || { task_fail; error "配置sing-box崩溃自动重启失败 / Failed to configure sing-box crash restart"; exit 1; }
        systemctl daemon-reload >> "$LOG_FILE" 2>&1 || { task_fail; error "systemctl daemon-reload失败 / systemctl daemon-reload failed"; exit 1; }
    fi

    # Restart sing-box to pick up the new config
    task_start "启动Sing-box服务 / Starting Sing-box Service"
    if [ "$ID" = "alpine" ] || [ "$ID_LIKE" = "alpine" ]; then
        if rc-service "$SINGBOX_SERVICE_NAME_ALPINE" restart >> "$LOG_FILE" 2>&1; then
            task_done
        else
            warn "重启Sing-box服务失败，请手动启动 / Failed to restart sing-box service, please start manually"
            task_done
        fi
    else
        if systemctl restart "$SINGBOX_SERVICE_NAME" >> "$LOG_FILE" 2>&1; then
            task_done
        else
            warn "重启Sing-box服务失败，请手动启动 / Failed to restart sing-box service, please start manually"
            task_done
        fi
    fi
}



show_help() {
    echo "Usage: singbox.sh [--port=PORT] [--domain=DOMAIN] [--uuid=UUID] [--netstack=4|6] [--force] [--remove] [--dry-run]"
}

parse_args() {
    local arg=""
    for arg in "$@"; do
        case "$arg" in
            --port=*) port="${arg#*=}" ;;
            --domain=*) domain="${arg#*=}" ;;
            --uuid=*) uuid="${arg#*=}" ;;
            --netstack=4) netstack=4 ;;
            --netstack=6) netstack=6 ;;
            --force) force_reinstall=1 ;;
            --remove) remove_mode=1 ;;
            --dry-run) dry_run=1 ;;
            --help) show_help; exit 0 ;;
            *) error "Unknown option: $arg"; return 1 ;;
        esac
    done
}

dry_run_preview() {
    info "Sing-box dry-run: no system changes will be made"
    info "Binary: ${GITHUB_RELEASE_BASE_URL}/$(resolve_singbox_arch_name)"
    info "Config: ${SINGBOX_CONFIG_DIR}/config.json"
    info "Port: ${port:-auto}"
    info "Domain: ${domain:-auto}"
}

output_results() {
    local server_ip="$ip"
    local link=""
    [[ "$netstack" == "6" ]] && server_ip="[$server_ip]"
    link="vless://${uuid}@${server_ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=${fingerprint}&pbk=${public_key}&sid=${shortid}#${current_hostname}"
    info "VLESS Reality share link:"
    echo "$link" | tee -a "$LOG_FILE"
    echo "$link" >> "$URL_FILE"

    local mihomo_server="$server_ip"
    [[ "$netstack" == "6" ]] && mihomo_server="${server_ip:1:-1}"
    local mihomo_config
    mihomo_config=$(cat <<-EOF
proxies:
  - name: ${current_hostname}
    type: vless
    server: ${mihomo_server}
    port: ${port}
    uuid: ${uuid}
    flow: xtls-rprx-vision
    network: tcp
    tls: true
    servername: ${domain}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${public_key}
      short-id: ${shortid}
EOF
)
    info "Mihomo/Clash config:"
    echo "$mihomo_config" | tee -a "$LOG_FILE"
    echo "$mihomo_config" >> "$URL_FILE"
    print_service_commands "$SINGBOX_SERVICE_NAME" "$SINGBOX_SERVICE_NAME_ALPINE"
}

main() {
    parse_args "$@" || exit 1
    if [[ "$dry_run" -eq 1 ]]; then
        dry_run_preview
        exit 0
    fi
    check_root
    init_output_files
    install_dependencies
    detect_network_interfaces
    initialize_ip_from_netstack
    if [[ "$remove_mode" -eq 1 ]]; then
        uninstall_singbox
        exit 0
    fi
    install_singbox
    output_results
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]] || [[ -n "${BASH_EXECUTION_STRING:-}" ]]; then
    main "$@"
fi
