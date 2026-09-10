#!/bin/bash
# shellcheck disable=SC2034,SC2154

readonly ACME_DEFAULT_HOME="${HOME}/.acme.sh"
readonly HYSTERIA_CERT_DIR="/etc/hysteria"
readonly HYSTERIA_CERT_FILE="/etc/hysteria/fullchain.pem"
readonly HYSTERIA_KEY_FILE="/etc/hysteria/private.key"
readonly ACME_INSTALL_URL="https://get.acme.sh"

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

domain=""
email=""
cf_token="${CF_Token:-}"
force_issue=0
dry_run=0
manager=""
acme_binary_path=""

if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
fi

show_help() {
    echo "Usage: acme-cert.sh --domain=DOMAIN [--email=EMAIL] [--cf-token=TOKEN] [--force] [--dry-run]"
    echo "Without a Cloudflare token, acme.sh uses standalone HTTP-01 on port 80."
}

read_tty_value() {
    local prompt="$1"
    local value=""
    if [[ ! -r /dev/tty ]]; then
        return 1
    fi
    read -r -p "$prompt" value < /dev/tty || return 1
    printf '%s' "$value"
}

read_tty_secret() {
    local prompt="$1"
    local value=""
    if [[ ! -r /dev/tty ]]; then
        return 1
    fi
    read -r -s -p "$prompt" value < /dev/tty || return 1
    echo >&2
    printf '%s' "$value"
}

parse_args() {
    local arg=""
    for arg in "$@"; do
        case "$arg" in
            --domain=*) domain="${arg#*=}" ;;
            --email=*) email="${arg#*=}" ;;
            --cf-token=*) cf_token="${arg#*=}" ;;
            --force) force_issue=1 ;;
            --dry-run) dry_run=1 ;;
            --help) show_help; exit 0 ;;
            *) error "Unknown option: $arg"; show_help; return 1 ;;
        esac
    done
}

ensure_acme_binary() {
    local acme_home="${ACME_HOME:-${ACME_DEFAULT_HOME}}"
    local acme_bin="${acme_home}/acme.sh"

    if [[ -x "$acme_bin" ]]; then
        acme_binary_path="$acme_bin"
        return 0
    fi

    task_start "安装 acme.sh / Install acme.sh"
    if [[ -n "$email" ]]; then
        if ! curl -fsSL "$ACME_INSTALL_URL" | sh -s email="$email" >> "$LOG_FILE" 2>&1; then
            task_fail
            error "安装acme.sh失败 / Failed to install acme.sh"
            return 1
        fi
    elif ! curl -fsSL "$ACME_INSTALL_URL" | sh >> "$LOG_FILE" 2>&1; then
        task_fail
        error "安装acme.sh失败 / Failed to install acme.sh"
        return 1
    fi
    task_done

    if [[ ! -x "$acme_bin" ]]; then
        error "找不到acme.sh: $acme_bin / acme.sh was not found at: $acme_bin"
        return 1
    fi
    acme_binary_path="$acme_bin"
}

issue_certificate() {
    local acme_bin="$1"
    local issue_args=(--issue -d "$domain")

    if [[ -n "$cf_token" ]]; then
        export CF_Token="$cf_token"
        issue_args+=(--dns dns_cf)
        info "使用Cloudflare DNS验证 / Using Cloudflare DNS validation"
    else
        issue_args+=(--standalone)
        warn "未提供Cloudflare token，将使用HTTP验证；请确保80端口空闲 / No Cloudflare token; using HTTP validation. Port 80 must be free"
    fi
    if [[ "$force_issue" -eq 1 ]]; then
        issue_args+=(--force)
    fi

    task_start "申请证书 / Issue certificate"
    if ! "$acme_bin" "${issue_args[@]}" >> "$LOG_FILE" 2>&1; then
        task_fail
        error "证书申请失败，请查看$LOG_FILE / Certificate issuance failed. Check $LOG_FILE"
        return 1
    fi
    task_done
}

install_certificate() {
    local acme_bin="$1"
    mkdir -p "$HYSTERIA_CERT_DIR"
    task_start "安装证书 / Install certificate"
    if ! "$acme_bin" --install-cert -d "$domain" \
        --fullchain-file "$HYSTERIA_CERT_FILE" \
        --key-file "$HYSTERIA_KEY_FILE" >> "$LOG_FILE" 2>&1; then
        task_fail
        error "证书安装失败 / Failed to install certificate"
        return 1
    fi
    chmod 600 "$HYSTERIA_KEY_FILE"
    task_done
    success "证书已保存 / Certificate files: $HYSTERIA_CERT_FILE and $HYSTERIA_KEY_FILE"
}

main() {
    parse_args "$@" || exit 1

    if [[ -z "$domain" ]]; then
        if [[ -t 0 || -r /dev/tty ]]; then
            domain="$(read_tty_value "Domain: ")" || exit 1
        else
            error "--domain is required in non-interactive mode"
            exit 1
        fi
    fi
    if [[ ! "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
        error "Invalid domain: $domain"
        exit 1
    fi

    if [[ -z "$cf_token" && ( -t 0 || -r /dev/tty ) && "$dry_run" -eq 0 ]]; then
        cf_token="$(read_tty_secret "Cloudflare API token (optional, press Enter for HTTP-01): ")" || true
    fi

    if [[ "$dry_run" -eq 1 ]]; then
        info "ACME dry-run: domain=$domain"
        if [[ -n "$cf_token" ]]; then
            info "Challenge: Cloudflare DNS-01"
        else
            info "Challenge: standalone HTTP-01 on port 80"
        fi
        info "Certificate output: $HYSTERIA_CERT_FILE"
        exit 0
    fi

    check_root
    init_output_files
    install_dependencies curl socat openssl
    ensure_acme_binary || exit 1
    if [[ ! -f "${ACME_HOME:-${ACME_DEFAULT_HOME}}/${domain}_ecc/fullchain.cer" && ! -f "${ACME_HOME:-${ACME_DEFAULT_HOME}}/${domain}/fullchain.cer" ]]; then
        issue_certificate "$acme_binary_path" || exit 1
    else
        info "检测到已有acme.sh证书，将重新安装到Hysteria路径 / Existing acme.sh certificate detected; installing it to the Hysteria path"
    fi
    install_certificate "$acme_binary_path"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]] || [[ -n "${BASH_EXECUTION_STRING:-}" ]]; then
    main "$@"
fi
