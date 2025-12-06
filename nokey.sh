#!/bin/bash

# Constants and Configuration

readonly SCRIPT_VERSION="2.7" 
readonly LOG_FILE="nokey.log"
readonly URL_FILE="nokey.url"
readonly DEFAULT_DOMAIN="www.apple.com"
readonly GITHUB_URL="https://github.com/livingfree2023/xray-vless-reality-nokey"
readonly GITHUB_CMD="bash <(curl -sL https://raw.githubusercontent.com/livingfree2023/xray-vless-reality-livefree/refs/heads/main/nokey.sh)"
readonly SERVICE_NAME="xray.service"
readonly SERVICE_NAME_ALPINE="xray"

readonly GITHUB_XRAY_OFFICIAL_SCRIPT_URL="https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"
readonly GITHUB_XRAY_OFFICIAL_SCRIPT_ALPINE_URL="https://github.com/XTLS/Xray-install/raw/main/alpinelinux/install-release.sh"
readonly GITHUB_XRAY_OFFICIAL_SCRIPT="install-release.sh"

mldsa_enabled=0
current_hostname=$(hostname)

# Color definitions
readonly red='\e[91m'
readonly green='\e[92m'
readonly yellow='\e[93m'
readonly magenta='\e[95m'
readonly cyan='\e[96m'
readonly none='\e[0m'


# Initialize info file
echo > "$LOG_FILE"
echo > "$URL_FILE"

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

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Error: Please run as root / 错误: 请以root身份运行此脚本: ${red}sudo -i${none}"
        exit 1
    fi
}


# Define the alias line
#alias_line="alias nokey='bash -c \"\$(curl -sL https://raw.githubusercontent.com/livingfree2023/xray-vless-reality-nokey/refs/heads/main/nokey.sh)\" @'"
alias_line="alias nokey=$GITHUB_CMD"
# Array of potential shell config files
config_files=(
    "$HOME/.bashrc"
    "$HOME/.bash_profile"
    "$HOME/.zshrc"
    "$HOME/.profile"
    "$HOME/.config/fish/config.fish"
)

# Function to add alias to a file if not already present
add_alias_if_missing() {
    task_start "添加nokey别名 / Add nokey alias to env"
    for file in "${config_files[@]}"; do
      if [ -f "$file" ]; then
          if ! grep -Fxq "$alias_line" "$file"; then
              echo "$alias_line" >> "$file"
          fi
      fi
    done
    task_done

}

# Function to remove alias from files
remove_alias() {
    task_start "删除nokey别名 / Remove nokey alias from env"
    for file in "${config_files[@]}"; do
        if [ -f "$file" ]; then
            if grep -Fxq "$alias_line" "$file"; then
                sed -i.bak "/$(echo "$alias_line" | sed 's/[\/&]/\\&/g')/d" "$file"
                echo "Removed alias from $file (backup created as $file.bak)"
            else
                echo "Alias not found in $file"
            fi
        fi
    done
    info "\nUninstallation complete."
    task_done
}

detect_network_interfaces() {
    
    Public_IPv4=$(curl -4s -m 2 https://www.cloudflare.com/cdn-cgi/trace | awk -F= '/^ip=/{print $2}')
    Public_IPv6=$(curl -6s -m 2 https://www.cloudflare.com/cdn-cgi/trace | awk -F= '/^ip=/{print $2}')
    
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

install_dependencies() {

    task_start "开始准备工作 / Starting Preparation"

    #todo: "qrencode" should be a flag controlled feature
    local tools=("curl")

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
            info "$tool is missing, attempting to install."
            eval "$install_cmd" "$tool"  >> "$LOG_FILE" 2>&1
            if ! command -v "$tool" > /dev/null 2>&1; then
                task_fail
                error "Failed to install '$tool'. Please install it manually and re-run the script."
                exit 1
            fi
        fi
    done
    
    task_done

}

install_xray() {
    if [[ $force_reinstall == 1 ]]; then
      uninstall_xray
    fi

    task_start "开始，安装或升级XRAY / Install or upgrade XRAY"
    
    if [ "$ID" = "alpine" ] || [ "$ID_LIKE" = "alpine" ]; then
      info "\nAlpine OS: install xray formal release, alpine install script does not support pre-release"
      ash $GITHUB_XRAY_OFFICIAL_SCRIPT >> $LOG_FILE 2>&1
      if [[ $? -ne 0 ]]; then
          task_fail
          error "Xray installation failed."
          exit 1
      fi
      rc-update add xray               >> $LOG_FILE 2>&1
      rc-service xray start            >> $LOG_FILE 2>&1
    else
      # info "\nInstalling latest xray including pre-release"
      bash $GITHUB_XRAY_OFFICIAL_SCRIPT install  >> "$LOG_FILE" 2>&1
      if [[ $? -ne 0 ]]; then
          task_fail
          error "Xray installation failed."
          exit 1
      fi
    fi

    task_done

}

uninstall_in_alpine() {
  rc-service xray stop        >> $LOG_FILE 2>&1
  rc-update del xray          >> $LOG_FILE 2>&1
  rm -rf "/usr/local/bin/xray"    >> $LOG_FILE 2>&1
  rm -rf "/usr/local/share/xray"  >> $LOG_FILE 2>&1
  rm -rf "/usr/local/etc/xray/"   >> $LOG_FILE 2>&1
  rm -rf "/var/log/xray/"         >> $LOG_FILE 2>&1
  rm -rf "/etc/init.d/xray"       >> $LOG_FILE 2>&1
}

uninstall_xray() {
# Check if geodata files exist and are recent (less than 1 week old)
    task_start "什么？要卸载重装？ / Force Reinstall"
    
    if [ "$ID" = "alpine" ] || [ "$ID_LIKE" = "alpine" ]; then
      info "\nAlpine OS: uninstall xray"
      uninstall_in_alpine
    else
      bash $GITHUB_XRAY_OFFICIAL_SCRIPT remove --purge >> "$LOG_FILE" 2>&1
    fi 

    task_done

}


enable_bbr() {
    task_start "最后，打开BBR / Finishing, Enabling BBR"
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    sysctl -p >> "$LOG_FILE" 2>&1
    task_done

}

show_banner() {
    echo -e "      ___         ___         ___         ___               "
    echo -e "     /__/\\       /  /\\       /__/|       /  /\\        ___   "
    echo -e "     \\  \\:\\     /  /::\\     |  |:|      /  /:/_      /__/|  "
    echo -e "      \\  \\:\\   /  /:/\\:\\    |  |:|     /  /:/ /\\    |  |:|  "
    echo -e "  _____\\__\\:\\ /  /:/  \\:\\ __|  |:|    /  /:/ /:/_   |  |:|  "
    echo -e " /__/::::::::/__/:/ \\__\\:/__/\_|:|___/__/:/ /:/ /\\__|__|:|  "
    echo -e " \\  \\:\\~~\\~~\\\\  \\:\\ /  /:\\  \\:\\/:::::\\  \\:\\/:/ /:/__/::::\\  "
    echo -e "  \\  \\:\\  ~~~ \\  \\:\\  /:/ \\  \\::/~~~~ \\  \\::/ /:/   ~\\~~\\:\\ "
    echo -e "   \\  \\:\\      \\  \\:\\/:/   \\  \\:\\      \\  \\:\\/:/      \\  \\:\\"
    echo -e "    \\  \\:\\      \\  \\::/     \\  \\:\\      \\  \\::/        \\__\\/"
    echo -e "     \\__\\/       \\__\\/       \\__\\/       \\__\\/              "



    echo "项目地址，欢迎点点点点星 / STAR ME PLEEEEEAAAASE "
    echo -e "${cyan}$GITHUB_URL${none}"
    echo -e "本脚本支持带参数执行, 不带参数将直接无敌 / See ${cyan}--help${none} for parameters"

}

parse_args() {
    # Parse command line arguments
    for arg in "$@"; do
      case $arg in
        --help)
          show_help
          ;;
        --force)
          force_reinstall=1
          ;;
        --netstack=*)
          case "${arg#*=}" in
            4)
              netstack=4
              ip=${IPv4}
              ;;
            6)
              netstack=6
              ip=${IPv6}
              ;;
            *)
              error "错误: 无效的网络协议栈值 / Error: Invalid netstack value"
              show_help
              ;;
          esac
          ;;
        --port=*)
          port="${arg#*=}"
          ;;
        --domain=*)
          domain="${arg#*=}"
          ;;
        --uuid=*)
          uuid="${arg#*=}"
          ;;
        --mldsa65Seed=*)
          mldsa65Seed="${arg#*=}"
          ;;
        --mldsa65Verify=*)
          mldsa65Verify="${arg#*=}"
          ;;
        --mldsa)
          mldsa_enabled=1
          ;;
        --shortid=*)
          shortid="${arg#*=}"
          ;;
        --remove)
          remove_alias
          uninstall_xray
          info "卸载完成 / Uninstallation complete ... [${green}OK${none}]"
          exit 0
          ;;
        *)
          error "Unknown option / 什么鬼参数: $arg"
          show_help
          ;;
      esac
    done

}




initialize_variables() {
    task_start "监测IP / Detect IP"
    if [[ -z $netstack ]]; then
      if [[ -n "$IPv4" ]]; then
        netstack=4
        ip=${IPv4}
      elif [[ -n "$IPv6" ]]; then
        netstack=6
        ip=${IPv6}
      else
        error "没有获取到公共IP / No public IP detected"
        exit 1
      fi
    fi
    task_done_with_info "$ip"

    task_start "寻找一个无辜的端口 / Find a Random Unused Port"
    if [[ -z $port ]]; then      
      base=$((10000 + RANDOM % 50000))  # Start at a random offset
      port_found=0
      for i in $(seq 0 1000); do
        port=$((base + i))
        (echo > /dev/tcp/127.0.0.1/$port) >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
          port_found=1
          break
        fi
      done
      if [[ $port_found -eq 0 ]]; then
        task_fail
        error "Could not find an unused port."
        exit 1
      fi
      # info "\n找到一个空闲随机端口，如果有防火墙需要放行 / Random unused port found, if firewall enabled, add tcp rules for: ${cyan}$port${none}"
    fi
    task_done_with_info "$port"

    if [[ -z $domain ]]; then
      # info "用户没有指定自己的SNI，使用默认 / User did not specify SNI, using default"
      domain="$DEFAULT_DOMAIN"
    else
      info "用户指定了自己的SNI / User specified SNI: ${cyan}${domain}${none}"
    fi
}

generate_crypto() {
    task_start "生成一个UUID / Generate UUID"
    if [[ -z $uuid ]]; then
        uuid=$(generate_uuid)
    fi
    task_done

    
    if [[ -z $private_key ]]; then
      keys=$(xray x25519)
      if [[ -z "$keys" ]]; then
        task_fail
        error "Failed to generate x25519 keys. Is xray installed correctly?"
        exit 1
      fi
      task_start "生成一个私钥 / Generate Private Key"
      private_key=$(echo "$keys" | awk '/PrivateKey:/ {print $2}')
      task_done_with_info "${private_key}"
      task_start "生成一个公钥 / Generate Public Key"
      public_key=$(echo "$keys" | awk '/Password:/ {print $2}')
      task_done_with_info "${public_key}" 
    fi

    task_start "生成一个shortid / Generate shortid"
    if [[ -z $shortid ]]; then
      shortid=$(generate_shortid)
      task_done_with_info "${shortid}" 
    fi


    if [[ $mldsa_enabled == 1 ]]; then
      task_start "生成ML-DSA-65密钥对 / Generate ML-DSA-65 Keys"
      if [[ -z $mldsa65Seed || -z $mldsa65Verify ]]; then
        # info "\nmldsa65Seed mldsa65Verify 没有指定，自动生成 / Generating mldsa65keys"
        mldsa65keys=$(xray mldsa65)
        if [[ -z "$mldsa65keys" ]]; then
          task_fail
          error "Failed to generate ML-DSA-65 keys. Is xray installed correctly?"
          exit 1
        fi
        mldsa65Seed=$(echo "$mldsa65keys" | awk '/Seed:/ {print $2}')
        mldsa65Verify=$(echo "$mldsa65keys" | awk '/Verify:/ {print $2}')
        # info "私钥 (PrivateKey) = ${cyan}${mldsa65Seed}${none}"
        # info "公钥 (PublicKey) = ${cyan}${mldsa65Verify}${none}"
      fi
      task_done
    else
      mldsa65Seed=""
      mldsa65Verify=""
    fi
}

build_xray_config() {
    # info "网络栈netstack = ${cyan}${netstack}${none}" 
    # info "本机IP = ${cyan}${ip}${none}"
    # info "端口Port = ${cyan}${port}${none}" 
    # info "用户UUID = ${cyan}${uuid}${none}" 
    # info "域名SNI = ${cyan}$domain${none}" 

    reality_template=$(cat <<-EOF
      { 
        "log": {
          "access": "/var/log/xray/access.log",
          "error": "/var/log/xray/error.log",
          "loglevel": "warning"
        },
        "inbounds": [
          {
            "listen": "0.0.0.0",
            "port": ${port},    // ***
            "protocol": "vless",
            "settings": {
              "clients": [
                {
                  "id": "${uuid}",    // ***
                  "flow": "xtls-rprx-vision"
                }
              ],
              "decryption": "none"
            },
            "streamSettings": {
              "network": "tcp",
              "security": "reality",
              "realitySettings": {
                "show": false,
                "dest": "${domain}:443",    // ***
                "xver": 0,
                "serverNames": ["${domain}"],    // ***
                "privateKey": "${private_key}",    // ***私钥
                "mldsa65Seed": "${mldsa65Seed}", // for xray 250724 and above
                "shortIds": ["${shortid}"]    // ***
              }
            },
            "sniffing": {
              "enabled": true,
              "destOverride": ["http", "tls", "quic"],
              "routeOnly": true
            }
          }
        ],
        "outbounds": [
          {
            "protocol": "freedom",
            "settings": {
                  "domainStrategy": "UseIPv4" or "UseIPv6"
              },
            "tag": "direct"
          },
          {
            "protocol": "blackhole",
            "tag": "block"
          }
        ],
        "dns": {
          "servers": [
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "localhost"
          ]
        },
        "routing": {
          "domainStrategy": "IPIfNonMatch",
          "rules": [
            {
              "type": "field",
              "ip": ["geoip:private"],
              "outboundTag": "block"
            },
            {
              "type": "field",
              "outboundTag": "block",
              "protocol": [
                "bittorrent"
              ]
            }
          ]
        }
      }
EOF
    )
    if [[ $mldsa_enabled != 1 ]]; then
      reality_template=$(echo "$reality_template" | sed '/"mldsa65Seed":/d')
    fi
    task_start "快好了，手搓 / Configuring /usr/local/etc/xray/config.json"
    
    config_path="/usr/local/etc/xray/config.json"
    config_dir=$(dirname "$config_path")

    if [[ ! -d "$config_dir" ]]; then
        mkdir -p "$config_dir"
        if [[ $? -ne 0 ]]; then
            task_fail
            error "Failed to create config directory: $config_dir"
            exit 1
        fi
    fi
    
    if ! echo "$reality_template" > "$config_path"; then
        task_fail
        error "Failed to write xray config to $config_path."
        [[ -f "$config_path" ]] && rm -f "$config_path"
        error "Partial config file removed. Check permissions, disk space, and $LOG_FILE for details."
        exit 1
    fi
    task_done
}

restart_xray_service() {
    task_start "冲刺，开启服务 / Starting Service"
    service xray restart  >> "$LOG_FILE" 2>&1
    task_done
}
configure_xray() {
    initialize_variables
    generate_crypto
    build_xray_config
    restart_xray_service
}


# Function to display help message
show_help() {
  echo -e "当前版本 / Version: ${cyan}${SCRIPT_VERSION}${none} "
  echo "使用方法: $0 [options] / Usage"
  echo "选项: / Options"
  echo "  --netstack=4|6     使用IPv4或IPv6 (默认: 自动检测) / Use IPv4 or IPv6"
  echo "  --port=NUMBER      设置端口号 (默认: 随机) / Set port number"
  echo "  --domain=DOMAIN    设置SNI域名 (默认: learn.microsoft.com) / Set SNI domain"
  echo "  --uuid=STRING      设置UUID (默认: 自动生成) / Set UUID"
  echo "  --mldsa            启用ML-DSA签名生成 (默认: 关闭) / Enable ML-DSA signature generation (default: off)"
  echo "  --mldsa65Seed=STRING  设置ML-DSA-65私钥 (默认: 自动生成) / Set ML-DSA-65 private key"
  echo "  --mldsa65Verify=STRING  设置ML-DSA-65公钥 (默认: 自动生成) / Set ML-DSA-65 public key"
  echo "  --force            强制重装 / Force Reinstall"
  echo "  --remove           卸载Xray和NoKey / Uninstall Xray and NoKey"
  echo "  --help             显示此帮助信息 / Show this help message"

  exit 0
}


check_service_status() {
    task_start "检查服务状态 / Checking Service"

    if [ "$ID" = "alpine" ] || [ "$ID_LIKE" = "alpine" ]; then
      if rc-service "$SERVICE_NAME_ALPINE" status >> "$LOG_FILE" 2>&1; then 
          task_done
      else
        error "[服务未运行 / Service is not active]" 
        service status "$SERVICE_NAME_ALPINE" | tee -a "$LOG_FILE"
        error "运行详细记录在 $LOG_FILE / See complete logs"
        exit 1
      fi
    else
      if systemctl is-active --quiet "$SERVICE_NAME"; then
        task_done
      else
        error "服务未运行 / Service is not active" 
        systemctl status "$SERVICE_NAME" | tee -a "$LOG_FILE"
        error "运行详细记录在 $LOG_FILE / See complete logs"
        exit 1
      fi
    fi
}

generate_share_links() {
    if [[ $netstack == "6" ]]; then
      ip="[$ip]"
    fi
    
    vless_reality_url_short="vless://${uuid}@${ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=${fingerprint}&pbk=${public_key}&sid=${shortid}#${current_hostname}"

    info "Share Link:"
    
    if [[ $mldsa_enabled == 1 ]]; then
      vless_reality_mldsa_url="vless://${uuid}@${ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=${fingerprint}&pbk=${public_key}&sid=${shortid}&pqv=${mldsa65Verify}&#${current_hostname}"
      echo -e "${magenta}${vless_reality_mldsa_url}${none}"  | tee -a "$LOG_FILE" | tee -a "$URL_FILE"
      info "Without mldsa:"
      echo -e "${magenta}${vless_reality_url_short}${none}"  | tee -a "$LOG_FILE" | tee -a "$URL_FILE"
    else
      echo -e "${magenta}${vless_reality_url_short}${none}"  | tee -a "$LOG_FILE" | tee -a "$URL_FILE"
    fi
}

generate_clash_config() {
    local server_ip_for_clash=$ip
    if [[ $netstack == "6" ]]; then
        # for clash meta, ipv6 does not need bracket.
        # The ip var is already bracketed for vless url.
        server_ip_for_clash=${ip:1:-1}
    fi

    clash_meta_config=$(cat <<-EOF
- name: ${current_hostname}
  type: vless
  server: ${server_ip_for_clash}
  port: ${port}
  client-fingerprint: ${fingerprint}
  tls: true
  servername: ${domain}
  flow: xtls-rprx-vision
  network: tcp
  reality-opts:
    public-key: ${public_key}
    short-id: ${shortid}
  uuid: ${uuid}
EOF
)
    info "Clash.meta 配置 / Clash.meta config block:"
    echo -e "${cyan}${clash_meta_config}${none}" | tee -a "$LOG_FILE" | tee -a "$URL_FILE"
}

output_results() {
    # 指纹FingerPrint
    fingerprint="random"


    # info "地址 / Address = ${cyan}${ip}${none}"
    # info "端口 / Port = ${cyan}${port}${none}"
    # info "用户ID / User ID (UUID) = ${cyan}${uuid}${none}"
    # info "流控 / Flow Control = ${cyan}xtls-rprx-vision${none}"
    # info "加密 / Encryption = ${cyan}none${none}"
    # info "传输协议 / Network Protocol = ${cyan}tcp${none}"
    # info "伪装类型 / Header Type = ${cyan}none${none}"
    # info "底层传输安全 / Transport Security = ${cyan}reality${none}"
    # info "SNI = ${cyan}${domain}${none}"
    # info "指纹 / Fingerprint = ${cyan}${fingerprint}${none}"
    # info "公钥 / PublicKey = ${cyan}${public_key}${none}"
    # info "ShortId = ${cyan}${shortid}${none}"
    # info "SpiderX = ${cyan}${spiderx}${none}"
    # if [[ $mldsa_enabled == 1 ]]; then
    #   info "mldsa65Seed = ${cyan}${mldsa65Seed}${none}"
    #   info "mldsa65Verify = ${cyan}${mldsa65Verify}${none}"
    # fi

    info "${yellow}二维码生成命令: / For QR code, install qrencode and run: ${none} qrencode -t UTF8 -r $URL_FILE" | tee -a "$LOG_FILE"

    check_service_status
    
    # info "舒服了 / Done: "
    
    generate_share_links
    generate_clash_config
}


download_official_script() {

    # Download official script
    task_start "下载，官方脚本 / Download Official Script"

    local url="$GITHUB_XRAY_OFFICIAL_SCRIPT_URL"

    if [ "$ID" = "alpine" ] || [ "$ID_LIKE" = "alpine" ]; then
        url="$GITHUB_XRAY_OFFICIAL_SCRIPT_ALPINE_URL"
        info "\nAlpine OS detected"        
    fi    

    curl -sL "$url" -o "$GITHUB_XRAY_OFFICIAL_SCRIPT" >> "$LOG_FILE" 2>&1
    if [[ -f "$GITHUB_XRAY_OFFICIAL_SCRIPT" ]]; then
        task_done
    else
        task_fail
        error "无法下载官方脚本，检查互联网链接，详细查看$LOG_FILE"
        exit 1
    fi

}

# Main function
main() {
    SECONDS=0
    
    check_root
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
    else
        error "无法识别的OS / Cannot determine OS."
        exit 1
    fi

    show_banner
    echo -e "当前版本 / Version: ${cyan}${SCRIPT_VERSION}${none} " | tee -a "$LOG_FILE"
    install_dependencies # the next function needs curl, in debian 9 curl is not shipped
    download_official_script
    detect_network_interfaces
    parse_args "$@"
    install_xray
    configure_xray
    enable_bbr
    add_alias_if_missing
    output_results
    info "总用时 / Elapsed Time:  ${green}$SECONDS 秒${none}"
    # info "日志文件 / Log File:  ${green}$LOG_FILE${none}"
    info "下次可以直接用别名${cyan}nokey${none}启动本脚本最新版"
    echo -e "---------- ${cyan}live free or die hard${none} -------------" | tee -a "$LOG_FILE"
}

main "$@"


