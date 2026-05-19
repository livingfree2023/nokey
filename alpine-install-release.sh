#!/usr/bin/env ash
# shellcheck shell=dash

set -eu

pkg_manager() {
    local OP="$1" PM=apk
    shift
    if [ -f /etc/gentoo-release ]; then
        PM=emerge
        case "$OP" in
        add)
            OP='-v'
            ;;
        del)
            OP='-C'
            ;;
        esac
    fi
    if [ $# -eq 0 ]; then
        echo "$PM $OP"
    else
        $PM "$OP" "$@"
    fi
}

check_distro() {
    if [ -f /etc/alpine-release ] || [ -f /etc/gentoo-release ]; then
        return 0
    else
        return 1
    fi
}

check_if_running_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        return 0
    else
        echo "error: You must run this script as root!"
        return 1
    fi
}

identify_architecture() {
    if [ "$(uname)" != 'Linux' ]; then
        echo "error: This operating system is not supported."
        return 1
    fi
    case "$(uname -m)" in
    'i386' | 'i686') MACHINE='32' ;;
    'amd64' | 'x86_64') MACHINE='64' ;;
    'armv5tel') MACHINE='arm32-v5' ;;
    'armv6l')
        MACHINE='arm32-v6'
        grep Features /proc/cpuinfo | grep -qw 'vfp' || MACHINE='arm32-v5'
        ;;
    'armv7' | 'armv7l')
        MACHINE='arm32-v7a'
        grep Features /proc/cpuinfo | grep -qw 'vfp' || MACHINE='arm32-v5'
        ;;
    'armv8' | 'aarch64') MACHINE='arm64-v8a' ;;
    'mips') MACHINE='mips32' ;;
    'mipsle') MACHINE='mips32le' ;;
    'mips64')
        MACHINE='mips64'
        lscpu | grep -q "Little Endian" && MACHINE='mips64le'
        ;;
    'mips64le') MACHINE='mips64le' ;;
    'ppc64') MACHINE='ppc64' ;;
    'ppc64le') MACHINE='ppc64le' ;;
    'riscv64') MACHINE='riscv64' ;;
    's390x') MACHINE='s390x' ;;
    *)
        echo "error: The architecture is not supported."
        return 1
        ;;
    esac
}

install_dependencies() {
    local NEED_PACKAGES=""
    if [ -z "$(command -v curl)" ]; then
        NEED_PACKAGES="$NEED_PACKAGES curl"
    fi

    if [ -n "$NEED_PACKAGES" ]; then
        if [ "$(command -v apk)" ]; then
            echo "Installing required dependencies:$NEED_PACKAGES..."
            pkg_manager add $NEED_PACKAGES
        else
            echo "error: The script does not support the package manager in this operating system."
            exit 1
        fi
    fi
}

download_xray() {
    echo "Downloading Xray files..."
    if ! curl -f -L -H 'Cache-Control: no-cache' -o "$ZIP_FILE" "$DOWNLOAD_LINK" -#; then
        echo 'error: Download failed! Please check your network or try again.'
        exit 1
    fi

    if ! curl -f -L -H 'Cache-Control: no-cache' -o "$ZIP_FILE.dgst" "$DOWNLOAD_LINK.dgst" -#; then
        echo 'error: Download failed! Please check your network or try again.'
        exit 1
    fi
}

verification_xray() {
    CHECKSUM=$(awk -F '= ' '/256=/ {print $2}' "$ZIP_FILE.dgst")
    LOCALSUM=$(sha256sum "$ZIP_FILE" | awk '{printf $1}')
    if [ "$CHECKSUM" != "$LOCALSUM" ]; then
        echo 'error: SHA256 check failed! Please check your network or try again.'
        return 1
    fi
}

decompression() {
    echo "Decompressing archive using busybox..."
    busybox unzip -o "$ZIP_FILE" -d "$TMP_DIRECTORY"
    
    # Give the container kernel 2 seconds to free unzipping memory allocations
    sleep 2
}

install_xray() {
    echo "Deploying Xray execution binaries and data assets..."
    mkdir -p /usr/local/bin/
    mkdir -p /usr/local/share/xray/

    # Using cp + chmod instead of install to avoid high memory buffering
    cp "${TMP_DIRECTORY}xray" "/usr/local/bin/xray"
    chmod 755 /usr/local/bin/xray

    cp "${TMP_DIRECTORY}geoip.dat" "/usr/local/share/xray/geoip.dat"
    cp "${TMP_DIRECTORY}geosite.dat" "/usr/local/share/xray/geosite.dat"
    chmod 644 /usr/local/share/xray/*.dat
}

install_confdir() {
    CONFDIR='0'
    if [ ! -d '/usr/local/etc/xray/' ]; then
        mkdir -p /usr/local/etc/xray/
        for BASE in 00_log 01_api 02_dns 03_routing 04_policy 05_inbounds 06_outbounds 07_transport 08_stats 09_reverse; do
            echo '{}' >"/usr/local/etc/xray/$BASE.json"
        done
        CONFDIR='1'
    fi
}

install_log() {
    LOG='0'
    if [ ! -d '/var/log/xray/' ]; then
        mkdir -p /var/log/xray/
        touch /var/log/xray/access.log /var/log/xray/error.log
        chmod 755 /var/log/xray/
        chmod 600 /var/log/xray/*.log
        LOG='1'
    fi
}

information() {
    echo 'installed: /usr/local/bin/xray'
    echo 'installed: /usr/local/share/xray/geoip.dat'
    echo 'installed: /usr/local/share/xray/geosite.dat'
    if [ "$CONFDIR" -eq '1' ]; then
        echo 'installed: /usr/local/etc/xray/ layout initialized.'
    fi
    
    rm -rf "$TMP_DIRECTORY"
    echo "removed: $TMP_DIRECTORY"
    echo "info: Xray installation completed successfully."
}

main() {
    check_distro || return 1
    check_if_running_as_root || return 1
    identify_architecture || return 1
    install_dependencies

    TMP_DIRECTORY="${HOME}/xray_tmp/"
    mkdir -p "$TMP_DIRECTORY"
    
    ZIP_FILE="${TMP_DIRECTORY}Xray-linux-$MACHINE.zip"
    DOWNLOAD_LINK="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$MACHINE.zip"

    download_xray
    verification_xray
    decompression
    install_xray
    install_confdir
    install_log
    information
}

main