#!/bin/bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${script_dir}/xray-warp.sh" ]]; then
    exec bash "${script_dir}/xray-warp.sh" "$@"
fi

script_url="${NOKEY_WARP_URL:-https://raw.githubusercontent.com/livingfree2023/nokey/refs/heads/main/xray-warp.sh}"
if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to load xray-warp.sh" >&2
    exit 1
fi
exec bash <(curl -fsSL "$script_url") "$@"
