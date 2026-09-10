#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

scripts=(nokey.sh nokey-common.sh realm.sh singbox.sh xray-socks.sh xray-warp.sh bbr.sh warp-helper.sh acme-cert.sh hysteria2.sh)
for script in "${scripts[@]}"; do
    [[ -x "$REPO_ROOT/$script" ]] || { echo "FAIL: $script is not executable"; exit 1; }
    bash -n "$REPO_ROOT/$script"
done

grep -q 'install_dependencies jq' "$REPO_ROOT/xray-socks.sh"
grep -q 'install_dependencies jq' "$REPO_ROOT/xray-warp.sh"

realm_output="$(bash "$REPO_ROOT/realm.sh" --remote=1.2.3.4:443 --dry-run)"
[[ "$realm_output" == *"Realm dry-run"* ]]

singbox_output="$(bash "$REPO_ROOT/singbox.sh" --dry-run)"
[[ "$singbox_output" == *"Sing-box dry-run"* ]]

bbr_output="$(bash "$REPO_ROOT/bbr.sh" --dry-run)"
[[ "$bbr_output" == *"BBR dry-run"* ]]

acme_output="$(bash "$REPO_ROOT/acme-cert.sh" --domain=example.com --dry-run)"
[[ "$acme_output" == *"ACME dry-run"* ]]

hysteria_output="$(bash "$REPO_ROOT/hysteria2.sh" --domain=example.com --dry-run)"
[[ "$hysteria_output" == *"Hysteria2 dry-run"* ]]

[[ -x "$REPO_ROOT/hysteria2.rc" ]]
grep -q 'ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml' "$REPO_ROOT/hysteria2.service"

[[ "$(bash "$REPO_ROOT/xray-socks.sh" --help)" == *"Usage: xray-socks.sh"* ]]

echo "All feature entrypoint tests passed."
