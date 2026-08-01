#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154,SC2317  # mock globals/functions read indirectly by sourced nokey.sh code
set -euo pipefail

# *_url vars below are assigned inside generate_share_links (sourced script).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=/dev/null
source "$REPO_ROOT/nokey.sh"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

# Test 1: netstack=4 resolves IP after detection values exist
netstack=""
ip=""
IPv4="198.51.100.10"
IPv6="2001:db8::10"
port="12345"
domain="example.com"
caddy_mode=0
initialize_variables >/dev/null 2>&1 || fail "initialize_variables auto mode"
[[ "$netstack" == "4" ]] || fail "auto netstack should prefer IPv4"
[[ "$ip" == "$IPv4" ]] || fail "auto netstack should assign IPv4 ip"
pass "auto netstack IP assignment"

# Test 2: explicit netstack=6 assigns IPv6 IP
netstack="6"
ip=""
IPv4="198.51.100.11"
IPv6="2001:db8::11"
port="12346"
domain="example.com"
caddy_mode=0
initialize_variables >/dev/null 2>&1 || fail "initialize_variables netstack=6"
[[ "$ip" == "$IPv6" ]] || fail "netstack=6 should assign IPv6 ip"
pass "explicit netstack=6 IP assignment"

# Test 3: public key extraction from xray x25519 output
keys_sample=$'PrivateKey: PRIVATE_VALUE\nPublicKey: PUBLIC_VALUE'
extracted="$(extract_public_key_from_x25519_output "$keys_sample")"
[[ "$extracted" == "PUBLIC_VALUE" ]] || fail "public key extraction should return PUBLIC_VALUE"
pass "public key extraction"

# Test 4: key extraction supports spaced labels used by some xray builds
keys_sample_spaced=$'Private key: PRIVATE_SPACED\nPublic key: PUBLIC_SPACED'
extracted_private="$(extract_private_key_from_x25519_output "$keys_sample_spaced")"
extracted_public="$(extract_public_key_from_x25519_output "$keys_sample_spaced")"
[[ "$extracted_private" == "PRIVATE_SPACED" ]] || fail "private key extraction should support 'Private key:' format"
[[ "$extracted_public" == "PUBLIC_SPACED" ]] || fail "public key extraction should support 'Public key:' format"
pass "spaced label key extraction"

# Test 5: architecture mapping helper
[[ "$(resolve_arch_binary_name x86_64)" == "xray_amd64" ]] || fail "x86_64 should map to xray_amd64"
[[ "$(resolve_arch_binary_name amd64)" == "xray_amd64" ]] || fail "amd64 should map to xray_amd64"
[[ "$(resolve_arch_binary_name aarch64)" == "xray_arm64" ]] || fail "aarch64 should map to xray_arm64"
[[ "$(resolve_arch_binary_name arm64)" == "xray_arm64" ]] || fail "arm64 should map to xray_arm64"
if resolve_arch_binary_name mips >/dev/null 2>&1; then
  fail "unsupported architecture should fail"
fi
pass "architecture mapping helper"

# Test 6: OS family helper
ID="alpine"
ID_LIKE=""
[[ "$(resolve_os_family)" == "alpine" ]] || fail "ID=alpine should map to alpine"
ID="debian"
ID_LIKE="debian"
[[ "$(resolve_os_family)" == "debian/systemd-compatible" ]] || fail "debian-like should map to debian/systemd-compatible"
pass "os family helper"

# Test 7: dry-run output includes expected download and service lines
ID="alpine"
ID_LIKE=""
dry_run_out="$(dry_run_preview 2>&1 || true)"
echo "$dry_run_out" | grep -Eq 'releases/latest/download/xray_(amd64|arm64) -> /usr/local/bin/xray' || fail "dry-run should include xray download path"
[[ "$dry_run_out" == *"releases/latest/download/geoip.dat -> /usr/local/share/xray/geoip.dat"* ]] || fail "dry-run should include geoip.dat download path"
[[ "$dry_run_out" == *"releases/latest/download/geosite.dat -> /usr/local/share/xray/geosite.dat"* ]] || fail "dry-run should include geosite.dat download path"
[[ "$dry_run_out" == *"/etc/init.d/xray"* ]] || fail "dry-run alpine should include OpenRC path"
pass "dry-run preview output"

# Test 8: BBR guard/message exists for readonly environments
enable_bbr_source="$(declare -f enable_bbr)"
[[ "$enable_bbr_source" == *'[[ ! -w /etc/sysctl.conf ]]'* ]] || fail "enable_bbr should check writable sysctl.conf"
[[ "$enable_bbr_source" == *'/etc/sysctl.conf is not writable'* ]] || fail "enable_bbr should expose clear skip message"
pass "bbr readonly guard present"

# Test 8b: enable_bbr verifies live kernel state instead of trusting sysctl -p exit code
sysctl_apply_cmd="sysctl -p >> \"\$LOG_FILE\" 2>&1 || true"
[[ "$enable_bbr_source" == *'cat /proc/sys/net/ipv4/tcp_congestion_control'* ]] || fail "enable_bbr should read back the live tcp_congestion_control value"
[[ "$enable_bbr_source" == *'BBR not active'* ]] || fail "enable_bbr should warn when BBR did not take effect"
[[ "$enable_bbr_source" == *"$sysctl_apply_cmd"* ]] || fail "enable_bbr should not abort when sysctl -p reports failure"
pass "bbr live-state verification present"

# Test 9: initialize_ip_from_netstack auto-detects IPv4 when IPv4/IPv6 empty
ip=""
IPv4=""
IPv6=""
netstack=""
detect_network_interfaces() {
    IPv4="203.0.113.10"
}
initialize_ip_from_netstack >/dev/null 2>&1 || fail "initialize_ip_from_netstack should trigger detection when IPv4/IPv6 empty"
[[ -n "$ip" ]] || fail "ip should be set after fallback detection"
[[ "$ip" == "203.0.113.10" ]] || fail "ip should match mock detection result"
pass "netstack fallback detection"

# Test 10: netstack=6 yields non-empty ip when IPv6 is present (defensive detection)
netstack="6"
ip=""
IPv4=""
IPv6="2001:db8::20"
port="12348"
domain="example.com"
caddy_mode=0
initialize_variables >/dev/null 2>&1 || fail "initialize_variables netstack=6 with IPv6"
[[ -n "$ip" ]] || fail "ip should be non-empty when netstack=6 and IPv6 is present"
[[ "$ip" == "$IPv6" ]] || fail "ip should match IPv6"
pass "netstack=6 IP validation after detection"

# Test 11: parse_args rejects invalid --port/--netstack/unknown flag (non-zero exit)
if (parse_args --port=abc >/dev/null 2>&1); then
  fail "invalid --port should exit non-zero"
fi
if (parse_args --netstack=9 >/dev/null 2>&1); then
  fail "invalid --netstack should exit non-zero"
fi
if (parse_args --unknown-flag >/dev/null 2>&1); then
  fail "unknown flag should exit non-zero"
fi
pass "parse_args rejects invalid input"

# Test 12: parse_args accepts valid --port
port=""
arg_port_set=0
parse_args --port=8443
[[ "$port" == "8443" ]] || fail "--port=8443 should set port=8443"
pass "parse_args valid --port"

# Test 13: parse_args --remove sets remove_mode without early exit
remove_mode=0
parse_args --remove
[[ "$remove_mode" -eq 1 ]] || fail "--remove should set remove_mode=1"
pass "parse_args --remove flag"

# Test 14: IPv6 vless share URL brackets the address
share_dir="$(mktemp -d)"
if (
  cd "$share_dir" || exit 1
  sing_box_mode=0
  netstack="6"
  ip="2001:db8::1"
  port="443"
  domain="example.com"
  uuid="test-uuid"
  fingerprint="chrome"
  public_key="test-pbk"
  shortid="abcd"
  current_hostname="testhost"
  mldsa_enabled=0
  generate_share_links >/dev/null 2>&1
  [[ "$vless_reality_url_short" == *"@[2001:db8::1]:443"* ]]
); then
  pass "IPv6 share URL bracketing"
else
  fail "IPv6 share URL should bracket the address"
fi
rm -rf "$share_dir"

# Test 15: mldsa URL uses &pqv= before # fragment, never &# 
share_dir="$(mktemp -d)"
if (
  cd "$share_dir" || exit 1
  sing_box_mode=0
  netstack="4"
  ip="198.51.100.10"
  port="443"
  domain="example.com"
  uuid="test-uuid"
  fingerprint="chrome"
  public_key="test-pbk"
  shortid="abcd"
  current_hostname="testhost"
  mldsa_enabled=1
  mldsa65Verify="VERIFYVALUE"
  generate_share_links >/dev/null 2>&1
  [[ "$vless_reality_mldsa_url" == *"&pqv=VERIFYVALUE#testhost" ]] \
    && [[ "$vless_reality_mldsa_url" != *"&#"* ]]
); then
  pass "mldsa share URL fragment"
else
  fail "mldsa URL should use &pqv= then #, never &#"
fi
rm -rf "$share_dir"

# Test 16: URL_FILE stays ANSI-free even on a TTY (colors active)
if command -v script >/dev/null 2>&1 && command -v mktemp >/dev/null 2>&1; then
  pty_dir="$(mktemp -d)"
  tmp_script="$(mktemp)"
  cat > "$tmp_script" <<'EOF'
cd "$1" || exit 1
source "$2" || exit 1
sing_box_mode=0
netstack=4
ip='198.51.100.10'
port='12345'
domain='example.com'
uuid='test-uuid'
fingerprint='chrome'
public_key='test-pbk'
shortid='abcd'
current_hostname='testhost'
mldsa_enabled=0
generate_share_links >/dev/null 2>&1
EOF
  script -qec "bash '$tmp_script' '$pty_dir' '$REPO_ROOT/nokey.sh'" /dev/null >/dev/null 2>&1 \
    || script -qc "bash '$tmp_script' '$pty_dir' '$REPO_ROOT/nokey.sh'" /dev/null >/dev/null 2>&1 \
    || true
  if [[ -s "$pty_dir/nokey.url" ]] && ! LC_ALL=C grep -qF "$(printf '\033')" "$pty_dir/nokey.url"; then
    pass "URL_FILE stays ANSI-free on a TTY"
  else
    fail "URL_FILE must not contain ANSI escapes even on a TTY"
  fi
  rm -rf "$pty_dir" "$tmp_script"
else
  pass "URL_FILE plainness skipped (script/mktemp unavailable)"
fi

# Test 17: is_port_reusable returns 0 when nothing is listening (free port)
if (
  ss() { return 0; }  # mock: no listeners
  is_port_reusable 443 xray "$SERVICE_NAME" "$SERVICE_NAME_ALPINE"
); then
  pass "port reusable when free"
else
  fail "free port should be reported reusable"
fi

# Test 18: is_port_reusable returns 1 when another process owns the port
if (
  ss() { echo "LISTEN 0 128 0.0.0.0:443 users:((\"nginx\"))"; }
  ! is_port_reusable 443 xray "$SERVICE_NAME" "$SERVICE_NAME_ALPINE"
); then
  pass "port not reusable when owned by another process"
else
  fail "foreign-owned port must not be reusable"
fi

# Test 19: is_port_reusable returns 0 when xray already owns the port
if (
  ss() { echo "LISTEN 0 128 0.0.0.0:443 users:((\"xray\"))"; }
  is_port_reusable 443 xray "$SERVICE_NAME" "$SERVICE_NAME_ALPINE"
); then
  pass "port reusable when owned by xray"
else
  fail "xray-owned port should be reusable"
fi

# Test 20: initialize_variables prefers 443 when it is reusable
if (
  is_port_reusable() { return 0; }  # mock: 443 deemed reusable
  netstack=""
  ip=""
  IPv4="198.51.100.30"
  IPv6="2001:db8::30"
  port=""
  domain="example.com"
  caddy_mode=0
  initialize_variables >/dev/null 2>&1
  [[ "$port" == "443" ]]
); then
  pass "443 preferred when reusable"
else
  fail "port should be 443 when reusable"
fi

# Test 21: initialize_variables falls back to a random port >= 10000 when 443 is taken
if (
  is_port_reusable() { return 1; }  # mock: 443 occupied by another process
  netstack=""
  ip=""
  IPv4="198.51.100.31"
  IPv6="2001:db8::31"
  port=""
  domain="example.com"
  caddy_mode=0
  initialize_variables >/dev/null 2>&1
  [[ "$port" != "443" && "$port" -ge 10000 ]]
); then
  pass "random fallback when 443 occupied"
else
  fail "port should be random >= 10000 when 443 is taken"
fi

# Test 22: probe_reality_target accepts a candidate whose curl probe reports h2
# and records TLS-handshake latency into probe_latency_ms
if (
  curl() { printf '2|0.045\n'; }  # mock: %{http_version}|%{time_appconnect} -> h2, 45ms
  probe_reality_target www.cloudflare.com
  [[ "$probe_latency_ms" == "45" ]]
); then
  pass "probe accepts h2 target with latency"
else
  fail "h2-negotiating target should be accepted and latency recorded"
fi

# Test 23: probe_reality_target rejects a candidate whose curl probe fails
if (
  curl() { return 1; }  # mock: connection/TLS failure
  probe_reality_target www.cloudflare.com
); then
  fail "failed probe must not be accepted"
else
  pass "probe rejects failed target"
fi

# Test 24: pick_default_domain picks the first feasible candidate, skipping failures
if (
  probe_reality_target() {
    [[ "$1" == "www.microsoft.com" ]] && return 0
    return 1
  }
  domain=""
  pick_default_domain >/dev/null 2>&1
  [[ "$domain" == "www.microsoft.com" ]]
); then
  pass "picker selects first feasible candidate"
else
  fail "picker should select first feasible candidate"
fi

# Test 25: pick_default_domain falls back to DEFAULT_DOMAIN when nothing is feasible
if (
  probe_reality_target() { return 1; }
  domain=""
  pick_default_domain >/dev/null 2>&1
  [[ "$domain" == "$DEFAULT_DOMAIN" ]]
); then
  pass "picker falls back to default domain"
else
  fail "picker should fall back to DEFAULT_DOMAIN when scan finds nothing"
fi

echo "All tests passed."
