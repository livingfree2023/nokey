#!/usr/bin/env bash
set -euo pipefail

# 检查依赖
for cmd in curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "错误: 缺少依赖命令 '$cmd'，请先安装。" >&2
    exit 1
  fi
done

# 生成 X25519 密钥对
if command -v wg >/dev/null 2>&1; then
  PRIV_KEY=$(wg genkey)
  PUB_KEY=$(echo "$PRIV_KEY" | wg pubkey)
elif command -v openssl >/dev/null 2>&1; then
  TMP_DIR=$(mktemp -d)
  trap 'rm -rf "$TMP_DIR"' EXIT

  openssl genpkey -algorithm X25519 -out "$TMP_DIR/priv.der" -outform DER 2>/dev/null
  PRIV_KEY=$(tail -c 32 "$TMP_DIR/priv.der" | base64 | tr -d '\n')

  openssl pkey -inform DER -in "$TMP_DIR/priv.der" -pubout -outform DER -out "$TMP_DIR/pub.der" 2>/dev/null
  PUB_KEY=$(tail -c 32 "$TMP_DIR/pub.der" | base64 | tr -d '\n')
else
  echo "错误: 系统中必须安装 'wg' 或 'openssl' 用于生成密钥对。" >&2
  exit 1
fi

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 构造 Cloudflare WARP 注册请求体
PAYLOAD=$(cat <<EOF
{
  "key": "${PUB_KEY}",
  "install_id": "",
  "fcm_token": "",
  "tos": "${NOW}",
  "model": "PC",
  "type": "Android",
  "locale": "en_US"
}
EOF
)

# 调用 Cloudflare 官方客户端注册 API
RESP=$(curl -sS -X POST "https://api.cloudflareclient.com/v0a2158/reg" \
  -H "Content-Type: application/json" \
  -H "User-Agent: okhttp/3.12.1" \
  -d "$PAYLOAD")

# 校验 API 响应：只要包含 id 和 config 即代表成功
CHECK_ID=$(echo "$RESP" | jq -r '.id // empty' 2>/dev/null)
if [ -z "$CHECK_ID" ]; then
  echo "注册失败，Cloudflare 返回信息：" >&2
  echo "$RESP" >&2
  exit 1
fi

# 提取字段（兼容顶层或 result 嵌套结构）
ADDR_V4=$(echo "$RESP" | jq -r '.config.interface.addresses.v4 // .result.config.interface.addresses.v4')
ADDR_V6=$(echo "$RESP" | jq -r '.config.interface.addresses.v6 // .result.config.interface.addresses.v6')
PEER_PUB=$(echo "$RESP" | jq -r '.config.peers[0].public_key // .result.config.peers[0].public_key')
PEER_EP=$(echo "$RESP" | jq -r '.config.peers[0].endpoint.host // .result.config.peers[0].endpoint.host')
CLIENT_ID=$(echo "$RESP" | jq -r '.config.client_id // .result.config.client_id // empty')

# 解析 reserved 字节 (3 字节)
RESERVED_JSON="null"
if [ -n "$CLIENT_ID" ]; then
  # 将 base64 client_id 解码为 3 个十进制整数
  HEX=$(echo "$CLIENT_ID" | base64 -d 2>/dev/null | od -An -tuC || true)
  if [ -n "$HEX" ]; then
    RESERVED_JSON=$(echo "$HEX" | awk '{print "["$1","$2","$3"]"}')
  fi
fi

# Endpoint 处理：默认使用官方优选 Anycast IP 保证连通性
if [ -z "$PEER_EP" ] || [ "$PEER_EP" = "null" ]; then
  PEER_EP="162.159.192.1:2408"
elif [[ "$PEER_EP" != *":"* ]]; then
  PEER_EP="${PEER_EP}:2408"
fi

# 输出标准 Xray-core outbound JSON
jq -n \
  --arg priv "$PRIV_KEY" \
  --arg v4 "${ADDR_V4}/32" \
  --arg v6 "${ADDR_V6}/128" \
  --arg peer_pub "$PEER_PUB" \
  --arg peer_ep "$PEER_EP" \
  --argjson reserved "$RESERVED_JSON" \
  '{
    tag: "warp-out",
    protocol: "wireguard",
    settings: {
      secretKey: $priv,
      address: [$v4, $v6],
      peers: [
        {
          publicKey: $peer_pub,
          endpoint: $peer_ep,
          keepAlive: 25
        }
      ],
      mtu: 1280
    } + (if $reserved != null then {reserved: $reserved} else {} end)
  }'
