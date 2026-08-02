#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MiaoVPS — 手动 WireGuard 服务器部署脚本
#  用途：在没有 MiaoVPS 桌面端的情况下手动部署
#  使用：bash bootstrap-server.sh
#  支持：Ubuntu 22.04 / 24.04
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✕]${NC} $1"; exit 1; }

# ── 默认配置 ──────────────────────────────────────────
WG_PORT="${WG_PORT:-51820}"
VPN_CIDR="${VPN_CIDR:-10.66.66.0/24}"
SERVER_VPN_IP="${SERVER_VPN_IP:-10.66.66.1}"
CLIENT_VPN_IP="${CLIENT_VPN_IP:-10.66.66.2}"
DNS="${DNS:-1.1.1.1}"
MTU="${MTU:-1380}"
MSS="${MSS:-$((MTU - 40))}"
BACKUP_DIR="/var/lib/miaovps/backups/$(date +%s)"
WG_DIR="/etc/wireguard"

# ── 权限检查 ──────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || err "请使用 root 运行"
log "root 权限确认"

# ── 检测 OS ───────────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    log "操作系统: $NAME $VERSION_ID"
    case "$ID" in
        ubuntu) ;;
        *) warn "非 Ubuntu 系统，可能不完全兼容" ;;
    esac
else
    warn "无法检测操作系统"
fi

# ── Step 1: 备份现有配置 ─────────────────────────────
log "备份现有配置 → $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
cp -r /etc/wireguard "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/sysctl.d "$BACKUP_DIR/" 2>/dev/null || true

# ── Step 2: 安装 WireGuard ────────────────────────────
if command -v wg &>/dev/null; then
    log "WireGuard 已安装: $(wg --version 2>&1 | head -1)"
else
    log "安装 WireGuard..."
    apt-get update -qq
    apt-get install -y -qq wireguard-tools
    log "WireGuard 安装完成"
fi

# ── Step 3: 生成密钥 ─────────────────────────────────
mkdir -p "$WG_DIR"
if [ ! -f "$WG_DIR/private.key" ]; then
    log "生成服务器密钥对..."
    wg genkey | tee "$WG_DIR/private.key" | wg pubkey > "$WG_DIR/public.key"
    chmod 600 "$WG_DIR/private.key"
else
    log "密钥已存在，跳过"
fi
SERVER_PRIVATE=$(cat "$WG_DIR/private.key")
SERVER_PUBLIC=$(cat "$WG_DIR/public.key")
log "服务器公钥: $SERVER_PUBLIC"

# ── Step 4: 配置 wg0.conf ────────────────────────────
log "生成 wg0.conf..."
cat > "$WG_DIR/wg0.conf" <<WGCONF
[Interface]
PrivateKey = $SERVER_PRIVATE
ListenPort = $WG_PORT
Address = $SERVER_VPN_IP/24
MTU = $MTU

# 客户端 Peer 将在添加设备时追加
WGCONF
chmod 600 "$WG_DIR/wg0.conf"
log "wg0.conf 已写入"

# ── Step 5: IP Forward + NAT + 防火墙 ────────────────
log "配置 IP Forward..."
cat > /etc/sysctl.d/99-miaovps.conf <<EOF
net.ipv4.ip_forward = 1
EOF
sysctl -p /etc/sysctl.d/99-miaovps.conf >/dev/null 2>&1

log "配置 iptables NAT..."
DEFAULT_IFACE=$(ip route show default | awk '{print $5}' | head -1)
if [ -n "$DEFAULT_IFACE" ]; then
    iptables -t nat -C POSTROUTING -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$DEFAULT_IFACE" -j MASQUERADE
    iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
    iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT
    # WireGuard MTU 1380: set TCP SYN MSS explicitly to avoid PMTUD black holes.
    iptables -t mangle -C FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS" 2>/dev/null || \
        iptables -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS"
    iptables -t mangle -C FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS" 2>/dev/null || \
        iptables -t mangle -A FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS"
    log "NAT + Forward 规则已配置 (iface: $DEFAULT_IFACE)"
else
    warn "无法检测默认网卡，请手动配置 NAT"
fi

# ── Step 6: 启动服务 ─────────────────────────────────
log "启动 WireGuard..."
systemctl enable wg-quick@wg0 2>/dev/null || true
systemctl start wg-quick@wg0
sleep 1

if systemctl is-active --quiet wg-quick@wg0; then
    log "WireGuard 服务已启动"
else
    err "WireGuard 启动失败，请检查 journalctl -u wg-quick@wg0"
fi

# ── Step 7: 验证 ─────────────────────────────────────
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
wg show wg0
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "部署完成！"
echo ""
echo "服务器公钥: $SERVER_PUBLIC"
echo "监听端口:   $WG_PORT"
echo "VPN 网段:   $VPN_CIDR"
echo ""
echo "下一步："
echo "  1. 确保云安全组已开放 UDP $WG_PORT"
echo "  2. 在客户端生成密钥对"
echo "  3. 添加 Peer: wg set wg0 peer <客户端公钥> allowed-ips $CLIENT_VPN_IP/32"
echo "  4. 生成客户端配置并导入 WireGuard 客户端"
