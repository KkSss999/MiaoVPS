#!/usr/bin/env bash
# 验证断线自动重连 — 在 VPS 侧阻断 WireGuard 端口，制造超过 105 秒的中断
#
# 为什么要 105 秒以上：
#   boringtun 自己会处理 15s 静默 + 90s 重传 = 105s 内的中断。
#   本脚本验证的是**超过**这个窗口后 Tunn 进入 Expired 终态、
#   由 MiaoVPS 强制复活的路径。短于 105s 的中断测不出这个功能。
#
# 用法: bash scripts/test-reconnect.sh [阻断秒数,默认130]
#
# 安全性: 脚本退出时（含 Ctrl+C / 出错）一定会移除阻断规则。
#         阻断只影响 UDP 51820，SSH 走 TCP 22 不受影响。

set -uo pipefail

VPS_IP="${VPS_IP:-203.0.113.10}"
VPS_USER="${VPS_USER:-ubuntu}"
VPS_KEY="${VPS_KEY:-$HOME/Downloads/VPS.pem}"
VPS_SUDO_PW="${VPS_SUDO_PW:-[REDACTED_PASSWORD]}"
WG_PORT=51820
BLOCK_SECS="${1:-130}"
PEER_IP="${PEER_IP:-10.66.66.1}"

ssh_vps() {
    ssh -i "$VPS_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$VPS_USER@$VPS_IP" "$@" 2>&1 | grep -v '^\[sudo'
}

# 阻断/解除都用 sudo -S，密码走 stdin —— 命令本身不能再占 stdin
block_port() {
    ssh_vps "echo '$VPS_SUDO_PW' | sudo -S iptables -I INPUT 1 -p udp --dport $WG_PORT -j DROP 2>/dev/null"
}

unblock_port() {
    # 循环删除，确保重复运行留下的规则都被清掉
    ssh_vps "for i in 1 2 3; do echo '$VPS_SUDO_PW' | sudo -S iptables -D INPUT -p udp --dport $WG_PORT -j DROP 2>/dev/null || true; done"
}

cleanup() {
    echo
    echo "[清理] 移除阻断规则..."
    unblock_port
    local remaining
    remaining=$(ssh_vps "echo '$VPS_SUDO_PW' | sudo -S iptables -S INPUT 2>/dev/null | grep -c \"dport $WG_PORT -j DROP\"" | tr -d '[:space:]')
    if [ "${remaining:-0}" = "0" ]; then
        echo "[清理] ✅ 规则已移除，链路恢复"
    else
        echo "[清理] ⚠ 仍有 $remaining 条阻断规则，请手动检查:"
        echo "       ssh VPS \"sudo iptables -S INPUT | grep $WG_PORT\""
    fi
}
trap cleanup EXIT INT TERM

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  断线自动重连验证"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  阻断时长: ${BLOCK_SECS}s (需 >105s 才能触发 Expired)"
echo

echo "[1/4] 确认隧道当前连通..."
if ping -c 2 -W 3000 "$PEER_IP" >/dev/null 2>&1; then
    echo "      ✅ ping $PEER_IP 通"
else
    echo "      ❌ ping $PEER_IP 不通 — 隧道未运行？先启动 sudo miaovps connect"
    exit 1
fi

echo "[2/4] 在 VPS 阻断 UDP $WG_PORT ..."
block_port
echo "      已阻断。观察 miaovps 日志，应依次出现:"
echo "        ~15s  boringtun 开始重传握手"
echo "        ~105s [隧道] 连接已失效…第 1 次重连"
echo "        之后  按 5s→10s→20s… 退避持续重连"
echo

for ((i = BLOCK_SECS; i > 0; i -= 10)); do
    printf "\r      阻断中，剩余 %3ds ..." "$i"
    sleep 10
done
printf "\r      阻断结束            \n"

echo "[3/4] 解除阻断..."
unblock_port
echo "      已解除。等待自动重连（退避最长 60s）..."

echo "[4/4] 验证恢复 —— 最多等 90s"
RECOVERED=0
for i in $(seq 1 18); do
    if ping -c 1 -W 2000 "$PEER_IP" >/dev/null 2>&1; then
        echo "      ✅ 第 $((i * 5))s 恢复连通"
        RECOVERED=1
        break
    fi
    sleep 5
done

echo
if [ "$RECOVERED" = "1" ]; then
    echo "🎉 重连成功。检查 miaovps 输出里的「重连 N 次」计数。"
else
    echo "❌ 90s 内未恢复。排查:"
    echo "   1. miaovps 日志是否有「第 N 次重连」——没有则说明未触发 Expired"
    echo "   2. ssh VPS \"sudo wg show\" 看 latest handshake"
    echo "   3. 确认跑的是新编译的二进制（含重连逻辑）"
    exit 1
fi
