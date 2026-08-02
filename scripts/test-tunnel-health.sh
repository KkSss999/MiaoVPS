#!/usr/bin/env bash
# MiaoVPS 隧道健康检查（只读）：出口 IP、VPN 网关连通、延迟/抖动/丢包、
# Cloudflare 上下行和 GitHub 目的地多次测速。
#
# 用法：
#   bash scripts/test-tunnel-health.sh
#   bash scripts/test-tunnel-health.sh --vps 203.0.113.10 --bytes 67108864
#
# 默认测速会消耗约 48 MiB 流量（下行 32 MiB、上行 16 MiB）。不改动路由、DNS 或隧道配置。

set -u -o pipefail

DEFAULT_VPS="203.0.113.10"
TEST_BYTES=33554432
PING_COUNT=10
SAMPLES=6
GITHUB_URL="https://github.com/KkSss999/pmem/archive/refs/heads/main.tar.gz"
VPS_IP=""

usage() {
    cat <<'EOF'
MiaoVPS 隧道健康检查

用法: bash scripts/test-tunnel-health.sh [选项]

  --vps <IPv4>     指定 VPS 公网 IP（默认从 ~/.miaovps/profile.json 读取）
  --bytes <bytes>  下行测速字节数，默认 33554432（32 MiB）
  --samples <n>    GitHub 测速次数，默认 6（取中位数）
  --help           显示帮助

示例:
  bash scripts/test-tunnel-health.sh
  bash scripts/test-tunnel-health.sh --vps 203.0.113.10 --bytes 67108864

测速服务：Cloudflare speed endpoint + GitHub 公共仓库归档；脚本不上传任何本机文件或配置。
EOF
}

die() {
    echo "错误: $*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --vps)
            [ "$#" -ge 2 ] || die "--vps 缺少 IPv4 参数"
            VPS_IP="$2"
            shift 2
            ;;
        --bytes)
            [ "$#" -ge 2 ] || die "--bytes 缺少字节数"
            TEST_BYTES="$2"
            shift 2
            ;;
        --samples)
            [ "$#" -ge 2 ] || die "--samples 缺少次数"
            SAMPLES="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *) die "未知参数: $1（使用 --help 查看帮助）" ;;
    esac
done

case "$TEST_BYTES" in
    ''|*[!0-9]*) die "--bytes 必须是正整数" ;;
esac
[ "$TEST_BYTES" -gt 0 ] || die "--bytes 必须大于 0"
case "$SAMPLES" in
    ''|*[!0-9]*) die "--samples 必须是正整数" ;;
esac
[ "$SAMPLES" -gt 0 ] || die "--samples 必须大于 0"

profile_endpoint() {
    local profile="$HOME/.miaovps/profile.json"
    [ -r "$profile" ] || return 1
    sed -nE 's/^[[:space:]]*"server_endpoint"[[:space:]]*:[[:space:]]*"([0-9.]+):[0-9]+".*/\1/p' "$profile" | head -1
}

if [ -z "$VPS_IP" ]; then
    VPS_IP="$(profile_endpoint || true)"
fi
VPS_IP="${VPS_IP:-$DEFAULT_VPS}"

case "$VPS_IP" in
    *[!0-9.]*|*..*|.*|*.) die "--vps 需要是 IPv4 地址" ;;
esac

command -v curl >/dev/null 2>&1 || die "未找到 curl"
command -v ping >/dev/null 2>&1 || die "未找到 ping"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/miaovps-health.XXXXXX")"
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

format_mbps() {
    awk -v bytes_per_sec="$1" 'BEGIN { printf "%.2f Mbps", bytes_per_sec * 8 / 1000000 }'
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  MiaoVPS 隧道健康检查（只读）"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "VPS: $VPS_IP"
echo

egress_via_vps=0
gateway_reachable=0
down_ok=0
up_ok=0
github_ok=0

echo "[1/5] 当前出口 IP"
egress_ip="$(curl -4fsS --connect-timeout 5 --max-time 12 https://api.ipify.org 2>/dev/null || true)"
if [ -n "$egress_ip" ]; then
    echo "  出口: $egress_ip"
    if [ "$egress_ip" = "$VPS_IP" ]; then
        egress_via_vps=1
        echo "  ✅ Full Tunnel 生效：流量正经由 VPS 出口"
    else
        echo "  ⚠ 出口不等于 VPS：可能未连接 Full Tunnel，或出口 IP 与节点 IP 不同"
    fi
else
    echo "  ❌ 无法查询出口 IP（DNS 或 HTTPS 不可用）"
fi

echo
echo "[2/5] VPN 网关 ICMP 与延迟（$PING_COUNT 次，辅助指标）"
ping_output="$tmp_dir/ping.txt"
if ping -c "$PING_COUNT" -W 1000 10.66.66.1 >"$ping_output" 2>&1; then
    gateway_reachable=1
    summary="$(tail -1 "$ping_output")"
    loss="$(printf '%s\n' "$summary" | sed -nE 's/.* ([0-9.]+)% packet loss.*/\1/p')"
    rtt="$(printf '%s\n' "$summary" | sed -nE 's/.*=[[:space:]]*([0-9.]+)\/([0-9.]+)\/([0-9.]+)\/([0-9.]+)[[:space:]]*ms.*/min \1 ms · avg \2 ms · max \3 ms · jitter \4 ms/p')"
    echo "  ✅ 网关 10.66.66.1 可达"
    [ -n "$loss" ] && echo "  丢包: $loss%"
    [ -n "$rtt" ] && echo "  延迟: $rtt"
else
    echo "  ⚠ 网关 10.66.66.1 未响应 ICMP"
    tail -3 "$ping_output" | sed 's/^/  /'
    echo "  注：这可能是 VPS 防火墙不回应 ping；若上方出口已是 VPS，不能仅凭此判定隧道断开。"
fi

echo
echo "[3/5] 下行测速（$(awk -v n="$TEST_BYTES" 'BEGIN { printf "%.0f MiB", n / 1048576 }')，Cloudflare）"
down_result="$(curl -4fsS -o /dev/null --connect-timeout 8 --max-time 90 \
    -w '%{speed_download} %{time_total}' "https://speed.cloudflare.com/__down?bytes=$TEST_BYTES" 2>&1 || true)"
if printf '%s' "$down_result" | awk 'NF == 2 && $1 ~ /^[0-9.]+$/ { exit 0 } { exit 1 }'; then
    down_ok=1
    down_speed="${down_result%% *}"
    down_time="${down_result#* }"
    echo "  ✅ 下行: $(format_mbps "$down_speed")（耗时 ${down_time}s）"
else
    echo "  ❌ 下行测速失败: $down_result"
fi

echo
echo "[4/5] GitHub 目的地测速（${SAMPLES} 次，每次最多 1 MiB）"
github_speeds="$tmp_dir/github-speeds.txt"
: >"$github_speeds"
for sample in $(seq 1 "$SAMPLES"); do
    github_result="$(curl -4LfsS --range 0-1048575 -o /dev/null --connect-timeout 8 --max-time 30 \
        -w '%{size_download} %{speed_download} %{time_total} %{remote_ip}' "$GITHUB_URL" 2>&1 || true)"
    if printf '%s' "$github_result" | awk 'NF == 4 && $1 ~ /^[0-9.]+$/ && $2 ~ /^[0-9.]+$/ { exit 0 } { exit 1 }'; then
        github_bytes="$(printf '%s' "$github_result" | awk '{print $1}')"
        github_speed="$(printf '%s' "$github_result" | awk '{print $2}')"
        github_time="$(printf '%s' "$github_result" | awk '{print $3}')"
        github_ip="$(printf '%s' "$github_result" | awk '{print $4}')"
        printf '%s\n' "$github_speed" >>"$github_speeds"
        echo "  #$sample: $(format_mbps "$github_speed") · ${github_bytes} B · ${github_time}s · $github_ip"
    else
        echo "  #$sample: ❌ 失败${github_result:+：$github_result}"
    fi
done
if [ -s "$github_speeds" ]; then
    github_ok=1
    github_median="$(sort -n "$github_speeds" | awk '{v[NR]=$1} END { if (NR % 2) print v[(NR+1)/2]; else print (v[NR/2]+v[NR/2+1])/2 }')"
    echo "  ✅ GitHub 中位数: $(format_mbps "$github_median")"
else
    echo "  ❌ GitHub 目的地测速全部失败"
fi

echo
echo "[5/5] 上行测速（$(awk -v n="$TEST_BYTES" 'BEGIN { printf "%.0f MiB", n / 2097152 }')，Cloudflare）"
upload_bytes=$((TEST_BYTES / 2))
up_result="$(dd if=/dev/zero bs=1048576 count=$(( (upload_bytes + 1048575) / 1048576 )) 2>/dev/null \
    | head -c "$upload_bytes" \
    | curl -4fsS -o /dev/null --connect-timeout 8 --max-time 90 --data-binary @- \
        -w '%{speed_upload} %{time_total}' https://speed.cloudflare.com/__up 2>&1 || true)"
if printf '%s' "$up_result" | awk 'NF == 2 && $1 ~ /^[0-9.]+$/ { exit 0 } { exit 1 }'; then
    up_ok=1
    up_speed="${up_result%% *}"
    up_time="${up_result#* }"
    echo "  ✅ 上行: $(format_mbps "$up_speed")（耗时 ${up_time}s）"
else
    echo "  ❌ 上行测速失败: $up_result"
fi

echo
if [ "$egress_via_vps" = "1" ] && [ "$down_ok" = "1" ] && [ "$up_ok" = "1" ] && [ "$github_ok" = "1" ]; then
    echo "结论：当前已验证数据可经 VPS 出口转发，测速结果可作为这一时刻的链路基线。"
    if [ "$gateway_reachable" != "1" ]; then
        echo "      网关 ICMP 未响应，建议后续在 VPS 放行 ICMP 后再把它纳入丢包/抖动指标。"
    fi
else
    echo "结论：本轮未完整验证隧道数据面，请先处理上面的失败项目后重试。"
fi
echo "建议在早晚高峰各运行一次；若 UDP 443 的握手或网关 ping 持续失败，再考虑线路升级。"
