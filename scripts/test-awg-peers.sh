#!/bin/bash
# Exercise the real enrollment script without root, systemd, or a live tunnel.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export work
mkdir -p "$work/bin" "$work/run/lock" "$work/etc/amnezia/amneziawg"
export PATH="$work/bin:$PATH"
export PYTHONUTF8=1
awk '{gsub(/\/run\//, ENVIRON["work"] "/run/"); gsub(/\/etc\//, ENVIRON["work"] "/etc/"); print}' \
    "$root/crates/miaovps-provisioner/src/awg-peers.py" > "$work/peers.py"

key() { printf '%043d=' "$1"; }
first=$(key 1); second=$(key 2); third=$(key 3)
conf=$work/etc/amnezia/amneziawg/miao-awg.conf
cat > "$conf" <<EOF
# MiaoVPS single-device AWG trial
[Interface]
PrivateKey = $(key 8)
ListenPort = 52181
Address = 172.29.67.1/30
MTU = 1380
H1 = 120
H2 = 240
H3 = 360
H4 = 480
S1 = 20
S2 = 24
PostUp = iptables -t nat -A POSTROUTING -s 172.29.67.2/32 -o ens3 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 172.29.67.2/32 -o ens3 -j MASQUERADE

[Peer]
PublicKey = $first
AllowedIPs = 172.29.67.2/32
EOF
cp "$conf" "$work/before"
printf '%s\t172.29.67.2/32\n' "$first" > "$work/live"
key 9 > "$work/public"
printf '%s' '[{"dst":"default"},{"dst":"172.29.67.0/30","dev":"miao-awg"},{"dst":"172.29.67.0","dev":"miao-awg","table":"local"},{"dst":"172.29.67.1","dev":"miao-awg","table":"local"},{"dst":"172.29.67.3","dev":"miao-awg","table":"local"}' > "$work/routes"
: > "$work/iptables"
cat > "$work/bin/awg" <<'EOF'
#!/bin/bash
set -eu
[[ $1 != pubkey ]] || { cat > /dev/null; cat "$work/public"; exit; }
[[ $2 == miao-awg ]]
case $1:$3 in
    show:allowed-ips) cat "$work/live" ;;
    show:listen-port) echo 52181 ;;
    show:public-key) cat "$work/public" ;;
    set:peer)
        [[ ! -e $work/fail-awg ]] || exit 1
        printf '%s\t%s\n' "$4" "$6" >> "$work/live"
        ;;
    *) exit 1 ;;
esac
EOF
cat > "$work/bin/ip" <<'EOF'
#!/bin/bash
set -eu
if [[ $1 == -j ]]; then
    if [[ $3 == address ]]; then printf '%s\n' '[{"addr_info":[{"local":"172.29.67.1","prefixlen":30}]}]'
    else printf '%s]\n' "$(<"$work/routes")"; fi
    exit
fi
[[ $1 == -4 && $2 == route && $3 == add && $5 == dev && $6 == miao-awg ]]
printf ',{"dst":"%s","dev":"%s"}' "${4%/32}" "$6" >> "$work/routes"
EOF
cat > "$work/bin/iptables" <<'EOF'
#!/bin/bash
set -eu
args=" $* "
rule="${args// -[CIA] / action }"
if [[ " $* " == *' -C '* ]]; then grep -Fxq -- "$rule" "$work/iptables"; else printf '%s\n' "$rule" >> "$work/iptables"; fi
EOF
chmod +x "$work/bin/"*
peers() { python3 "$work/peers.py" "$@"; }
reject() {
    if peers "$@" > "$work/error" 2>&1; then echo "unexpected success: $*" >&2; exit 1; fi
}

cp "$work/routes" "$work/routes-before"
printf ',{"dst":"172.29.67.128/25","dev":"other"}' >> "$work/routes"
reject add "$second" '第二台设备'
grep -q 'overlaps VPS route' "$work/error"
cmp "$conf" "$work/before"
cp "$work/routes-before" "$work/routes"
touch "$work/run/miaovps-miao-awg-port"
reject add "$second" '第二台设备'
rm "$work/run/miaovps-miao-awg-port"

# Drop the runtime update after the durable allocation. Retry must finish the same peer.
touch "$work/fail-awg"
reject add "$second" '第二台设备'
peers list | grep -q '第二台设备.*(pending)'
rm "$work/fail-awg"
peers add "$second" '第二台设备' > "$work/reply"
grep -Fxq '172.29.67.4/32' "$work/reply"
if grep -Fxq "$(key 8)" "$work/reply"; then echo 'server private key was returned' >&2; exit 1; fi
peers add "$second" '第二台设备' | cmp - "$work/reply"
[[ $(wc -l < "$work/iptables") -eq 3 ]]
reject add "$second" '另一台设备'
peers add "$third" '第三台设备' > "$work/reply"
grep -Fxq '172.29.67.5/32' "$work/reply"
peers list | grep -q '第三台设备'
[[ $(wc -l < "$work/live") -eq 3 ]]
[[ $(wc -l < "$work/iptables") -eq 6 ]]
# All original lines (including the original peer and firewall hooks) are still present.
while IFS= read -r line; do grep -Fxq -- "$line" "$conf"; done < "$work/before"
python3 -c 'import os, sys; assert os.stat(sys.argv[1]).st_mode & 0o777 == 0o600' "$conf"
printf 'AWG peer enrollment checks passed\n'
