#!/bin/bash
# Invoked over SSH by deploy-awg. Only public client data is passed in.
set -euo pipefail
umask 077
port=$1
peer=$2
fail() { echo "$*" >&2; exit 1; }
[[ $port =~ ^[1-9][0-9]{0,4}$ && $port -le 65535 ]] || fail 'Invalid UDP port'
[[ $peer =~ ^[A-Za-z0-9+/]{43}=$ ]] || fail 'Invalid peer key'
. /etc/os-release
[[ $ID == ubuntu && ( $VERSION_ID == 22.04 || $VERSION_ID == 24.04 ) ]] || fail 'Requires Ubuntu 22.04/24.04'

exec 9>/run/lock/miaovps-miao-awg-port.lock
flock -x 9
[[ ! -e /run/miaovps-miao-awg-port ]] || fail 'Port trial already in progress'
iface=miao-awg
unit=awg-quick@$iface
dir=/etc/amnezia/amneziawg
conf=$dir/$iface.conf
marker='# MiaoVPS single-device AWG trial'
[[ ! -L $conf ]] || fail 'Refusing config symlink'
if [[ -e $conf ]]; then
    grep -Fxq "$marker" "$conf" && grep -Fxq "PublicKey = $peer" "$conf" && grep -Fxq "ListenPort = $port" "$conf" || fail 'Refusing to replace existing AWG trial, device or port'
elif systemctl is-active --quiet "$unit"; then
    fail 'Unmanaged AWG service already running'
fi
if ! systemctl is-active --quiet "$unit"; then
    ! ip link show "$iface" >/dev/null 2>&1 || fail 'Interface already exists'
    sockets=$(ss -H -uan "sport = :$port"); [[ -z $sockets ]] || fail 'UDP port already in use'
    command -v python3 >/dev/null || { apt-get update >&2; apt-get install -y python3 >&2; }
    # Reject both narrower and broader existing routes, not just an exact /30 match.
    subnet_check=()
    if [[ -f $conf ]]; then
        subnet_check=("$(awk '$1 == "Address" {print $3}' "$conf")")
    fi
    prefix=$(ip -j -4 route show table all | python3 -c 'import ipaddress as ip, json, sys
routes = [ip.ip_network(r["dst"], strict=False) for r in json.load(sys.stdin) if r.get("dst", "default") != "default"]
candidates = [ip.ip_network(n, strict=False) for n in (sys.argv[1:] or ["10.67.67.0/30", "172.29.67.0/30", "192.168.237.0/30"])]
for net in candidates:
    if net.prefixlen == 30 and not any(net.overlaps(r) for r in routes):
        print(str(net.network_address).rsplit(".", 1)[0]); break
else: sys.exit("Trial subnet overlaps an existing route")' "${subnet_check[@]}")
fi
if [[ ! -e $conf ]]; then
    if ! command -v awg >/dev/null || ! command -v awg-quick >/dev/null || ! command -v iptables >/dev/null || ! command -v python3 >/dev/null || ! modinfo amneziawg >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update >&2
        apt-get install -y software-properties-common python3 python3-launchpadlib gnupg2 iptables "linux-headers-$(uname -r)" >&2
        add-apt-repository -y ppa:amnezia/ppa >&2
        apt-get update >&2
        apt-get install -y amneziawg >&2
    fi
    modprobe amneziawg
    wan=$(ip -4 route get 1.1.1.1 | awk 'NR == 1 {for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}')
    [[ $wan =~ ^[A-Za-z0-9_.:-]+$ ]] || fail 'No IPv4 egress interface'
    mkdir -p "$dir"
    tmp=$(mktemp "$dir/.miao-awg.XXXXXXXX")
    trap 'rm -f "$tmp"' EXIT
    key=$(awg genkey)
    {
        printf '%s\n[Interface]\nPrivateKey = %s\nListenPort = %s\n' "$marker" "$key" "$port"
        printf 'Address = %s.1/30\nMTU = 1380\n' "$prefix"
        python3 -c 'import secrets
for i in range(4): print(f"H{i+1} = {5+i*100000000+secrets.randbelow(100000000)}")
for i in range(2): print(f"S{i+1} = {16+secrets.randbelow(40)}")'
        # Restrict forwarding to this peer and its replies. Undo rules on shutdown.
        for rule in "FORWARD -i %i -o $wan -s $prefix.2/32 -j ACCEPT" "FORWARD -i $wan -o %i -d $prefix.2/32 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"; do
            printf 'PostUp = iptables -I %s\nPostDown = iptables -D %s\n' "$rule" "$rule"
        done
        for dir_flag in -i -o; do
            rule="FORWARD $dir_flag %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340"
            printf 'PostUp = iptables -t mangle -I %s\nPostDown = iptables -t mangle -D %s\n' "$rule" "$rule"
        done
        rule="POSTROUTING -s $prefix.2/32 -o $wan -j MASQUERADE"
        printf 'PostUp = iptables -t nat -A %s\nPostDown = iptables -t nat -D %s\n' "$rule" "$rule"
        printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s.2/32\n' "$peer" "$prefix"
    } > "$tmp"
    ln "$tmp" "$conf" # never overwrite an existing configuration
fi
if [[ $(sysctl -n net.ipv4.ip_forward) != 1 ]]; then
    printf 'net.ipv4.ip_forward = 1\n' > /etc/sysctl.d/99-miaovps-awg.conf
    sysctl -p /etc/sysctl.d/99-miaovps-awg.conf >&2
fi
systemctl start "$unit" >&2
[[ $(awg show "$iface" listen-port) == "$port" && $(awg show "$iface" peers) == "$peer" ]] || fail 'AWG runtime differs from requested trial'
systemctl enable "$unit" >&2
# Output is deliberately limited to a public key and numeric framing parameters.
awg show "$iface" public-key
awg show "$iface" allowed-ips | awk '{print $2}'
grep -E '^(H[1-4]|S[12]) = [0-9]+$' "$conf"
