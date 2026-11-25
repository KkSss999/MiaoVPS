#!/bin/bash
# Two-phase port change: runtime only until the client authenticates on the new port.
set -euo pipefail
umask 077
mode=$1 proto=$2 token=$3 old=$4 new=$5 public=$6 peer=$7
case $proto in
    wg) iface=wg0; conf=/etc/wireguard/wg0.conf ;;
    awg) iface=miao-awg; conf=/etc/amnezia/amneziawg/miao-awg.conf ;;
    *) exit 1 ;;
esac
[[ $token =~ ^[a-f0-9]{32}$ && $old =~ ^[1-9][0-9]{0,4}$ && $new =~ ^[1-9][0-9]{0,4}$ && $old -le 65535 && $new -le 65535 && $old != "$new" ]] || exit 1
fail() { echo "$*" >&2; exit 1; }
unit=miaovps-port-$token
lock=/run/lock/miaovps-$iface-port.lock
pending=/run/miaovps-$iface-port
exec 9>"$lock"
flock -x 9

config_port() {
    awk '/^[[:space:]]*ListenPort[[:space:]]*=/ {sub(/^[^=]+=[[:space:]]*/, ""); sub(/[[:space:]]*(#.*)?$/, ""); print}' "$1"
}

# Shared with the detached timer. The on-disk port is the commit record.
restore() {
    [[ -f $pending && $(<"$pending") == "$token" ]] || return 0
    if [[ $("$proto" show "$iface" public-key) == "$public" && $("$proto" show "$iface" listen-port) == "$new" ]]; then
        "$proto" set "$iface" listen-port "$old" || return 1
        [[ $("$proto" show "$iface" listen-port) == "$old" ]] || return 1
    fi
    rm -f "$pending"
}

case $mode in
    prepare)
        [[ ! -e $pending ]] || fail 'Port trial already in progress'
        [[ -f $conf && ! -L $conf && $("$proto" show "$iface" public-key) == "$public" ]] || fail 'VPN interface, public key or configuration mismatch'
        [[ $("$proto" show "$iface" listen-port) == "$old" ]] || fail 'Current server port differs; check status and pass the actual port'
        "$proto" show "$iface" peers | grep -Fxq -- "$peer" || fail 'Client is not registered on this interface'
        [[ $(config_port "$conf") =~ ^[1-9][0-9]{0,4}$ && $(config_port "$conf") != "$new" ]] || fail 'Disk port is missing or already equals the candidate'
        ! grep -Eiq '^[[:space:]]*SaveConfig[[:space:]]*=[[:space:]]*true' "$conf" || fail 'SaveConfig is incompatible with port trials'
        sockets=$(ss -H -uan "sport = :$new") || fail 'Could not check candidate UDP port'
        [[ -z $sockets ]] || fail 'Candidate UDP port is occupied'
        # Reserve a rollback independent of the SSH client before touching runtime.
        rollback=/run/$unit.sh
        {
            printf 'set -eu\nproto=%q iface=%q conf=%q pending=%q token=%q old=%q new=%q public=%q\n' \
                "$proto" "$iface" "$conf" "$pending" "$token" "$old" "$new" "$public"
            printf 'exec 9>%q\nflock -x 9\ntrap %q EXIT\n' "$lock" "rm -f $rollback"
            declare -f config_port restore
            printf '%s\n' '[[ -f $pending && $(<"$pending") == "$token" ]] || exit 0' \
                'if [[ $(config_port "$conf") == "$new" ]]; then rm -f "$pending"; else restore; fi'
        } > "$rollback"
        if ! systemd-run --quiet --unit="$unit" --on-active=60s --timer-property=AccuracySec=1s /bin/bash "$rollback"; then
            rm -f "$rollback"
            fail 'Could not schedule rollback; no listener changed'
        fi
        printf '%s\n' "$token" > "$pending"
        if ! "$proto" set "$iface" listen-port "$new" || [[ $("$proto" show "$iface" listen-port) != "$new" ]]; then
            restore
            fail 'Could not bind candidate UDP port'
        fi
        ;;
    commit)
        [[ -f $pending && $(<"$pending") == "$token" ]] || fail 'Port trial expired'
        [[ -f $conf && ! -L $conf && $("$proto" show "$iface" public-key) == "$public" && $("$proto" show "$iface" listen-port) == "$new" ]] || fail 'VPN runtime or configuration changed during trial'
        tmp=$(mktemp "${conf}.XXXXXXXX")
        trap 'rm -f "$tmp"' EXIT
        awk -v port="$new" '/^[[:space:]]*ListenPort[[:space:]]*=/ {$0="ListenPort = " port} {print}' "$conf" > "$tmp"
        [[ $(config_port "$tmp") == "$new" ]] || fail 'Could not update disk port'
        mv -f "$tmp" "$conf"
        rm -f "$pending"
        ;;
    abort)
        [[ $(config_port "$conf") != "$new" ]] || fail 'Port change already committed'
        restore
        ;;
    *) exit 1 ;;
esac
