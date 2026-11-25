#!/bin/bash
# Exercise the actual remote transaction without root, systemd, or a live tunnel.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export work
mkdir -p "$work/bin" "$work/run/lock" "$work/etc/wireguard" "$work/etc/amnezia/amneziawg"
export PATH="$work/bin:$PATH"
awk '{gsub(/\/run\//, ENVIRON["work"] "/run/"); gsub(/\/etc\//, ENVIRON["work"] "/etc/"); print}' \
    "$root/crates/miaovps-provisioner/src/switch-port.sh" > "$work/switch.sh"
printf 'wg test key\n' > "$work/public"
cat > "$work/bin/wg" <<'EOF'
#!/bin/bash
set -eu
case $1:$3 in
    show:public-key) cat "$work/public" ;;
    show:listen-port) cat "$work/live" ;;
    show:peers) printf '%s\n' 'test-peer'; if [[ -e $work/shared ]]; then printf '%s\n' 'second-peer'; fi ;;
    set:listen-port) printf '%s\n' "$4" > "$work/live" ;;
    *) exit 1 ;;
esac
EOF
ln -s wg "$work/bin/awg"
cat > "$work/bin/systemd-run" <<'EOF'
#!/bin/bash
[[ ! -e $work/timer-blocked ]] || exit 1
printf '%s\n' "${!#}" > "$work/timer"
EOF
cat > "$work/bin/ss" <<'EOF'
#!/bin/bash
if [[ -e $work/occupied ]]; then printf 'occupied\n'; fi
EOF
cat > "$work/bin/flock" <<'EOF'
#!/bin/bash
# Test operations run serially.
exit 0
EOF
chmod +x "$work/bin/"*
for proto in awg wg; do
    if [[ $proto == wg ]]; then
        conf=$work/etc/wireguard/wg0.conf
    else
        conf=$work/etc/amnezia/amneziawg/miao-awg.conf
    fi
    printf '[Interface]\nPrivateKey = unchanged\nListenPort = 12501\n[Peer]\nPublicKey = test-peer\n' > "$conf"
    cp "$conf" "$work/before"
    printf '12518\n' > "$work/live"
    token=0123456789abcdef0123456789abcdef
    change() { bash "$work/switch.sh" "$1" "$proto" "$token" 12518 12519 'wg test key' test-peer "${2:-0}"; }
    reject() { if change "$@" > "$work/error" 2>&1; then echo "unexpected success: $*" >&2; exit 1; fi; }
    if [[ $proto == awg ]]; then
        touch "$work/shared"; reject prepare 1; rm "$work/shared"
        printf '\n[Peer]\nPublicKey = second-peer\n' >> "$conf"
        reject prepare 1
        cmp "$work/live" <(printf '12518\n')
        cp "$work/before" "$conf"
        change prepare 1
        change abort
        bash "$(<"$work/timer")"
    fi
    touch "$work/occupied"; reject prepare; rm "$work/occupied"
    touch "$work/timer-blocked"; reject prepare; rm "$work/timer-blocked"
    [[ $(<"$work/live") == 12518 ]]
    change prepare
    reject prepare
    [[ $(<"$work/live") == 12519 ]]
    cmp "$conf" "$work/before"
    change abort
    [[ $(<"$work/live") == 12518 ]]
    bash "$(<"$work/timer")"
    cmp "$conf" "$work/before"
    change prepare
    bash "$(<"$work/timer")" # simulates dropped SSH/client death
    [[ $(<"$work/live") == 12518 ]]
    cmp "$conf" "$work/before"
    reject commit
    change prepare
    change commit
    bash "$(<"$work/timer")"
    [[ $(<"$work/live") == 12519 ]]
    awk '{sub(/ListenPort = 12501/, "ListenPort = 12519"); print}' "$work/before" > "$work/expected"
    cmp "$conf" "$work/expected"
done
printf 'Port transaction checks passed (AWG and WG)\n'
