# Invoked over SSH as root. Only public client data is passed in.
import fcntl
import ipaddress as ip
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


IFACE = 'miao-awg'
CONF = Path('/etc/amnezia/amneziawg/miao-awg.conf')
KEY = r'[A-Za-z0-9+/]{43}='


def require(test, message):
    if not test:
        sys.exit(message)


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    require(result.returncode == 0, f'{args[0]} {args[1]} failed; check the AWG service and retry')
    return result.stdout.strip()


def field(section, key, pattern):
    values = re.findall(rf'^{key} = ({pattern})$', section, re.M)
    require(len(values) == 1, f'Invalid MiaoVPS AWG {key}')
    return values[0]


def main():
    mode, *args = sys.argv[1:]
    require(not Path('/run/miaovps-miao-awg-port').exists(), 'Port trial already in progress')
    require(CONF.is_file() and not CONF.is_symlink(), 'Deploy MiaoVPS AWG first')
    interface, *sections = CONF.read_text().split('\n[Peer]\n')
    require(interface.startswith('# MiaoVPS single-device AWG trial\n[Interface]\n') and sections,
            'Unmanaged AWG configuration; refusing to modify it')
    require(not re.search(r'^\s*(SaveConfig|Table)\s*=', interface, re.I | re.M),
            'Custom SaveConfig or Table is incompatible with AWG enrollment')
    peers = {}
    addresses = set()
    for section in sections:
        key = field(section, 'PublicKey', KEY)
        address = ip.IPv4Interface(field(section, 'AllowedIPs', r'[\d.]+/32'))
        require(key not in peers and address.network not in addresses, 'Duplicate AWG peer or address')
        addresses.add(address.network)
        match = re.search(r'^# MiaoVPS device: (.+)$', section, re.M)
        peers[key] = (address, match[1] if match else '(initial peer)')
    live = dict(line.split(maxsplit=1) for line in run('awg', 'show', IFACE, 'allowed-ips').splitlines())
    if mode == 'list':
        for key, (address, name) in peers.items():
            print(f'{address}  {key}  {name}' + ('' if live.get(key) == str(address) else '  (pending)'))
        return

    peer, name = args
    require(mode == 'add' and re.fullmatch(KEY, peer) and 0 < len(name) <= 100 and name.strip()
            and name.splitlines() == [name], 'Invalid peer key or device name')
    require(all(live.get(key) == str(addr) for key, (addr, _) in peers.items() if key != peer)
            and all(key in peers for key in live), 'AWG runtime and saved peers differ; finish the previous enrollment first')
    port = run('awg', 'show', IFACE, 'listen-port')
    require(port == field(interface, 'ListenPort', r'[1-9]\d{0,4}'), 'AWG runtime and saved ports differ')
    public = run('awg', 'show', IFACE, 'public-key')
    require(re.fullmatch(KEY, public), 'AWG service has no public key')
    private = field(interface, 'PrivateKey', KEY)
    disk_public = subprocess.run(['awg', 'pubkey'], input=private + '\n', capture_output=True, text=True)
    require(disk_public.returncode == 0 and disk_public.stdout.strip() == public,
            'AWG runtime and saved server keys differ')
    framing = [f'{key} = {field(interface, key, pattern)}' for key, pattern in
               [(f'H{i}', r'\d{1,10}') for i in range(1, 5)] + [(f'S{i}', r'\d{1,3}') for i in range(1, 3)]]
    gateway = ip.IPv4Interface(field(interface, 'Address', r'[\d.]+/30'))
    # Keep the original /30 and its broadcast address. Routes for extra peers are host routes.
    # shortcut: use the surrounding /24, require an explicit pool design if it overlaps another VPS route.
    pool = ip.IPv4Network(f'{gateway.ip}/24', strict=False)
    require(gateway.ip == pool[1] and any(pool.subnet_of(ip.IPv4Network(net)) for net in
            ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')), 'Unsupported AWG subnet')
    require(all(net.subnet_of(pool) for net in addresses), 'Saved peer is outside the AWG address pool')
    address_show = json.loads(run('ip', '-j', '-4', 'address', 'show', 'dev', IFACE))
    require(any(info.get('local') == str(gateway.ip) and info.get('prefixlen') == 30
                for link in address_show for info in link.get('addr_info', [])), 'AWG runtime gateway differs')
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all'))
    for route in routes:
        dst = route.get('dst', 'default')
        if dst == 'default':
            continue
        net = ip.IPv4Network(dst, strict=False)
        owned = route.get('dev') == IFACE and (net in addresses or net.subnet_of(gateway.network))
        require(not pool.overlaps(net) or owned,
                f'AWG pool {pool} overlaps VPS route {net}; no address was changed')

    # Reuse the egress interface already configured for the original peer.
    first = f'{pool[2]}/32'
    require(ip.IPv4Network(first) in addresses, 'Original AWG peer is missing')
    wan = field(interface, 'PostUp', rf'iptables -t nat -A POSTROUTING -s {re.escape(first)} -o [A-Za-z0-9_.:-]+ -j MASQUERADE').split()[-3]
    new = peer not in peers
    if new:
        address = next((net for host in list(pool.hosts())[3:]
                        if (net := ip.IPv4Network(f'{host}/32')) not in addresses), None)
        require(address is not None, 'No free AWG addresses in this pool')
    else:
        current, previous_name = peers[peer]
        require(name == previous_name and current.ip >= pool[4], 'AWG peer is already registered under another enrollment')
        address = current.network
        require(live.get(peer, str(address)) == str(address), 'AWG runtime peer address differs')

    rules = [([], 'FORWARD', '-I', ['-i', IFACE, '-o', wan, '-s', str(address), '-j', 'ACCEPT']),
             ([], 'FORWARD', '-I', ['-i', wan, '-o', IFACE, '-d', str(address), '-m', 'conntrack',
                                   '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT']),
             (['-t', 'nat'], 'POSTROUTING', '-A', ['-s', str(address), '-o', wan, '-j', 'MASQUERADE'])]
    if new:
        hooks = ''.join(f'\n{step} = ' + ' '.join(['iptables', *table, action, chain, *rule])
                        for table, chain, add, rule in rules
                        for step, action in [('PostUp', add), ('PostDown', '-D')])
        updated = ('\n[Peer]\n'.join([interface.rstrip() + hooks + '\n', *sections]).rstrip()
                   + f'\n\n[Peer]\n# MiaoVPS device: {name}\nPublicKey = {peer}\nAllowedIPs = {address}\n')
        # Commit the allocation before runtime changes. Retry by the same key reconciles partial work.
        fd, staged = tempfile.mkstemp(dir=CONF.parent)
        try:
            with os.fdopen(fd, 'w') as out:
                out.write(updated)
                out.flush()
                os.fsync(out.fileno())
            os.replace(staged, CONF)
        finally:
            Path(staged).unlink(missing_ok=True)

    if not any(r.get('dst') in (str(address), str(address.network_address)) and r.get('dev') == IFACE
               and r.get('table', 'main') == 'main' for r in routes):
        run('ip', '-4', 'route', 'add', str(address), 'dev', IFACE)
    for table, chain, add, rule in rules:
        cmd = ['iptables', '-w', *table]
        if subprocess.run([*cmd, '-C', chain, *rule], capture_output=True).returncode != 0:
            run(*cmd, add, chain, *rule)
    if peer not in live:
        run('awg', 'set', IFACE, 'peer', peer, 'allowed-ips', str(address))
    print(port, public, address, *framing, sep='\n')


with open('/run/lock/miaovps-miao-awg-port.lock', 'a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    try:
        main()
    except (ValueError, OSError):
        sys.exit('Invalid AWG configuration or failed to save it; check the VPS and retry the same enrollment')
