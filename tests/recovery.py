"""Recovery regression tests. Run only in a disposable network namespace."""
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time

binary = sys.argv[1]

def ip(*args):
    return subprocess.check_output(['ip', *args], text=True)

def ctl(device, key, value=None):
    path = pathlib.Path(f'/proc/sys/net/ipv6/conf/{device}/{key}')
    if value is not None:
        path.write_text(str(value))
    return int(path.read_text())

def addr(device):
    return {a['local']: a for i in json.loads(ip('-j', '-6', 'addr', 'show', 'dev', device))
            for a in i['addr_info']}

def routes():
    return json.loads(ip('-j', '-6', 'route', 'show', 'dev', 'down0'))

def has_route(address):
    return any(r['dst'] == address for r in routes())

def wait_for(check, description):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.05)
    raise AssertionError(description)

ip('link', 'set', 'lo', 'up')
for a, b in [('up0', 'router0'), ('down0', 'client0')]:
    ip('link', 'add', a, 'type', 'veth', 'peer', 'name', b)
    ip('link', 'set', a, 'up')
    ip('link', 'set', b, 'up')
source = '2001:db8:10::1'
client = '2001:db8:10::2'
ip('-6', 'addr', 'add', source + '/64', 'dev', 'up0', 'nodad',
   'valid_lft', '180', 'preferred_lft', '120')
ip('-6', 'addr', 'add', client + '/64', 'dev', 'client0', 'nodad')
ctl('up0', 'accept_ra', 0)
ctl('down0', 'accept_ra', 2)
ctl('down0', 'disable_ipv6', 1)
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory) / 'daemon.log'
    with path.open('w') as log:
        proc = subprocess.Popen([binary, '-A', '-P', '79', '-v', 'up0', 'down0'],
                                env={**os.environ, 'PATH': '/nonexistent'},
                                stdout=log, stderr=log)
    try:
        wait_for(lambda: ctl('up0', 'accept_ra') == 2 and
                 ctl('down0', 'accept_ra') == 0 and ctl('down0', 'disable_ipv6') == 0,
                 'startup sysctl repair')
        wait_for(lambda: source in addr('down0'), 'startup address repair')
        mac = json.loads(ip('-j', 'link', 'show', 'client0'))[0]['address']
        ip('-6', 'neigh', 'replace', client, 'lladdr', mac, 'nud', 'permanent', 'dev', 'down0')
        wait_for(lambda: has_route(client), 'initial host route')
        # A policy-routing failure generates no link/address/route-deletion
        # notification. Incoming NS packets must trigger recovery via sendmsg.
        time.sleep(2)
        ctl('down0', 'accept_ra', 2)
        time.sleep(.3)
        assert ctl('down0', 'accept_ra') == 2
        ip('-6', 'rule', 'add', 'pref', '100', 'oif', 'down0', 'unreachable')
        target = '2001:db8:10::dead'
        request = struct.pack('!BBHI16s', 135, 0, 0, 0,
                              socket.inet_pton(socket.AF_INET6, target))
        index = socket.if_nametoindex('router0')
        with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as sock:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            for _ in range(20):
                sock.sendto(request, ('ff02::1:ff00:dead', 0, 0, index))
                time.sleep(.02)
        wait_for(lambda: ctl('down0', 'accept_ra') == 0, 'relay-error recovery trigger')
        assert path.read_text().count(f'Failed to relay to {target}%down0') == 1
        ip('-6', 'rule', 'del', 'pref', '100', 'oif', 'down0', 'unreachable')
        ip('-6', 'route', 'del', client, 'dev', 'down0', 'proto', '79')
        wait_for(lambda: has_route(client), 'deleted host route restoration')
        ip('-6', 'addr', 'del', source + '/64', 'dev', 'down0')
        wait_for(lambda: source in addr('down0'), 'deleted address restoration')
        assert addr('down0')[source]['valid_life_time'] <= addr('up0')[source]['valid_life_time'] + 1
        ip('-6', 'route', 'del', '2001:db8:10::/64', 'dev', 'down0')
        wait_for(lambda: has_route('2001:db8:10::/64'), 'connected route restoration')
        ip('-6', 'addr', 'flush', 'dev', 'down0', 'scope', 'link')
        wait_for(lambda: any(a.startswith('fe80:') for a in addr('down0')), 'link-local restoration')
        ctl('down0', 'accept_ra', 2)
        ctl('down0', 'disable_ipv6', 1)
        wait_for(lambda: ctl('down0', 'disable_ipv6') == 0 and ctl('down0', 'accept_ra') == 0,
                 'live IPv6 disable repair')
        wait_for(lambda: source in addr('down0') and has_route(client), 'reset address/route restoration')
        # Admin-down and carrier-down must both suppress all recovery writes.
        for down_device in ('down0', 'client0'):
            ip('link', 'set', down_device, 'down')
            time.sleep(.3)
            ctl('down0', 'accept_ra', 2)
            ctl('down0', 'disable_ipv6', 1)
            before = path.read_text().count('Checking IPv6 state on down0')
            time.sleep(6)
            assert ctl('down0', 'disable_ipv6') == 1 and ctl('down0', 'accept_ra') == 2
            assert source not in addr('down0')
            assert path.read_text().count('Checking IPv6 state on down0') == before
            ip('link', 'set', down_device, 'up')
            wait_for(lambda: ctl('down0', 'disable_ipv6') == 0 and source in addr('down0'),
                     f'recovery after {down_device} came up')
        # Restore once more to exercise withdrawal of a repaired prefix route.
        ip('-6', 'route', 'del', '2001:db8:10::/64', 'dev', 'down0')
        wait_for(lambda: has_route('2001:db8:10::/64'), 'prefix repair before withdrawal')
        assert sum(r['dst'] == '2001:db8:10::/64' for r in routes()) == 1
        assert '2001:db8:10::/64' in ip('-6', 'route', 'show', 'dev', 'up0')
        # Withdrawal must not resurrect an old upstream address.
        ip('-6', 'addr', 'del', source + '/64', 'dev', 'up0')
        wait_for(lambda: source not in addr('down0'), 'upstream withdrawal')
        wait_for(lambda: not has_route('2001:db8:10::/64'), 'withdrawal of repaired prefix')
        ip('link', 'set', 'down0', 'down')
        ip('link', 'set', 'down0', 'up')
        time.sleep(2)
        assert source not in addr('down0')
        # A conflicting foreign route cannot be repaired. Retries must stop,
        # and the foreign route must never be replaced.
        conflict = '2001:db8:20::99'
        ip('-6', 'route', 'add', conflict, 'dev', 'down0', 'proto', '80')
        ip('-6', 'neigh', 'replace', conflict, 'lladdr', mac,
           'nud', 'permanent', 'dev', 'down0')
        wait_for(lambda: 'IPv6 recovery on down0 paused after 3 attempts' in path.read_text(),
                 'bounded recovery retries')
        before = path.read_text().count('Checking IPv6 state on down0')
        time.sleep(2)
        assert path.read_text().count('Checking IPv6 state on down0') == before
        assert any(r['dst'] == conflict and str(r['protocol']) == '80' for r in routes())
    except BaseException:
        print(ip("-6", "route", "show"), addr("up0"), addr("down0"), file=sys.stderr)
        print(path.read_text(), file=sys.stderr)
        raise
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            raise
    assert proc.returncode == 0
print(f'Recovery tests passed (uid={os.getuid()})')
