"""Exercise the real daemon in a disposable network namespace."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

binary = sys.argv[1]

def ip(*args):
    return subprocess.check_output(['ip', *args], text=True)

def routes():
    return json.loads(ip('-j', '-6', 'route', 'show', 'proto', '78'))

def addresses(device="down0"):
    return {a['local'] for i in json.loads(ip('-j', '-6', 'addr', 'show', 'dev', device))
            for a in i['addr_info']}

def wait_for(check):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.05)
    raise AssertionError('Timed out waiting for kernel state')

# Invalid protocol values must fail before opening privileged sockets.
for value in ('0', '256', '-1', '66%s', '9999999999999999999999', ''):
    result = subprocess.run([binary, '-P', value, '-N', 'up0', 'down0'],
                            capture_output=True, text=True)
    assert result.returncode == 1 and 'Invalid route protocol' in result.stderr

ip('link', 'set', 'lo', 'up')
for name in ('up0', 'down0', 'down1'):
    ip('link', 'add', name, 'type', 'dummy')
    ip('link', 'set', name, 'up')
ip('-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'up0', 'nodad',
   'valid_lft', '300', 'preferred_lft', '200')
# Enough entries to exercise a multipart neighbor dump.
expected = {f'2001:db8:1::{n:x}' for n in range(256, 456)}
for address in expected:
    ip('-6', 'neigh', 'add', address, 'lladdr', '02:00:00:00:00:02',
       'nud', 'permanent', 'dev', 'down0')
foreign = '2001:db8:99::1'
ip('-6', 'route', 'add', foreign, 'dev', 'lo', 'proto', '78')
with tempfile.TemporaryFile(mode='w+') as log:
    # The daemon must work without access to the ip executable.
    process = subprocess.Popen([binary, '-N', '-r', '-P', '78', 'up0', 'down0', 'down1'],
                               env={**os.environ, 'PATH': '/nonexistent'},
                               stdout=log, stderr=log)
    try:
        wait_for(lambda: all('2001:db8:1::1' in addresses(d) for d in ('down0', 'down1')))
        wait_for(lambda: expected <= {r['dst'] for r in routes()})
        ip('-6', 'neigh', 'del', '2001:db8:1::100', 'dev', 'down0')
        wait_for(lambda: '2001:db8:1::100' not in {r['dst'] for r in routes()})
        ip('-6', 'addr', 'del', '2001:db8:1::1/64', 'dev', 'up0')
        wait_for(lambda: all('2001:db8:1::1' not in addresses(d) for d in ('down0', 'down1')))
        ip('-6', 'addr', 'add', '2001:db8:4::1/64', 'dev', 'up0', 'nodad')
        wait_for(lambda: '2001:db8:4::1' in addresses())
        log.flush(); log.seek(0)
        output = log.read()
        assert 'Unable to' not in output and 'dump failed' not in output, output
        # Negative ACKs from address configuration must be surfaced in logs.
        pathlib.Path('/proc/sys/net/ipv6/conf/down0/disable_ipv6').write_text('1')
        ip('-6', 'addr', 'add', '2001:db8:5::1/64', 'dev', 'up0', 'nodad')
        def address_error():
            log.seek(0)
            return 'Unable to set address 2001:db8:5::1 on down0:' in log.read()
        wait_for(address_error)
        wait_for(lambda: "2001:db8:5::1" in addresses("down1"))
    finally:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()
            raise
    assert process.returncode == 0
    assert {r['dst'] for r in routes()} == {foreign}, routes()
print('Daemon address sync, initial neighbor dump, route learning and error tests passed')
