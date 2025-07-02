#!/usr/bin/env python3
import argparse
import sys
import time
import re
import configparser
from pathlib import Path
from pymetasploit3.msfrpc import MsfRpcClient, MsfError

ENV_FILE = Path('.msfwrap.env')
ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")  
PROMPT = 'meterpreter >'


def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)


def load_cfg():
    cfg = configparser.ConfigParser()
    if ENV_FILE.exists() and cfg.read(ENV_FILE) and 'msf' in cfg:
        eprint(f"[*] Loaded config from {ENV_FILE}")
        return cfg['msf']
    return {}


def save_cfg(d):
    cfg = configparser.ConfigParser()
    cfg['msf'] = d
    with ENV_FILE.open('w', encoding='utf-8') as f:
        cfg.write(f)
    eprint(f"[+] Saved config to {ENV_FILE}")


def mrun(session, cmd, prompt=PROMPT, timeout=10.0, poll=0.15):
    """Reliable Meterpreter command runner that waits for the prompt."""
    while session.read():
        pass

        session.runsingle(cmd)

    buf, start = [], time.time()
    while time.time() - start < timeout:
        chunk = session.read()
        if chunk:
            buf.append(chunk)
            if prompt in ''.join(buf):
                break
        else:
            time.sleep(poll)

    output = ''.join(buf)
    if prompt in output:
        output = output.split(prompt, 1)[0]
    return ANSI.sub('', output).rstrip()


def parse_args():
    p = argparse.ArgumentParser(
        description='Send Meterpreter commands via msgrpc with persistent config.')
    p.add_argument('-H', '--host', help='RPC server address')
    p.add_argument('-P', '--port', type=int, help='RPC port')
    p.add_argument('-u', '--user', help='RPC username')
    p.add_argument('-p', '--password', help='RPC password')
    p.add_argument('-s', '--session', type=int,
                   help='Session ID to use (default newest)')
    p.add_argument('--timeout', type=float,
                   default=10.0, help='Read timeout (s)')
    p.add_argument('--poll', type=float, default=0.15,
                   help='Poll interval when reading (s)')
    p.add_argument('commands', nargs='*',
                   help='Meterpreter commands (quote them)')
    return p.parse_args()


def main():
    a = parse_args()
    cfg = load_cfg()

    host = a.host or cfg.get('host', '127.0.0.1')
    port = a.port or int(cfg.get('port', '55555'))
    user = a.user or cfg.get('user', 'python')
    pw = a.password or cfg.get('password')
    if pw is None:
        pw = input('RPC password: ')
        save_cfg({'host': host, 'port': str(port),
                 'user': user, 'password': pw})

    eprint(f"[*] Connecting to {host}:{port} as {user}")
    try:
        client = MsfRpcClient(password=pw, username=user,
                              port=port, server=host, ssl=False)
    except Exception as e:
        eprint(f"[!] Failed to connect/authenticate: {e}")
        sys.exit(1)

    if not client.sessions.list:
        eprint('[-] No active sessions.')
        sys.exit(1)

    sid = str(a.session) if a.session is not None else max(
        client.sessions.list, key=lambda s: int(s))
    if sid not in client.sessions.list:
        eprint(f'[-] Session {sid} not found.')
        sys.exit(1)

    session = client.sessions.session(sid)
    info = client.sessions.list[sid]
    is_meterp = info['type'] == 'meterpreter'
    eprint(f"[+] Using session {sid} ({info['type']}, {info['info']})")

    cmds = a.commands or (
        [l.strip() for l in sys.stdin if l.strip()] if not sys.stdin.isatty() else [])
    if not cmds:
        eprint('[-] No commands provided.')
        sys.exit(1)

    for cmd in cmds:
        eprint(f"[>] {cmd}")
        try:
            if is_meterp:
                output = mrun(session, cmd, timeout=a.timeout, poll=a.poll)
            else:
                output = session.run_with_output(cmd, timeout=a.timeout)
        except (AttributeError, MsfError):
            session.write(cmd + '\n')
            time.sleep(a.poll)
            output = session.read() or '[!] No output returned'

        print(output or '[!] No output returned')


if __name__ == '__main__':
    main()
