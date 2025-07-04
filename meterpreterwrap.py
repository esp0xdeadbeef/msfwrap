#!/usr/bin/env python3
"""meterpreterwrap.py – Attach to a Meterpreter session via msfrpc and execute commands."""
import argparse, sys, time, re, configparser
from pathlib import Path
from pymetasploit3.msfrpc import MsfRpcClient, MsfError

# Configuration file
ENV_FILE = Path('.msfwrap.env')  # reuse credentials file
ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
PROMPT = 'meterpreter >'

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def load_config():
    cfg = configparser.ConfigParser()
    if ENV_FILE.exists():
        cfg.read(ENV_FILE)
        if 'msf' in cfg:
            return cfg['msf']
    return {}

def save_config(data):
    cfg = configparser.ConfigParser(); cfg['msf'] = data
    with ENV_FILE.open('w', encoding='utf-8') as f:
        cfg.write(f)
    eprint(f"[+] Saved config to {ENV_FILE}")

# Meterpreter reliable runner
def mrun(sess, cmd, timeout, poll):
    # Drain stale output
    while sess.read(): pass
    first = sess.runsingle(cmd) or ''
    buf = [first]
    if PROMPT in first:
        return ANSI.sub('', first.split(PROMPT,1)[0]).strip()
    start = time.time()
    while time.time() - start < timeout:
        chunk = sess.read()
        if chunk:
            buf.append(chunk)
            if PROMPT in chunk:
                break
        else:
            time.sleep(poll)
    data = ''.join(buf)
    if PROMPT in data:
        data = data.split(PROMPT,1)[0]
    return ANSI.sub('', data).strip()

# Attach and run

def attach_and_run(client, sid, commands, timeout, poll):
    sessions = client.sessions.list
    if sid not in sessions:
        eprint(f"[-] Session {sid} not found")
        sys.exit(1)
    sess = client.sessions.session(sid)
    info = sessions[sid]
    is_m = info['type'] == 'meterpreter'
    eprint(f"[+] Attached to session {sid} ({info['type']}, {info.get('info','')})")
    for cmd in commands:
        eprint(f"[>] {cmd}")
        try:
            out = mrun(sess, cmd, timeout, poll) if is_m else sess.run_with_output(cmd, timeout)
        except (AttributeError, MsfError):
            sess.write(cmd + '\n')
            time.sleep(poll)
            out = sess.read() or ''
        print(out or '[!] No output returned')

# Argument parsing

def parse_args():
    p = argparse.ArgumentParser(
        description="Attach to Meterpreter session and run commands via RPC"
    )
    p.add_argument('-H','--host', help="RPC host")
    p.add_argument('-P','--port', type=int, help="RPC port")
    p.add_argument('-u','--user', help="RPC user")
    p.add_argument('-p','--password', help="RPC password")
    p.add_argument('-s','--session', type=int, help="Session ID to attach (default: latest)")
    p.add_argument('--timeout', type=float, default=10.0, help="Command timeout (s)")
    p.add_argument('--poll', type=float, default=0.15, help="Read poll interval (s)")
    p.add_argument('commands', nargs='*', help="Commands to run (if empty, reads from stdin)")
    return p.parse_args()

# Main

def main():
    args = parse_args()
    cfg = load_config()
    # Credentials
    host = args.host or cfg.get('host')
    port = args.port or (int(cfg.get('port')) if cfg.get('port','').isdigit() else None)
    user = args.user or cfg.get('user')
    pwd  = args.password or cfg.get('password')
    if not all([host, port, user, pwd]):
        eprint('[!] Missing RPC credentials; please enter:')
        if not host:
            host = input('RPC host [127.0.0.1]: ') or '127.0.0.1'
        if not port:
            while True:
                v = input('RPC port [55555]: ') or '55555'
                if v.isdigit(): port = int(v); break
                eprint('Invalid port')
        if not user:
            user = input('RPC user [python]: ') or 'python'
        if not pwd:
            pwd = input('RPC password: ')
        save_config({'host':host,'port':str(port),'user':user,'password':pwd})
    eprint(f"[*] Connecting to {host}:{port} as {user}")
    client = MsfRpcClient(password=pwd, username=user, port=port, server=host, ssl=False)

    # Determine session
    sess_list = client.sessions.list or {}
    if args.session is not None:
        sid = str(args.session)
    else:
        # pick highest numeric ID
        mets = {k:v for k,v in sess_list.items() if v['type']=='meterpreter'}
        if not mets:
            eprint('[-] No Meterpreter sessions available')
            sys.exit(1)
        sid = max(mets.keys(), key=lambda x:int(x))

    # Collect commands
    if args.commands:
        cmds = args.commands
    else:
        cmds = [l.strip() for l in sys.stdin if l.strip()]
    if not cmds:
        eprint('[-] No commands provided.')
        sys.exit(1)

    # Run
    attach_and_run(client, sid, cmds, args.timeout, args.poll)

if __name__ == '__main__':
    main()
