#!/usr/bin/env python3
import argparse
import sys
import configparser
from pathlib import Path
from pymetasploit3.msfrpc import MsfRpcClient

env_file = Path('.') / '.msfwrap.env'

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def load_config():
    config = configparser.ConfigParser()
    if env_file.exists():
        config.read(env_file)
        if 'msf' in config:
            eprint(f"[*] Loaded config from {env_file}")
            return config['msf']
    return {}

def save_config(cfg):
    config = configparser.ConfigParser()
    config['msf'] = cfg
    with env_file.open('w', encoding='utf-8') as f:
        config.write(f)
    eprint(f"[+] Saved config to {env_file}")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Send meterpreter commands via msgrpc with persistent config."
    )
    parser.add_argument('-H', '--host', help="RPC server address")
    parser.add_argument('-P', '--port', type=int, help="RPC port")
    parser.add_argument('-u', '--user', help="RPC username")
    parser.add_argument('-p', '--password', help="RPC password")
    parser.add_argument('-s', '--session', type=int,
        help="Session ID to use (default: most recent)")
    parser.add_argument('commands', nargs='*', help="Meterpreter commands")
    return parser.parse_args()

def main():
    args = parse_args()
    cfg = load_config()

    # Determine credentials, precedence: CLI > config > prompt (only if config missing)
    host = args.host or cfg.get('host')
    port = args.port or (int(cfg.get('port')) if cfg.get('port') and cfg.get('port').isdigit() else None)
    user = args.user or cfg.get('user')
    password = args.password or cfg.get('password')

    # Prompt for missing
    if not all([host, port, user, password]):
        eprint("[!] Missing configuration; please enter:")
        if not host:
            host = input(f"RPC host [127.0.0.1]: ") or '127.0.0.1'
        if not port:
            while True:
                val = input(f"RPC port [55555]: ") or '55555'
                if val.isdigit():
                    port = int(val)
                    break
                eprint("Invalid port, must be a number.")
        if not user:
            user = input(f"RPC username [python]: ") or 'python'
        if not password:
            password = input("RPC password: ")
        save_config({'host': host, 'port': str(port), 'user': user, 'password': password})

    eprint(f"[*] Connecting to {host}:{port} as {user}")
    try:
        client = MsfRpcClient(password=password, username=user, port=port, ssl=False, server=host)
    except Exception as e:
        eprint(f"[!] Failed to connect or authenticate: {e}")
        eprint("Use msfconsole like so:")
        eprint(f"  msfconsole -q -x 'load msgrpc ServerHost={host} ServerPort={port} User={user} Pass={password}'")
        sys.exit(1)

    sessions = client.sessions.list
    if not sessions:
        eprint("[-] No active sessions.")
        sys.exit(1)

    # pick session
    if args.session is not None:
        sid = str(args.session)
    else:
        sid = sorted(sessions.keys(), key=lambda x: int(x))[-1]
    if sid not in sessions:
        eprint(f"[-] Session {sid} not found.")
        sys.exit(1)

    session = client.sessions.session(sid)
    info = sessions[sid]
    eprint(f"[+] Using session {sid} ({info['type']}, {info['info']})")

    # collect commands
    if not sys.stdin.isatty():
        commands = [l.strip() for l in sys.stdin if l.strip()]
    else:
        commands = args.commands
    if not commands:
        eprint("[-] No commands provided.")
        sys.exit(1)

    for cmd in commands:
        eprint(f"[>] Running: {cmd}\n")
        try:
            output = session.run_with_output(cmd)
        except AttributeError:
            session.write(cmd + '\n')
            output = session.read()
        print(output or '[!] No output returned')

if __name__ == '__main__':
    main()


