#!/usr/bin/env python3
"""msfwrap.py – Execute Metasploit console commands via RPC and print output."""
import argparse, sys, time, re, configparser
from pathlib import Path
from pymetasploit3.msfrpc import MsfRpcClient, MsfError

# Configuration
ENV_FILE = Path('.msfwrap.env')
ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
PROMPT = 'meterpreter >'

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def load_config():
    cfg = configparser.ConfigParser()
    if ENV_FILE.exists():
        cfg.read(ENV_FILE)
        if 'msf' in cfg:
            eprint(f"[*] Loaded config from {ENV_FILE}")
            return cfg['msf']
    return {}

def save_config(data):
    cfg = configparser.ConfigParser(); cfg['msf'] = data
    with ENV_FILE.open('w', encoding='utf-8') as f:
        cfg.write(f)
    eprint(f"[+] Saved config to {ENV_FILE}")

# Argument parser

def parse_args():
    p = argparse.ArgumentParser(
        description="msfwrap: run Metasploit console commands via RPC"
    )
    p.add_argument('-H','--host',help="RPC host")
    p.add_argument('-P','--port',type=int,help="RPC port")
    p.add_argument('-u','--user',help="RPC user")
    p.add_argument('-p','--password',help="RPC password")
    p.add_argument('-q','--quiet',action='store_true',help="suppress banner")
    p.add_argument('--timeout',type=float,default=10.0,help="read timeout (s)")
    p.add_argument('--poll',type=float,default=0.15,help="read poll interval (s)")
    p.add_argument('commands',nargs='*',help="commands to run (e.g. 'sessions')")
    return p.parse_args()

# RPC console flow

def console_flow(client, cmds, quiet, timeout, poll):
    console = client.consoles.console()
    if not quiet:
        eprint(f"[+] Opened RPC console {console.cid}")
    # drain banner
    if quiet:
        while True:
            r = console.read()
            if not r or (isinstance(r, dict) and not r.get('data')):
                break
    out = ''
    for c in cmds:
        if not quiet:
            eprint(f"msf> {c}")
        console.write(c + '\n')
        start = time.time()
        while time.time() - start < timeout:
            r = console.read()
            if isinstance(r, dict):
                out += r.get('data','')
                if not r.get('busy', True):
                    break
            else:
                if not r:
                    break
                out += r
            time.sleep(poll)
    console.destroy()
    print(out.strip())
    if not quiet:
        eprint(f"[+] RPC console closed")

# Main function
def main():
    args = parse_args()
    cfg = load_config()
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
                if v.isdigit():
                    port = int(v)
                    break
                eprint('Invalid port')
        if not user:
            user = input('RPC user [python]: ') or 'python'
        if not pwd:
            pwd = input('RPC password: ')
        save_config({'host':host,'port':str(port),'user':user,'password':pwd})
    eprint(f"[*] Connecting to {host}:{port} as {user}")
    client = MsfRpcClient(password=pwd, username=user, port=port, server=host, ssl=False)
    # If no commands, exit
    if not args.commands:
        eprint('[-] No commands provided.'); sys.exit(1)
    console_flow(client, args.commands, args.quiet, args.timeout, args.poll)

if __name__ == '__main__':
    main()

