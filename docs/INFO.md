# pam_totp — Installation and operations guide

TOTP second factor (RFC 6238) over **libcotp**, with the seed encrypted at
rest using **libgcrypt**, plus an enrollment tool and OpenSSH integration.

Developed and tested on Ubuntu 24.04. Fedora/RHEL and Arch are documented
too, since they differ in several places.

---

> ## ⚠️ Before you start
>
> A broken PAM stack can lock you out of the machine.
>
> 1. **Snapshot the VM.**
> 2. Keep a **root session open in another terminal** and do not close it
>    until you have verified you can still log in.
> 3. Have the VM's **graphical console** available.
>
> If you get locked out, see [section 9](#9-recovery).

---

# QUICK START

Each step is explained in detail below.

```bash
# 1. Dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential libcotp-dev libpam0g-dev \
                 libgcrypt20-dev qrencode

# 2. Clock in sync  (NOTHING WORKS WITHOUT THIS)
sudo timedatectl set-ntp true
timedatectl status          # "System clock synchronized: yes"

# 3. Build and install
cd totp
make
sudo make install

# 4. Enroll the user  (BEFORE touching PAM)
totp-admin                  # asks for your password, prints the QR
                            # scan it and save the recovery codes

# 5. Configure PAM  -> /etc/pam.d/sshd, below "@include common-auth"
#    auth required pam_totp.so nullok debug

# 6. Configure sshd -> /etc/ssh/sshd_config.d/99-totp.conf
#    UsePAM yes
#    KbdInteractiveAuthentication yes
#    PasswordAuthentication no

sudo sshd -t && sudo systemctl restart ssh    # 'sshd' on Fedora/Arch

# 7. Test FROM ANOTHER TERMINAL, without closing the current one
ssh tiago@<vm-ip>
```

If something fails:

```bash
sudo journalctl -u ssh -f | grep pam_totp
```

---

# 1. How it is organised

Three files with different owners:

| File | Owner | Holds | Changed by |
|---|---|---|---|
| `/etc/totp.conf` | `root:root 0644` | digits, period, window, algorithm, rate limit | root only |
| `/etc/pam.d/totp-admin` | `root:root 0644` | PAM service the tool uses to validate the password | root only |
| `~/.totp_auth` | `user 0600` | **encrypted** seed and recovery codes, plus counters | the user |

Keeping the parameters in a separate file is the point of the design: if
they lived in the user's file, the user could loosen the security settings
on their own.

**The module verifies the permissions of both files on every login.** If
`/etc/totp.conf` is not owned by root or is writable by others, or if
`~/.totp_auth` is not owned by the user or is not `0600`, it **denies
access** rather than continuing. Setting permissions happens once, at
creation; verifying them has to happen every time, because nothing stops a
`chmod 644` the next day.

## The seed is encrypted

The seed and the recovery codes are stored with **AES-256-GCM**. The key is
derived from the user's password with **PBKDF2-HMAC-SHA256** (200,000
iterations), so neither root nor anyone with access to the file can read
them.

Three consequences follow:

- **`pam_totp.so` must come AFTER `common-auth`** in `/etc/pam.d/sshd`. The
  password is taken from `PAM_AUTHTOK`, where `pam_unix` leaves it when it
  runs first. Placed before, there is nothing to use.
- **It only works with password authentication.** A public-key login does
  not go through the PAM auth stack and carries no password.
- **If the user changes their password, the seed must be regenerated**
  (section 8).

The counters (`LAST_COUNTER`, `RATE`) are kept **in plaintext** on purpose:
they are not secret, they change on every attempt, and keeping them outside
avoids re-encrypting — and therefore generating a new nonce — on every
login. Reusing a nonce with the same key breaks GCM.

## Parameters

| Key in `totp.conf` | Default | Note |
|---|---|---|
| `algorithm` | SHA1 | Apps ignore this parameter in the QR and use SHA1 anyway |
| `digits` | 6 | Apps ignore `digits`; other values produce codes that never validate |
| `period` | 30 | RFC 6238 §5.2 |
| `window` | 3 | **Total** codes accepted, centred. 3 = ±1 step ≈ 90 s |
| `rate_limit_attempts` | 3 | Per user; survives reconnections |
| `rate_limit_window` | 30 | Seconds of silence needed to unblock |

> **Careful with `digits` and `algorithm`.** Google Authenticator ignores
> both and always uses SHA1 with 6 digits. Changing them makes that app
> generate codes that **never** validate, with no error. The tool warns
> when the parameters deviate from SHA1/6/30.

## Attempt limiting

**3 attempts per 30 seconds, per user.** Past the limit everything is
rejected — including the correct code — until 30 seconds pass **with no
attempts at all**. Each new attempt, even a blocked one, restarts that
wait.

It is deliberately different from what the system already provides:

| Mechanism | Scope | What it misses |
|---|---|---|
| `MaxAuthTries` (sshd) | per TCP connection | the attacker reconnects |
| `pam_faillock` | per account, all failures | does not distinguish TOTP |
| `fail2ban` | per IP | the attacker rotates IPs |
| **pam_totp** | **per user, TOTP only** | slow distributed attacks |

All four are complementary; none replaces the others.

**Operational consequence:** the module writes to `~/.totp_auth` on *every*
attempt, successful or not. If failures were not persisted, the counter
would reset on each new connection and the limit would be useless.

## The `nullok` hole

Since the file belongs to the user, the user can delete it. With `nullok`
enabled, `rm ~/.totp_auth` **disables the second factor for that account**.

The fix is to **remove `nullok`** once migration is done: from then on,
whoever deletes their file is locked out and needs the administrator.

---

# 2. Dependencies

## Ubuntu / Debian

```bash
sudo apt update
sudo apt install build-essential libcotp-dev libpam0g-dev \
                 libgcrypt20-dev qrencode
```

| Package | For |
|---|---|
| `build-essential` | compiler and `make` |
| `libcotp-dev` | TOTP library |
| `libpam0g-dev` | PAM headers |
| `libgcrypt20-dev` | seed encryption |
| `qrencode` | draws the QR — *optional*; without it only the URI is shown |

> `libgcrypt` was already installed, because libcotp uses it internally.
> What the `-dev` package adds is the header; without it the error is
> `gcrypt.h: No such file or directory`.

## Fedora / RHEL

**libcotp is not packaged on Fedora**, so it has to be built:

```bash
sudo dnf install gcc make cmake pam-devel libgcrypt-devel qrencode git

git clone https://github.com/paolostivanin/libcotp.git
cd libcotp && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make && sudo make install
sudo ldconfig
cd ../..
```

This installs **libcotp v4**, which renamed the constants relative to
Ubuntu's v3 (`SHA1` → `COTP_SHA1`, `MIN_DIGTS` → `MIN_DIGITS`). The code
has a compatibility shim in `totp_common.h` and builds against both.

## Arch

```bash
sudo pacman -S base-devel libgcrypt qrencode
yay -S libcotp        # it is in the AUR
```

## Time synchronisation — not optional

TOTP derives the code from the clock. If it drifts beyond the tolerance
window, **no user can log in**:

```bash
timedatectl status              # "System clock synchronized: yes"
sudo timedatectl set-ntp true
```

If your system uses **chrony** and the drift is large, chrony will not fix
it on its own (it adjusts gradually and refuses large jumps):

```bash
sudo chronyc makestep
date -u
```

On VirtualBox, install the Guest Additions: the VM's clock drifts
noticeably after suspending the host, and then 2FA stops working for
everyone.

```bash
sudo apt install virtualbox-guest-utils
sudo reboot
```

---

# 3. Build and install

Five source files:

```
src/totp_common.h   shared definitions
src/totp_common.c   file I/O, generation, verification
src/totp_crypto.c   seed encryption with libgcrypt
src/pam_totp.c      the PAM module
src/totp-admin.c    the enrollment tool
```

`totp_common.c` and `totp_crypto.c` are compiled into **both** binaries, so
the module and the tool cannot diverge in how they read and write files.

```bash
cd totp
make
sudo make install
```

| What | Where | Mode |
|---|---|---|
| `pam_totp.so` | PAM module directory (auto-detected) | 0644 |
| `totp-admin` | `/usr/local/bin/` | 0755 |
| `totp.conf` | `/etc/totp.conf` (not overwritten if present) | 0644 |
| `totp-admin.pam` | `/etc/pam.d/totp-admin` | 0644 |

The Makefile locates the PAM module directory by looking for where
`pam_permit.so` lives, because it varies by distribution:

| Distribution | Directory |
|---|---|
| Debian / Ubuntu | `/usr/lib/x86_64-linux-gnu/security` |
| Fedora / RHEL | `/usr/lib64/security` |
| Arch / openSUSE | `/usr/lib/security` |

If it picks the wrong one:

```bash
sudo make install SECURITYDIR=/usr/lib64/security
```

> **`/lib/security` does not exist on Ubuntu 24.04.** It is what most older
> tutorials say, and the single most common cause of
> `PAM unable to dlopen()`.

## Fedora / RHEL: SELinux

With SELinux in *enforcing* mode, a PAM module without the correct context
**will not load**, and the login fails with nothing pointing at the cause.
`make install` runs `restorecon` when it is available.

If it still fails:

```bash
sudo ausearch -m avc -ts recent
```

To confirm SELinux is the problem and not your code, set it permissive
**temporarily**:

```bash
sudo setenforce 0        # diagnosis only
sudo setenforce 1
```

---

# 4. Enrolling users

**Do this BEFORE touching PAM.** If you enable the module without `nullok`
and nobody has a seed, nobody can log in.

Each user, in their own session, with no privileges:

```bash
totp-admin
```

The tool:

1. Asks for **your system password** and **validates it against PAM**. If
   you mistype it, it says so immediately and generates nothing.
2. Generates a 160-bit seed with `getentropy()`.
3. Encrypts it with that password and stores it in `~/.totp_auth` (0600).
4. Prints the QR, the `otpauth://` URI, the seed in text, and five
   single-use **recovery codes**.

> **The password must be the same one you log in with**, because the module
> takes it from there to decrypt. That is why the tool validates it: a typo
> would leave the seed encrypted with a key nobody knows.
>
> Validation uses `pam_unix` through `/etc/pam.d/totp-admin`. It does not
> read `/etc/shadow`: PAM delegates to `/usr/sbin/unix_chkpwd`, which is
> setgid `shadow`, and that is why it works unprivileged — the same
> mechanism `su` and `screen` use.

Verify on the spot, before the user leaves, that the code on their phone
matches. If the QR did not scan or the clock is off, it is much better to
find out then.

> **About the delivery channel.** Whoever sees the QR *is* the second
> factor, permanently and without leaving a trace. Enrolling over SSH with
> only a password means whoever has that password can enroll *their own*
> device. Prefer doing it in person, and keep the `nullok` window short.

## Removing a user

The administrator deletes the file:

```bash
sudo rm /home/tiago/.totp_auth
```

---

# 5. PAM configuration

Edit `/etc/pam.d/sshd`. **The reference line differs by distribution**, and
position matters: the module needs the password to already be in
`PAM_AUTHTOK`.

## Debian / Ubuntu

Find `@include common-auth` and add **below it**:

```
auth    required    pam_totp.so nullok debug
```

## Fedora / RHEL

Find `auth substack password-auth` and add the same line **below it**.

## Arch

Find `auth include system-remote-login` and add the same line **below it**.

## Module options

| Option | Effect |
|---|---|
| `debug` | verbose logging. Never records the seed or the code, only its length |
| `nullok` | abstain if the user has no 2FA configured |

**`nullok`** is essential during rollout; **remove it** once everyone is
enrolled. **`debug`** should come out in production.

> ### A note on `PAM_IGNORE`
>
> If `pam_totp.so` with `nullok` were the **only** module in the `auth`
> stack, libpam would have no result to aggregate and would return
> `PAM_PERM_DENIED`. That never happens in `/etc/pam.d/sshd` because
> `common-auth` is always there — but it will happen if you build a minimal
> PAM service for testing.

---

# 6. sshd configuration

```bash
sudo nano /etc/ssh/sshd_config.d/99-totp.conf
```

```
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
```

- **`KbdInteractiveAuthentication yes`** enables the dialogue the code
  prompt travels through. Without it PAM never gets to ask anything. On
  OpenSSH older than 8.7 the directive is called
  `ChallengeResponseAuthentication`.
- **`PasswordAuthentication no`** disables sshd's native password method.
  Through that path sshd hands PAM **a single string** and replies with it
  to *every* prompt, so the code prompt receives the password and always
  fails.

If your version does not support `sshd_config.d/`, put those lines directly
in `/etc/ssh/sshd_config`.

```bash
sudo sshd -t

sudo systemctl restart ssh      # Debian / Ubuntu
sudo systemctl restart sshd     # Fedora / RHEL / Arch
```

## Optional: public key **or** password + code

```
AuthenticationMethods publickey keyboard-interactive
```

The **space** separates alternatives: the user logs in with a public key
alone, **or** with password plus code. A **comma** would require both.

On the public-key path sshd does not run the PAM `auth` stack at all, so
the module never sees it — the "no password to decrypt with" problem does
not arise.

> **The cost:** the public key becomes a complete bypass of the second
> factor. Whoever steals the private key gets in without touching TOTP.
> Sometimes that is deliberate (emergency access), but it is a conscious
> decision.

---

# 7. Verification

From another terminal, **without closing the current one**:

```bash
ssh tiago@192.168.1.58
```

Expected:

```
(tiago@192.168.1.58) Password:
(tiago@192.168.1.58) Codigo de verificacion:
```

With the log alongside:

```bash
sudo journalctl -u ssh -f       # or -u sshd on Fedora/Arch
```

With `debug` on:

```
sshd(pam_totp): user=tiago archivo=/home/tiago/.totp_auth algo=SHA1 digits=6 period=30 window=3
sshd(pam_totp): codigo de 6 digitos
sshd(pam_totp): segundo factor aceptado para tiago
```

## What to test

- [ ] Correct code → logs in
- [ ] Wrong code → `codigo invalido`
- [ ] **Same code twice** → `codigo ya utilizado (anti-replay)`
- [ ] Recovery code → logs in, and `quedan 4`
- [ ] Same recovery code again → rejected
- [ ] 4 wrong codes in a row → `demasiados intentos`
- [ ] While blocked, the **correct** code also fails
- [ ] After 30 s with no attempts, it works again
- [ ] `chmod 644 ~/.totp_auth` → `permisos o propietario inseguros`
- [ ] `sudo chmod 666 /etc/totp.conf` → **denied**
- [ ] Flip a byte in the `" DATA` line → **denied**, GCM detects it
- [ ] `totp-admin` with the wrong password → refuses, creates nothing
- [ ] User with no seed and `nullok` → logs in with password only
- [ ] User with no seed and **no** `nullok` → denied

Restore permissions afterwards:

```bash
chmod 600 ~/.totp_auth
sudo chmod 644 /etc/totp.conf
```

> **When testing by hand, wait 30 seconds between rounds.** With 3 attempts
> per window it is easy to get blocked and believe you broke something else.

---

# 8. Password changes

The seed is encrypted with the user's password, so **changing it makes the
seed undecryptable**. After `passwd`, the 2FA has to be regenerated:

```bash
totp-admin
```

That produces a **new seed**: the QR has to be scanned again and the
previous recovery codes stop working.

If the user forgets, the login fails with an explicit message:

```
pam_totp(sshd:auth): no se pudo descifrar el seed de tiago: la contrasena
no coincide con la que lo cifro, o el archivo fue alterado
```

> **Why there is no automatic re-encryption.** Implementing
> `pam_sm_chauthtok` was evaluated, but it would only cover password
> changes made through PAM. When root runs `passwd other-user`, PAM never
> asks for the old password and re-encryption is impossible anyway;
> `chpasswd` and `usermod -p` bypass PAM entirely. Since the regeneration
> procedure would be needed in those cases regardless, documenting a single
> path was preferred over maintaining two.

---

# 9. Recovery

**SSH broken, console access available:**

```bash
sudo sed -i '/pam_totp.so/d' /etc/pam.d/sshd
sudo systemctl restart ssh      # or sshd
```

**The parameters are wrong and nobody can log in.** The module denies when
`/etc/totp.conf` is invalid or insecure:

```bash
sudo chown root:root /etc/totp.conf && sudo chmod 644 /etc/totp.conf
# or remove it: without the file, defaults are used
sudo mv /etc/totp.conf /etc/totp.conf.bak
```

**The user lost their phone.** Use a recovery code. If none are left, the
administrator deletes the file and the user enrolls again:

```bash
sudo rm /home/tiago/.totp_auth
```

**No access at all.** Boot into *recovery mode* from GRUB
(*Advanced options* → *recovery mode* → *root shell*):

```bash
mount -o remount,rw /
sed -i '/pam_totp.so/d' /etc/pam.d/sshd
reboot
```

---

# 10. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `gcrypt.h: No such file or directory` | missing dev package | `sudo apt install libgcrypt20-dev` |
| `undefined reference to 'pam_start'` linking `totp-admin` | `-lpam` missing from the tool's Makefile rule | add it |
| `error: unknown type name 'size_t'` | libcotp's header uses `size_t` without including `<stddef.h>` | already handled: `<stddef.h>` goes before `<cotp.h>` |
| `SHA1 undeclared` | libcotp v4 renamed the constants | already handled by the shim in `totp_common.h` |
| No code prompt appears | `KbdInteractiveAuthentication` is `no`, or the line is missing from `/etc/pam.d/sshd` | check the sshd drop-in |
| `PAM unable to dlopen(...)` | the `.so` is in the wrong directory | `sudo make install SECURITYDIR=...` |
| Everything fails on Fedora with no clear message | SELinux context on the module | `sudo restorecon -F .../pam_totp.so`; see `ausearch -m avc -ts recent` |
| **Every code fails** | clock drift | see below |
| `no se pudo descifrar el seed` | the password changed, or the file was tampered with | regenerate with `totp-admin` |
| `no hay contrasena disponible` | the module runs before `common-auth`, or the login used a public key | move the line below `common-auth` |
| `permisos o propietario inseguros` | `~/.totp_auth` is not owned by the user or not 0600 | `chmod 600 ~/.totp_auth` |
| `parametros invalidos` | `/etc/totp.conf` is not root-owned, is writable by others, or has an out-of-range value | `chown root:root`, `chmod 644` |
| `codigo ya utilizado` | anti-replay: that step was already used | wait for the next code |
| `demasiados intentos` | rate limit active | wait 30 s **with no attempts** |
| The app shows codes that never validate | `digits` or `algorithm` differ from 6/SHA1 | back to defaults and regenerate |

## Clock drift — the most common failure

The symptom is `codigo invalido`, which does not point at the cause.

**Note:** since the seed is encrypted, you can no longer extract it with
`head -1 ~/.totp_auth`. Use the one `totp-admin` printed at enrollment, or
generate a throwaway one for diagnosis.

```bash
sudo apt install oathtool

SEED=<the one totp-admin printed>
CODE=<the one the phone shows right now>

HIT=$(oathtool --totp -b --now="$(date -u -d '-24 hours' +'%Y-%m-%d %H:%M:%S UTC')" \
      -w 5760 "$SEED" | grep -n "^$CODE$" | head -1 | cut -d: -f1)

if [ -n "$HIT" ]; then
  OFF=$(( (HIT-1)*30 - 86400 ))
  echo "drift: $OFF s  =  $((OFF/3600)) h $(( (OFF%3600)/60 )) min"
else
  echo "not found within +/- 24 h: the phone has a different seed"
fi
```

If a drift comes out, fix the clock (section 2). If nothing is found, the
phone has a different seed: delete **all** entries in the app and scan once.

## The QR will not scan

- Use `qrencode`'s default margin; the standard requires a quiet zone of
  four modules.
- Set the terminal's **line spacing to 1.00** — anything more leaves gaps
  between rows and the camera will not recognise it.
- Increase the font size with `Ctrl` `+`.
- More reliable alternative: render it to a PNG and open it in an image
  viewer.

## Typing the seed by hand

32 characters. The Base32 alphabet excludes `0`, `1`, `8`, `O`, `I` and `B`
precisely to avoid confusion, and it is case-insensitive.

---

# 11. State file format

`~/.totp_auth`, mode `0600`:

```
" TOTP_ENC 1
" SALT 886c51536300feb5c8cc1ab17bb2f5d3     <- KDF salt
" NONCE 706b547142d3dad74ea8b807            <- AES-GCM nonce
" TAG 6b5c43b4eeb243a84e3dde2fe32804cd      <- authentication tag
" DATA aeec85034a99c9c277b2fe78141f96fb...  <- seed + recovery codes, encrypted
" LAST_COUNTER 0                            <- anti-replay, plaintext
" RATE 0 0                                  <- rate limit, plaintext
```

**Changing the parameters:** edit `/etc/totp.conf` as root. Nothing needs
restarting — the module reads it on every authentication. Test a login
before closing your rescue session.

**Unblocking a user without waiting 30 s:**

```bash
sed -i '/^" RATE/d' ~/.totp_auth
```

---

# 12. Security notes

## What the module implements

- **160-bit seed** from `getentropy()` (kernel CSPRNG), the size
  recommended by RFC 4226 §4 R6.
- **Seed and recovery codes encrypted** with AES-256-GCM, key derived from
  the password via PBKDF2-HMAC-SHA256, 200,000 iterations. Fresh salt and
  nonce on every encryption.
- **GCM detects tampering**: altering a byte makes decryption fail rather
  than yielding garbage that would be mistaken for a seed.
- **Replay protection**: the last accepted step is persisted. RFC 6238
  §5.2 **requires** this.
- **Single-use recovery codes**, encrypted alongside the seed.
- **Per-user attempt limiting**, persisted to disk so it survives
  reconnections. Checked *after* prompting for the code: rejecting without
  showing the prompt would let an attacker distinguish "I am blocked" from
  "wrong code". Future timestamps are discarded, so setting the clock back
  cannot lock someone out permanently.
- **Constant-time comparison**, and the full window is traversed even after
  a match.
- **Permission validation on every login**, using `fstat()` on the
  already-open descriptor rather than `stat()` on the path, closing the
  TOCTOU window.
- **`O_NOFOLLOW`**: the file lives in the user's home, so it could be
  replaced with a symlink to someone else's.
- **Privilege dropping**: the module runs as root inside sshd but lowers
  `euid`/`egid` to the user's before touching their file.
- **No credentials in logs**: with `debug`, the *length* of the code is
  recorded, never its value nor the seed.
- **Fail-closed**: any insecure or malformed file results in denial.

## Known limitations

- **Root can impersonate any user.** It cannot read the seed offline, but
  it can capture the password at the next login or patch the module.
  Encryption protects against a stolen disk or a backup, not against the
  administrator.
- **The user can disable their own 2FA** by deleting `~/.totp_auth`, if
  `nullok` is enabled.
- **Password authentication only.** A public-key login does not supply the
  password needed to decrypt.
- **TOTP does not resist real-time phishing.** A proxy relaying the code
  within its window gets in. FIDO2/WebAuthn solves this by binding the
  credential to the origin.
- **Rate limiting reduces brute force, it does not eliminate it.** At 6
  digits and a window of 3, the per-attempt probability is 3/10⁶. Without
  a limit a scripted attacker succeeds within a day; at 3 per 30 s that
  drops to about 2.6 % per day. Minutes into months, not into never.
- **A patient attacker never gets blocked**: waiting 31 s between attempts
  yields roughly 116 per hour.
- **Race condition in the attempt counter.** Two simultaneous
  authentications read the same state and both write; the last one wins.
- **Writes are not atomic.** A crash mid-write could leave the file
  truncated.
- **Denial of service through the rate limit.** Knowing a username is
  enough to keep that account blocked.
- **No device management.** Enrolling a phone is copying the seed: no
  device limit, no registry, no individual revocation.
- **Home directory permissions are not verified**, only the file's.
  `O_NOFOLLOW` covers the symlink case, not direct replacement.
- **PBKDF2 is CPU-only** and parallelises well on GPUs. Argon2id would be
  stronger, being memory-hard.

---

# 13. Uninstalling

```bash
sudo sed -i '/pam_totp.so/d' /etc/pam.d/sshd
sudo rm -f /etc/ssh/sshd_config.d/99-totp.conf
sudo systemctl restart ssh      # or sshd
sudo make uninstall
```

Neither `/etc/totp.conf` nor the `~/.totp_auth` files are removed
automatically:

```bash
sudo rm -f /etc/totp.conf
sudo find /home -maxdepth 2 -name .totp_auth -delete
```
