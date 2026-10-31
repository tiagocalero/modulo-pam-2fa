# pam_totp

A PAM module that adds TOTP two-factor authentication to Linux logins,
with the shared secret encrypted at rest so that not even root can read it.

Written in C for a university IT security workshop (Taller de Seguridad
Informática, UDELAR), using **libcotp** for the OTP algorithm and
**libgcrypt** for encryption.

---

## What it looks like

Enrollment: the user runs this in their own session, no root needed:

```
$ totp-admin
Contrasena de tu cuenta (para cifrar el seed):

2FA generado para 'tiago' en /home/tiago/.totp_auth

    █▀▀▀▀▀█ ▀▄▀ ▄█▀█ █▀▀▀▀▀█
    █ ███ █ █▀▄ ▀▄█▄ █ ███ █
    █ ▀▀▀ █ ▀█▄▀▀▄ ▀ █ ▀▀▀ █
    ▀▀▀▀▀▀▀ ▀ █ ▀▄█▄▀ ▀▀▀▀▀▀▀
    ...

URI: otpauth://totp/Lab1_TSI-G08:tiago?secret=T2BZDVDV3BDIQPJRKK6F...
Seed: T2BZDVDV3BDIQPJRKK6FAOAJWZ6V5VEC
Parametros: SHA1, 6 digitos, periodo 30 s

Codigos de recuperacion (un solo uso cada uno):
  90925966
  41457618
  ...
```

Logging in afterwards:

```
$ ssh tiago@192.168.1.2
(tiago@192.168.1.2) Password:
(tiago@192.168.1.2) Codigo de verificacion:
tiago@server:~$
```

And what the server records:

```
sshd(pam_totp): user=tiago archivo=/home/tiago/.totp_auth algo=SHA1 digits=6 period=30 window=3
sshd(pam_totp): codigo de 6 digitos
sshd(pam_totp): segundo factor aceptado para tiago
```

The stored secret is unreadable:

```
" TOTP_ENC 1
" SALT  886c51536300feb5c8cc1ab17bb2f5d3
" NONCE 706b547142d3dad74ea8b807
" TAG   6b5c43b4eeb243a84e3dde2fe32804cd
" DATA  aeec85034a99c9c277b2fe78141f96fbf2b7b0...
" LAST_COUNTER 59598195
" RATE 1788017607 2
```

---

## Scope

Three parts, built in order:

1. A PAM module implementing TOTP (RFC 6238) against libcotp, integrated
   with OpenSSH
2. Replay protection, single-use recovery codes, per-user rate limiting,
   and an enrollment tool
3. Encryption of the seed at rest with libgcrypt, keyed to the user's
   password

```
src/totp_common.h    shared definitions
src/totp_common.c    file I/O, seed generation, code verification
src/totp_crypto.c    seed encryption (libgcrypt)
src/pam_totp.c       the PAM module
src/totp-admin.c     enrollment tool
```

`totp_common.c` and `totp_crypto.c` compile into **both** binaries, so the
module and the tool cannot drift apart in how they read and write files.

---

## Try it

Use a VM. This modifies the authentication stack.

```bash
# Debian / Ubuntu
sudo apt install build-essential libcotp-dev libpam0g-dev \
                 libgcrypt20-dev qrencode

sudo timedatectl set-ntp true      # TOTP depends on the clock

make && sudo make install
totp-admin                         # scan the QR with any authenticator app
```

Then add to `/etc/pam.d/sshd`, **below** `@include common-auth`:

```
auth required pam_totp.so nullok debug
```

and to `/etc/ssh/sshd_config.d/99-totp.conf`:

```
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
```

```bash
sudo sshd -t && sudo systemctl restart ssh
```

> **Keep a root session open in another terminal** until you have verified
> you can still log in, and snapshot the VM first.

On Fedora, libcotp is not packaged and has to be built from source.
[INSTALL.md](docs/INSTALL.md) covers that, plus Arch, SELinux, the per-distro
differences in `/etc/pam.d/sshd`, a troubleshooting table and recovery
procedures.
