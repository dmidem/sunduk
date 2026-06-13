# Threat Model

Sunduk protects API tokens **at rest**. It stores them encrypted on disk and
decrypts them only when needed, using a PIV private key stored in a hardware
token that never leaves the device.

That reduces accidental leaks and some local token theft. It does **not** make
a compromised machine safe — once code runs as you (or as root), the protection
largely ends.

```text
token entered interactively
  -> encrypted with the PIV certificate
  -> stored as a CMS file on disk
  -> decrypted through the PIV hardware token when needed (PIN + optional touch)
  -> passed to the target command via an environment variable
```

## At a Glance

| Threat | Protected? | Why |
|---|:---:|---|
| Plaintext tokens on disk | ✅ | Stored as encrypted CMS, undecryptable without the hardware token |
| Private-key extraction | ✅ | Key is generated on-device and never exported |
| Shell-history / argv leaks | ✅ | Tokens are entered interactively, never passed as arguments |
| Root compromise | ❌ | Root can read memory, trace processes, swap binaries |
| Keyloggers | ⚠️ | PIN can be captured; physical touch confirmation (if supported by your token) helps but isn't a full fix |
| Malicious target command | ❌ | The tool you run *receives* the token by design |
| Compromised user session | ❌ | An attacker acting as you can just run Sunduk |
| Compromised OpenSSL/OpenSC | ❌ | Sunduk trusts the crypto stack it calls |
| Token live in the environment | ⚠️ | Exists while the command runs; child processes inherit it |
| Config / certificate tampering | ⚠️ | Mitigated by file permissions + `--doctor`, not prevented |
| Lost hardware token / PIV key | ❌ | No recovery; encrypted tokens become unreadable |
| Overprivileged / stale tokens | ❌ | Out of scope — limit and rotate tokens server-side |

The rest of this document explains each row.

## What Sunduk Helps With

### Plaintext tokens on disk

Instead of secrets sitting in plaintext —

```text
~/.config/gh/hosts.yml   ~/.npmrc   ~/.pypirc   .env   shell scripts
```

— tokens live as encrypted CMS files (`~/.config/sunduk/*.cms`) that cannot be
decrypted without the PIV private key.

### Private-key extraction

The PIV private key is generated **inside** the hardware token and never written to
disk. Sunduk asks the device to perform the decrypt operation; the key itself
stays on the device.

### Command-line and shell-history leaks

Tokens are never passed as command-line arguments, and they're entered
interactively only during encryption — so normal use never puts a token into
your shell history or a process's argv.

### Optional hardening

Sunduk also offers, in increasing order of strictness:

- **physical touch** confirmation on every decrypt, if your token supports it (YubiKey:
  `touch-policy=always`; check your token's documentation for equivalent settings);
- **isolated-user mode** to run tools as a separate system user;
- **command SHA-256 pinning** to refuse altered binaries;
- **`sunduk --doctor`** permission and configuration checks.

These help, but none of them make a compromised system safe.

## What Sunduk Does Not Protect Against

### Root compromise

With root, an attacker can read process memory, trace processes, replace
binaries, capture terminal input, or modify Sunduk/OpenSSL/OpenSC. Sunduk
offers no defense against root.

### Malicious target commands

The target command *is given* the decrypted token by design — that's the whole
point. `sunduk gh api user` hands `GH_TOKEN` to `/usr/bin/gh`. If that binary,
a plugin, a package lifecycle script, or a wrapper is malicious, it can take the
token. Command hash pinning helps against a *swapped binary*, not against a tool
that is malicious as shipped.

### Compromised user session

If your shell or desktop session is compromised, an attacker can run Sunduk as
you, alter your scripts, replace user-writable commands, or simply wait for you
to unlock the token. Sunduk protects tokens at rest, not a hijacked session.

### Keyloggers

The PIV PIN is typed at the host's OpenSC prompt, so a keylogger or malicious
terminal can capture it. Requiring a physical touch confirmation (where supported)
raises the bar but does not fully solve this.

### Token exposure while running

While the command runs, the token exists in its environment (`GH_TOKEN`,
`TWINE_PASSWORD`, `ANTHROPIC_API_KEY`, …). Environment variables can leak via
child processes, debug output, crash reports, or anything that dumps `environ`.
**Don't run untrusted code while a token variable is present.**

### Config or certificate tampering

The config holds no plaintext tokens, but it decides which command runs, which
token gets decrypted, which env var receives it, and which certificate encrypts
new tokens. So:

- modifying the config can redirect a token to a malicious command;
- replacing the certificate, then getting you to encrypt a new token, can
  encrypt that token to the attacker's key.

Mitigate with file permissions and `sunduk --doctor` (which checks them):

```bash
chmod 700 ~/.config/sunduk
chmod 600 ~/.config/sunduk/config.toml ~/.config/sunduk/*.cms
chmod 644 ~/.config/sunduk/*.pem
```

### Lost hardware token or PIV key

If the hardware token is lost, every encrypted token file becomes permanently
unreadable — Sunduk has no recovery. Plan ahead with a backup token (tokens must
be encrypted separately for its certificate, or use a multi-recipient CMS
workflow), server-side token reissue, or securely stored emergency tokens.
See [yubikey-setup.md](yubikey-setup.md#backup-and-recovery).

### Overprivileged API tokens

Sunduk protects local storage and the local usage flow; it has no say in what a
token can do on the remote service. Use least-privilege tokens, expiry where
available, regular rotation, and revoke on any suspicion.

## Current User vs Isolated User

Current-user mode is the default and the most compatible — the tool keeps access
to your repo, `$HOME`, and Git/SSH config (see
[options.md](options.md#cli-options)). Isolated-user mode runs the tool as a
separate system user, which can reduce exposure to *other* processes running as
you, at the cost of sudoers setup and possibly breaking local-file access. It
does **not** protect against root or a malicious target command.

## Safer Usage Patterns

- Prefer running tools *through* Sunduk —
  `sunduk gh api user` or `sunduk --with gh -- /path/script.sh` — over decrypting
  into a shell variable.
- Avoid plaintext token files entirely.
- Never run untrusted commands while a token env var is set.
- Run `sunduk --doctor` to check permissions and the OpenSSL/OpenSC setup.

## Summary

Sunduk is a meaningful improvement over plaintext token files and a convenient
way to gate token use behind a hardware key. It is **not** a defense against an
attacker who already controls your account, your session, or the machine. Treat
it as "tokens safe at rest, used deliberately" — not "tokens safe on a
compromised host."
