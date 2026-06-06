# YubiKey Setup

This guide explains how to create a YubiKey PIV key and certificate for Sunduk.

Sunduk uses:

- a **public certificate** to encrypt tokens;
- a **private PIV key inside the YubiKey** to decrypt them.

The private key never leaves the YubiKey.

> For Sunduk configuration (`[piv]`, profiles, permissions), see
> [options.md](options.md). This guide only covers the YubiKey itself.

## Quick Setup

Run the provided setup script. It checks prerequisites, refuses to overwrite an
existing key or certificate, generates the PIV key in slot `9d`, builds the
certificate, and imports it into the YubiKey:

> **⚠️ This generates a new key in PIV slot `9d`, overwriting anything already
> there** (it leaves other PIV slots and other YubiKey apps — FIDO2, OpenPGP,
> OATH — untouched, and refuses to run if slot `9d` is already in use). It's a
> convenience script and isn't extensively tested.
>
> **If your YubiKey already holds important keys**, don't run it blindly — read
> [`scripts/yubikey-setup.sh`](../scripts/yubikey-setup.sh), run the steps
> yourself one at a time, or use another method you trust. Provided as-is, at
> your own risk (see the project license).

```bash
scripts/yubikey-setup.sh
```

The script will prompt for your YubiKey PIV PIN and management key when needed.

When it finishes, continue with Sunduk:

```bash
sunduk --init-config
sunduk --doctor
```

See [options.md](options.md) for editing the config and
[recipes.md](recipes.md) for per-tool examples.

## What the Script Creates

```text
~/.config/sunduk/
├── yk1_piv_9d_public.pem   # public key exported from the YubiKey
└── yk1_piv_9d_cert.pem     # certificate used to encrypt tokens
```

| File | Secret? | Description |
|---|---:|---|
| `yk1_piv_9d_public.pem` | No | Public key exported from YubiKey slot `9d` |
| `yk1_piv_9d_cert.pem` | No | Certificate used to encrypt tokens |

The private key is **not** stored on disk. It remains inside the YubiKey.

## Recommended Settings

Sunduk defaults assume PIV slot `9d`:

```text
PIV slot:     9d
Algorithm:    RSA2048
PIN policy:   always   (PIN required for every decrypt)
Touch policy: always   (physical touch required for every decrypt)
PKCS#11 URI:  pkcs11:id=%03;type=private
```

Notes:

- **RSA2048** — best compatibility with OpenSSL CMS and PKCS#11 tooling, and
  sufficient for local token encryption.
- **PIN policy `always`** — every decrypt requires the PIV PIN.
- **Touch policy `always`** — every decrypt requires a physical touch. This is
  the strongest setting and the one this guide uses. It means each token
  decrypt needs a touch, including inside scripts that run several commands.
- **`id=%03`** is the OpenSC PKCS#11 id that corresponds to PIV slot `9d`.

## Verify the YubiKey

Read the certificate from slot `9d`:

```bash
yubico-piv-tool -s 9d -a read-certificate
```

List PKCS#11 objects (adjust the module path if needed):

```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -O
find /usr/lib -name opensc-pkcs11.so 2>/dev/null   # if the path differs
```

If your private-key URI differs from `pkcs11:id=%03;type=private`, configure it
per [options.md](options.md#pkcs11_uri).

## Test Decryption

```bash
sunduk --encrypt-token gh
sunduk gh api user
```

Expected flow:

1. Sunduk starts OpenSSL/OpenSC.
2. OpenSC asks for the YubiKey PIV PIN; you enter it.
3. The YubiKey blinks; you touch it.
4. The token is decrypted and `gh` runs with `GH_TOKEN` set.

## Why Not `selfsign-certificate`?

Some YubiKey/OpenSSL/OpenSC combinations fail to self-sign a certificate
directly with the slot `9d` key. The setup script instead builds the
certificate with OpenSSL and forces its public key to match the
YubiKey-generated key (`-force_pubkey ...`), then imports it. This avoids
relying on PIV self-sign behavior.

The certificate is only a container for the public key. It does not need to be
trusted by any browser or OS trust store. The only thing that matters is:

```text
certificate public key == YubiKey PIV slot 9d public key
```

## Backup and Recovery

Public/encrypted artifacts can be backed up freely:

```text
~/.config/sunduk/*.pem   # public
~/.config/sunduk/*.cms   # encrypted
```

**If you lose the YubiKey PIV private key, encrypted token files cannot be
decrypted.** Sunduk has no key recovery. Plan ahead with one of:

- a backup YubiKey (encrypt tokens separately for its certificate, or use a
  multi-recipient CMS workflow);
- reissuing tokens from each service;
- securely stored emergency recovery tokens.

See [threat-model.md](threat-model.md#lost-yubikey-private-key) for details.
