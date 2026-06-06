<p align="center">
  <img src="logo.svg" alt="Sunduk">
</p>

**Sunduk** is a tool that keeps a program's API tokens encrypted and unlocks them with your
YubiKey only while the program runs.

**Simple by default** — run `sunduk gh api user` instead of saving your GitHub token to a file.  
**Powerful when needed** — use profiles for `gh`, `npm`, `claude`, custom scripts, and other token-based CLIs.

The token is passed to the program through an environment variable and exists
only for that run.

## Quick Start

```bash
# 1. Install dependencies on Debian/Ubuntu
sudo apt update
sudo apt install openssl opensc pcscd libengine-pkcs11-openssl sudo yubico-piv-tool
sudo systemctl enable --now pcscd

# 2. Install Sunduk
sudo install -o root -g root -m 0755 sunduk.py /usr/local/bin/sunduk

# 3. Generate the YubiKey PIV key and certificate (slot 9d)
#    WARNING: this creates/overwrites slot 9d. If your YubiKey already holds
#    important keys, set it up manually instead — see docs/yubikey-setup.md.
scripts/yubikey-setup.sh

# 4. Create config, then uncomment the profiles you need
sunduk --init-config
nano ~/.config/sunduk/config.toml

# 5. Check setup
sunduk --doctor

# 6. Encrypt your GitHub token and use it
sunduk --encrypt-token gh
sunduk gh api user

# Run a script with GH_TOKEN from the gh profile
sunduk --with gh -- /home/user/bin/my-gh-script.sh
```

## Table of Contents

- [What It Does](#what-it-does)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [License](#license)

### What It Does

Sunduk stores API tokens encrypted on disk and decrypts them only when needed using a YubiKey PIV private key.

```text
API token
  -> encrypted CMS file on disk
  -> decrypted through YubiKey PIV
  -> passed to a command via environment variable
```

The private key stays inside the YubiKey.

Sunduk works with tools like `gh`, `npm`, `claude`, `curl`, package-publishing tools, custom scripts, and other CLIs that accept tokens via environment variables.

### Features

- single standalone Python script with TOML configuration
- no GPG agent, no SSH agent, no background secret daemon
- YubiKey PIV-based decryption with PIN prompt and touch confirmation
- OpenSSL CMS encryption and OpenSC PKCS#11 integration
- clean `stdout` for decrypted tokens; prompts and errors go to `stderr`
- run tools as current user or isolated user
- optional command SHA-256 pinning
- built-in diagnostics with `--doctor`

### Documentation

- [docs/yubikey-setup.md](docs/yubikey-setup.md) — YubiKey PIV setup
- [docs/options.md](docs/options.md) — CLI and config reference
- [docs/recipes.md](docs/recipes.md) — practical examples for common CLIs and scripts
- [docs/threat-model.md](docs/threat-model.md) — security model and remaining risks

### Security Model

Short version: Sunduk helps avoid plaintext tokens on disk and reduces accidental token leaks.

It does not protect against:

- root compromise
- keyloggers
- malicious target applications
- malicious shell/session
- a fully compromised user account
- losing the YubiKey private key
- overprivileged API tokens

Read [docs/threat-model.md](docs/threat-model.md).

## Installation

### Requirements

- Debian/Ubuntu (primary target)
- Python 3.11+
- A YubiKey with PIV support
- The packages below

```bash
sudo apt update
sudo apt install openssl opensc pcscd libengine-pkcs11-openssl sudo yubico-piv-tool
sudo systemctl enable --now pcscd
```

### Install as a single-file executable

```bash
git clone https://github.com/dmidem/sunduk.git
cd sunduk

sudo install -o root -g root -m 0755 sunduk.py /usr/local/bin/sunduk
```

The repository file is named `sunduk.py`; after installation the command is `sunduk`.

Check:

```bash
sunduk --help
```

## Configuration

### 1. Set up the YubiKey

Generate the PIV key and certificate before configuring Sunduk:

> ⚠️ The `yubikey-setup` script overwrites PIV slot `9d`. If your YubiKey
> already holds important keys, **stop and read
> [docs/yubikey-setup.md](docs/yubikey-setup.md)** — it covers the warning in
> full and explains what the script does and how to verify it.

```bash
scripts/yubikey-setup.sh
```

### 2. Create the config

```bash
sunduk --init-config
```

Default path:

```text
~/.config/sunduk/config.toml
```

Recommended permissions:

```bash
chmod 700 ~/.config/sunduk
chmod 600 ~/.config/sunduk/config.toml
```

### 3. Define a profile

The generated config has commented examples. A minimal `gh` profile:

```toml
[profiles.gh]
command = "/usr/bin/gh"
token_file = "~/.config/sunduk/github.cms"
env = "GH_TOKEN"
run_mode = "current"
```

The PIV certificate path (created in step 1) is referenced under `[piv]`:

```toml
[piv]
cert = "~/.config/sunduk/yk1_piv_9d_cert.pem"
pkcs11_uri = "pkcs11:id=%03;type=private"
```

For all configuration options, see [docs/options.md](docs/options.md).

## Usage

Encrypt and store a token for a configured profile:

```bash
sunduk --encrypt-token gh
```

Run the configured command:

```bash
sunduk gh api user
```

Run as current user (default, most compatible):

```bash
sunduk -C gh pr list
```

Isolated-user mode is also supported, but requires sudoers configuration. See [docs/recipes.md](docs/recipes.md#isolated-user-mode).

Run a custom script with a profile token:

```bash
sunduk --with gh -- /home/user/bin/my-gh-script.sh
```

List configured profiles:

```bash
sunduk --list
```

Check installation and configuration:

```bash
sunduk --doctor
```

Run tests (for developers):

```bash
python3 -m pytest tests/test_sunduk.py
```

For more examples, see [docs/recipes.md](docs/recipes.md).

## License

Dual-licensed under:

- [Apache License 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

Choose either license for your use.

Copyright © 2026 Dmitry Demin
