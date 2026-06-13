# Options Reference

Complete reference for Sunduk's CLI options and config fields.

- New here? Start with the [README](../README.md) and [recipes.md](recipes.md).
- Setting up your PIV token? See [yubikey-setup.md](yubikey-setup.md) (YubiKey)
  or your token's documentation.

For the exact, always-current command synopsis, run:

```bash
sunduk --help
```

## Synopsis

```text
sunduk PROFILE [ARGS...]              run a configured profile
sunduk -C | --current PROFILE [ARGS]  force current-user mode
sunduk -u | --user USER PROFILE [ARGS] force isolated-user mode
sunduk -w | --with PROFILE -- APP     run APP with PROFILE's token settings

sunduk --encrypt-token PROFILE        store a token for a profile
sunduk --decrypt-token PROFILE        print a profile's token to stdout

sunduk --list                         list configured profiles
sunduk --doctor                       run diagnostics
sunduk --command-hash PROFILE         print SHA-256 of a profile's command
sunduk --init-config                  create the default config
sunduk --help | --version
```

## CLI Options

| Option | Argument | Meaning |
|---|---|---|
| `-C`, `--current` | — | Run the command as the current user (default mode). |
| `-u`, `--user` | `USER` | Run the command via `sudo -n -u USER` (isolated mode). |
| `-w`, `--with` | `PROFILE` | Borrow a profile's token settings but run a different command after `--`. |
| `-v`, `--verbose` | — | Show raw OpenSSL/OpenSC output (for debugging decrypt issues). |
| `--config` | `PATH` | Use a different config file. Also via `SUNDUK_CONFIG`. |
| `--cert` | `CERT.pem` | Override the encryption certificate. |
| `--pkcs11-uri` | `URI` | Override the private-key PKCS#11 URI. |
| `--pkcs11-module` | `PATH` | Override the OpenSC PKCS#11 module (rarely needed). |
| `--engine-dir` | `PATH` | Override the OpenSSL engine directory (rarely needed). |
| `--force` | — | Allow overwriting in `--encrypt-token` and `--init-config`. |

Notes on the ones that aren't self-explanatory:

- **`--current` / `--user`** — current-user mode is the default and the most
  compatible: the tool keeps access to your repo, `$HOME`, Git/SSH config, etc.
  Isolated mode requires sudoers setup; see
  [recipes.md](recipes.md#isolated-user-mode).
- **`--with`** — borrows the profile's `token_file`, `env`, `extra_env`,
  `run_mode`, `cert`, and `pkcs11_uri`, but runs the command after `--` instead
  of the profile's own `command`. That command must be an absolute path.
- **`--verbose`** — by default Sunduk hides OpenSSL/OpenSC noise and prints a
  short hint on decrypt failure. Add `-v` when diagnosing PIV token/PKCS#11
  problems.
- **`--pkcs11-module` / `--engine-dir`** — Sunduk auto-detects both; you only
  need these on unusual installs.

## Config File

```text
~/.config/sunduk/config.toml        # default path
SUNDUK_CONFIG=/path/config.toml     # or set this
```

Create it with `sunduk --init-config`. Generated profiles start commented out —
uncomment only what you need. Recommended permissions:

```bash
chmod 700 ~/.config/sunduk
chmod 600 ~/.config/sunduk/config.toml
```

### Config Fields

| Field | Section | Default | Meaning |
|---|---|---|---|
| `cert` | `[piv]` | — | Public certificate used to encrypt tokens and as CMS recipient. |
| `pkcs11_uri` | `[piv]` | `pkcs11:id=%03;type=private` | PKCS#11 URI of the private key (slot `9d`). |
| `pkcs11_module` | `[piv]` | auto-detected | Path to `opensc-pkcs11.so`. |
| `engine_dir` | `[piv]` | auto-detected | OpenSSL engine dir containing `pkcs11.so`. |
| `run_mode` | `[defaults]` | `current` | Default mode: `current` or `isolated`. |
| `isolated_user` | `[defaults]` | `sunduk-run` | Default user for isolated mode. |
| `command` | `[profiles.NAME]` | — | **Absolute path** of the command to run. |
| `token_file` | `[profiles.NAME]` | — | Encrypted CMS token file (created by `--encrypt-token`). |
| `env` | `[profiles.NAME]` | — | Env var name that receives the decrypted token. |
| `run_mode` | `[profiles.NAME]` | from `[defaults]` | Per-profile override of run mode. |
| `isolated_user` | `[profiles.NAME]` | from `[defaults]` | Per-profile isolated user. |
| `extra_env` | `[profiles.NAME]` | — | Extra static env vars (a TOML table). |
| `sha256` | `[profiles.NAME]` | — | Optional SHA-256 pin for the command binary. |

A complete profile using every field:

```toml
[piv]
cert = "~/.config/sunduk/yk1_piv_9d_cert.pem"
pkcs11_uri = "pkcs11:id=%03;type=private"

[defaults]
run_mode = "current"
isolated_user = "sunduk-run"

[profiles.twine]
command = "/usr/bin/twine"
token_file = "~/.config/sunduk/pypi.cms"
env = "TWINE_PASSWORD"
run_mode = "current"
extra_env = { TWINE_USERNAME = "__token__" }
sha256 = "0123456789abcdef..."
```

The fields worth a word of explanation:

- **`command` must be absolute.** Sunduk refuses relative paths so the binary
  that runs can't be silently swapped via `$PATH`.
- **`extra_env`** is for tools needing more than the one token variable —
  `twine`, for instance, also wants `TWINE_USERNAME=__token__`.
- **`sha256`** pins the command binary. If the file's hash later differs,
  Sunduk refuses to run it. Generate it with `sunduk --command-hash PROFILE`,
  paste it into the profile, and re-run after package upgrades to refresh it.
- Any CLI flag (`--cert`, `--pkcs11-uri`, `--run-mode` via `-C`/`-u`, …)
  overrides the matching config field for that one invocation.

## Commands

### `PROFILE [ARGS...]`

Reads the profile, decrypts its `token_file`, sets `env`, and runs `command`
with `ARGS`. For example, with the profile above:

```bash
sunduk twine upload dist/*
# runs: /usr/bin/twine upload dist/*
# with: TWINE_PASSWORD=<decrypted>  TWINE_USERNAME=__token__
```

### `--encrypt-token` / `--decrypt-token`

```bash
sunduk --encrypt-token gh        # prompts for a token, stores it for profile gh
sunduk --decrypt-token gh        # prints the token to stdout (errors -> stderr)
```

Encryption needs only the **public certificate** — no hardware token. Decryption
needs the **PIV token** (PIN, and touch if your token supports it).

For files outside a profile:

```bash
sunduk --encrypt-token --cert CERT.pem --out token.cms
sunduk --decrypt-token token.cms --cert CERT.pem
```

`--decrypt-token` makes `TOKEN="$(sunduk --decrypt-token gh)"` possible, but
prefer running tools *through* Sunduk so the token never lands in a shell
variable. See [threat-model.md](threat-model.md#token-exposure-while-running).

### `--list`

```bash
sunduk --list
```

```text
Profiles:
  gh    GH_TOKEN          current   /usr/bin/gh    token=~/.config/sunduk/github.cms
  npm   NODE_AUTH_TOKEN   current   /usr/bin/npm   token=~/.config/sunduk/npm.cms
```

### `--doctor`

Checks the config (and its permissions), OpenSSL, the OpenSC module and engine,
`pcscd`, the PIV certificate, and every profile's command, token file, and
optional SHA-256 pin. Run it first whenever something breaks.

### `--command-hash PROFILE`

Prints the binary's hash to paste into `sha256`:

```bash
sunduk --command-hash gh
# profile = gh
# command = /usr/bin/gh
# sha256 = "..."
```

### `--init-config`

Creates `~/.config/sunduk/config.toml` (or `--config PATH`). Won't overwrite an
existing file unless you pass `--force`.

## Environment Variables

| Variable | Purpose |
|---|---|
| `SUNDUK_CONFIG` | Alternative config path (same as `--config`). |
| *(per-profile `env`)* | Receives the decrypted token, e.g. `GH_TOKEN`. |

Common token variables by tool:

| Tool | Env var | Tool | Env var |
|---|---|---|---|
| `gh` | `GH_TOKEN` | `cargo` | `CARGO_REGISTRY_TOKEN` |
| `npm` | `NODE_AUTH_TOKEN` | `claude` | `ANTHROPIC_API_KEY` |
| `twine` | `TWINE_PASSWORD` | OpenAI-style | `OPENAI_API_KEY` |

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | success |
| non-zero | error (message on `stderr`) |

For `--decrypt-token`, on success `stdout` contains the token and nothing else.
