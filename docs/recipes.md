# Recipes

Practical examples. Sunduk can run **any** command that takes a token via an
environment variable, so this is a starting set, not a complete list.

For every option and config field, see [options.md](options.md).

## Per-Tool Profiles

Most tools follow the same shape: set `command`, `token_file`, and `env`, then
`sunduk --encrypt-token NAME` once and run `sunduk NAME ...` thereafter. The
only things that change per tool are the command, the env var, and (rarely)
`extra_env`.

| Profile | `command` | `env` | `extra_env` | Typical run |
|---|---|---|---|---|
| `gh` | `/usr/bin/gh` | `GH_TOKEN` | — | `sunduk gh api user` |
| `npm` | `/usr/bin/npm` | `NODE_AUTH_TOKEN` | — | `sunduk npm publish` |
| `twine` | `/usr/bin/twine` | `TWINE_PASSWORD` | `TWINE_USERNAME = "__token__"` | `sunduk twine upload dist/*` |
| `cargo` | `/usr/bin/cargo` | `CARGO_REGISTRY_TOKEN` | — | `sunduk cargo publish` |
| `claude` | `/usr/local/bin/claude` | `ANTHROPIC_API_KEY` | — | `sunduk claude` |
| `codex` | `/usr/local/bin/codex` | `OPENAI_API_KEY` | — | `sunduk codex` |
| `mytool` | `/usr/local/bin/mytool` | `API_TOKEN` | — | `sunduk mytool sync` |

A profile from the table, written out in full:

```toml
[profiles.gh]
command = "/usr/bin/gh"
token_file = "~/.config/sunduk/github.cms"
env = "GH_TOKEN"
run_mode = "current"
```

```bash
sunduk --encrypt-token gh   # store the token once
sunduk gh api user          # use it
```

Adjust `command` to match where each tool is installed (`which gh`, etc.).
The examples below cover the cases that need more than this pattern.

## When a Tool Needs Extra Variables

`twine` needs a username as well as the token. Use `extra_env` for static
values that always accompany the secret:

```toml
[profiles.twine]
command = "/usr/bin/twine"
token_file = "~/.config/sunduk/pypi.cms"
env = "TWINE_PASSWORD"
run_mode = "current"
extra_env = { TWINE_USERNAME = "__token__" }
```

```bash
sunduk --encrypt-token twine
sunduk twine upload dist/*
```

The command then runs with both `TWINE_PASSWORD` (decrypted) and
`TWINE_USERNAME=__token__` set.

## curl and Other Shell-Expansion Cases

`curl` needs the token inside a header string, which requires shell expansion.
Run it through `/bin/sh` and **quote with single quotes** so your *current*
shell doesn't expand the variable before Sunduk sets it:

```toml
[profiles.api-shell]
command = "/bin/sh"
token_file = "~/.config/sunduk/api.cms"
env = "API_TOKEN"
run_mode = "current"
```

```bash
sunduk --encrypt-token api-shell
sunduk api-shell -c 'curl -H "Authorization: Bearer $API_TOKEN" https://example.com/api/me'
```

If you used double quotes there, `$API_TOKEN` would be empty — it gets expanded
by your shell before Sunduk ever runs.

## Running a Script with a Profile's Token

`--with` borrows a profile's token settings but runs a *different* command —
useful for scripts that issue many calls without a dedicated profile:

```bash
#!/usr/bin/env bash
set -euo pipefail
gh api user
gh pr list
gh repo view
```

```bash
chmod +x /home/user/bin/my-gh-script.sh
sunduk --with gh -- /home/user/bin/my-gh-script.sh   # or: sunduk -w gh -- ...
```

The script receives `GH_TOKEN`. The command after `--` must be an absolute
path.

If you run a script often, give it its own profile instead — that also lets you
pin its hash:

```toml
[profiles.my-gh-script]
command = "/home/user/bin/my-gh-script.sh"
token_file = "~/.config/sunduk/github.cms"
env = "GH_TOKEN"
run_mode = "current"
```

```bash
sunduk my-gh-script
```

## Sharing One Token File Across Profiles

Several profiles can point at the same `token_file` — handy when one service is
used by different tools under different env var names:

```toml
[profiles.gh]
command = "/usr/bin/gh"
token_file = "~/.config/sunduk/github.cms"
env = "GH_TOKEN"

[profiles.github-curl]
command = "/bin/sh"
token_file = "~/.config/sunduk/github.cms"
env = "GITHUB_TOKEN"
```

```bash
sunduk gh api user
sunduk github-curl -c 'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user'
```

## Command Hash Pinning

Pin a command's binary so Sunduk refuses to run it if it changes:

```bash
sunduk --command-hash gh        # prints sha256 = "..."
```

Add the value to the profile:

```toml
[profiles.gh]
command = "/usr/bin/gh"
token_file = "~/.config/sunduk/github.cms"
env = "GH_TOKEN"
sha256 = "..."
```

After a package upgrade the binary changes, so re-run `--command-hash gh` and
update the pin.

## Isolated-User Mode

Current-user mode is the default and the most compatible (see
[options.md](options.md#cli-options)). Isolated mode runs the tool as a
separate system user via `sudo`, which can reduce exposure to other processes
running as you — but it requires sudoers setup and may break access to your
repo, `$HOME`, and Git/SSH config. It does **not** protect against root or a
malicious target command; see
[threat-model.md](threat-model.md#current-user-vs-isolated-user).

Create the user:

```bash
sudo useradd --system --home /var/lib/sunduk-run --create-home \
  --shell /usr/sbin/nologin sunduk-run
```

Configure the profile:

```toml
[profiles.gh-api]
command = "/usr/bin/gh"
token_file = "~/.config/sunduk/github.cms"
env = "GH_TOKEN"
run_mode = "isolated"
isolated_user = "sunduk-run"
```

Grant the privilege (replace `YOUR_USER`):

```bash
sudo visudo -f /etc/sudoers.d/sunduk-run
```

```sudoers
Defaults env_keep += "GH_TOKEN NODE_AUTH_TOKEN TWINE_PASSWORD CARGO_REGISTRY_TOKEN ANTHROPIC_API_KEY OPENAI_API_KEY API_TOKEN TERM LANG LC_ALL LC_CTYPE"

YOUR_USER ALL=(sunduk-run) NOPASSWD: SETENV: /usr/bin/gh *
YOUR_USER ALL=(sunduk-run) NOPASSWD: SETENV: /usr/bin/npm *
YOUR_USER ALL=(sunduk-run) NOPASSWD: SETENV: /usr/bin/twine *
YOUR_USER ALL=(sunduk-run) NOPASSWD: SETENV: /usr/bin/cargo *
```

```bash
sunduk gh-api api user
```

If isolated mode breaks repository access, fall back to current-user mode:
`sunduk -C gh pr list`.

## Diagnostics

Start with:

```bash
sunduk --doctor
```

For raw OpenSSL/OpenSC output during a decrypt, add `-v`:

```bash
sunduk -v gh api user
```

Manual checks if `--doctor` flags something:

```bash
sudo systemctl enable --now pcscd                 # PC/SC daemon
openssl engine -t -c pkcs11                        # OpenSSL pkcs11 engine
find /usr/lib -name opensc-pkcs11.so 2>/dev/null   # OpenSC module path
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -O  # YubiKey objects
```

## File Permissions

```bash
chmod 700 ~/.config/sunduk
chmod 600 ~/.config/sunduk/config.toml
chmod 600 ~/.config/sunduk/*.cms
chmod 644 ~/.config/sunduk/*.pem
```
