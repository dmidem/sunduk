# Alternatives to Sunduk

Sunduk is a purpose-built wrapper for one workflow:

```text
keep app tokens encrypted
unlock them with a hardware-backed key only when needed
run the target app with the token
```

It is not new cryptography and not a general secret manager. Its value is convenience for this specific task: profiles, predictable environment injection, `--with`, `--doctor`, and optional command hash pinning.

## Built-in Tool Authentication

Many tools already have their own login flow:

```bash
gh auth login
npm login
cargo login
```

This is usually the best default. It is convenient, integrated, and requires no extra wrapper.

The tradeoff is that in many desktop setups, built-in auth ends up using an OS keyring or credential helper. Then the security boundary is the unlocked user session/keyring: once it is unlocked, other processes in that session may be able to request secrets depending on platform, policy, prompts, and access controls.

Some tools also expose external auth hooks or token helpers, but these interfaces are not universal. A clean workflow for one tool may not exist for another.

If built-in auth works well for you, use it. Sunduk is useful when you want one consistent local model across different tools.

## OS and Desktop Keyrings

Keyrings such as GNOME Keyring, KWallet, macOS Keychain, and similar systems are convenient after login.

The tradeoff is the trust boundary. Once the keyring/session is unlocked, secrets may become available to other applications in that session depending on platform policy.

Sunduk instead decrypts a token for one invocation, passes it to one target process, and exits.

The token can still be stolen while the target process is running, especially by a malicious target app or sufficiently privileged attacker. Sunduk does not eliminate runtime risk; it reduces the time and scope in which the token is available.

## `pass`, GPG, `age`, SOPS, and Wrappers

Encrypted stores plus shell wrappers are the strongest real alternative.

Example:

```bash
#!/usr/bin/env bash
GH_TOKEN="$(pass show github/token)" exec gh "$@"
```

or:

```bash
#!/usr/bin/env bash
API_TOKEN="$(age -d -i ~/.ssh/id_ed25519 token.age)" exec app "$@"
```

These tools may be simpler, more mature, or already part of your workflow.

The tradeoff is that, to make them easy to use for this specific task, you need to build the wrapper/runner layer yourself.

Sunduk is also a wrapper, and it already provides this workflow:

```text
profile -> decrypt token -> set env -> exec command
```

If you are happy maintaining your own wrappers, you may not need Sunduk.

## Password Manager CLIs

Password managers are excellent general-purpose secret stores.

Some can fetch secrets from the command line or run a command with environment variables injected.

Their security model is usually different from Sunduk. Hardware keys, when supported, are typically used for account authentication, unlock, or second factor. The secrets themselves are then handled by the password manager vault, app, session, or agent.

Sunduk's model is narrower: each run requires a hardware-backed private-key operation, then the token is injected into one command invocation and Sunduk exits.

If your password manager already gives you a comfortable workflow, use it. Sunduk is for this narrower local runner workflow.

## Summary

| Approach | Best part | Main tradeoff |
|---|---|---|
| Built-in auth | Most convenient | Often keyring/session-based; otherwise tool-specific and not universal |
| OS/Desktop keyring | Convenient after login | Unlocked secrets may become available to other apps in the session |
| `pass` / GPG / `age` / SOPS | Strong encrypted-file tools | You build and maintain the runner/wrapper layer |
| Password manager CLI | Great general secret management | Different vault/account/session/agent model |
| **Sunduk** | Simple all-in-one runner for this specific task | Convenient all-in-one tool for this common token workflow |
