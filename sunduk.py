#!/usr/bin/python3 -I

import argparse
import ctypes
import getpass
import glob
import hashlib
import os
import pwd
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import tomllib
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

PROGRAM = "sunduk"
VERSION = "0.1.0"
PROGRAM_ENV_CONFIG = f"{PROGRAM.upper()}_CONFIG"

# ---------------------------------------------------------------------------
# Defaults and search paths
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATH   = f"~/.config/{PROGRAM}/config.toml"
DEFAULT_PKCS11_URI    = "pkcs11:id=%03;type=private"
DEFAULT_RUN_MODE      = "current"
DEFAULT_ISOLATED_USER    = f"{PROGRAM}-run"
INTERNAL_ISOLATED_NS_ARG = "--_isolated-ns-exec"  # internal; not shown in --help

LOCALE_ENV_KEYS = ("TERM", "LANG", "LC_ALL", "LC_CTYPE")

OPENSSL_CANDIDATES = [
    "/usr/bin/openssl",
    "/usr/local/bin/openssl",
    "/opt/homebrew/bin/openssl",
]
PKCS11_MODULE_CANDIDATES = [
    "/usr/lib/*/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/opt/homebrew/lib/opensc-pkcs11.so",
]
ENGINE_DIR_CANDIDATES = [
    "/usr/lib/*/engines-3",
    "/usr/lib/engines-3",
    "/usr/lib/ssl/engines-3",
    "/usr/local/lib/engines-3",
    "/opt/homebrew/lib/engines-3",
]

# ---------------------------------------------------------------------------
# String constants: long messages kept out of logic
# ---------------------------------------------------------------------------

DEFAULT_INIT_CONFIG = f"""# {PROGRAM} config
#
# Uncomment and edit profiles you need.
# Then run, for example:
#   {PROGRAM} --doctor
#   {PROGRAM} --encrypt-token gh
#   {PROGRAM} gh api user

[piv]
cert = "~/.config/{PROGRAM}/yk1_piv_9d_cert.pem"
pkcs11_uri = "pkcs11:id=%03;type=private"

[defaults]
run_mode = "current"
isolated_user = "{PROGRAM}-run"

# GitHub CLI
#
# [profiles.gh]
# command = "/usr/bin/gh"
# token_file = "~/.config/{PROGRAM}/github.cms"
# env = "GH_TOKEN"
# run_mode = "current"

# npm publishing
#
# [profiles.npm]
# command = "/usr/bin/npm"
# token_file = "~/.config/{PROGRAM}/npm.cms"
# env = "NODE_AUTH_TOKEN"
# run_mode = "current"

# PyPI publishing with twine
#
# [profiles.twine]
# command = "/usr/bin/twine"
# token_file = "~/.config/{PROGRAM}/pypi.cms"
# env = "TWINE_PASSWORD"
# run_mode = "current"
# extra_env = {{ TWINE_USERNAME = "__token__" }}

# Rust crates.io publishing
#
# [profiles.cargo]
# command = "/usr/bin/cargo"
# token_file = "~/.config/{PROGRAM}/cargo.cms"
# env = "CARGO_REGISTRY_TOKEN"
# run_mode = "current"

# Claude CLI
#
# [profiles.claude]
# command = "/usr/local/bin/claude"
# token_file = "~/.config/{PROGRAM}/anthropic.cms"
# env = "ANTHROPIC_API_KEY"
# run_mode = "current"

# Codex/OpenAI-style CLI
#
# [profiles.codex]
# command = "/usr/local/bin/codex"
# token_file = "~/.config/{PROGRAM}/openai.cms"
# env = "OPENAI_API_KEY"
# run_mode = "current"
"""

INIT_CONFIG_NEXT_STEPS = """\
created: {path}

Next steps:
  1. Set up a PIV-compatible hardware token (YubiKey, Nitrokey, etc.) if not done yet.
  2. Edit config.toml and uncomment profiles you need.
  3. Run: {prog} --doctor
  4. Encrypt a token for a profile, for example: {prog} --encrypt-token gh
  5. Run the profile, for example: {prog} gh api user"""

DECRYPT_HINT = """\
Hint: OpenSSL/PKCS#11 decrypt failed.

Configured PKCS#11 URI: {pkcs11_uri}
OpenSC module: {pkcs11_module}

Check:
  - hardware token is inserted
  - pcscd is running
  - PIV PIN is correct
  - the token file was encrypted for this certificate and key
  - configured pkcs11_uri matches the private key
  - OpenSC PKCS#11 module is correct

Try:
  - rerun with the --verbose argument: {prog} --verbose ...
  - run the built-in diagnostic tool: {prog} --doctor
  - inspect the token using OpenSC: pkcs11-tool --module "{pkcs11_module}" -O"""

DECRYPT_HINT_QUIET_SUFFIX = (
    "\n\nRaw OpenSSL/OpenSC output is hidden. Re-run with --verbose to see it."
)

HELP_EPILOG = f"""
examples:
  {PROGRAM} --init-config
  {PROGRAM} --doctor
  {PROGRAM} gh api user
  {PROGRAM} --encrypt-token gh
  {PROGRAM} -C gh pr list
  {PROGRAM} --with gh -- /home/user/bin/my-gh-script.sh
  {PROGRAM} --verbose gh api user

config:
  {DEFAULT_CONFIG_PATH}
  or set {PROGRAM_ENV_CONFIG}=/path/config.toml

install packages on Debian/Ubuntu:
  sudo apt install openssl opensc pcscd libengine-pkcs11-openssl sudo
  # for YubiKey also run: sudo apt install yubico-piv-tool
  # for other hardware: follow your vendor's guide
"""

# ---------------------------------------------------------------------------
# Errors and small helpers
# ---------------------------------------------------------------------------

class ProgramError(Exception):
    pass


def die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def eprint(*args) -> None:
    print(*args, file=sys.stderr)


def expand(path: str | None) -> str | None:
    return str(Path(path).expanduser().resolve()) if path else path


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def clean_env(**extra: str) -> dict:
    """Sanitised environment: fixed PATH, current user identity, locale passthrough."""
    pw = pwd.getpwuid(os.getuid())
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin",
           "HOME": pw.pw_dir, "USER": pw.pw_name, "LOGNAME": pw.pw_name}
    env.update({k: v for k in LOCALE_ENV_KEYS if (v := os.environ.get(k))})
    env.update(extra)
    return env

# ---------------------------------------------------------------------------
# Process hardening
# ---------------------------------------------------------------------------

PR_SET_DUMPABLE = 4
MCL_CURRENT, MCL_FUTURE = 1, 2


def harden_process() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        libc.mlockall(MCL_CURRENT | MCL_FUTURE)
    except Exception:
        pass

def _require_sudo() -> str:
    sudo = "/usr/bin/sudo"
    if not os.path.isfile(sudo):
        raise ProgramError("sudo not found; install: sudo apt install sudo")
    return sudo

# ---------------------------------------------------------------------------
# Tools: locate openssl, pkcs11 module, engine dir; run openssl subprocesses
# ---------------------------------------------------------------------------

@dataclass
class Tools:
    openssl:       str
    pkcs11_module: str
    engine_dir:    str

    @staticmethod
    def _find_glob(patterns: list[str], required_file: str | None = None) -> str | None:
        for pattern in patterns:
            for candidate in glob.glob(pattern):
                if required_file:
                    if os.path.isfile(os.path.join(candidate, required_file)):
                        return candidate
                elif os.path.isfile(candidate):
                    return candidate
        return None

    @staticmethod
    def find_openssl(config: dict) -> str:
        if path := expand(config.get("openssl", {}).get("bin")):
            if os.path.isfile(path):
                return path
            raise ProgramError(f"openssl not found: {path}")
        for path in OPENSSL_CANDIDATES:
            if os.path.isfile(path):
                return path
        if found := shutil.which("openssl"):
            return found
        raise ProgramError("openssl not found; install: sudo apt install openssl")

    @staticmethod
    def find_pkcs11_module(config: dict, override: str | None = None) -> str:
        if path := expand(override or config.get("piv", {}).get("pkcs11_module")):
            if os.path.isfile(path):
                return path
            raise ProgramError(f"PKCS#11 module not found: {path}")
        if found := Tools._find_glob(PKCS11_MODULE_CANDIDATES):
            return found
        raise ProgramError("opensc-pkcs11.so not found; install: sudo apt install opensc pcscd")

    @staticmethod
    def find_engine_dir(config: dict, override: str | None = None) -> str:
        if path := expand(override or config.get("piv", {}).get("engine_dir")):
            if os.path.isfile(os.path.join(path, "pkcs11.so")):
                return path
            raise ProgramError(f"OpenSSL PKCS#11 engine not found in: {path}")
        if found := Tools._find_glob(ENGINE_DIR_CANDIDATES, required_file="pkcs11.so"):
            return found
        raise ProgramError(
            "OpenSSL pkcs11 engine not found; install: sudo apt install libengine-pkcs11-openssl"
        )

    @staticmethod
    def find(config: dict, pkcs11_override: str | None = None, engine_override: str | None = None) -> "Tools":
        return Tools(
            Tools.find_openssl(config),
            Tools.find_pkcs11_module(config, pkcs11_override),
            Tools.find_engine_dir(config, engine_override),
        )

    def run(
        self,
        cmd: list[str],
        env: dict,
        input_bytes: bytes | None = None,
        tee_stderr: bool = False,
    ) -> tuple[int, bytes, bytes]:
        """Run a command, streaming stderr live (for PIN/touch prompts) while also
        capturing it for error reporting. Returns (returncode, stdout, stderr)."""
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if input_bytes is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            close_fds=True,
        )

        stderr_chunks: list[bytes] = []

        def read_stderr():
            assert proc.stderr is not None
            try:
                while data := proc.stderr.read(4096):
                    stderr_chunks.append(data)
                    if tee_stderr:
                        sys.stderr.buffer.write(data)
                        sys.stderr.buffer.flush()
            except ValueError:
                pass

        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()

        try:
            if input_bytes is not None:
                assert proc.stdin is not None
                try:
                    proc.stdin.write(input_bytes)
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
            assert proc.stdout is not None
            stdout_data = proc.stdout.read() or b""
            rc = proc.wait()
        finally:
            for stream in (proc.stdout, proc.stderr, proc.stdin):
                try:
                    if stream:
                        stream.close()
                except Exception:
                    pass
            stderr_thread.join()

        return rc, stdout_data, b"".join(stderr_chunks)

    def pubkey(self, args: list[str]) -> bytes | None:
        """Extract a PEM public key via openssl; return None on failure."""
        try:
            r = subprocess.run([self.openssl] + args,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=clean_env(), check=True)
            return r.stdout.strip() or None
        except (subprocess.CalledProcessError, OSError):
            return None

# ---------------------------------------------------------------------------
# Config: load TOML and provide typed access to its sections
# ---------------------------------------------------------------------------

@dataclass
class Config:
    data: dict
    path: str | None

    @staticmethod
    def load(cli_config: str | None, required: bool = True) -> "Config":
        path = Config._find_path(cli_config)
        if not path:
            if required:
                raise ProgramError(f"config not found; create {DEFAULT_CONFIG_PATH}")
            return Config({}, None)
        if not os.path.isfile(path):
            if required:
                raise ProgramError(f"config not found: {path}")
            return Config({}, path)
        with open(path, "rb") as f:
            return Config(tomllib.load(f), path)

    @staticmethod
    def _find_path(cli_config: str | None) -> str | None:
        if cli_config:
            return expand(cli_config)
        if env := os.environ.get(PROGRAM_ENV_CONFIG):
            return expand(env)
        if path := expand(DEFAULT_CONFIG_PATH):
            return path if os.path.isfile(path) else None
        return None

    def profile(self, name: str) -> dict:
        profiles = self.data.get("profiles", {})
        if name not in profiles:
            known = ", ".join(sorted(profiles)) or "none"
            raise ProgramError(f"unknown profile: {name}; known profiles: {known}")
        return profiles[name]

    def profiles(self) -> dict:
        return self.data.get("profiles", {})

    def piv(self) -> dict:
        return self.data.get("piv", {})

    def defaults(self) -> dict:
        return self.data.get("defaults", {})

# ---------------------------------------------------------------------------
# Crypto: encrypt and decrypt tokens using openssl cms + PIV (PKCS#11 via OpenSC)
# ---------------------------------------------------------------------------

@dataclass
class Crypto:
    tools: Tools

    @staticmethod
    def for_config(config: Config, pkcs11_override: str | None = None, engine_override: str | None = None) -> "Crypto":
        return Crypto(Tools.find(config.data, pkcs11_override, engine_override))

    def encrypt(self, cert: str, out_file: str, force: bool) -> None:
        out_file = expand(out_file)
        if not out_file:
            raise ProgramError("empty output file")

        out_dir = os.path.dirname(out_file) or "."
        os.makedirs(out_dir, mode=0o700, exist_ok=True)

        if os.path.exists(out_file) and not force:
            answer = input(f"Overwrite existing token file {out_file}? [y/N] ")
            if answer.lower() not in ("y", "yes"):
                raise ProgramError("cancelled")

        harden_process()

        token1 = getpass.getpass("Token: ")
        if not token1:
            raise ProgramError("empty token")
        token2 = getpass.getpass("Repeat token: ")
        if token1 != token2:
            raise ProgramError("tokens do not match")

        fd, tmp = tempfile.mkstemp(prefix=f".{PROGRAM}.", suffix=".cms", dir=out_dir)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

        cmd = [self.tools.openssl, "cms", "-encrypt", "-binary",
               "-outform", "DER", "-aes-256-cbc",
               "-in", "/dev/stdin", "-out", tmp, cert]
        rc, _, _ = self.tools.run(cmd, clean_env(), input_bytes=token1.encode())
        if rc != 0:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise ProgramError(f"openssl cms encrypt failed with exit code {rc}")

        os.replace(tmp, out_file)
        os.chmod(out_file, 0o600)
        eprint(f"written: {out_file}")

    def decrypt(self, enc_file: str, cert: str | None, pkcs11_uri: str, verbose: bool = False) -> bytes:
        enc_file = expand(enc_file)
        if not enc_file or not os.path.isfile(enc_file):
            raise ProgramError(f"encrypted token file not found: {enc_file}")
        if not os.isatty(0):
            raise ProgramError("stdin is not a TTY; refusing non-interactive PIN prompt")

        env = clean_env(OPENSSL_ENGINES=self.tools.engine_dir, PKCS11_MODULE_PATH=self.tools.pkcs11_module)
        cmd = [self.tools.openssl, "cms", "-decrypt", "-binary", "-inform", "DER",
               "-in", enc_file, "-out", "/dev/stdout",
               "-engine", "pkcs11", "-keyform", "engine", "-inkey", pkcs11_uri]
        if cert:
            cmd += ["-recip", cert]

        if verbose:
            eprint(">>> OpenSSL/OpenSC verbose output enabled. Enter PIV PIN when prompted; touch your token if it blinks. <<<")
        else:
            eprint(">>> PIV PIN may be required. Enter PIN if requested; touch your token if it blinks. Use --verbose for raw OpenSSL/OpenSC output. <<<")

        rc, stdout_data, _ = self.tools.run(cmd, env, tee_stderr=verbose)

        if rc != 0:
            hint = DECRYPT_HINT.format(pkcs11_uri=pkcs11_uri, pkcs11_module=self.tools.pkcs11_module, prog=PROGRAM)
            if not verbose:
                hint += DECRYPT_HINT_QUIET_SUFFIX
            raise ProgramError(f"token decrypt failed\n{hint}")

        token = stdout_data.rstrip(b"\r\n")
        if not token:
            raise ProgramError("decrypted token is empty")
        if b"\x00" in token:
            raise ProgramError("decrypted token contains NUL byte")
        if len(token) > 8192:
            raise ProgramError("decrypted token is too large")
        return token

# ---------------------------------------------------------------------------
# Profile: resolve all settings from config + CLI overrides, then run
# ---------------------------------------------------------------------------

@dataclass
class Profile:
    name:       str
    command:    str
    token_file: str
    env_name:   str
    cert:       str
    pkcs11_uri: str
    run_mode:   str
    iso_user:   str
    extra_env:  dict

    @staticmethod
    def resolve(config: Config, name: str, cli: argparse.Namespace,
                command_override: str | None = None) -> "Profile":
        p = config.profile(name)
        d = config.defaults()

        env_name = p.get("env")
        if not env_name:
            raise ProgramError(f"profile '{name}' has no env")

        extra_env = p.get("extra_env", {})
        if extra_env and not isinstance(extra_env, dict):
            raise ProgramError(f"profile '{name}' extra_env must be a table")

        run_mode = p.get("run_mode", d.get("run_mode", DEFAULT_RUN_MODE))
        iso_user = p.get("isolated_user", d.get("isolated_user", DEFAULT_ISOLATED_USER))
        if cli.current:
            run_mode = "current"
        if cli.user:
            run_mode, iso_user = "isolated", cli.user

        return Profile(
            name       = name,
            command    = command_override or Profile._resolve_command(name, p),
            token_file = Profile._resolve_token_file(name, p),
            env_name   = env_name,
            cert       = Profile._resolve_cert(config, p, cli.cert),
            pkcs11_uri = cli.pkcs11_uri or p.get("pkcs11_uri") or config.piv().get("pkcs11_uri") or DEFAULT_PKCS11_URI,
            run_mode   = run_mode,
            iso_user   = iso_user,
            extra_env  = extra_env,
        )

    @staticmethod
    def _resolve_command(name: str, p: dict) -> str:
        command = expand(p.get("command"))
        if not command:
            raise ProgramError(f"profile '{name}' has no command")
        if not command.startswith("/"):
            raise ProgramError(f"profile '{name}' command must be an absolute path")
        if not os.path.isfile(command):
            raise ProgramError(f"profile '{name}' command not found: {command}")
        if expected := p.get("sha256"):
            actual = sha256_file(command)
            if actual.lower() != expected.lower():
                raise ProgramError(
                    f"command hash mismatch for profile '{name}'\n"
                    f"command:  {command}\n"
                    f"expected: {expected}\n"
                    f"actual:   {actual}"
                )
        return command

    @staticmethod
    def _resolve_token_file(name: str, p: dict) -> str:
        raw = p.get("token_file")
        if not raw:
            raise ProgramError(f"profile '{name}' has no token_file")
        path = expand(raw)
        if not path:
            raise ProgramError(f"profile '{name}' has empty token_file")
        return path

    @staticmethod
    def _resolve_cert(config: Config, p: dict, cli_cert: str | None) -> str:
        raw = cli_cert or p.get("cert") or config.piv().get("cert")
        if not raw:
            raise ProgramError("certificate is not configured; set [piv].cert or use --cert")
        path = expand(raw)
        if not path or not os.path.isfile(path):
            raise ProgramError(f"certificate not found: {path}")
        return path

    def run(self, config: Config, app_args: list[str], cli: argparse.Namespace) -> None:
        if self.run_mode == "current":
            self._run_current(config, app_args, cli)

        elif self.run_mode == "isolated":
            self._run_isolated(config, app_args, cli)

        elif self.run_mode == "isolated_ns":
            self._run_isolated_ns(config, app_args, cli)

        else:
            raise ProgramError(f"unknown run_mode: {self.run_mode}")

    def _run_current(self, config: Config, app_args: list[str], cli: argparse.Namespace) -> None:
        harden_process()
        token = Crypto.for_config(config, cli.pkcs11_module, cli.engine_dir).decrypt(
            self.token_file, self.cert, self.pkcs11_uri, cli.verbose,
        )
        env = clean_env(
            **{self.env_name: token.decode()},
            **{str(k): str(v) for k, v in self.extra_env.items()},
        )
        os.execve(self.command, [self.command] + list(app_args), env)

    def _run_isolated(self, config: Config, app_args: list[str], cli: argparse.Namespace) -> None:
        """Classic isolated mode: decrypt in current UID, exec target as iso_user."""
        harden_process()
        token = Crypto.for_config(config, cli.pkcs11_module, cli.engine_dir).decrypt(
            self.token_file, self.cert, self.pkcs11_uri, cli.verbose,
        )
        env = clean_env(
            **{self.env_name: token.decode()},
            **{str(k): str(v) for k, v in self.extra_env.items()},
        )
        sudo = _require_sudo()
        preserve = ",".join(sorted({self.env_name, *self.extra_env.keys(), *LOCALE_ENV_KEYS}))
        target_argv = [self.command] + list(app_args)
        os.execve(sudo, [sudo, "-n", "-u", self.iso_user,
                         f"--preserve-env={preserve}", "--"] + target_argv, env)

    def _run_isolated_ns(self, config: Config, app_args: list[str], cli: argparse.Namespace) -> None:
        """Isolated-ns mode: switch to iso_user first, decrypt there, then exec target
        inside a user namespace that maps iso_user's UID back to the original UID.

        Security properties:
          - Decryption happens under iso_user's UID — token never in original UID's memory
          - Target process runs as iso_user to the kernel (ptrace/environ protection)
          - Target process sees original UID on the filesystem (files created with correct owner)
          - Requires: setup-isolated-ns.sh run once, run_mode = "isolated_ns" in profile
        """
        sudo   = _require_sudo()
        script = str(Path(__file__).resolve())

        # Pass the original UID/GID so the namespace mapping can restore them
        original_uid = str(os.getuid())
        original_gid = str(os.getgid())

        # Build the sudo → sunduk --_isolated-ns-exec invocation.
        # Sunduk re-invokes itself as iso_user; the internal handler does the
        # decrypt and the unshare+exec from there.
        sudo_argv = [
            sudo, "-n", "-u", self.iso_user,
            # Preserve TTY-related vars so PIN prompt works, plus config path
            "--preserve-env=TERM,LANG,LC_ALL,LC_CTYPE", "--",
            script,
            INTERNAL_ISOLATED_NS_ARG,
            "--original-uid", original_uid,
            "--original-gid", original_gid,
        ]
        if config.path:
            sudo_argv += ["--config", config.path]
        if cli.verbose:
            sudo_argv += ["--verbose"]
        if cli.pkcs11_module:
            sudo_argv += ["--pkcs11-module", cli.pkcs11_module]
        if cli.engine_dir:
            sudo_argv += ["--engine-dir", cli.engine_dir]
        if cli.cert:
            sudo_argv += ["--cert", cli.cert]

        sudo_argv += [self.name] + list(app_args)

        os.execve(sudo, sudo_argv, clean_env())

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init_config(cli_config: str | None, force: bool) -> None:
    path = expand(cli_config or DEFAULT_CONFIG_PATH)
    if not path:
        raise ProgramError("empty config path")

    config_dir = os.path.dirname(path) or "."
    os.makedirs(config_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(config_dir, 0o700)
    except Exception:
        pass

    if os.path.exists(path) and not force:
        raise ProgramError(f"config already exists: {path}; use --force to overwrite")

    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, DEFAULT_INIT_CONFIG.encode())
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)

    eprint(INIT_CONFIG_NEXT_STEPS.format(path=path, prog=PROGRAM))


def cmd_list(config: Config) -> None:
    profiles = config.profiles()
    if not profiles:
        print("No profiles configured.")
        return
    default_run_mode = config.defaults().get("run_mode", DEFAULT_RUN_MODE)
    print("Profiles:")
    for name in sorted(profiles):
        p = profiles[name]
        run_mode = p.get("run_mode", default_run_mode)
        print(f"  {name:16} {p.get('env',''):20} {run_mode:9} {p.get('command','')}  token={p.get('token_file','')}")


def cmd_command_hash(config: Config, profile_name: str) -> None:
    profile = config.profile(profile_name)
    command = expand(profile.get("command"))
    if not command or not os.path.isfile(command):
        raise ProgramError(f"profile '{profile_name}' command not found: {command}")
    print(f"profile = {profile_name}")
    print(f"command = {command}")
    print(f'sha256 = "{sha256_file(command)}"')


def cmd_encrypt_token(config: Config, cli: argparse.Namespace) -> None:
    profile_or_file = cli.encrypt_token
    out_file = cli.out

    if profile_or_file and not out_file:
        p        = config.profile(profile_or_file)
        cert     = Profile._resolve_cert(config, p, cli.cert)
        out_file = Profile._resolve_token_file(profile_or_file, p)
    elif out_file:
        cert = Profile._resolve_cert(config, {}, cli.cert)
    else:
        die(f"usage: {PROGRAM} --encrypt-token PROFILE  OR"
            f"  {PROGRAM} --encrypt-token --cert CERT.pem --out TOKEN.cms")

    Crypto.for_config(config).encrypt(cert, out_file, cli.force)


def cmd_decrypt_token(config: Config, cli: argparse.Namespace) -> None:
    profile_or_file = cli.decrypt_token
    profiles = config.profiles()

    if profile_or_file in profiles:
        p          = config.profile(profile_or_file)
        enc_file   = Profile._resolve_token_file(profile_or_file, p)
        pkcs11_uri = cli.pkcs11_uri or p.get("pkcs11_uri") or config.piv().get("pkcs11_uri") or DEFAULT_PKCS11_URI
        try:
            cert = Profile._resolve_cert(config, p, cli.cert)
        except ProgramError:
            cert = None
    else:
        enc_file   = profile_or_file
        pkcs11_uri = cli.pkcs11_uri or config.piv().get("pkcs11_uri") or DEFAULT_PKCS11_URI
        try:
            cert = Profile._resolve_cert(config, {}, cli.cert)
        except ProgramError:
            cert = None

    harden_process()
    token = Crypto.for_config(config, cli.pkcs11_module, cli.engine_dir).decrypt(enc_file, cert, pkcs11_uri, cli.verbose)
    sys.stdout.buffer.write(token + b"\n")
    sys.stdout.buffer.flush()


def cmd_doctor(config: Config, pkcs11_override: str | None, engine_override: str | None) -> int:
    fail_count = 0

    def report(level: str, msg: str) -> None:
        nonlocal fail_count
        if level == "FAIL":
            fail_count += 1
        print(f"{level:<4} {msg}")

    ok   = lambda msg: report("OK",   msg)
    warn = lambda msg: report("WARN", msg)
    fail = lambda msg: report("FAIL", msg)

    # Config file and directory permissions
    if config.path and os.path.isfile(config.path):
        ok(f"config: {config.path}")
        mode = stat.S_IMODE(os.stat(config.path).st_mode)
        if mode & stat.S_IWGRP: warn(f"config is group-writable: {config.path} mode={oct(mode)}")
        if mode & stat.S_IWOTH: warn(f"config is world-writable: {config.path} mode={oct(mode)}")
        if mode & stat.S_IROTH: warn(f"config is world-readable: {config.path} mode={oct(mode)}; recommended 0600")
        config_dir = os.path.dirname(config.path)
        if config_dir and os.path.isdir(config_dir):
            dmode = stat.S_IMODE(os.stat(config_dir).st_mode)
            if dmode & stat.S_IWGRP: warn(f"config dir is group-writable: {config_dir} mode={oct(dmode)}")
            if dmode & stat.S_IWOTH: warn(f"config dir is world-writable: {config_dir} mode={oct(dmode)}")
    else:
        fail("config not found")

    # System tools — each checked independently so one missing item doesn't hide others
    for label, finder in [
        ("openssl",                lambda: Tools.find_openssl(config.data)),
        ("OpenSC PKCS#11 module",  lambda: Tools.find_pkcs11_module(config.data, pkcs11_override)),
        ("OpenSSL PKCS#11 engine", lambda: Tools.find_engine_dir(config.data, engine_override)),
    ]:
        try:
            ok(f"{label}: {finder()}")
        except ProgramError as e:
            fail(str(e))

    # pcscd — accept either service or socket activation
    if shutil.which("systemctl"):
        def systemctl_active(unit: str) -> bool:
            return subprocess.run(
                ["systemctl", "is-active", "--quiet", unit],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ).returncode == 0

        if systemctl_active("pcscd.service") or systemctl_active("pcscd.socket"):
            ok("pcscd: active")
        else:
            warn("pcscd is not active; try: sudo systemctl enable --now pcscd.socket")

    # PIV certificate + optional public-key match check
    cert = expand(config.piv().get("cert"))
    if cert and os.path.isfile(cert):
        ok(f"cert: {cert}")
        public_pem = expand(config.piv().get("public_key")) or cert.replace("_cert.pem", "_public.pem")
        if public_pem and os.path.isfile(public_pem):
            try:
                tools    = Tools.find(config.data)
                cert_pub = tools.pubkey(["x509", "-in", cert,       "-pubkey", "-noout"])
                key_pub  = tools.pubkey(["pkey",  "-pubin", "-in", public_pem, "-pubout"])
                if cert_pub is None or key_pub is None:
                    warn(f"could not compare cert and public key: {cert} / {public_pem}")
                elif cert_pub == key_pub:
                    ok(f"cert public key matches: {public_pem}")
                else:
                    fail(f"cert public key does NOT match {public_pem} — decryption will fail")
            except ProgramError:
                pass
        else:
            warn(f"cannot verify cert/key match: public key not found (expected alongside {cert}, e.g. *_public.pem)")
    else:
        warn(f"cert missing: {cert}")

    # Profiles
    profiles = config.profiles()
    if not profiles:
        ok("no profiles configured yet; uncomment profiles in config.toml when ready")

    for name, p in sorted(profiles.items()):
        command    = expand(p.get("command"))
        token_file = expand(p.get("token_file"))

        if command and os.path.isfile(command):
            ok(f"profile {name}: command {command}")
            if os.stat(command).st_mode & stat.S_IWOTH:
                warn(f"profile {name}: command is world-writable: {command}")
            if expected := p.get("sha256"):
                if sha256_file(command).lower() == expected.lower():
                    ok(f"profile {name}: sha256 matches")
                else:
                    fail(f"profile {name}: sha256 mismatch")
        else:
            fail(f"profile {name}: command missing: {command}")

        if token_file and os.path.isfile(token_file):
            ok(f"profile {name}: token {token_file}")
            mode = stat.S_IMODE(os.stat(token_file).st_mode)
            if mode != 0o600:
                warn(f"profile {name}: token file mode is {oct(mode)}, recommended 0600")
        else:
            warn(f"profile {name}: token missing: {token_file}")

        if not p.get("env"):
            fail(f"profile {name}: env is missing")

    return 0 if fail_count == 0 else 1

# ---------------------------------------------------------------------------
# CLI: argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Store API tokens encrypted on disk and run CLI tools"
                    " with tokens decrypted via a PIV-compatible hardware token.",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=VERSION)
    p.add_argument("--config",        metavar="PATH",      help="config file (default: %(default)s)", default=None)
    p.add_argument("--cert",   "-c",  metavar="CERT.pem",  help="override PIV certificate")
    p.add_argument("--out",    "-o",  metavar="TOKEN.cms",  help="output path for --encrypt-token")
    p.add_argument("--pkcs11-uri",    metavar="URI",   dest="pkcs11_uri",    help="override PKCS#11 private key URI")
    p.add_argument("--pkcs11-module", metavar="PATH",  dest="pkcs11_module", help="override OpenSC PKCS#11 module path")
    p.add_argument("--engine-dir",    metavar="PATH",  dest="engine_dir",    help="override OpenSSL engine directory")
    p.add_argument("--current", "-C", action="store_true", dest="current",   help="force current-user run mode")
    p.add_argument("--user",    "-u", metavar="USER",      help="run command as USER via sudo (implies isolated mode)")
    p.add_argument("--with",    "-w", metavar="PROFILE",   dest="with_profile",
                   help="use token from PROFILE for a custom command (follow with -- CMD ARGS...)")
    p.add_argument("--force",         action="store_true", help="allow overwriting existing files")
    p.add_argument("--verbose", "-v", action="store_true", help="show raw OpenSSL/OpenSC output")

    # Actions — mutually exclusive; each captures its own argument (or True for flag-only)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--init-config",   action="store_true", dest="init_config",
                   help="create default config file")
    g.add_argument("--list",          action="store_true",
                   help="list configured profiles")
    g.add_argument("--doctor",        action="store_true",
                   help="check installation and configuration")
    g.add_argument("--encrypt-token", metavar="PROFILE", nargs="?", const="", dest="encrypt_token",
                   help="encrypt and store a token (for PROFILE, or use --cert/--out for ad-hoc)")
    g.add_argument("--decrypt-token", "-d", metavar="PROFILE_OR_FILE", dest="decrypt_token",
                   help="decrypt a token to stdout")
    g.add_argument("--command-hash",  metavar="PROFILE", dest="command_hash",
                   help="print SHA-256 of a profile's command for config pinning")

    # Internal arguments for isolated_ns re-invocation (not shown in help)
    p.add_argument("--original-uid", dest="original_uid", help=argparse.SUPPRESS)
    p.add_argument("--original-gid", dest="original_gid", help=argparse.SUPPRESS)

    # Profile run: first positional is the profile name, rest are forwarded verbatim
    p.add_argument("profile",  nargs="?",                help="profile name to run")
    p.add_argument("app_args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    return p

def _handle_isolated_ns_exec(cli: argparse.Namespace) -> None:
    """Internal handler: called when sunduk is re-invoked as iso_user by
    _run_isolated_ns(). At this point we are already running as iso_user.

    Responsibilities:
      1. Decrypt the token (under iso_user's UID — never touches original UID memory)
      2. Build the target environment
      3. exec into unshare, mapping iso_user's UID back to original UID on the filesystem
    """
    if not cli.original_uid or not cli.original_gid:
        die("internal error: --original-uid/--original-gid missing in isolated_ns re-entry")

    unshare = shutil.which("unshare")
    if not unshare:
        die("unshare not found; install: sudo apt install util-linux")

    config  = Config.load(cli.config)
    profile = Profile.resolve(config, cli.profile, cli)

    # Decrypt here — we are iso_user, token never exists in original UID's process
    harden_process()
    token = Crypto.for_config(config, cli.pkcs11_module, cli.engine_dir).decrypt(
        profile.token_file, profile.cert, profile.pkcs11_uri, cli.verbose,
    )

    env = clean_env(
        **{profile.env_name: token.decode()},
        **{str(k): str(v) for k, v in profile.extra_env.items()},
    )

    target_argv = [profile.command] + list(cli.app_args)

    # exec into unshare --user, mapping our UID (iso_user) back to original UID.
    # Inside the namespace the target process sees itself as the original user,
    # so filesystem operations (reads, file creation) work transparently.
    # To the host kernel the process is still iso_user — ptrace and /proc protection hold.
    unshare_argv = [
        unshare,
        "--user",
        "--map-user",  cli.original_uid,
        "--map-group", cli.original_gid,
        "--",
    ] + target_argv

    os.execve(unshare, unshare_argv, env)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # Detect internal isolated_ns re-invocation before argparse runs.
    # When sunduk is re-invoked as iso_user, INTERNAL_ISOLATED_NS_ARG is
    # always sys.argv[1] (right after the interpreter path).
    _isolated_ns_reentry = len(sys.argv) > 1 and sys.argv[1] == INTERNAL_ISOLATED_NS_ARG
    if _isolated_ns_reentry:
        # Remove the internal flag so argparse sees: profile [app_args...]
        sys.argv.pop(1)

    parser = _build_parser()
    cli = parser.parse_args()

    if not _isolated_ns_reentry and not any([
                cli.init_config, cli.list, cli.doctor,
                cli.encrypt_token is not None, cli.decrypt_token,
                cli.command_hash, cli.profile, cli.with_profile]):
        parser.print_help()
        sys.exit(1)

    try:
        if cli.init_config:
            cmd_init_config(cli.config, cli.force)
            return

        if cli.with_profile:
            # After `--`, argparse puts the first item in cli.profile and the
            # rest in cli.app_args, so we reconstruct the full override argv.
            override_argv = ([cli.profile] if cli.profile else []) + list(cli.app_args)
            if override_argv and override_argv[0] == "--":
                override_argv = override_argv[1:]
            if not override_argv:
                die(f"usage: {PROGRAM} --with PROFILE -- /absolute/path/to/app [ARGS...]")
            command = expand(override_argv[0])
            if not command or not command.startswith("/"):
                raise ProgramError("--with command must be an absolute path")
            if not os.path.isfile(command):
                raise ProgramError(f"--with command not found: {command}")
            config  = Config.load(cli.config)
            profile = Profile.resolve(config, cli.with_profile, cli, command_override=command)
            profile.run(config, override_argv[1:], cli)
            return

        if cli.list:
            cmd_list(Config.load(cli.config))
            return

        if cli.doctor:
            config = Config.load(cli.config, required=False)
            sys.exit(cmd_doctor(config, cli.pkcs11_module, cli.engine_dir))

        if cli.command_hash:
            cmd_command_hash(Config.load(cli.config), cli.command_hash)
            return

        if cli.encrypt_token is not None:
            config = Config.load(cli.config, required=not (cli.out and cli.cert))
            cmd_encrypt_token(config, cli)
            return

        if cli.decrypt_token:
            cmd_decrypt_token(Config.load(cli.config, required=False), cli)
            return

        # Internal: re-invoked as iso_user by _run_isolated_ns; not user-facing
        if _isolated_ns_reentry and cli.profile:
            _handle_isolated_ns_exec(cli)
            return

        if cli.profile:
            config  = Config.load(cli.config)
            profile = Profile.resolve(config, cli.profile, cli)
            profile.run(config, cli.app_args, cli)
            return

        parser.print_help()
        sys.exit(1)

    except ProgramError as e:
        die(str(e))


if __name__ == "__main__":
    main()
