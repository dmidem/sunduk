#!/usr/bin/python3 -I

import os
import sys
import pwd
import stat
import glob
import shutil
import ctypes
import hashlib
import getpass
import tempfile
import resource
import subprocess
import threading
import textwrap


try:
    import tomllib
except Exception:
    print("error: Python 3.11+ is required for tomllib", file=sys.stderr)
    sys.exit(1)


PROGRAM = "sunduk"
VERSION = "0.1.0"

DEFAULT_CONFIG_PATH = f"~/.config/{PROGRAM}/config.toml"
DEFAULT_CONFIG_PATHS = [DEFAULT_CONFIG_PATH]

DEFAULT_INIT_CONFIG = f"""# Sunduk config
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
# pip installs Python packages.
# twine uploads/publishes Python packages to PyPI.
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

DEFAULT_PKCS11_URI = "pkcs11:id=%03;type=private"
DEFAULT_RUN_MODE = "current"
DEFAULT_ISOLATED_USER = f"{PROGRAM}-run"

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

PR_SET_DUMPABLE = 4
MCL_CURRENT = 1
MCL_FUTURE = 2

USAGE = f"""Sunduk {VERSION}

Store API tokens encrypted on disk and run CLI tools with tokens decrypted via YubiKey PIV.

Usage:
  {PROGRAM} --init-config

  {PROGRAM} PROFILE [ARGS...]
  {PROGRAM} -C PROFILE [ARGS...]
  {PROGRAM} --current PROFILE [ARGS...]

  {PROGRAM} --with PROFILE -- /absolute/path/to/app [ARGS...]
  {PROGRAM} -w PROFILE -- /absolute/path/to/app [ARGS...]

  {PROGRAM} --encrypt-token PROFILE
  {PROGRAM} --decrypt-token PROFILE

  {PROGRAM} --encrypt-token --cert CERT.pem --out TOKEN.cms
  {PROGRAM} --decrypt-token TOKEN.cms --cert CERT.pem

  {PROGRAM} --list
  {PROGRAM} --doctor
  {PROGRAM} --command-hash PROFILE
  {PROGRAM} --help
  {PROGRAM} --version

Global options:
  -v, --verbose        show raw OpenSSL/OpenSC output
  -C, --current        force current-user mode
  -u, --user USER      run target command as USER through sudo
  -w, --with PROFILE   use token settings from PROFILE for another command
  --config PATH        use another config file
  --cert CERT.pem      override certificate
  --pkcs11-uri URI     override PKCS#11 private key URI
  --pkcs11-module PATH override OpenSC PKCS#11 module path
  --engine-dir PATH    override OpenSSL engine directory
  --force              allow overwrite in selected operations

Examples:
  {PROGRAM} --init-config
  {PROGRAM} --doctor
  {PROGRAM} --encrypt-token gh
  {PROGRAM} gh api user
  {PROGRAM} -C gh pr list
  {PROGRAM} --with gh -- /home/user/bin/my-gh-script.sh
  {PROGRAM} --verbose gh api user

Config:
  {DEFAULT_CONFIG_PATH}
  or set SUNDUK_CONFIG=/path/config.toml

Install packages on Debian/Ubuntu:
  sudo apt update
  sudo apt install openssl opensc pcscd libengine-pkcs11-openssl sudo yubico-piv-tool
"""

USAGE_ENCRYPT = (
    f"usage: {PROGRAM} --encrypt-token PROFILE  OR  "
    f"{PROGRAM} --encrypt-token --cert CERT.pem --out TOKEN.cms"
)
USAGE_DECRYPT = (
    f"usage: {PROGRAM} --decrypt-token PROFILE  OR  "
    f"{PROGRAM} --decrypt-token TOKEN.cms --cert CERT.pem"
)
USAGE_WITH = f"usage: {PROGRAM} --with PROFILE -- /absolute/path/to/app [ARGS...]"

INIT_CONFIG_NEXT_STEPS = f"""\
created: {{path}}

Next steps:
  1. Set up YubiKey PIV key and certificate if not done yet.
  2. Edit config.toml and uncomment profiles you need.
  3. Run: {PROGRAM} --doctor
  4. Encrypt a token for a profile, for example: {PROGRAM} --encrypt-token gh
  5. Run the profile, for example: {PROGRAM} gh api user"""


class SundukError(Exception):
    pass


def eprint(*args) -> None:
    print(*args, file=sys.stderr)


def die(msg: str, code: int = 1) -> None:
    eprint(f"error: {msg}")
    sys.exit(code)


def usage(code: int = 1) -> None:
    eprint(USAGE)
    sys.exit(code)


def expand_path(value: str | None) -> str | None:
    if not value:
        return value
    return os.path.abspath(os.path.expandvars(os.path.expanduser(value)))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def openssl_pubkey(openssl: str, args: list[str]) -> bytes | None:
    """Extract a PEM public key via openssl; return None on failure."""
    try:
        result = subprocess.run(
            [openssl] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=clean_base_env(),
            check=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    return result.stdout.strip() or None


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


def find_first_existing_glob(patterns: list[str], required_file: str | None = None) -> str | None:
    for pattern in patterns:
        for candidate in glob.glob(pattern):
            if required_file:
                if os.path.isfile(os.path.join(candidate, required_file)):
                    return candidate
            elif os.path.isfile(candidate):
                return candidate
    return None


def find_openssl(config: dict) -> str:
    value = config.get("openssl", {}).get("bin")
    if value:
        path = expand_path(value)
        if path and os.path.isfile(path):
            return path
        raise SundukError(f"openssl not found: {path}")

    for path in OPENSSL_CANDIDATES:
        if os.path.isfile(path):
            return path

    found = shutil.which("openssl")
    if found:
        return found

    raise SundukError("openssl not found; install: sudo apt install openssl")


def find_pkcs11_module(config: dict, cli_value: str | None) -> str:
    value = cli_value or config.get("piv", {}).get("pkcs11_module")
    if value:
        path = expand_path(value)
        if path and os.path.isfile(path):
            return path
        raise SundukError(f"PKCS#11 module not found: {path}")

    found = find_first_existing_glob(PKCS11_MODULE_CANDIDATES)
    if found:
        return found

    raise SundukError("opensc-pkcs11.so not found; install: sudo apt install opensc pcscd")


def find_engine_dir(config: dict, cli_value: str | None) -> str:
    value = cli_value or config.get("piv", {}).get("engine_dir")
    if value:
        path = expand_path(value)
        if path and os.path.isfile(os.path.join(path, "pkcs11.so")):
            return path
        raise SundukError(f"OpenSSL PKCS#11 engine not found in: {path}")

    found = find_first_existing_glob(ENGINE_DIR_CANDIDATES, required_file="pkcs11.so")
    if found:
        return found

    raise SundukError(
        "OpenSSL pkcs11 engine not found; install: sudo apt install libengine-pkcs11-openssl"
    )


def find_config_path(cli_config: str | None) -> str | None:
    if cli_config:
        return expand_path(cli_config)

    env_config = os.environ.get("SUNDUK_CONFIG")
    if env_config:
        return expand_path(env_config)

    for p in DEFAULT_CONFIG_PATHS:
        path = expand_path(p)
        if path and os.path.isfile(path):
            return path

    return None


def load_config(path: str | None, required: bool = True) -> tuple[dict, str | None]:
    if not path:
        if required:
            raise SundukError(f"config not found; create {DEFAULT_CONFIG_PATH}")
        return {}, None

    if not os.path.isfile(path):
        if required:
            raise SundukError(f"config not found: {path}")
        return {}, path

    with open(path, "rb") as f:
        return tomllib.load(f), path


def init_config(cli_config: str | None, force: bool) -> None:
    path = expand_path(cli_config or DEFAULT_CONFIG_PATH)
    if not path:
        raise SundukError("empty config path")

    config_dir = os.path.dirname(path) or "."
    os.makedirs(config_dir, mode=0o700, exist_ok=True)

    try:
        os.chmod(config_dir, 0o700)
    except Exception:
        pass

    if os.path.exists(path) and not force:
        raise SundukError(f"config already exists: {path}; use --force to overwrite")

    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if force else os.O_EXCL

    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, DEFAULT_INIT_CONFIG.encode("utf-8"))
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)

    eprint(INIT_CONFIG_NEXT_STEPS.format(path=path))
    

def get_profiles(config: dict) -> dict:
    return config.get("profiles", {})


def get_profile(config: dict, name: str) -> dict:
    profiles = get_profiles(config)
    if name not in profiles:
        known = ", ".join(sorted(profiles.keys())) or "none"
        raise SundukError(f"unknown profile: {name}; known profiles: {known}")
    return profiles[name]


def resolve_cert(config: dict, profile: dict | None, cli_cert: str | None) -> str:
    value = cli_cert
    if not value and profile:
        value = profile.get("cert")
    if not value:
        value = config.get("piv", {}).get("cert")

    if not value:
        raise SundukError("certificate is not configured; set [piv].cert or use --cert")

    path = expand_path(value)
    if not path or not os.path.isfile(path):
        raise SundukError(f"certificate not found: {path}")

    return path


def resolve_pkcs11_uri(config: dict, profile: dict | None, cli_uri: str | None) -> str:
    if cli_uri:
        return cli_uri
    if profile and profile.get("pkcs11_uri"):
        return profile["pkcs11_uri"]
    return config.get("piv", {}).get("pkcs11_uri", DEFAULT_PKCS11_URI)


def resolve_token_file_from_profile(profile_name: str, profile: dict) -> str:
    value = profile.get("token_file")
    if not value:
        raise SundukError(f"profile '{profile_name}' has no token_file")

    path = expand_path(value)
    if not path:
        raise SundukError(f"profile '{profile_name}' has empty token_file")

    return path


def clean_base_env() -> dict:
    pw = pwd.getpwuid(os.getuid())

    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": pw.pw_dir,
        "USER": pw.pw_name,
        "LOGNAME": pw.pw_name,
    }

    for key in LOCALE_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            env[key] = value

    return env


def run_with_tee_stderr(
    cmd: list[str],
    env: dict,
    input_bytes: bytes | None = None,
    tee_stderr: bool = False,
) -> tuple[int, bytes, bytes]:
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input_bytes is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        close_fds=True,
    )

    stderr_chunks = []

    def stderr_reader():
        assert proc.stderr is not None
        try:
            while True:
                data = proc.stderr.read(4096)
                if not data:
                    break

                stderr_chunks.append(data)

                if tee_stderr:
                    try:
                        sys.stderr.buffer.write(data)
                        sys.stderr.buffer.flush()
                    except Exception:
                        pass
        except ValueError:
            pass

    t = threading.Thread(target=stderr_reader, daemon=True)
    t.start()

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

        t.join()

    return rc, stdout_data, b"".join(stderr_chunks)


def decrypt_error_hint(pkcs11_uri: str, pkcs11_module: str, verbose: bool) -> str:
    msg = (
        f"Hint: OpenSSL/PKCS#11 decrypt failed.\n"
        f"\n"
        f"Configured PKCS#11 URI: {pkcs11_uri}\n"
        f"OpenSC module: {pkcs11_module}\n"
        f"\n"
        f"Check:\n"
        f"  - YubiKey is inserted\n"
        f"  - pcscd is running\n"
        f"  - YubiKey PIV PIN is correct\n"
        f"  - the token file was encrypted for this certificate/YubiKey\n"
        f"  - configured pkcs11_uri matches the private key\n"
        f"  - OpenSC PKCS#11 module is correct\n"
        f"\n"
        f"Try:\n"
        f"  - rerun with the --verbose argument: {PROGRAM} --verbose ...\n"
        f"  - run the built-in diagnostic tool: {PROGRAM} --doctor\n"
        f"  - inspect the token using OpenSC: pkcs11-tool --module \"{pkcs11_module}\" -O"
    )

    if not verbose:
        msg += "\n\nRaw OpenSSL/OpenSC output is hidden. Re-run with --verbose to see it."

    return msg


def encrypt_token(config: dict, cert: str, out_file: str, force: bool) -> None:
    openssl = find_openssl(config)

    out_file = expand_path(out_file)
    if not out_file:
        raise SundukError("empty output file")

    out_dir = os.path.dirname(out_file) or "."
    os.makedirs(out_dir, mode=0o700, exist_ok=True)

    if os.path.exists(out_file) and not force:
        answer = input(f"Overwrite existing token file {out_file}? [y/N] ")
        if answer.lower() not in ("y", "yes"):
            raise SundukError("cancelled")

    harden_process()

    token1 = getpass.getpass("Token: ")
    if not token1:
        raise SundukError("empty token")

    token2 = getpass.getpass("Repeat token: ")
    if token1 != token2:
        raise SundukError("tokens do not match")

    fd, tmp = tempfile.mkstemp(prefix=f".{PROGRAM}.", suffix=".cms", dir=out_dir)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)

    cmd = [
        openssl,
        "cms",
        "-encrypt",
        "-binary",
        "-outform",
        "DER",
        "-aes-256-cbc",
        "-in",
        "/dev/stdin",
        "-out",
        tmp,
        cert,
    ]

    try:
        subprocess.run(
            cmd,
            input=token1.encode("utf-8"),
            check=True,
            close_fds=True,
            env=clean_base_env(),
        )
    except subprocess.CalledProcessError as e:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise SundukError(f"openssl cms encrypt failed with exit code {e.returncode}")

    os.replace(tmp, out_file)
    os.chmod(out_file, 0o600)
    eprint(f"written: {out_file}")


def decrypt_token_bytes(
    config: dict,
    enc_file: str,
    cert: str | None,
    pkcs11_uri: str,
    pkcs11_module_cli: str | None,
    engine_dir_cli: str | None,
    verbose: bool = False,
) -> bytes:
    openssl = find_openssl(config)
    pkcs11_module = find_pkcs11_module(config, pkcs11_module_cli)
    engine_dir = find_engine_dir(config, engine_dir_cli)

    enc_file = expand_path(enc_file)
    if not enc_file or not os.path.isfile(enc_file):
        raise SundukError(f"encrypted token file not found: {enc_file}")

    if not os.isatty(0):
        raise SundukError("stdin is not a TTY; refusing non-interactive PIN prompt")

    env = clean_base_env()
    env["OPENSSL_ENGINES"] = engine_dir
    env["PKCS11_MODULE_PATH"] = pkcs11_module

    cmd = [
        openssl,
        "cms",
        "-decrypt",
        "-binary",
        "-inform",
        "DER",
        "-in",
        enc_file,
        "-out",
        "/dev/stdout",
        "-engine",
        "pkcs11",
        "-keyform",
        "engine",
        "-inkey",
        pkcs11_uri,
    ]

    if cert:
        cmd += ["-recip", cert]

    if verbose:
        eprint(
            ">>> OpenSSL/OpenSC verbose output enabled. "
            "Enter YubiKey PIN when prompted; touch YubiKey if it blinks. <<<"
        )
    else:
        eprint(
            ">>> YubiKey PIN may be required. "
            "Enter PIN if requested; touch YubiKey if it blinks. "
            "Use --verbose for raw OpenSSL/OpenSC output. <<<"
        )

    rc, stdout_data, _ = run_with_tee_stderr(cmd, env, tee_stderr=verbose)

    if rc != 0:
        hint = decrypt_error_hint(pkcs11_uri, pkcs11_module, verbose)
        raise SundukError(f"token decrypt failed\n{hint}")

    token = stdout_data.rstrip(b"\r\n")

    if not token:
        raise SundukError("decrypted token is empty")

    if b"\x00" in token:
        raise SundukError("decrypted token contains NUL byte")

    if len(token) > 8192:
        raise SundukError("decrypted token is too large")

    return token


def check_command_hash(profile_name: str, profile: dict) -> None:
    expected = profile.get("sha256")
    if not expected:
        return

    command = expand_path(profile.get("command"))
    if not command or not os.path.isfile(command):
        raise SundukError(f"profile '{profile_name}' command not found: {command}")

    actual = sha256_file(command)

    if actual.lower() != expected.lower():
        raise SundukError(
            f"command hash mismatch for profile '{profile_name}'\n"
            f"command:  {command}\n"
            f"expected: {expected}\n"
            f"actual:   {actual}"
        )


def resolve_target_command(profile_name: str, profile: dict, app_args: list[str],
                           override_argv: list[str] | None) -> tuple[str, list[str]]:
    if override_argv is None:
        command = expand_path(profile.get("command"))
        if not command:
            raise SundukError(f"profile '{profile_name}' has no command")
        if not command.startswith("/"):
            raise SundukError(f"profile '{profile_name}' command must be an absolute path")
        if not os.path.isfile(command):
            raise SundukError(f"profile '{profile_name}' command not found: {command}")
        check_command_hash(profile_name, profile)
        return command, [command] + app_args

    if not override_argv:
        raise SundukError("--with requires a command after --")
    command = expand_path(override_argv[0])
    if not command:
        raise SundukError("empty command after --with")
    if not command.startswith("/"):
        raise SundukError("--with command must be an absolute path")
    if not os.path.isfile(command):
        raise SundukError(f"--with command not found: {command}")
    return command, [command] + override_argv[1:]


def run_profile(
    config: dict,
    profile_name: str,
    app_args: list[str],
    cli_current: bool,
    cli_user: str | None,
    cli_cert: str | None,
    cli_pkcs11_uri: str | None,
    cli_pkcs11_module: str | None,
    cli_engine_dir: str | None,
    cli_verbose: bool,
    override_argv: list[str] | None = None,
) -> None:
    profile = get_profile(config, profile_name)

    command, target_argv = resolve_target_command(
        profile_name, profile, app_args, override_argv
    )

    token_file = resolve_token_file_from_profile(profile_name, profile)

    env_name = profile.get("env")
    if not env_name:
        raise SundukError(f"profile '{profile_name}' has no env")

    cert = resolve_cert(config, profile, cli_cert)
    pkcs11_uri = resolve_pkcs11_uri(config, profile, cli_pkcs11_uri)

    harden_process()

    token = decrypt_token_bytes(
        config=config,
        enc_file=token_file,
        cert=cert,
        pkcs11_uri=pkcs11_uri,
        pkcs11_module_cli=cli_pkcs11_module,
        engine_dir_cli=cli_engine_dir,
        verbose=cli_verbose,
    )

    env = clean_base_env()
    env[env_name] = token.decode("utf-8")

    extra_env = profile.get("extra_env", {})
    if extra_env:
        if not isinstance(extra_env, dict):
            raise SundukError(f"profile '{profile_name}' extra_env must be a table")
        for k, v in extra_env.items():
            env[str(k)] = str(v)

    defaults = config.get("defaults", {})
    run_mode = profile.get("run_mode", defaults.get("run_mode", DEFAULT_RUN_MODE))
    isolated_user = profile.get("isolated_user", defaults.get("isolated_user", DEFAULT_ISOLATED_USER))

    if cli_current:
        run_mode = "current"

    if cli_user:
        run_mode = "isolated"
        isolated_user = cli_user

    if run_mode == "current":
        os.execve(command, target_argv, env)

    if run_mode != "isolated":
        raise SundukError(f"unknown run_mode: {run_mode}")

    sudo = "/usr/bin/sudo"
    if not os.path.isfile(sudo):
        raise SundukError("sudo not found; install: sudo apt install sudo")

    preserve = sorted(set([env_name] + list(extra_env.keys()) + list(LOCALE_ENV_KEYS)))

    sudo_args = [
        sudo,
        "-n",
        "-u",
        isolated_user,
        "--preserve-env=" + ",".join(preserve),
        "--",
    ] + target_argv

    os.execve(sudo, sudo_args, env)


def list_profiles(config: dict) -> None:
    profiles = get_profiles(config)

    if not profiles:
        print("No profiles configured.")
        return

    default_run_mode = config.get("defaults", {}).get("run_mode", DEFAULT_RUN_MODE)

    print("Profiles:")
    for name in sorted(profiles.keys()):
        p = profiles[name]
        command = p.get("command", "")
        env_name = p.get("env", "")
        token_file = p.get("token_file", "")
        run_mode = p.get("run_mode", default_run_mode)
        print(f"  {name:16} {env_name:20} {run_mode:9} {command}  token={token_file}")


def doctor(config: dict, config_path: str | None, cli_pkcs11_module: str | None, cli_engine_dir: str | None) -> int:
    warnings = 0
    failures = 0

    def ok(msg):
        print(f"OK   {msg}")

    def warn(msg):
        nonlocal warnings
        warnings += 1
        print(f"WARN {msg}")

    def fail(msg):
        nonlocal failures
        failures += 1
        print(f"FAIL {msg}")

    def check_config_permissions(path: str) -> None:
        mode = stat.S_IMODE(os.stat(path).st_mode)

        if mode & stat.S_IWGRP:
                warn(f"config is group-writable: {path} mode={oct(mode)}")
        if mode & stat.S_IWOTH:
            warn(f"config is world-writable: {path} mode={oct(mode)}")
        if mode & stat.S_IROTH:
            warn(f"config is world-readable: {path} mode={oct(mode)}; recommended 0600")

        config_dir = os.path.dirname(path)
        if config_dir and os.path.isdir(config_dir):
            dmode = stat.S_IMODE(os.stat(config_dir).st_mode)
            if dmode & stat.S_IWGRP:
                warn(f"config directory is group-writable: {config_dir} mode={oct(dmode)}")
            if dmode & stat.S_IWOTH:
                warn(f"config directory is world-writable: {config_dir} mode={oct(dmode)}")

    def check_finder(label: str, finder) -> None:
        try:
            ok(f"{label}: {finder()}")
        except Exception as e:
            fail(str(e))

    if config_path and os.path.isfile(config_path):
        ok(f"config: {config_path}")
        check_config_permissions(config_path)
    else:
        fail("config not found")

    check_finder("openssl", lambda: find_openssl(config))
    check_finder("OpenSC PKCS#11 module", lambda: find_pkcs11_module(config, cli_pkcs11_module))
    check_finder("OpenSSL PKCS#11 engine dir", lambda: find_engine_dir(config, cli_engine_dir))

    if shutil.which("systemctl"):
        def systemctl_active(unit: str) -> bool:
            return subprocess.run(
                ["systemctl", "is-active", "--quiet", unit],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode == 0

        if systemctl_active("pcscd.service"):
            ok("pcscd.service: active")
        elif systemctl_active("pcscd.socket"):
            ok("pcscd.socket: active")
        else:
            warn("pcscd is not active; try: sudo systemctl enable --now pcscd.socket")

    piv = config.get("piv", {})
    cert = expand_path(piv.get("cert"))

    if cert and os.path.isfile(cert):
        ok(f"cert: {cert}")

        # Verify cert's public key matches the YubiKey-generated public key.
        # Uses the stored *.pem next to the cert, so no device/PIN/touch needed.
        public_pem = expand_path(piv.get("public_key"))
        if not public_pem:
            guess = cert.replace("_cert.pem", "_public.pem")
            public_pem = guess if os.path.isfile(guess) else None

        if public_pem and os.path.isfile(public_pem):
            try:
                openssl = find_openssl(config)
            except SundukError:
                openssl = None

            if openssl:
                cert_pub = openssl_pubkey(openssl, ["x509", "-in", cert, "-pubkey", "-noout"])
                key_pub = openssl_pubkey(openssl, ["pkey", "-pubin", "-in", public_pem, "-pubout"])

                if cert_pub is None or key_pub is None:
                    warn(f"could not compare cert and public key: {cert} / {public_pem}")
                elif cert_pub == key_pub:
                    ok(f"cert public key matches: {public_pem}")
                else:
                    fail(
                        f"cert public key does NOT match {public_pem}\n"
                        f"     the certificate was not built for this key; "
                        f"decryption will fail"
                    )
        else:
            warn(
                f"cannot verify cert/key match: public key file not found "
                f"(expected alongside {cert}, e.g. *_public.pem)"
            )
    else:
        warn(f"cert missing: {cert}")

    profiles = get_profiles(config)
    if not profiles:
        ok("no profiles configured yet; uncomment profiles in config.toml when ready")

    for name, p in sorted(profiles.items()):
        command = expand_path(p.get("command"))
        token_file = expand_path(p.get("token_file"))

        if command and os.path.isfile(command):
            ok(f"profile {name}: command {command}")

            if os.stat(command).st_mode & stat.S_IWOTH:
                warn(f"profile {name}: command is world-writable: {command}")

            expected = p.get("sha256")
            if expected:
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

    return 0 if failures == 0 else 1


def print_command_hash(config: dict, profile_name: str) -> None:
    profile = get_profile(config, profile_name)
    command = expand_path(profile.get("command"))
    if not command or not os.path.isfile(command):
        raise SundukError(f"profile '{profile_name}' command not found: {command}")

    print(f"profile = {profile_name}")
    print(f"command = {command}")
    print(f"sha256 = \"{sha256_file(command)}\"")


def take_value(argv: list[str], i: int, option: str) -> str:
    if i + 1 >= len(argv):
        die(f"missing value after {option}")
    return argv[i + 1]


def parse_encrypt_args(rest: list[str]) -> tuple[str | None, str | None, str | None, bool]:
    profile_or_file = None
    out_file = None
    cert = None
    force = False

    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg in ("--out", "-o"):
            out_file = take_value(rest, i, "--out")
            i += 2
        elif arg in ("--cert", "-c"):
            cert = take_value(rest, i, "--cert")
            i += 2
        elif arg == "--force":
            force = True
            i += 1
        elif arg.startswith("-"):
            die(f"unknown option for --encrypt-token: {arg}")
        else:
            if profile_or_file is not None:
                die("too many arguments for --encrypt-token")
            profile_or_file = arg
            i += 1

    return profile_or_file, out_file, cert, force


def parse_decrypt_args(rest: list[str]) -> tuple[str | None, str | None]:
    profile_or_file = None
    cert = None

    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg in ("--cert", "-c"):
            cert = take_value(rest, i, "--cert")
            i += 2
        elif arg.startswith("-"):
            die(f"unknown option for --decrypt-token: {arg}")
        else:
            if profile_or_file is not None:
                die("too many arguments for --decrypt-token")
            profile_or_file = arg
            i += 1

    return profile_or_file, cert


def main() -> None:
    argv = sys.argv[1:]

    if not argv:
        usage(1)

    cli_config = None
    cli_cert = None
    cli_pkcs11_uri = None
    cli_pkcs11_module = None
    cli_engine_dir = None
    cli_current = False
    cli_user = None
    cli_with_profile = None
    force = False
    cli_verbose = False

    i = 0
    while i < len(argv):
        arg = argv[i]

        if arg in ("--help", "-h"):
            usage(0)
        elif arg == "--version":
            print(VERSION)
            return
        elif arg == "--config":
            cli_config = take_value(argv, i, "--config")
            i += 2
        elif arg in ("--cert", "-c"):
            cli_cert = take_value(argv, i, "--cert")
            i += 2
        elif arg == "--pkcs11-uri":
            cli_pkcs11_uri = take_value(argv, i, "--pkcs11-uri")
            i += 2
        elif arg == "--pkcs11-module":
            cli_pkcs11_module = take_value(argv, i, "--pkcs11-module")
            i += 2
        elif arg == "--engine-dir":
            cli_engine_dir = take_value(argv, i, "--engine-dir")
            i += 2
        elif arg in ("-C", "--current"):
            cli_current = True
            i += 1
        elif arg in ("-u", "--user"):
            cli_user = take_value(argv, i, "--user")
            i += 2
        elif arg in ("-w", "--with"):
            cli_with_profile = take_value(argv, i, "--with")
            i += 2
        elif arg == "--force":
            force = True
            i += 1
        elif arg in ("-v", "--verbose"):
            cli_verbose = True
            i += 1
        else:
            break

    rest = argv[i:]

    if not rest:
        usage(1)

    config_path = find_config_path(cli_config)

    try:
        if cli_with_profile:
            if rest[0] != "--" or len(rest) < 2:
                die(USAGE_WITH)

            config, _ = load_config(config_path, required=True)
            run_profile(
                config=config,
                profile_name=cli_with_profile,
                app_args=[],
                cli_current=cli_current,
                cli_user=cli_user,
                cli_cert=cli_cert,
                cli_pkcs11_uri=cli_pkcs11_uri,
                cli_pkcs11_module=cli_pkcs11_module,
                cli_engine_dir=cli_engine_dir,
                cli_verbose=cli_verbose,
                override_argv=rest[1:],
            )
            return

        action = rest[0]

        if action == "--init-config":
            local_force = force
            if len(rest) == 2 and rest[1] == "--force":
                local_force = True
            elif len(rest) != 1:
                die(f"usage: {PROGRAM} --init-config [--config PATH] [--force]")
            init_config(cli_config, local_force)
            return

        if action == "--list":
            config, _ = load_config(config_path, required=True)
            list_profiles(config)
            return

        if action == "--doctor":
            config, loaded_path = load_config(config_path, required=False)
            sys.exit(doctor(config, loaded_path, cli_pkcs11_module, cli_engine_dir))

        if action == "--command-hash":
            if len(rest) != 2:
                die(f"usage: {PROGRAM} --command-hash PROFILE")
            config, _ = load_config(config_path, required=True)
            print_command_hash(config, rest[1])
            return

        if action == "--encrypt-token":
            profile_or_file, out_file, local_cert, local_force = parse_encrypt_args(rest[1:])
            force_final = force or local_force
            cert_override = local_cert or cli_cert

            config_required = not (out_file and cert_override)
            config, _ = load_config(config_path, required=config_required)

            if profile_or_file and not out_file:
                profile = get_profile(config, profile_or_file)
                cert = resolve_cert(config, profile, cert_override)
                out_file = resolve_token_file_from_profile(profile_or_file, profile)
            else:
                if not out_file:
                    die(USAGE_ENCRYPT)
                cert = resolve_cert(config, None, cert_override)

            encrypt_token(config, cert, out_file, force_final)
            return

        if action == "--decrypt-token":
            profile_or_file, local_cert = parse_decrypt_args(rest[1:])

            if not profile_or_file:
                die(USAGE_DECRYPT)

            config, _ = load_config(config_path, required=False)
            profiles = get_profiles(config)

            profile = None
            if profile_or_file in profiles:
                profile = get_profile(config, profile_or_file)
                enc_file = resolve_token_file_from_profile(profile_or_file, profile)
            else:
                enc_file = profile_or_file

            cert_override = local_cert or cli_cert
            try:
                cert = resolve_cert(config, profile, cert_override)
            except SundukError:
                cert = None

            pkcs11_uri = resolve_pkcs11_uri(config, profile, cli_pkcs11_uri)

            harden_process()
            token = decrypt_token_bytes(
                config=config,
                enc_file=enc_file,
                cert=cert,
                pkcs11_uri=pkcs11_uri,
                pkcs11_module_cli=cli_pkcs11_module,
                engine_dir_cli=cli_engine_dir,
                verbose=cli_verbose,
            )
            sys.stdout.buffer.write(token)
            sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()
            return

        config, _ = load_config(config_path, required=True)
        run_profile(
            config=config,
            profile_name=action,
            app_args=rest[1:],
            cli_current=cli_current,
            cli_user=cli_user,
            cli_cert=cli_cert,
            cli_pkcs11_uri=cli_pkcs11_uri,
            cli_pkcs11_module=cli_pkcs11_module,
            cli_engine_dir=cli_engine_dir,
            cli_verbose=cli_verbose,
        )

    except SundukError as e:
        die(str(e))


if __name__ == "__main__":
    main()
