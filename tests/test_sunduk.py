#!/usr/bin/python3

"""
Integration tests for sunduk.py.

Run with:  python3 -m pytest tests/ -v          (from repo root)
Or:        python3 -m pytest tests/test_sunduk.py -v
"""

import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "sunduk.py"
sys.path.insert(0, str(SCRIPT.parent))
import sunduk as s


def run(*args, env=None):
    return subprocess.run(
        [sys.executable, SCRIPT] + list(args),
        capture_output=True, text=True, env=env,
    )


@pytest.fixture()
def tmp(tmp_path):
    """Provides a temp dir with a ready-made config and profile fixtures.

    Profile layout:
      missing   — command points inside tmp_path (guaranteed absent) -> FAIL command missing
      npm       — command /usr/bin/true (always present), no token   -> WARN token missing
      pinned    — /usr/bin/true with wrong sha256                    -> FAIL sha256 mismatch
    """
    cfg = tmp_path / "config.toml"
    cfg.write_text(textwrap.dedent(f"""
        [piv]
        cert = "{tmp_path}/cert.pem"
        pkcs11_uri = "pkcs11:id=%03;type=private"

        [defaults]
        run_mode = "current"
        isolated_user = "test-run"

        [profiles.missing]
        command = "{tmp_path}/no_such_binary"
        token_file = "{tmp_path}/missing.cms"
        env = "MISSING_TOKEN"

        [profiles.npm]
        command = "/usr/bin/true"
        token_file = "{tmp_path}/npm.cms"
        env = "NODE_AUTH_TOKEN"
        extra_env = {{ EXTRA = "val" }}

        [profiles.pinned]
        command = "/usr/bin/true"
        token_file = "{tmp_path}/pinned.cms"
        env = "PINNED_TOKEN"
        sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
    """))
    cfg.chmod(0o600)
    return tmp_path, str(cfg)


# ---------------------------------------------------------------------------
# Basic flags
# ---------------------------------------------------------------------------

def test_help():
    r = run("--help")
    assert r.returncode == 0
    assert "usage:" in r.stdout

def test_help_short():
    r = run("-h")
    assert r.returncode == 0
    assert "usage:" in r.stdout

def test_version():
    r = run("--version")
    assert r.returncode == 0
    assert r.stdout.strip() != ""

def test_no_args_shows_help_and_exits_1():
    r = run()
    assert r.returncode == 1
    assert "usage:" in r.stdout

def test_unknown_flag_errors():
    assert run("--notaflag").returncode != 0

# ---------------------------------------------------------------------------
# --init-config
# ---------------------------------------------------------------------------

def test_init_config_creates_file(tmp_path):
    cfg = str(tmp_path / "config.toml")
    r = run("--config", cfg, "--init-config")
    assert r.returncode == 0
    assert os.path.isfile(cfg)
    assert oct(os.stat(cfg).st_mode & 0o777) == "0o600"

def test_init_config_stderr_format(tmp_path):
    cfg = str(tmp_path / "config.toml")
    r = run("--config", cfg, "--init-config")
    assert r.stderr.startswith("created: ")
    assert "Next steps:" in r.stderr
    assert "{prog}" not in r.stderr
    assert "{path}" not in r.stderr

def test_init_config_template_content(tmp_path):
    cfg = str(tmp_path / "config.toml")
    run("--config", cfg, "--init-config")
    content = open(cfg).read()
    for section in ["[piv]", "[defaults]", "profiles.gh", "profiles.npm",
                    "profiles.twine", "profiles.cargo", "profiles.claude", "profiles.codex"]:
        assert section in content, f"Missing section: {section}"

def test_init_config_refuses_overwrite_without_force(tmp_path):
    cfg = str(tmp_path / "config.toml")
    run("--config", cfg, "--init-config")
    r = run("--config", cfg, "--init-config")
    assert r.returncode == 1
    assert "already exists" in r.stderr

def test_init_config_force_overwrites(tmp_path):
    cfg = str(tmp_path / "config.toml")
    run("--config", cfg, "--init-config")
    assert run("--config", cfg, "--init-config", "--force").returncode == 0

# ---------------------------------------------------------------------------
# --list
# ---------------------------------------------------------------------------

def test_list_empty_config(tmp_path):
    cfg = str(tmp_path / "config.toml")
    run("--config", cfg, "--init-config")
    r = run("--config", cfg, "--list")
    assert r.returncode == 0
    assert "No profiles" in r.stdout

def test_list_format(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--list")
    assert r.returncode == 0
    profile_lines = [l for l in r.stdout.splitlines() if l.startswith("  ")]
    assert len(profile_lines) == 3  # missing, npm, pinned
    for l in profile_lines:
        assert "  token=" in l
    npm_line = next(l for l in profile_lines if "npm" in l)
    assert "NODE_AUTH_TOKEN" in npm_line
    assert "current" in npm_line
    assert "/usr/bin/true" in npm_line

# ---------------------------------------------------------------------------
# --command-hash
# ---------------------------------------------------------------------------

def test_command_hash_format(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--command-hash", "npm")
    assert r.returncode == 0
    lines = r.stdout.splitlines()
    assert lines[0] == "profile = npm"
    assert lines[1] == "command = /usr/bin/true"
    assert lines[2].startswith('sha256 = "') and lines[2].endswith('"')

def test_command_hash_unknown_profile(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--command-hash", "noexist")
    assert r.returncode == 1
    assert "unknown profile" in r.stderr

def test_command_hash_missing_command(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--command-hash", "missing")  # command path guaranteed absent
    assert r.returncode == 1
    assert "not found" in r.stderr

# ---------------------------------------------------------------------------
# --doctor
# ---------------------------------------------------------------------------

def test_doctor_all_lines_well_formed(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--doctor")
    for line in r.stdout.splitlines():
        if line.strip():
            assert line.startswith(("OK  ", "WARN ", "FAIL ")), f"Malformed: {line!r}"

def test_doctor_no_duplicate_lines(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--doctor")
    lines = r.stdout.splitlines()
    assert len(lines) == len(set(lines)), \
        f"Duplicates: {[l for l in lines if lines.count(l) > 1]}"

def test_doctor_exactly_one_line_per_tool(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--doctor")
    lines = r.stdout.splitlines()
    assert sum(1 for l in lines if "openssl:" in l or "openssl not found" in l.lower()) == 1
    assert sum(1 for l in lines if "opensc" in l.lower()) == 1
    assert sum(1 for l in lines if "engine" in l.lower()) == 1

def test_doctor_sha256_mismatch_is_fail(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--doctor")
    assert any("FAIL" in l and "sha256 mismatch" in l for l in r.stdout.splitlines())

def test_doctor_missing_token_is_warn(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--doctor")
    assert any("WARN" in l and "token missing" in l for l in r.stdout.splitlines())

def test_doctor_missing_command_is_fail(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--doctor")
    assert any("FAIL" in l and "command missing" in l for l in r.stdout.splitlines())

def test_doctor_world_readable_config_warns(tmp):
    d, cfg = tmp
    os.chmod(cfg, 0o644)
    r = run("--config", cfg, "--doctor")
    assert "world-readable" in r.stdout
    os.chmod(cfg, 0o600)

def test_doctor_no_config_still_runs(tmp_path):
    r = run("--config", str(tmp_path / "nonexistent.toml"), "--doctor")
    assert "config not found" in r.stdout  # FAIL line, not a crash

# ---------------------------------------------------------------------------
# --with
# ---------------------------------------------------------------------------

def test_with_reaches_cert_resolution(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--with", "npm", "--", "/usr/bin/true")
    assert r.returncode == 1
    assert "cert" in r.stderr.lower()

def test_with_extra_args_pass_through(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--with", "npm", "--", "/usr/bin/true", "a", "b")
    assert r.returncode == 1
    assert "cert" in r.stderr.lower()

def test_with_no_separator_errors(tmp):
    _, cfg = tmp
    assert run("--config", cfg, "--with", "npm").returncode == 1

def test_with_separator_no_cmd_errors(tmp):
    _, cfg = tmp
    assert run("--config", cfg, "--with", "npm", "--").returncode == 1

def test_with_unknown_profile_errors(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--with", "noexist", "--", "/usr/bin/true")
    assert r.returncode == 1
    assert "unknown profile" in r.stderr

def test_with_nonexistent_command_errors(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--with", "npm", "--", "/nonexistent/cmd")
    assert r.returncode == 1
    assert "not found" in r.stderr

# ---------------------------------------------------------------------------
# --encrypt-token
# ---------------------------------------------------------------------------

def test_encrypt_token_no_arg_errors(tmp):
    _, cfg = tmp
    assert run("--config", cfg, "--encrypt-token").returncode == 1

def test_encrypt_token_unknown_profile_errors(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--encrypt-token", "noexist")
    assert r.returncode == 1
    assert "unknown profile" in r.stderr

def test_encrypt_token_missing_cert_errors(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--encrypt-token", "npm")
    assert r.returncode == 1
    assert "cert" in r.stderr.lower()

def test_encrypt_token_out_without_cert_errors(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--encrypt-token", "--out", "/tmp/x.cms")
    assert r.returncode == 1

# ---------------------------------------------------------------------------
# --decrypt-token
# ---------------------------------------------------------------------------

def test_decrypt_token_nonexistent_file_errors(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--decrypt-token", "/nonexistent.cms")
    assert r.returncode == 1
    assert r.stdout == ""  # nothing on stdout on error

def test_decrypt_token_nonexistent_profile_path(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "--decrypt-token", "/tmp/this_does_not_exist.cms")
    assert r.returncode == 1

def test_decrypt_token_short_flag_recognised(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "-d", "/nonexistent.cms")
    assert "unrecognized" not in r.stderr

# ---------------------------------------------------------------------------
# Mutual exclusion
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pair", [
    ("--list", "--doctor"),
    ("--init-config", "--list"),
    ("--command-hash", "npm", "--list"),
])
def test_mutual_exclusion(tmp, pair):
    _, cfg = tmp
    assert run("--config", cfg, *pair).returncode != 0

# ---------------------------------------------------------------------------
# Short flags are recognised
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("args", [
    ("-C", "--list"),
    ("-v", "--doctor"),
    ("-u", "nobody", "--list"),
    ("-c", "/tmp/x.pem", "--doctor"),
    ("-w", "npm", "--", "/usr/bin/true"),
])
def test_short_flags_recognised(tmp, args):
    _, cfg = tmp
    r = run("--config", cfg, *args)
    assert "unrecognized" not in r.stderr

# ---------------------------------------------------------------------------
# Config discovery
# ---------------------------------------------------------------------------

def test_config_env_var(tmp):
    d, cfg = tmp
    env = os.environ.copy()
    env[s.PROGRAM_ENV_CONFIG] = cfg
    r = subprocess.run([sys.executable, SCRIPT, "--list"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0
    assert "npm" in r.stdout

def test_config_flag_overrides_env_var(tmp, tmp_path):
    d, cfg = tmp
    other = str(tmp_path / "other.toml")
    open(other, "w").write("[piv]\n")
    os.chmod(other, 0o600)
    env = os.environ.copy()
    env[s.PROGRAM_ENV_CONFIG] = cfg
    r = subprocess.run([sys.executable, SCRIPT, "--config", other, "--list"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0
    assert "No profiles" in r.stdout

# ---------------------------------------------------------------------------
# Unknown profile error message
# ---------------------------------------------------------------------------

def test_unknown_profile_error_message(tmp):
    _, cfg = tmp
    r = run("--config", cfg, "nonexistent")
    assert r.returncode == 1
    assert "unknown profile: nonexistent" in r.stderr
    assert "known profiles:" in r.stderr



# ---------------------------------------------------------------------------
# Unit tests: expand() — path normalisation
# ---------------------------------------------------------------------------

def test_expand_none_returns_none():
    assert s.expand(None) is None

def test_expand_empty_returns_none():
    assert s.expand("") == ""  # empty string passes through unchanged

def test_expand_home():
    assert s.expand("~") == str(Path.home())

def test_expand_resolves_dotdot():
    assert s.expand("/a/b/../c") == "/a/c"

# ---------------------------------------------------------------------------
# Unit tests: Config — profile lookup and pkcs11_uri precedence
# ---------------------------------------------------------------------------

def test_config_profile_found():
    cfg = s.Config({"profiles": {"gh": {"env": "GH_TOKEN", "token_file": "~/x.cms"}}}, None)
    assert cfg.profile("gh")["env"] == "GH_TOKEN"

def test_config_profile_unknown_raises():
    cfg = s.Config({"profiles": {"gh": {}}}, None)
    with pytest.raises(s.ProgramError, match="unknown profile"):
        cfg.profile("nope")

def test_config_profile_error_lists_known():
    cfg = s.Config({"profiles": {"gh": {}, "npm": {}}}, None)
    with pytest.raises(s.ProgramError, match="known profiles"):
        cfg.profile("nope")

# ---------------------------------------------------------------------------
# Unit tests: Profile._resolve_token_file — ~ expansion
# ---------------------------------------------------------------------------

def test_resolve_token_file_expands_home():
    path = s.Profile._resolve_token_file("gh", {"token_file": "~/x.cms"})
    assert path == str(Path.home() / "x.cms")

def test_resolve_token_file_missing_raises():
    with pytest.raises(s.ProgramError, match="no token_file"):
        s.Profile._resolve_token_file("gh", {})

# ---------------------------------------------------------------------------
# Unit tests: pkcs11_uri precedence (cli > profile > config > default)
# ---------------------------------------------------------------------------

def test_pkcs11_uri_default_when_nothing_set():
    cfg = s.Config({}, None)
    uri = None or {}.get("pkcs11_uri") or cfg.piv().get("pkcs11_uri") or s.DEFAULT_PKCS11_URI
    assert uri == s.DEFAULT_PKCS11_URI

def test_pkcs11_uri_cli_beats_all():
    cfg = s.Config({"piv": {"pkcs11_uri": "from-config"}}, None)
    profile = {"pkcs11_uri": "from-profile"}
    uri = "from-cli" or profile.get("pkcs11_uri") or cfg.piv().get("pkcs11_uri") or s.DEFAULT_PKCS11_URI
    assert uri == "from-cli"

def test_pkcs11_uri_profile_beats_config():
    cfg = s.Config({"piv": {"pkcs11_uri": "from-config"}}, None)
    profile = {"pkcs11_uri": "from-profile"}
    uri = None or profile.get("pkcs11_uri") or cfg.piv().get("pkcs11_uri") or s.DEFAULT_PKCS11_URI
    assert uri == "from-profile"

# ---------------------------------------------------------------------------
# Unit tests: cmd_init_config round-trip
# (file mode, overwrite guard, --force, TOML round-trip)
# ---------------------------------------------------------------------------

def test_init_config_round_trip(tmp_path):
    path = str(tmp_path / "sub" / "config.toml")

    s.cmd_init_config(path, force=False)
    assert os.path.isfile(path)
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"

    cfg = s.Config.load(path, required=True)
    assert cfg.data["defaults"]["run_mode"] == "current"

    with pytest.raises(s.ProgramError, match="already exists"):
        s.cmd_init_config(path, force=False)

    s.cmd_init_config(path, force=True)   # must not raise
    assert os.path.isfile(path)

# ---------------------------------------------------------------------------
# Unit tests: Tools.pubkey — openssl key extraction
# (skipped automatically if openssl is unavailable)
# ---------------------------------------------------------------------------

def _openssl(config_data: dict = {}):
    try:
        return s.Tools.find_openssl(config_data)
    except s.ProgramError:
        pytest.skip("openssl not available")

def _gen_keypair(openssl: str, tmp_path: Path) -> tuple[Path, Path]:
    """Generate RSA key + public PEM; return (key_path, pub_path)."""
    key = tmp_path / "a.key"
    pub = tmp_path / "a.pub"
    subprocess.run([openssl, "genrsa", "-out", str(key), "2048"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    subprocess.run([openssl, "pkey", "-in", str(key), "-pubout", "-out", str(pub)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    return key, pub

def _self_signed_cert(openssl: str, key: Path, cert: Path) -> None:
    subprocess.run(
        [openssl, "req", "-x509", "-new", "-key", str(key),
         "-out", str(cert), "-days", "1", "-subj", "/CN=test/"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
    )

def test_pubkey_extracts_public_key(tmp_path):
    openssl = _openssl()
    _, pub = _gen_keypair(openssl, tmp_path)
    tools = s.Tools(openssl, "", "")
    out = tools.pubkey(["pkey", "-pubin", "-in", str(pub), "-pubout"])
    assert out is not None
    assert b"PUBLIC KEY" in out

def test_pubkey_returns_none_on_garbage(tmp_path):
    openssl = _openssl()
    junk = tmp_path / "junk.pem"
    junk.write_text("not a key\n")
    tools = s.Tools(openssl, "", "")
    assert tools.pubkey(["pkey", "-pubin", "-in", str(junk), "-pubout"]) is None

def test_cert_pubkey_matches_own_key(tmp_path):
    openssl = _openssl()
    key, pub = _gen_keypair(openssl, tmp_path)
    cert = tmp_path / "a_cert.pem"
    _self_signed_cert(openssl, key, cert)
    tools = s.Tools(openssl, "", "")
    cert_pub = tools.pubkey(["x509", "-in", str(cert), "-pubkey", "-noout"])
    key_pub  = tools.pubkey(["pkey",  "-pubin", "-in", str(pub), "-pubout"])
    assert cert_pub is not None and key_pub is not None
    assert cert_pub == key_pub        # the --doctor "OK" path

def test_cert_pubkey_does_not_match_other_key(tmp_path):
    openssl = _openssl()
    # Generate two independent keypairs with flat filenames in tmp_path
    key_a = tmp_path / "a.key"
    pub_a = tmp_path / "a.pub"
    key_b = tmp_path / "b.key"
    pub_b = tmp_path / "b.pub"
    cert_a = tmp_path / "a_cert.pem"
    for key, pub in [(key_a, pub_a), (key_b, pub_b)]:
        subprocess.run([openssl, "genrsa", "-out", str(key), "2048"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run([openssl, "pkey", "-in", str(key), "-pubout", "-out", str(pub)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    _self_signed_cert(openssl, key_a, cert_a)
    tools = s.Tools(openssl, "", "")
    cert_pub = tools.pubkey(["x509", "-in", str(cert_a), "-pubkey", "-noout"])
    key_pub  = tools.pubkey(["pkey",  "-pubin", "-in", str(pub_b), "-pubout"])
    assert cert_pub is not None and key_pub is not None
    assert cert_pub != key_pub        # the --doctor "FAIL" path

if __name__ == "__main__":
    # Run without pytest: just execute all test functions manually
    import traceback
    passed = failed = 0
    globs = list(globals().items())
    for name, obj in globs:
        if not (callable(obj) and name.startswith("test_")):
            continue
        sig = obj.__code__.co_varnames[:obj.__code__.co_argcount]
        if sig:
            continue  # skip fixture-dependent tests when running standalone
        try:
            obj()
            print(f"PASS  {name}")
            passed += 1
        except Exception:
            print(f"FAIL  {name}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed (fixture tests skipped in standalone mode)")
    sys.exit(0 if failed == 0 else 1)
