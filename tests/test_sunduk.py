#!/usr/bin/python3
"""Smoke tests for sunduk. Run: python3 -m pytest test_sunduk.py -v
No YubiKey / OpenSSL / network required."""

import os
import sys
import shutil
import tempfile
import pytest
import subprocess

import sunduk as s  # adjust if your file is named differently


HOME = os.path.expanduser("~")


def run_main(args):
    """Run main() with given argv, returning the exit code."""
    old = sys.argv
    sys.argv = ["sunduk"] + args
    try:
        s.main()
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    finally:
        sys.argv = old


# --- constants are wired up ---

def test_program_constant():
    assert s.PROGRAM == "sunduk"

def test_config_path_uses_program():
    assert s.PROGRAM in s.DEFAULT_CONFIG_PATH

def test_init_config_uses_program():
    assert f"{s.PROGRAM}-run" in s.DEFAULT_INIT_CONFIG


# --- expand_path ---

def test_expand_path_none():
    assert s.expand_path(None) is None

def test_expand_path_empty():
    assert not s.expand_path("")

def test_expand_path_home():
    assert s.expand_path("~") == HOME

def test_expand_path_absolute():
    assert s.expand_path("/a/b/../c") == "/a/c"


# --- arg parsers ---

def test_encrypt_bare_profile():
    assert s.parse_encrypt_args(["gh"]) == ("gh", None, None, False)

def test_encrypt_full_flags():
    result = s.parse_encrypt_args(["--cert", "c.pem", "--out", "t.cms", "--force"])
    assert result == (None, "t.cms", "c.pem", True)

def test_decrypt_file_and_cert():
    assert s.parse_decrypt_args(["t.cms", "-c", "c.pem"]) == ("t.cms", "c.pem")

def test_take_value_reads_next_arg():
    assert s.take_value(["--x", "val"], 0, "--x") == "val"

def test_take_value_missing_exits():
    with pytest.raises(SystemExit):
        s.take_value(["--x"], 0, "--x")


# --- profile resolution ---

@pytest.fixture
def cfg():
    return {
        "profiles": {
            "gh": {"command": "/usr/bin/gh", "env": "GH_TOKEN",
                   "token_file": "~/x.cms"}
        }
    }

def test_get_profile_found(cfg):
    assert s.get_profile(cfg, "gh")["env"] == "GH_TOKEN"

def test_get_profile_unknown_raises(cfg):
    with pytest.raises(s.SundukError, match="unknown profile"):
        s.get_profile(cfg, "nope")

def test_token_file_expanded(cfg):
    path = s.resolve_token_file_from_profile("gh", cfg["profiles"]["gh"])
    assert path == os.path.join(HOME, "x.cms")


# --- pkcs11 uri precedence ---

def test_pkcs11_default():
    assert s.resolve_pkcs11_uri({}, None, None) == s.DEFAULT_PKCS11_URI

def test_pkcs11_cli_wins():
    result = s.resolve_pkcs11_uri(
        {"piv": {"pkcs11_uri": "x"}}, {"pkcs11_uri": "y"}, "z")
    assert result == "z"


# --- CLI exit codes (help text is captured by pytest, not printed) ---

def test_help_exits_zero():
    assert run_main(["--help"]) == 0

def test_version_exits_zero():
    assert run_main(["--version"]) == 0

def test_no_args_exits_one():
    assert run_main([]) == 1


# --- init_config round trip (security-relevant: 0600 + overwrite guard) ---

def test_init_config_round_trip():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "sub", "config.toml")
        s.init_config(path, force=False)

        assert os.path.isfile(path)
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"

        cfg, loaded = s.load_config(path, required=True)
        assert loaded == path
        assert cfg["defaults"]["run_mode"] == "current"

        with pytest.raises(s.SundukError):
            s.init_config(path, force=False)

        # --force must overwrite
        s.init_config(path, force=True)
        assert os.path.isfile(path)


# --- cert / public-key match check (mirrors --doctor) -----------------------

def _openssl():
    """Locate openssl or skip the test if it's unavailable."""
    path = shutil.which("openssl")
    if not path:
        try:
            path = s.find_openssl({})
        except s.SundukError:
            path = None
    if not path or not os.path.isfile(path):
        pytest.skip("openssl not available")
    return path


def _gen_keypair(openssl, key_path):
    """Generate an RSA private key and return its canonical public PEM."""
    subprocess.run(
        [openssl, "genrsa", "-out", key_path, "2048"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
    )
    pub = key_path + ".pub"
    subprocess.run(
        [openssl, "pkey", "-in", key_path, "-pubout", "-out", pub],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
    )
    return pub


def _selfsigned_cert(openssl, key_path, cert_path):
    subprocess.run(
        [openssl, "req", "-x509", "-new", "-key", key_path,
         "-out", cert_path, "-days", "1", "-subj", "/CN=test/"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
    )


def test_openssl_pubkey_extracts():
    openssl = _openssl()
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "a.key")
        pub = _gen_keypair(openssl, key)
        out = s.openssl_pubkey(openssl, ["pkey", "-pubin", "-in", pub, "-pubout"])
        assert out is not None
        assert b"PUBLIC KEY" in out


def test_openssl_pubkey_returns_none_on_garbage():
    openssl = _openssl()
    with tempfile.TemporaryDirectory() as d:
        junk = os.path.join(d, "junk.pem")
        with open(junk, "w") as f:
            f.write("not a key\n")
        assert s.openssl_pubkey(openssl, ["pkey", "-pubin", "-in", junk, "-pubout"]) is None


def test_cert_matches_its_own_key():
    openssl = _openssl()
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "a.key")
        cert = os.path.join(d, "a_cert.pem")
        pub = _gen_keypair(openssl, key)
        _selfsigned_cert(openssl, key, cert)

        cert_pub = s.openssl_pubkey(openssl, ["x509", "-in", cert, "-pubkey", "-noout"])
        key_pub = s.openssl_pubkey(openssl, ["pkey", "-pubin", "-in", pub, "-pubout"])
        assert cert_pub is not None and key_pub is not None
        assert cert_pub == key_pub          # the --doctor "match" path


def test_cert_does_not_match_other_key():
    openssl = _openssl()
    with tempfile.TemporaryDirectory() as d:
        key_a = os.path.join(d, "a.key")
        key_b = os.path.join(d, "b.key")
        cert_a = os.path.join(d, "a_cert.pem")
        _gen_keypair(openssl, key_a)
        pub_b = _gen_keypair(openssl, key_b)
        _selfsigned_cert(openssl, key_a, cert_a)

        cert_pub = s.openssl_pubkey(openssl, ["x509", "-in", cert_a, "-pubkey", "-noout"])
        key_pub = s.openssl_pubkey(openssl, ["pkey", "-pubin", "-in", pub_b, "-pubout"])
        assert cert_pub is not None and key_pub is not None
        assert cert_pub != key_pub          # the --doctor "FAIL" path
