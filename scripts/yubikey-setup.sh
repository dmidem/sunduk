#!/usr/bin/env bash
#
# yubikey-setup.sh — generate a YubiKey PIV key + certificate for Sunduk.
#
# Slot 9d, RSA2048, PIN policy "always", touch policy "always".
#
# WARNING
# -------
# This script GENERATES A NEW KEY in PIV slot 9d. That OVERWRITES anything
# already in slot 9d, IRRECOVERABLY. It does NOT touch other PIV slots, the
# device PIN/PUK/management key, or other applications (FIDO2, OpenPGP, OATH).
#
# This script is a convenience and is NOT extensively tested. If your YubiKey
# already holds important data or keys, prefer the manual, step-by-step setup
# in docs/yubikey-setup.md, or proceed only if you accept the risk. Losing a
# PIV key means any tokens encrypted to it become permanently unreadable.
#
# Env:
#   SUNDUK_DIR=...        output directory (default: ~/.config/sunduk)
#   SUNDUK_ASSUME_YES=1   skip the interactive confirmation (use with care)
#
# NO WARRANTY. Provided as-is under the project license (Apache-2.0 / MIT).
# You run this at your own risk and are responsible for your YubiKey.
set -euo pipefail

SLOT="9d"
ALGO="RSA2048"
CONFIG_DIR="${SUNDUK_DIR:-$HOME/.config/sunduk}"
PUBLIC_PEM="$CONFIG_DIR/yk1_piv_9d_public.pem"
CERT_PEM="$CONFIG_DIR/yk1_piv_9d_cert.pem"

REQUIRED_CMDS=(yubico-piv-tool openssl pkcs11-tool)

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*" >&2; }

# --- 0. warning + confirmation -----------------------------------------------

info "============================================================"
info " Sunduk YubiKey setup"
info ""
info " This GENERATES A NEW KEY in PIV slot $SLOT and OVERWRITES"
info " anything already there, IRRECOVERABLY."
info ""
info " It does NOT touch other PIV slots, the device PIN/PUK/"
info " management key, or other apps (FIDO2, OpenPGP, OATH)."
info ""
info " This script is NOT extensively tested. If your YubiKey holds"
info " important keys/data, read the script and run the steps"
info " yourself, or use another method you trust."
info "============================================================"
info ""

if [ ! -t 0 ]; then
  die "no interactive terminal; this script requires manual confirmation"
fi

info "Type exactly:  yes I accept the risk"
printf 'to generate a new key in slot %s (this overwrites it): ' "$SLOT" >&2
read -r answer
[ "$answer" = "yes I accept the risk" ] || die "cancelled"

# --- 1. prerequisites ---------------------------------------------------------

info ">>> Checking prerequisites"

missing=()
for cmd in "${REQUIRED_CMDS[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done

if [ "${#missing[@]}" -ne 0 ]; then
  die "missing tools: ${missing[*]}
Install on Debian/Ubuntu:
  sudo apt update
  sudo apt install yubico-piv-tool openssl opensc pcscd libengine-pkcs11-openssl
  sudo systemctl enable --now pcscd"
fi

# pcscd must be reachable for the YubiKey to be seen
if command -v systemctl >/dev/null 2>&1; then
  if ! systemctl is-active --quiet pcscd.service \
     && ! systemctl is-active --quiet pcscd.socket; then
    die "pcscd is not active; run: sudo systemctl enable --now pcscd.socket"
  fi
fi

if ! yubico-piv-tool -a status >/dev/null 2>&1; then
  die "no YubiKey detected; insert the YubiKey and ensure pcscd is running"
fi

# Refuse to guess which device if several PIV readers are present.
reader_count="$(yubico-piv-tool -a list-readers 2>/dev/null | grep -c . || true)"
if [ "${reader_count:-0}" -gt 1 ]; then
  die "multiple smart-card readers detected ($reader_count).
Refusing to guess which YubiKey to write to.
Leave only the target YubiKey connected, then re-run."
fi

info "OK   tools present and a single YubiKey detected"

# --- 2. refuse to overwrite ---------------------------------------------------

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if [ -e "$PUBLIC_PEM" ] || [ -e "$CERT_PEM" ]; then
  die "output files already exist in $CONFIG_DIR:
  $( [ -e "$PUBLIC_PEM" ] && echo "$PUBLIC_PEM" )
  $( [ -e "$CERT_PEM" ]   && echo "$CERT_PEM" )
Remove or back them up first; this script will not overwrite them."
fi

# Detect an existing cert OR key in slot 9d. The certificate check alone is not
# enough: a slot can hold a private key without a certificate.
status="$(yubico-piv-tool -a status 2>/dev/null || true)"

if yubico-piv-tool -s "$SLOT" -a read-certificate >/dev/null 2>&1; then
  die "YubiKey slot $SLOT already contains a CERTIFICATE.
Refusing to overwrite. Use a different slot, or reset slot $SLOT deliberately
if you are sure (see docs/yubikey-setup.md)."
fi

# `status` prints a "Slot 9d:" stanza when a key is present. Be conservative:
# if we see the slot mentioned at all, stop and let the user check manually.
if printf '%s\n' "$status" | grep -qiE "slot[^0-9a-f]*${SLOT}\b"; then
  die "YubiKey slot $SLOT appears to already hold a key.
Refusing to overwrite an existing key. Inspect with:
  yubico-piv-tool -a status
and proceed manually if you are sure (see docs/yubikey-setup.md)."
fi

# --- 3. generate the PIV key on the YubiKey -----------------------------------

# Track whether the on-device key was created, so the trap can give a useful
# recovery hint if a later step fails mid-way.
KEY_GENERATED=0
cleanup() {
  local rc=$?
  [ -n "${TMP:-}" ] && rm -rf "$TMP"
  if [ "$rc" -ne 0 ] && [ "$KEY_GENERATED" -eq 1 ]; then
    info ""
    info "NOTE: a key was generated in slot $SLOT but setup did not finish."
    info "The on-disk PEM files (if present) are valid. To retry only the"
    info "certificate import once it exists:"
    info "  yubico-piv-tool -s $SLOT -a import-certificate -i \"$CERT_PEM\""
  fi
}
trap cleanup EXIT

info ">>> Generating PIV key in slot $SLOT ($ALGO, pin-policy=always, touch-policy=always)"
info "    You may be prompted for the PIV management key."

yubico-piv-tool \
  -s "$SLOT" \
  -a generate \
  -A "$ALGO" \
  --pin-policy=always \
  --touch-policy=always \
  -o "$PUBLIC_PEM"

KEY_GENERATED=1
chmod 644 "$PUBLIC_PEM"
info "OK   public key written: $PUBLIC_PEM"

# --- 4. build the certificate (forcing the YubiKey public key) ----------------

info ">>> Building certificate"

TMP="$(mktemp -d)"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$TMP/ca.key" -out "$TMP/ca.crt" \
  -days 3650 -subj "/CN=local-sunduk-ca/" >/dev/null 2>&1

openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$TMP/dummy.key" -out "$TMP/dummy.csr" \
  -subj "/CN=sunduk-piv-9d-token-decryption/" >/dev/null 2>&1

cat > "$TMP/ext.cnf" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,keyEncipherment,dataEncipherment
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req \
  -in "$TMP/dummy.csr" \
  -CA "$TMP/ca.crt" -CAkey "$TMP/ca.key" -CAcreateserial \
  -out "$CERT_PEM" \
  -days 3650 -sha256 \
  -force_pubkey "$PUBLIC_PEM" \
  -extfile "$TMP/ext.cnf" >/dev/null 2>&1

chmod 644 "$CERT_PEM"
info "OK   certificate written: $CERT_PEM"

# --- 5. import the certificate into the YubiKey -------------------------------

info ">>> Importing certificate into YubiKey slot $SLOT"
info "    You may be prompted for the PIV management key."

yubico-piv-tool \
  -s "$SLOT" \
  -a import-certificate \
  -i "$CERT_PEM"

info "OK   certificate imported into slot $SLOT"

# --- done ---------------------------------------------------------------------

trap - EXIT
rm -rf "$TMP"

info ""
info "Done. Next steps:"
info "  sunduk --init-config"
info "  sunduk --doctor"
info "  sunduk --encrypt-token gh"
info "  sunduk gh api user"
