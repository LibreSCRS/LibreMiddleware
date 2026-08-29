#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# softhsm-bootstrap.sh — provision an isolated SoftHSM2 token store so the
# SoftHSM-gated signing tests (CAdES/PAdES/JAdES/XAdES/ASiC-E,
# NativeSigningService, Pkcs11ModuleManager — see test/*_test.cpp
# findSoftHsmPath() / findSoftHsmTestSlot() call sites) actually run
# instead of GTEST_SKIP()-ing everywhere.
#
# This follows, exactly, the recipe already documented as comments in
# test/signing_test_support/signing_test_support.h (kSoftHsmTokenLabel,
# kSoftHsmExpiredKeyLabel): one token holding two self-signed RSA
# key+cert pairs.
#
#   - "test-token" (SO-PIN 0000, PIN 1234): the token label every test
#     looks up via findSoftHsmTestSlot(). The slot ID is intentionally
#     NOT assumed to be 0 anywhere downstream — SoftHSM2 >= 2.2
#     reassigns a freshly initialised token to a random slot.
#   - "test-key" / CKA_ID 01: a self-signed RSA leaf, valid 10 years.
#     Self-signed with no issuer on the token is deliberate — it keeps
#     the on-token chain at length 1, which the long-term revocation
#     gate treats as an unproven terminal.
#   - "expired-key" / CKA_ID 02: a second self-signed RSA leaf whose
#     notBefore AND notAfter both sit in the past, so the signer-expiry
#     policy can be exercised without waiting for a clock.
#
# A bare --keypairgen is NOT enough: every format module reads the
# signer certificate off the token, so both pairs need their
# certificate imported too, under the same CKA_ID as the key.
#
# Usage:
#   softhsm-bootstrap.sh [token-store-dir]
#
# token-store-dir defaults to /var/tmp/librescrs-softhsm. Refuses any
# path under /tmp: on this project's machines /tmp is tmpfs (RAM), and a
# token store is exactly the kind of build-adjacent state that must not
# live there.
#
# Idempotent: safe to run twice. The token and each key/cert object are
# probed individually before being (re)created, so a second run neither
# fails nor duplicates anything.
#
# On success, two lines are written to STDOUT (nothing else goes to
# stdout — all logging goes to stderr) so the caller can do either:
#   eval "$(ci/scripts/softhsm-bootstrap.sh)"
# or, under GitHub Actions, this script also appends the same two
# variables to $GITHUB_ENV directly when that file exists, so a plain
# `run: ci/scripts/softhsm-bootstrap.sh` step is enough.
#
# Exit codes:
#   0 - store ready (already existed, or freshly provisioned)
#   2 - a required tool (softhsm2-util / pkcs11-tool / openssl) is
#       missing, or no libsofthsm2.so could be found anywhere this
#       script knows to look — nothing was changed
#   3 - a softhsm2-util / pkcs11-tool invocation failed
set -euo pipefail

STORE_DIR="${1:-/var/tmp/librescrs-softhsm}"

TOKEN_LABEL="test-token"
SO_PIN="0000"
PIN="1234"
KEY_LABEL="test-key"
KEY_ID="01"
EXPIRED_LABEL="expired-key"
EXPIRED_ID="02"

log() { echo "softhsm-bootstrap: $*" >&2; }
fatal() {
    local code="$1"
    shift
    echo "softhsm-bootstrap: FATAL: $*" >&2
    exit "$code"
}

case "$STORE_DIR" in
    /tmp | /tmp/*)
        fatal 2 "refusing token store under $STORE_DIR — /tmp is tmpfs (RAM) here; pass a /var/tmp/... path instead"
        ;;
esac

# ---------------------------------------------------------------------------
# 0. Required tools. Fail loudly and specifically — a missing softhsm2-util
#    must never be mistaken for "tests correctly skipped".
# ---------------------------------------------------------------------------
for tool in softhsm2-util pkcs11-tool openssl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        fatal 2 "'$tool' not found on PATH. Install SoftHSM2 + OpenSC pkcs11-tool first:
  Arch/Manjaro : sudo pacman -S softhsm opensc
  Debian/Ubuntu: sudo apt-get install softhsm2 opensc
  macOS/brew   : brew install softhsm opensc"
    fi
done

# ---------------------------------------------------------------------------
# 1. Locate libsofthsm2.so. Honours the same SOFTHSM2_LIB override that
#    test/signing_test_support/signing_test_support.cpp::findSoftHsmPath()
#    already checks first (upstream pkcs11-tool/opensc convention), so a
#    module resolved here and one resolved by the test binary always agree.
#    Falls back to the same fixed path list the test support carries, plus
#    the Debian/Ubuntu multiarch layout (softhsm2 .deb installs there, and
#    it is not in the C++ fallback list), then ldconfig as a last resort.
# ---------------------------------------------------------------------------
find_softhsm_lib() {
    if [[ -n "${SOFTHSM2_LIB:-}" && -f "${SOFTHSM2_LIB}" ]]; then
        printf '%s' "$SOFTHSM2_LIB"
        return 0
    fi

    local candidates=(
        /usr/lib/softhsm/libsofthsm2.so
        /usr/lib64/softhsm/libsofthsm2.so
        /usr/local/lib/softhsm/libsofthsm2.so
        /opt/homebrew/lib/softhsm/libsofthsm2.so
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
        /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so
    )
    local c
    for c in "${candidates[@]}"; do
        if [[ -f "$c" ]]; then
            printf '%s' "$c"
            return 0
        fi
    done

    if command -v ldconfig >/dev/null 2>&1; then
        local via_ldconfig
        via_ldconfig="$(ldconfig -p 2>/dev/null | awk '/libsofthsm2\.so/ {print $NF; exit}')"
        if [[ -n "$via_ldconfig" && -f "$via_ldconfig" ]]; then
            printf '%s' "$via_ldconfig"
            return 0
        fi
    fi

    return 1
}

SOFTHSM_LIB="$(find_softhsm_lib)" || fatal 2 "softhsm2-util is on PATH but libsofthsm2.so could not be found anywhere (checked SOFTHSM2_LIB, the standard install paths, and ldconfig). Re-install the softhsm2 package or set SOFTHSM2_LIB explicitly."
log "using PKCS#11 module: $SOFTHSM_LIB"

# ---------------------------------------------------------------------------
# 2. Token store layout + softhsm2.conf. mkdir -p and rewriting the conf
#    file are both naturally idempotent.
# ---------------------------------------------------------------------------
mkdir -p "$STORE_DIR/tokens"
CONF_FILE="$STORE_DIR/softhsm2.conf"
cat >"$CONF_FILE" <<EOF
# Generated by ci/scripts/softhsm-bootstrap.sh — safe to regenerate.
directories.tokendir = $STORE_DIR/tokens
objectstore.backend = file
log.level = ERROR
EOF
export SOFTHSM2_CONF="$CONF_FILE"
log "SOFTHSM2_CONF=$SOFTHSM2_CONF"

# ---------------------------------------------------------------------------
# 3. Token: init only if a token with our label is not already present.
#    softhsm2-util --init-token --slot 0 does NOT keep the token pinned to
#    slot 0 (SoftHSM2 >= 2.2 reassigns it) — that is fine, every caller
#    downstream (findSoftHsmTestSlot, and this script) resolves the slot by
#    label, never by number.
# ---------------------------------------------------------------------------
if softhsm2-util --show-slots 2>/dev/null | grep -qE "Label:[[:space:]]+${TOKEN_LABEL}[[:space:]]*\$"; then
    log "token '$TOKEN_LABEL' already initialised, leaving it alone"
else
    log "initialising token '$TOKEN_LABEL'"
    softhsm2-util --init-token --slot 0 --label "$TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$PIN" >&2 \
        || fatal 3 "softhsm2-util --init-token failed"
fi

# ---------------------------------------------------------------------------
# 4. Key/cert pairs: probe each object individually before creating it, so a
#    partially-provisioned store (e.g. a previous run interrupted between the
#    two objects of a pair) is completed rather than re-run wholesale, and a
#    fully-provisioned store adds nothing on a second pass.
# ---------------------------------------------------------------------------
object_exists() {
    local type="$1" label="$2"
    pkcs11-tool --module "$SOFTHSM_LIB" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
        --list-objects --type "$type" 2>/dev/null | grep -qE "label:[[:space:]]+${label}\$"
}

WORKDIR="$(mktemp -d "$STORE_DIR/certgen.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

# Run an openssl sub-command, keeping its stderr for the failure message.
# Swallowing it (>/dev/null 2>&1) turns every failure into a bare "failed"
# with no reason, which is exactly how the -not_before flag below shipped
# green locally and died opaquely on the runner.
openssl_or_fatal() {
    local what="$1"
    shift
    if ! openssl "$@" >"$WORKDIR/openssl.out" 2>"$WORKDIR/openssl.err"; then
        fatal 3 "openssl $what failed: $(tr '\n' ' ' < "$WORKDIR/openssl.err" | head -c 400)"
    fi
}

# Self-sign a backdated certificate for an existing key.
#
# `openssl req -x509 -not_before/-not_after` would be the obvious way, but
# those flags arrived in OpenSSL 3.5 and the CI runner (Ubuntu 24.04) ships
# 3.0.13, where they are unknown options. `openssl ca -selfsign` with
# -startdate/-enddate has accepted explicit dates for far longer, so it is
# the single path used everywhere -- deliberately NOT behind a version
# probe, because a branch only one environment ever takes is a branch that
# drifts unnoticed.
selfsign_backdated() {
    local key_pem="$1" subject="$2" out_pem="$3" start="$4" end="$5"
    local csr="$WORKDIR/backdated.csr" cnf="$WORKDIR/backdated.cnf"

    cat > "$cnf" <<EOF
[ ca ]
default_ca = selfsign_ca

[ selfsign_ca ]
database       = $WORKDIR/index.txt
serial         = $WORKDIR/serial
new_certs_dir  = $WORKDIR
default_md     = sha256
policy         = any_policy
email_in_dn    = no
rand_serial    = no
unique_subject = no

[ any_policy ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
EOF
    : > "$WORKDIR/index.txt"
    echo 01 > "$WORKDIR/serial"

    openssl_or_fatal "req -new (backdated CSR)" \
        req -new -key "$key_pem" -subj "$subject" -out "$csr"
    openssl_or_fatal "ca -selfsign (backdated cert)" \
        ca -config "$cnf" -selfsign -keyfile "$key_pem" -in "$csr" \
           -out "$out_pem" -batch -notext -startdate "$start" -enddate "$end"
}

provision_pair() {
    local label="$1" id="$2" subject="$3" validity="$4"
    # validity: "current" -> valid 10 years from now
    #           "expired" -> notBefore AND notAfter both in the past
    local key_pem="$WORKDIR/$label-key.pem" cert_pem="$WORKDIR/$label-cert.pem"
    local key_der="$WORKDIR/$label-key.der" cert_der="$WORKDIR/$label-cert.der"

    local need_key=0 need_cert=0
    object_exists privkey "$label" || need_key=1
    object_exists cert "$label" || need_cert=1
    if [[ "$need_key" -eq 0 && "$need_cert" -eq 0 ]]; then
        log "pair '$label' (id $id) already present, skipping"
        return 0
    fi

    log "generating '$label' (id $id) key material"
    if [[ "$validity" == "expired" ]]; then
        openssl_or_fatal "genrsa for '$label'" \
            genrsa -out "$key_pem" 2048
        selfsign_backdated "$key_pem" "$subject" "$cert_pem" \
            20200101000000Z 20210101000000Z
    else
        openssl_or_fatal "req -x509 for '$label'" \
            req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
                -keyout "$key_pem" -out "$cert_pem" -subj "$subject"
    fi
    openssl_or_fatal "rsa (DER conversion) for '$label'" \
        rsa -in "$key_pem" -outform DER -out "$key_der"
    openssl_or_fatal "x509 (DER conversion) for '$label'" \
        x509 -in "$cert_pem" -outform DER -out "$cert_der"

    if [[ "$need_key" -eq 1 ]]; then
        log "importing '$label' private key (id $id)"
        pkcs11-tool --module "$SOFTHSM_LIB" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
            --write-object "$key_der" --type privkey --label "$label" --id "$id" >&2 \
            || fatal 3 "pkcs11-tool --write-object (privkey) failed for '$label'"
    fi
    if [[ "$need_cert" -eq 1 ]]; then
        log "importing '$label' certificate (id $id)"
        pkcs11-tool --module "$SOFTHSM_LIB" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
            --write-object "$cert_der" --type cert --label "$label" --id "$id" >&2 \
            || fatal 3 "pkcs11-tool --write-object (cert) failed for '$label'"
    fi
}

provision_pair "$KEY_LABEL" "$KEY_ID" "/CN=LibreSCRS SoftHSM Test Signer" current

provision_pair "$EXPIRED_LABEL" "$EXPIRED_ID" "/CN=LibreSCRS SoftHSM Expired Test Signer" expired

rm -rf "$WORKDIR"
trap - EXIT

log "SoftHSM2 store ready at $STORE_DIR"

# ---------------------------------------------------------------------------
# 5. Hand the two env vars to the caller. GITHUB_ENV first (CI convention
#    already used by release.yml in this repo), plain stdout export lines
#    always — a local `eval "$(...)"` works with or without GITHUB_ENV.
# ---------------------------------------------------------------------------
if [[ -n "${GITHUB_ENV:-}" ]]; then
    {
        echo "SOFTHSM2_CONF=$SOFTHSM2_CONF"
        echo "SOFTHSM2_LIB=$SOFTHSM_LIB"
    } >>"$GITHUB_ENV"
fi

echo "export SOFTHSM2_CONF=\"$SOFTHSM2_CONF\""
echo "export SOFTHSM2_LIB=\"$SOFTHSM_LIB\""
