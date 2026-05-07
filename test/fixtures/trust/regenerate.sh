#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Regenerate the signed synthetic TL fixture from the template + test key.
# Run after rotating the key/cert or editing the template.
#
# Hermetic: requires xmlsec1 (with openssl backend).
#   Arch:   pacman -S xmlsec
#   Debian: apt install xmlsec1
set -euo pipefail

cd "$(dirname "$0")"

TEMPLATE=synthetic-tl.template.xml
SIGNED=synthetic-tl.xml
KEY=test-tl-signing-key.pem
CERT=test-tl-signing-cert.pem

if ! command -v xmlsec1 >/dev/null 2>&1; then
    echo "error: xmlsec1 not found in PATH; cannot regenerate fixture" >&2
    exit 1
fi

# The KeyName "testkey" inside the template binds to the --privkey-pem:testkey
# argument; the named-key form is required because xmlsec1's signature template
# processor binds keys via KeyInfo descent.
xmlsec1 --sign \
    --privkey-pem:testkey "$KEY,$CERT" \
    --node-id TLSignature \
    --id-attr:Id "http://www.w3.org/2000/09/xmldsig#:Signature" \
    --output "$SIGNED" \
    "$TEMPLATE"

# Verify round-trip — the LM TlSignatureVerifier ignores KeyInfo and uses the
# caller-supplied cert; xmlsec1 needs key-data hints to bypass its internal
# KeyName lookup during verification.
xmlsec1 --verify \
    --trusted-pem "$CERT" \
    --enabled-key-data x509,key-name,rsa \
    --id-attr:Id "http://www.w3.org/2000/09/xmldsig#:Signature" \
    "$SIGNED"

echo "Regenerated $SIGNED"
