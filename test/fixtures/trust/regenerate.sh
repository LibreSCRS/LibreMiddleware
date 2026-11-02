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

# Two references to SchemeInformation by Id, one with the enveloped-signature
# transform and one without, and one to the list itself by Id.
SI_ID="http://uri.etsi.org/02231/v2#:SchemeInformation"
TSL_ID="http://uri.etsi.org/02231/v2#:TrustServiceStatusList"
xmlsec1 --sign \
    --privkey-pem:testkey "$KEY,$CERT" \
    --node-id TLSignature \
    --id-attr:Id "http://www.w3.org/2000/09/xmldsig#:Signature" \
    --id-attr:Id "$SI_ID" \
    --id-attr:Id "$TSL_ID" \
    --output two-reference-tl.xml \
    two-reference-tl.template.xml
xmlsec1 --verify \
    --trusted-pem "$CERT" \
    --enabled-key-data x509,key-name,rsa \
    --id-attr:Id "http://www.w3.org/2000/09/xmldsig#:Signature" \
    --id-attr:Id "$SI_ID" \
    --id-attr:Id "$TSL_ID" \
    two-reference-tl.xml

echo "Regenerated two-reference-tl.xml"

# One reference, to SchemeInformation only: a valid signature that leaves the
# rest of the list unsigned.
xmlsec1 --sign \
    --privkey-pem:testkey "$KEY,$CERT" \
    --node-id TLSignature \
    --id-attr:Id "http://www.w3.org/2000/09/xmldsig#:Signature" \
    --id-attr:Id "$SI_ID" \
    --output scheme-only-tl.xml \
    scheme-only-tl.template.xml
xmlsec1 --verify \
    --trusted-pem "$CERT" \
    --enabled-key-data x509,key-name,rsa \
    --id-attr:Id "http://www.w3.org/2000/09/xmldsig#:Signature" \
    --id-attr:Id "$SI_ID" \
    scheme-only-tl.xml

echo "Regenerated scheme-only-tl.xml"

# The same list with a NextUpdate in the past.
xmlsec1 --sign \
    --privkey-pem:testkey "$KEY,$CERT" \
    --node-id TLSignature \
    --id-attr:Id "http://www.w3.org/2000/09/xmldsig#:Signature" \
    --output stale-tl.xml \
    stale-tl.template.xml
echo "Regenerated stale-tl.xml"

# The same list with its one service a qualified time-stamping service.
xmlsec1 --sign \
    --privkey-pem:testkey "$KEY,$CERT" \
    --node-id TLSignature \
    --id-attr:Id "http://www.w3.org/2000/09/xmldsig#:Signature" \
    --output tsa-tl.xml \
    tsa-tl.template.xml
xmlsec1 --verify \
    --trusted-pem "$CERT" \
    --enabled-key-data x509,key-name,rsa \
    --id-attr:Id "http://www.w3.org/2000/09/xmldsig#:Signature" \
    tsa-tl.xml
echo "Regenerated tsa-tl.xml"
