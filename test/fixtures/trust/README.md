# Hermetic Trusted-List test fixtures

This directory holds a synthetic ETSI Trusted-List XML, plus the test signing
key + cert that produced its XML-DSig, used by LibreMiddleware tests to
exercise the public `LibreSCRS::Signing::SigningService` trust-store wiring
end-to-end without touching the network.

## Files

| File | Purpose |
| --- | --- |
| `test-tl-signing-key.pem` | RSA-2048 private key. **Not a secret** — only used to sign the test fixture below. Never reused for real signatures. |
| `test-tl-signing-cert.pem` | Self-signed X.509 cert wrapping the public half of the key above. Doubles as the synthetic trust anchor inside `synthetic-tl.xml`. |
| `synthetic-tl.template.xml` | Unsigned TL XML template; carries one TSP service whose `X509Certificate` element is the (base64 DER of) the test cert. The `ds:Signature` element holds empty placeholders to be filled in by the signing tool. |
| `synthetic-tl.xml` | Signed TL XML produced from the template above. Frozen artefact — committed verbatim so tests are hermetic and don't require xmlsec1 at build time. Regenerate via `regenerate.sh` after rotating the key/cert or editing the template. |

## Why these are not secrets

The PEM key never signs anything except the synthetic fixture in this
directory. It cannot be used to forge a real Trusted List because:

- The cert's subject (`CN=LibreSCRS Test TL Signer`) does not match any pinned
  signing certificate in `pinned_tl_certs` and is not derived from any LOTL
  pointer in production paths.
- The fixture is loaded only via the `file://` branch of the TL-fetch path,
  which is gated by `TrustedListEntry::localFileOnly` (set internally only
  when the URL was synthesised from `TrustConfig::trustedListFile`). Public
  `TrustedListSource`s cannot reach the `file://` branch.

## Rotating the key

```bash
cd test/fixtures/trust   # from the LibreMiddleware repo root
openssl genrsa -out test-tl-signing-key.pem 2048
openssl req -x509 -new -key test-tl-signing-key.pem -days 36500 \
    -subj "/C=RS/CN=LibreSCRS Test TL Signer" \
    -out test-tl-signing-cert.pem
# Update the X509Certificate base64 inside synthetic-tl.template.xml to match
# the new cert (DER then base64), then:
./regenerate.sh
```

## Regenerating the signed fixture

`regenerate.sh` invokes `xmlsec1` (apt: `libxmlsec1-dev`, arch:
`xmlsec`) on the template + key to produce `synthetic-tl.xml`.
The result is then verified against the cert as a sanity check.

## Approach trade-off (2026-04)

The preferred approach is an in-tree C++ fixture generator (built at CMake
time when `BUILD_TESTING=ON`, regenerating the signed XML from the template +
key on every configure). That approach was deferred to a future iteration because
faithfully reproducing the verifier's reference-resolve / canonicalize
sequence in C++ pushed the fixture authoring time. The xmlsec1-based frozen
fixture below is the equivalent in functional terms — same digests, same
algorithm URIs, deterministic output — but pushes the regeneration cost to
key-rotation time rather than every build.
