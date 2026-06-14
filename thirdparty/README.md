# Vendored Third-Party Sources

## curl-source

**Upstream:** https://github.com/curl/curl
**Pinned commit:** `75a2079d5` (tag `curl-8_11_1`)
**License:** curl (MIT/X-derivative)
**Vendored on:** 2026-06-11

Why vendored: the host distribution's `libcurl.so` is linked against the
*system* OpenSSL, so loading it would drag a SECOND OpenSSL (the host's
`libssl`/`libcrypto.so`) into every process that also uses our bundled static
OpenSSL 3.5.5 — two OpenSSL instances in one address space. The native signing
engine registers a custom OpenSSL provider (`librescrs`) in the bundled
OpenSSL's default `OSSL_LIB_CTX`; a second OpenSSL is a portability
inconsistency (macOS universal builds have no system OpenSSL at all) and a
latent hazard. We therefore build a minimal **static** `libcurl.a` against the
**bundled** OpenSSL (`thirdparty/openssl-3.5.5`), guaranteeing exactly ONE
OpenSSL per process on every platform. curl is reached only by the TSA / CRL /
OCSP / Trusted-List HTTP paths (B-T and higher); B-B detached signing never
calls it. Built via `ExternalProject_Add(curl_external)` in
`thirdparty/CMakeLists.txt` (HTTPS-only: no ldap/psl/ssh/nghttp2/brotli/zstd/
idn2); linked through the `curl_static_with_deps` INTERFACE target.

Update procedure:
```
cd thirdparty/curl-source
git fetch origin
git checkout <new-tag>     # e.g. curl-8_12_0
cd ../..
git add thirdparty/curl-source
# rebuild + verify: ldd libLibreSCRS_Signing.so shows NO system libssl/libcrypto/libcurl
```

## opensc-source

**Upstream:** https://github.com/OpenSC/OpenSC (canonical upstream)
**Pinned commit:** `bdab0aad1` on `srbeid-raw-signing` (LibreSCRS/OpenSC) — includes the merged srbeid PRs:
  - PR #3595 (commit `82d8fb895`): Serbian CardEdge driver introduction
  - PR #3662 (commit `28ace0595`): bound CardEdge dir entry count before allocation (Coverity CID 503167)
  - PR #3665 (commit `7d5d10ef3`): match by ATR whitelist, drop AID fallback (issue #3663)
  - PR #3701 (commit `bdab0aad1`): srbeid RSA-2048 raw signing + decryption — advertise
    PKCS#1 *and* raw RSA, pick the MSE algorithm byte from the requested flags, and only
    carry the first cryptogram byte in P2 for the 256-byte block (a smaller DigestInfo is
    sent as-is). Supersedes the earlier `1b2d5c5b9` which always split the first byte into
    P2, malforming the PSO APDU for non-256-byte raw-sign inputs.
  ... plus subsequent upstream OpenSC fixes folded in via the #3701 range.
**License:** LGPL-2.1
**Vendored on:** 2026-05-10 (re-pointed from LibreSCRS/OpenSC fork to upstream)

Why vendored: avoid runtime dependency on system OpenSC version; pin to the
specific commit where our merged srbeid CardEdge support lives so the bundled
`librescrs-opensc-pkcs11.so` always picks up rs-eid / PKS / RFZO via the
upstream srbeid driver irrespective of the host distribution's OpenSC age.

Update procedure:
```
cd thirdparty/opensc-source
git fetch origin
git checkout <new-sha>
cd ../..
git add thirdparty/opensc-source
# rebuild + run regression suite
```

PCSC: vendored OpenSC is built with `--enable-pcsc`; it owns its own PCSC
session per card it claims. The bundled `librescrs-opensc-pkcs11` module
runs alongside the in-tree LibreSCRS PKCS#15 module — each owns its own
PCSC connection to the card it claims, with the dispatcher in
`lib/pkcs11/` routing C_FindObjects/C_Sign requests to whichever module
asserts ownership of a given slot.

Disable: pass `-DLIBRESCRS_VENDOR_OPENSC=OFF` at configure time to skip the
~5-10 minute autoconf+make build (the resulting `librescrs-opensc-pkcs11`
fallback module will not be built either).
