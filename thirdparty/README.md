# Vendored Third-Party Sources

## opensc-source

**Upstream:** https://github.com/OpenSC/OpenSC (canonical upstream)
**Pinned commit:** `a7586e080` on `master` — includes the merged srbeid PRs:
  - PR #3595 (commit `82d8fb895`): Serbian CardEdge driver introduction
  - PR #3662 (commit `28ace0595`): bound CardEdge dir entry count before allocation (Coverity CID 503167)
  - PR #3665 (commit `7d5d10ef3`): match by ATR whitelist, drop AID fallback (issue #3663)
  ... plus subsequent post-merge fixes (`a7586e080` "Add new paths to pkcs11-register" et al).
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
