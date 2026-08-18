# certificates-legacy

Archived MUP certificates that are **not part of the active trust bundle** and are
**not installed** (only `thirdparty/certificates/` is installed and loaded).

They were moved here 2026-07-16 because none of them anchors anything the active
bundle needs to verify:

- **Malformed CAs / certs** — their `serialNumber` uses non-minimal DER INTEGER
  encoding, which OpenSSL 3.5+ rejects at load (`d2i_X509` → "illegal padding"); the
  trust-store loaders skip them silently. This is the known period when MUP issued
  structurally-invalid certificates (generation 1–2 roots/intermediates and the older
  "format" certs).
- **Expired document-signer leaves** — `StrongSecurityFormat_06/07/08` expired in
  2018/2019/2021 and can no longer anchor anything.
- **Well-formed but out of scope** — `MUPSluzbeniciCA4.cer` (`MUP Sluzbenici CA 4`,
  notAfter 2045) and `PKSCARoot.crt` (`PKS CA Root`, notAfter 2039) parse cleanly and
  are unexpired. They sit here because the eID document-signer path does not walk the
  officials' branch and the Chamber of Commerce root anchors nothing this bundle
  verifies — a scope decision, not a load failure.

They are kept in-tree (not deleted) as the **source material** for any future
lenient-load remedy that would restore verification of old-generation cards, and for
provenance. They must NOT be re-added to `thirdparty/certificates/` without such a
remedy.

Current-generation cards verify through the g4 hierarchy (`MUP Root CA 4` /
`MUP Resursi CA 4`, still in the active bundle); g3 (`MUPCA Root 3` / `MUPCA Resursi
3`) and the `StrongSecurityFormat_09` leaf (notAfter 2026-08-05) remain in the active
bundle too.
