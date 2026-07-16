# certificates-legacy

Archived MUP certificates that are **not part of the active trust bundle** and are
**not installed** (only `thirdparty/certificates/` is installed and loaded).

They were moved here 2026-07-16 because they contribute nothing to the loaded store:

- **Malformed CAs / certs** — their `serialNumber` uses non-minimal DER INTEGER
  encoding, which OpenSSL 3.5+ rejects at load (`d2i_X509` → "illegal padding"); the
  trust-store loaders skip them silently. This is the known period when MUP issued
  structurally-invalid certificates (generations 1–3 roots/intermediates, older
  "format" certs, and the unrelated PKS Chamber-of-Commerce root).
- **Expired document-signer leaves** — `StrongSecurityFormat_06/07/08` expired in
  2018/2019/2021 and can no longer anchor anything.

They are kept in-tree (not deleted) as the **source material** for any future
lenient-load remedy that would restore verification of old-generation cards, and for
provenance. They must NOT be re-added to `thirdparty/certificates/` without such a
remedy.

Current-generation cards verify through the g4 hierarchy (`MUP Root CA 4` /
`MUP Resursi CA 4`, still in the active bundle); g3 (`MUPCA Root 3` / `MUPCA Resursi
3`) and the still-valid `StrongSecurityFormat_09` leaf remain in the active bundle too.
