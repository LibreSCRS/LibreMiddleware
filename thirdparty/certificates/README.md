# Bundled certificates

This directory bundles a curated set of Serbian PKI certificates used by
LibreMiddleware as a fallback trust store when no live Trusted List (TL)
is configured, or for issuers that are not (yet) listed in any TL.

## Authoritative source: Serbian TL

For document-signing trust the **authoritative source is the Serbian
Trusted List** at `https://www.mit.gov.rs/TrustedList/TSL-RS.xml`,
loaded eagerly by `NativeSigningService` when the application
configures a `TrustedListEntry` for it (LibreCelik does so by default).

Certificates that already appear in the Serbian TL by exact
SHA-256(DER) match are NOT shipped here, to avoid duplication and to
keep the trust surface in one place.

## What stays bundled

The remaining files cover three needs that the TL does not satisfy:

1. **Offline / no-TL operation** — when a deployment runs without a
   configured TL, `BundledCertsProvider` still supplies the chain
   anchors needed to verify Serbian eID, GEM, NAM and similar cards.
2. **Legacy issuers** — older MUP CA generations (e.g. the
   `Root CA MUP 001` line, MUPCA Root / Sluzbenici / Resursi v1+v2)
   that issued cards still in field use but are no longer tracked in
   the TL.
3. **Card / formatization roots not in TL** — e.g. `PKS CA Root`,
   `Sigurnosna formatizacija`, `Security Formatization Strong PCI`
   variants, used for card-side verification, not document signing.

## Subdirectories

- `rs-mup/` — Ministry of Interior CAs (eID document signers, root +
  intermediate CAs).
- `rs-mup-format/` — Card formatization / personalisation chain.
- `rs-pks/` — Privredna Komora Srbije (Serbian Chamber of Commerce, "PKS")
  root CA. Note: the Serbian TL lists only PKS intermediate CAs (Class 1,
  Cloud, TSA, QTSA, QSVA); the self-signed PKS CA Root that issues those
  intermediates is not in the TL, so it stays bundled.

When in doubt, prefer adding a TL configuration over bundling new
files here.
