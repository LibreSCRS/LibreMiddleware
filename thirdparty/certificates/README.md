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

What is left covers two needs the TL does not satisfy:

1. **Offline / no-TL operation** — when a deployment runs without a
   configured TL, `BundledCertsProvider` still supplies the MUP chain
   anchors needed to verify Serbian eID certificate chains.
2. **Card-side roots not in TL** — the personalisation
   ("formatization") document signer, used to verify the card's
   document security object, not to verify signed documents.

`BundledCertsProvider` descends exactly one level below this directory:
every subdirectory listed below is walked, flat files directly in this
directory are loaded too, and nothing deeper or outside is looked at.

## Subdirectories

- `rs-mup/` — Ministry of Interior CAs: the self-signed root and the
  resource intermediate of each generation that issues cards still in
  field use (`MUPCA Root 3` / `MUPCA Resursi 3` from 2014, `MUP Root
  CA 4` / `MUP Resursi CA 4` from 2020).
- `rs-mup-format/` — card personalisation chain: the
  `StrongSecurityFormat` document signer issued by `MUPCA Resursi`
  (`StrongSecurityFormat_09`, notBefore 2021-08-05, notAfter
  2026-08-05). Its successor has to be added here once MUP publishes
  one; the earlier signers of this line are archived, see below.

This list is load-bearing: a test asserts that the subdirectories named
here and the subdirectories on disk are the same set, in both
directions. Adding or removing one means editing this section.

## Archived material

Earlier MUP CA generations, the superseded formatization signers, and
the unrelated Chamber of Commerce root are no longer bundled. They were
moved to the sibling directory `certificates-legacy/`. Most of them
cannot be loaded at all: their `serialNumber` uses non-minimal DER
INTEGER encoding, which OpenSSL 3.5+ rejects, so the trust-store
loaders skip them silently. The few that do parse are either expired
(`StrongSecurityFormat_06` / `_07` / `_08`) or outside the chains this
bundle anchors — the officials' branch intermediate `MUP Sluzbenici
CA 4`, which the eID document-signer path does not walk, and the
self-signed `PKS CA Root` of the Chamber of Commerce.

That directory is deliberately unreachable from the running code:

- it is not installed — the install rule copies `certificates/` only;
- it cannot be resolved at runtime — every rung of the resolver ends in
  a directory named `certificates` (env override, the two compile-time
  paths, the library-relative and executable-relative data roots), and
  the one-level descent described above never leaves the resolved
  directory, so a sibling of it is never read.

It is kept in-tree, rather than deleted, as the source material for a
future lenient-load remedy and for historical verification of documents
and cards issued under those generations. See
`../certificates-legacy/README.md`.

When in doubt, prefer adding a TL configuration over bundling new
files here.
