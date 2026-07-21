# LibreMiddleware Changelog

Notable user-visible changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/) loosely.

## [Unreleased] — 4.3.0

### Added

- **Buffer-based signing.** New `sign()` overload accepts an in-memory
  document as bytes and returns the signed document bytes directly, in
  addition to the existing file-based path. Suits callers that never
  touch the filesystem.
- **AdES long-term signature levels.** B-T (timestamped), B-LT and
  B-LTA (long-term / archival validation material) are produced by
  composing the certificate chain from the Trusted List, extending the
  prior B-B baseline profile.
- **Uniform credential activation across plugins.** Cards protected by a
  Card Access Number (CAN) — such as the contactless NAM vehicle card —
  now share a single credential-activation architecture, so the CAN is
  supplied the same way regardless of plugin.
- **On-card SHA-256 RSA signing** for hash-on-card IAS-ECC cards that
  compute the digest on the card rather than accepting a pre-hashed
  value.
- **On-card RSA decipher** over a single-session libopensc bridge.
- **CKA_ID key selection** for PKCS#11 signing, so a specific key can be
  targeted by its identifier when a card exposes several.
- **`eid-sod-verify` diagnostic tool.** A standalone PC/SC utility that
  independently reads and verifies the eID Security Object (SOD),
  useful for troubleshooting card trust outside the signing path.
- **Arch Linux packaging.** A release-shaped `PKGBUILD` for
  `librescrs-middleware`.

### Changed

- **Invalid input documents fail fast.** Malformed or unsupported input
  documents now surface a distinct `InvalidDocument` outcome instead of
  a generic failure, letting callers tell a bad input apart from a
  signing error.
- **eID SOD signer is pinned** to the MUP document-signer domain,
  rejecting Security Objects signed outside the expected issuer domain.
- **Long-term signing path hardened** — fail-closed behaviour and
  SSRF-resistant fetching when gathering B-LT/B-LTA validation material.
- Signing now **warns when a PKCS#11 module is resolved by bare name**
  rather than an absolute path, flagging a fragile module lookup.

### Fixed

- **PACE-MRZ key derivation** now uses the full 20-byte SHA-1 of the MRZ
  information per BSI/ICAO, fixing PACE with MRZ-derived keys.
- **Cards already present at startup are reported.** Reader monitoring
  now signals cards that were inserted before monitoring began, not only
  those inserted afterwards.
- The PKCS#15 plugin manifest no longer **over-declares `IdentityData`**.
- Error paths are noexcept-safe and a PKCS#11 argument guard was added,
  hardening behaviour under allocation failure and bad arguments.

### Removed

- Malformed and expired MUP certificates were archived out of the active
  certificate bundle.

## [Unreleased] — 4.1.0

### Added

- **PKCS#11 multi-PIN support.** Cards with multiple PIN gates (e.g.
  dual-PIN eID profiles with separate Authentication and Signing (QSCD)
  PINs) now expose each PIN as a distinct PKCS#11 slot. Per-slot
  login state isolates Authentication from Signing without forcing
  a single shared PIN. `C_GetSlotList` returns one slot per
  (card × PIN); single-PIN cards (rs-eid Apollo, plain PKCS#15,
  PIV) keep their single-slot shape unchanged.
- **`PKCS11Card` + `PKCS11Slot` two-tier abstraction** (mirrors
  OpenSC `sc_pkcs11_card` / `sc_pkcs11_slot`). `PKCS11Slot` owns
  per-PIN `mechanisms`, `enumerateObjects`, `signData`,
  `signWithDigestInfo`, `signatureSize`, `isLoggedIn`. Stable
  PKCS#11 slot IDs are derived via FNV-1a over
  `(reader name, PIN id, slot kind)` so the same card in the same
  reader always yields the same slot IDs.
- **Inline RESET-recovery retry-once** via `PKCS11Card::handleReset()`
  in the `C_Sign` / `C_SignFinal` paths, restoring legacy parity
  for transient PCSC `SCARD_W_RESET_CARD` faults.

### Changed

- **PKCS#11 internals refactored.** Legacy
  `smartcard::PKCS11CardProvider` interface and `SlotEntry` struct
  removed; replaced by
  `LibreSCRS::Pkcs11::Internal::PKCS11CardProvider` whose `probe()`
  returns bound `PKCS11Card` instances. C entry points reroute
  through `findSlot(slotID) → PKCS11Slot` virtual dispatch.
- **Per-slot object cache + global object handle map.** Cache is
  invalidated on both `C_Login` and `C_Logout` for symmetric
  private-object visibility on entry to and exit from the
  logged-in state.

## [Unreleased] — 4.0.0-rc2

### Added

- **Visual signature FILL_BOX layout API.** New public function
  `LibreSCRS::Signing::layoutVisualSignature(textUtf8, box)` returns
  a `VisualSignatureLayout` with auto-fit `fontSize`, `lineHeight`,
  wrapped `lines`, and a `clipped` flag. Single source of truth for
  PAdES native engine and GUI preview surfaces (LibreCelik,
  LibreMac, future LibreKDE) — preview now matches the signed PDF
  exactly. New header
  `<LibreSCRS/Signing/VisualSignatureLayout.h>`.
- **Embedded appearance-font accessor.**
  `LibreSCRS::Signing::embeddedAppearanceFontData()` returns the raw
  bytes of the bundled Liberation Sans Regular TTF as
  `std::span<const std::byte>`. GUI consumers register these bytes
  with their font system to render preview-mode appearance text in
  the same font as the embedded PDF subset.
- Standalone Qt-free example at
  `examples/visual_signature_layout/` demonstrating the layout API.
- Developer guide at
  `docs/dev-guide/visual-signature-layout-{en,sr-Cyrl,sr-Latn}.md`
  (will hand-port to the LibreSCRS.github.io Hugo site).

### Changed

- **Visual signature appearance bytes differ from 4.0.0-rc1.** The
  PAdES native emitter now auto-fits the appearance text to the
  annotation rectangle (FILL_BOX semantics) rather than emitting at
  a fixed 9 pt with no wrap. Both font size and line count are
  computed from the text + box. PDFs signed with rc1 are not
  byte-identical to PDFs signed with rc2 for the same input — this
  is by design and resolves the rc1 symptom of cert-serial overflow
  silently clipping past the annotation right edge.
- The PAdES emitter writes a `q ... re W n ... Q` clipping path
  when the layout reports `clipped == true`, so PDF viewers crop
  cleanly at the annotation rectangle.

### Removed

- Internal constants `kAppearanceFontSize`, `kAppearanceLineHeight`,
  `kAppearanceLeftMargin` in `lib/libresign/src/native/pades_module.cpp`.
  Replaced by the public sentinels in
  `<LibreSCRS/Signing/VisualSignatureLayout.h>`. Internal-only — no
  consumer impact.
