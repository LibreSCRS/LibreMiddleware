# LibreMiddleware Changelog

Notable user-visible changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/) loosely.

## [Unreleased] — 5.0.0

### Changed

- **The installed CMake package exports one target namespace, `LibreSCRS::`.**
  Up to 4.x the export carried `LibreMiddleware::` and the config file then
  mirrored every target under `LibreSCRS::` so a consumer could write either —
  while the mirror's own comment called `LibreSCRS::` the preferred spelling for
  new code. The preferred spelling is now the export and the mirror is gone.
  `LibreMiddleware` still names the package you ask `find_package` for; it no
  longer names the targets inside it. Consumers linking `LibreMiddleware::Auth`
  and friends must move to `LibreSCRS::Auth`; this is a major release and that
  is the window for it.

- **The PKCS#11 module is no longer registered with p11-kit, and no longer
  published as a release artefact.** One card should offer one provider, and it
  is the agent proxy shipped by the Linux host: the PIN is collected by a
  prompter behind an authorization prompt and a lease, and never enters the
  browser's address space. Shipping this module alongside it offered a second,
  weaker device for the same card and let the choice between two security
  models fall to whichever dialog a user happened to type into. The library is
  still built and installed; only the declaration is gone.
  `-DLIBREMIDDLEWARE_INSTALL_P11KIT_MODULE=ON` restores it for a headless host
  that runs no agent. The macOS replacement — an agent proxy of its own — is
  not in this release, so a macOS user who needs a PKCS#11 provider must build
  this module and register it explicitly.

  **Upgrading.** Three populations, and a package manager cleans only one of
  them. A *package* install heals itself: pacman, dpkg and rpm remove files
  that leave the manifest (derived, not measured — no `librescrs-*` package has
  ever been published, so that install base does not yet exist). A *source*
  install (`cmake --install`) does **not** heal: `install()` overwrites and
  never deletes. A *release-archive* install does not heal either, and it is
  the install base that actually exists, because the published archive is what
  created it — its instructions had you register the module by hand. Remove
  that registration:

  ```
  rm ~/.config/pkcs11/modules/librescrs.module
  ```

- **The PKCS#11 module is found on library directories that are not called
  `lib`.** The lookup spelled the library directory as a literal, so a build
  installing into `lib64` or a Debian multiarch triplet probed beside a
  directory that does not exist there and fell back to a bare name the loader
  could not resolve — signing then failed with an opaque engine error, after
  the PIN had already been collected.

### Added

- **A logging facade the consumer can redirect: `LibreSCRS::log`**
  (`<LibreSCRS/Logging.h>`). `init(sink, category)` installs a
  `std::function<void(Level, std::string_view)>` that receives every
  diagnostic LibreMiddleware emits without being asked; the built-in sink
  writes to `std::clog`. The four exception shields around consumer
  callbacks in `MonitorService` now report through it. Until now they called
  `std::fprintf(stderr, ...)` and the source said why — "a defense-in-depth
  fallback because the SDK does not currently inject a logger across the
  public ABI boundary". A library writing to a stream it does not own, with
  no way to redirect it, is a defect rather than a matter of taste, and this
  is the boundary that was missing. The shape is deliberately identical to
  the facade the LibreSCRS agent already ships, so one diagnostic grep reads
  the host layer and the core the same way.
  **Scope, stated so it is not mistaken for coverage:** only unconditional
  writers are routed here. Roughly 150 sites behind `LIBRESCRS_SIGN_TRACE`,
  `LIBRESCRS_PCSC_TRACE`, `LIBRESCRS_PROBE_TRACE`, `LIBRESCRS_OPENSC_DEBUG`
  and `PKCS11_DEBUG` still write to `stderr` directly; they sit in PC/SC
  transmit, PKCS#15 profile reading and the signing engine and are unchanged.
- **Buffer-based signing.** New `sign()` overload accepts an in-memory
  document as bytes and returns the signed document bytes directly, in
  addition to the existing file-based path. Suits callers that never
  touch the filesystem.
- **Document name on a signing request.** A request can now carry an
  explicit document name. It names the in-memory document on the
  buffer-based signing path — where there is no input file to derive a
  name from — and supplies the ASiC-E container entry name and the
  detached XAdES/JAdES reference basename. Only the final path component
  is kept, so a name can never introduce directory separators into a
  container. Without it, buffer-mode container signing had no name at
  all and ASiC-E packaging failed.
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
- **CSCA master-list import API.** New public `LibreSCRS::Trust`
  functions read an ICAO 9303-12 country-signing master list: verify the
  signed object and return the trust anchors it carries, compute the
  fingerprint that pins its publisher, and decide whether a new
  publisher chains to an anchor the previously trusted list already
  carried — the rule that lets a country's key rotation be followed
  without anyone re-pinning by hand. A host that imports master lists no
  longer needs an OpenSSL dependency and a certificate path builder of
  its own. A verified list also comes back with the certificate that
  signed it and, when the list carries one, the instant it was signed
  at, taken from the attribute the signature covers — so a host can put
  the rotation question and refuse a replayed older list without being
  handed, out of band, data that is already inside the file it just
  read.
- **Hosts can tell a plugin where their country-signing certificates
  are.** `CardPluginService::setCscaAnchorDirectory` publishes one
  directory to every plugin it loaded, and the eMRTD plugin judges a
  travel document's passive authentication against what is in it. The
  directory used to be named by an environment variable, which anything
  running as the person at the keyboard can set — so a forged document
  could be reported as chaining to a national authority. That read was
  removed in 5.0 and, until now, nothing replaced it: a host that really
  had imported country signing certificates was still told none were
  configured. Only the path is published; the certificates in it are
  read afresh at each document, so a list imported after startup takes
  effect on the next read. A host that publishes nothing keeps the
  honest "not configured" answer.
- **Arch Linux packaging.** A release-shaped `PKGBUILD` for
  `librescrs-middleware`.

### Changed

- **The shared objects' SONAME moved to `libLibreSCRS_<Component>.so.5`**
  (and `librescrs-pkcs11.so.5` with them). This release changes the
  in-memory shape of the public surface: four public types changed size,
  and the plugin base class's virtual table gained entries in the middle
  of itself rather than at the end. A program linked against a 4.x build
  cannot load a 5.x one, and the SONAME is what lets the dynamic loader
  say so instead of crashing later. The integer is deliberately **not**
  the release major — it is raised whenever the shape moves, in whatever
  release that happens to be — so packagers should read it off the
  artefact (`readelf -d … | grep SONAME`) rather than derive it from the
  version. The plugin ABI sentinel moves with it, to v9.
- **`SmProtocolRequest` gained a third alternative** (`ChipAuthRequest`,
  for eMRTD Chip Authentication). The extension is source-compatible —
  the variant is documented append-only — but it changes the C++
  mangling of `CardSession::activateChannelWithSm`, so binaries built
  against older headers must be rebuilt against this release. Source
  consumers (`find_package` / FetchContent) are unaffected. Its mangling
  is one of several shape changes this release; the SONAME entry above
  covers the rest.
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

- **PDFs carrying a leading wrapper are no longer refused up front.** The
  fail-fast input check demanded the `%PDF-` header at the very first
  byte, while the PAdES engine itself accepts it anywhere in the first
  1024 bytes — the tolerance Acrobat and friends apply to files wrapped
  by web-form uploads. Documents the engine can sign are no longer
  rejected before signing begins; both sides now read one shared window.
- **PACE-MRZ key derivation** now uses the full 20-byte SHA-1 of the MRZ
  information per BSI/ICAO, fixing PACE with MRZ-derived keys.
- **Cards already present at startup are reported.** Reader monitoring
  now signals cards that were inserted before monitoring began, not only
  those inserted afterwards.
- The PKCS#15 plugin manifest no longer **over-declares `IdentityData`**.
- Error paths are noexcept-safe and a PKCS#11 argument guard was added,
  hardening behaviour under allocation failure and bad arguments.

### Removed

- **The published macOS PKCS#11 archive.** The release no longer produces a
  macOS tarball of this module, and nothing replaces it inside this project.
  What was published was a *direct* module: it opened the card itself, took the
  PIN inside the loading application's address space, and its own instructions
  told the reader to click past Gatekeeper because the file was unsigned. Its
  replacement forwards to the agent instead, so the PIN is collected outside the
  browser and the file is signed rather than excused — and it ships with the
  macOS host, not from here.

  A macOS user whose provider disappears at upgrade reads this rather than
  discovering it: remove the module you registered by hand, and register the one
  the host installs. The Linux half of the same decision is the entry above.
- Malformed and expired MUP certificates were archived out of the active
  certificate bundle.
- **`CardPlugin::getPINTriesLeft()`** — the last deprecated entry point
  anywhere in the project. Its value has been available from
  `readCounters(session).retriesLeft` since the credential-lifecycle
  surface landed, and it had no caller left. (The PKCS#15 card class has
  an unrelated method of the same name; that one stays.)
- **`LIBRESCRS_DEPRECATED`** — the deprecation macro is gone from the
  public `include/LibreSCRS/Export.h`, since nothing is marked with it.
- **`PreReadAuthMethod::BacMrz` and `PreReadAuthMethod::PaceCan`** —
  renamed to `Mrz` and `Can`. The old spellings do not exist any more;
  the enumerators name the credential, not the protocol that consumes
  it.

No exported symbol disappeared with any of these: all four were inline
or header-only, which is precisely why the symbol snapshot could not see
them going. The shape baseline (`ci/abi/layout-baseline.txt`) is what
records their departure, and the SONAME moved with it.

- **`tools/migrate-3x-to-4.0.sh`** — an assistant for consumers moving an
  SDK integration from 3.x to 4.0. It shipped in the source archive, nothing
  in this project referenced it, and it still pointed at a documentation URL
  that no longer resolves. A major release is where the previous major's
  migration burden ends, not where it accumulates.
- **`LIBREMIDDLEWARE_HAS_SIGNING`** — a cache variable exported "for
  consumers"; no consumer, in this repository or any other, ever read it.
- **`LIBRESCRS_SIGNING_BACKEND` and `SIGNING_BACKEND=dss`.** An environment
  variable chose the signing implementation at run time, and one of the choices
  silently dropped TSA credentials and the `/ContactInfo` entry — guarded by two
  branches that refused loudly rather than fixing it. The project's own
  packaging scripts already called that backend deprecated while it stayed
  selectable. It remains buildable as the cross-verification oracle the native
  engine is checked against (`SIGNING_BACKEND=both`, `BUILD_DSS_ORACLE=ON`),
  which is what it is for, and stops being something a deployment can turn on by
  accident. `SIGNING_BACKEND=dss` — which used to build the DSS engine *instead
  of* the native one — is now a configure error rather than a build that
  compiles and then fails at the first signature.

- **Five public symbols nothing can reach.**
  `SecureChannel::ChannelOperationError` and
  `SigningResult::tsaUnreachableDiagnosticOnly()` have no producer inside this
  library, so no consumer could ever have been handed one;
  `LocalizedText::formattedDefault()`, `Auth::ErrorKeys::pinIncorrect()` and
  `Auth::ErrorKeys::pinBlocked()` have no caller in any of the seven
  repositories, and no translation carries their message keys.
  `pinIncorrectWithRetries()` — the one a card with a retry counter actually
  produces — stays. A public symbol can only be removed in a major release, so
  leaving these would have locked them in until the release after this one.
  The symbol and layout baselines are unchanged by their removal: all five are
  header-inline or a type, so neither gate ever recorded them. That is a fact
  about the gates, not evidence of safety.
- **Eleven internal helpers with a declaration, a definition and no third
  occurrence** — among them `berFindBytes`, `PdfValue::asReal`,
  `EIdCard::setCertificateFolderPath` and `TrustStoreInternalAccess::addProvider`.
  None appears in the ABI baseline, and that proves nothing about safety:
  they were never public. Removing the certificate-folder setter also
  removed the state only it could set and the branch that read that state,
  which would otherwise have been dead the moment the setter went.

## [4.2.0] — 2026-05-29

### Added

- **AET SafeSign QSCD signing.** The attestation-locked signing key on
  AET SafeSign cards is now unlocked automatically via the card's
  software-attestation prompt, so signing works out of the box.
- **Reader-list snapshot API.** `MonitorService` exposes a snapshot of
  the current reader list, and `CardDataAccess` gains convenience
  accessors for common field lookups.
- **CardSession same-thread re-entrancy guard.** Re-entrant `open()`
  on the thread that already holds a session fails fast instead of
  deadlocking.

### Changed

- **Cross-reader secure-messaging teardown** was remediated so an SM
  channel established on one reader can no longer leak APDUs onto a
  connection that was repurposed for another reader or applet.
- **Minimal public API surface.** The 4.2 review wave trimmed
  incidental exports and enforces the public-surface policy from CMake;
  internal OpenSSL/OpenSC/PC/SC/dlopen handles moved to RAII wrappers.
- **Vendored component licenses** (OpenSC, OpenSSL, Liberation Sans)
  are declared in the license bundle manifest.
- The vendored OpenSC build **no longer links GIO/GLib** (its notify
  backend is disabled), slimming packaging dependencies.

### Fixed

- The PKCS#15 plugin's SM-wrapped applet probe **rejects foreign
  passports** instead of misclaiming them.
- **Reader monitoring lifecycle hardening:** subscription bootstrap no
  longer races the initial poll, reader-list delivery is consistent,
  and the poll thread's PC/SC context is torn down on all exit paths.

## [4.1.0] — 2026-05-21

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

## [4.0.0-rc2] — 2026-05-09

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
