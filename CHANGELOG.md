# LibreMiddleware Changelog

Notable user-visible changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/) loosely.

## [Unreleased] — 5.0.0

### Added

- **Every release carries a source tarball this project built**, cosigned and
  listed in the signed `SHA256SUMS` manifest like every other asset — so the
  manifest a release publishes is larger than it was. The Arch recipe fetches
  that asset instead of the archive GitHub generates for a tag: the generated
  one omits every submodule tree, and its bytes are not ours to assert, so the
  recipe's `sha256sums` line said nothing about what was actually built. The
  published tarball is a function of the commit — every member carries the
  commit's own timestamp, owner `0/0` and a mode no umask can widen — so a
  packager who rebuilds it gets the same bytes back, up to the gzip
  implementation. It is named so that one file can serve as the `.orig` for
  `dpkg-source`; the `deb` and `rpm` builds still build from the checkout and
  do not consume it yet.

- **Debian and RPM packages, built by the project.** `deb` packages for Debian
  13 and Ubuntu 26.04 LTS and `rpm` packages for Fedora 43, built in the target
  distribution's own container and installed with one command. The middleware
  ships as four packages: the runtime libraries, the card plugins, the
  development files, and an architecture-independent package holding nothing but
  the p11-kit registration file — which is what lets a machine choose between
  the direct PKCS#11 module and the agent proxy without ending up with two
  providers for one card.

  **Each published file names the distribution it was built for.** Release
  assets are `<package>.<distribution>.<deb|rpm>`: the runtime library package
  arrives as `liblibrescrs5_5.0.0-1_amd64.debian13.deb`, not as
  `liblibrescrs5_5.0.0-1_amd64.deb`. The source changelog carries no
  distribution suffix, so Debian 13 and Ubuntu 26.04 build byte-different files
  under identical names; without the slug one of the two would quietly replace
  the other on the release, with nothing afterwards to say which one survived.
  A consumer fetching packages from a release therefore has to match on that
  slug rather than on the extension alone.

  **Which distributions, and why not the others.** The bundled OpenSSL archive
  contains x86_64 objects only and references symbols that appear in glibc 2.38,
  so Debian 12 and every Ubuntu up to and including 24.04 LTS cannot link these
  binaries at all, and neither can any `arm64` target. Fedora 42 and older ship
  sdbus-c++ 1.5, below the 2.0 the agent requires. Excluding Ubuntu 24.04 LTS is
  a product decision rather than a technicality: it is the largest installed
  base left out.

  **The cryptography is bundled and a bill of materials ships with every
  artefact.** OpenSSL, curl and OpenSC are linked in statically, so a CVE in any
  of them is invisible to every distribution security tracker and every
  container scanner — nothing in the packaging metadata says which versions are
  inside. The SBOM published beside each artefact is the only place they are
  named. These packages are therefore not candidates for the Debian or Fedora
  archives, and `packaging/README-bundling.md` says so in the repository rather
  than hiding it behind lint overrides.

  **There is no update channel.** These packages and the source tarball are
  release assets: a `.deb` or `.rpm` downloaded from a release page never updates
  itself, and no APT, DNF, AUR, Flathub or Homebrew repository serves them. With
  OpenSSL, curl and OpenSC linked in statically, a security fix in any of them is
  a new release and nothing on an installed machine will say so. Watch the
  releases page, or the repository's release feed, and re-download.

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
  targeted by its identifier when a card exposes several. Both public
  `libresign::Pkcs11Token` constructors gained a `std::vector<uint8_t>
  const&` `keyId` parameter carrying it.
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
  directory used to be named by the `LIBRESCRS_CSCA_STORE` environment
  variable, which anything running as the person at the keyboard can
  set — so a forged document could be reported as chaining to a
  national authority. That read was removed in 5.0 and, until now,
  nothing replaced it: a host that really
  had imported country signing certificates was still told none were
  configured. Only the path is published; the certificates in it are
  read afresh at each document, so a list imported after startup takes
  effect on the next read. A host that publishes nothing keeps the
  honest "not configured" answer.
- **Arch Linux packaging.** A release-shaped `PKGBUILD` for
  `librescrs-middleware`.
- **Four new public headers**: `ActivationProfile.h` (the declarative
  channel-activation descriptor plugins publish), `CredentialCounters.h`
  (per-credential retry/use counters), `PinOutcome.h` (the shared
  verify/change/unblock outcome classifier), and `SessionKey.h` (the
  per-session state-map key plugins use to avoid raw-pointer keying).
  Alongside them, ten new public enum values: the new `DecipherMechanism`,
  `DecipherResultOutcome`, `MasterListError`, `PinKind`, `PinState`,
  `PinRecovery` and `UnblockStyle` enums, plus three enumerators appended to
  existing enums — `ChannelActivationError::PaceDowngradeDetected`,
  `PINResultOutcome::KeyActivationFailed` and `SignMechanism::RSA_SHA256`.

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
  version. The plugin ABI sentinel moves with it, from 6 to v9.
- **`SmProtocolRequest` gained a third alternative** (`ChipAuthRequest`,
  for eMRTD Chip Authentication). The extension is source-compatible —
  the variant is documented append-only — but it changes the C++
  mangling of `CardSession::activateChannelWithSm`, so binaries built
  against older headers must be rebuilt against this release. Source
  consumers (`find_package` / FetchContent) are unaffected. Its mangling
  is one of several shape changes this release; the SONAME entry above
  covers the rest.
- **`Internal::changeReferenceData` gained a fourth parameter** (`p1`,
  defaulting to the ordinary-change value) so transport-PIN activation can
  pass an explicit P1. Internal, not part of the installed headers, but
  another of the shape changes the SONAME move above covers.
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

- **A signature no longer breaks another signature that is already running.**
  Each signing call owned its own PKCS#11 module manager, and nothing counted
  the module across them: the manager whose `C_Initialize` had returned first
  called `C_Finalize` when its call returned, and every PKCS#11 call the other
  one still had to make then failed with `CKR_CRYPTOKI_NOT_INITIALIZED`. The
  signature was reported as an engine error, with nothing in the message to
  suggest that finishing one signature had broken the other.

  A module is now shared by every user of it in the process and finalised only
  after the last of them has let go. Two cases had to be closed, not one: two
  users at the same time, and a user arriving while the previous one's module is
  being finalised — a window a few instructions wide that the first half of the
  fix left open. A module being released now stays listed as such, present but
  spent, for as long as the finalise takes; that finalise runs without holding
  the registry that hands modules out, because it can wait on the card. A call
  arriving in that window therefore finds the module accounted for and waits for
  it — with a time limit, after which that one signature is refused rather than
  held open — instead of loading a second copy underneath the first.

- **PACE key material is zeroed when it is released again.** The ephemeral
  private keys, the x-coordinate of the ECDH shared secret and the decrypted
  nonce exist only as OpenSSL `BIGNUM`s, and their deleter had stopped wiping
  the limb buffer before handing it back — so those bytes stayed readable in a
  core dump, in swap, or in the next allocation of that size. The deleter
  cleanses again, and the behaviour is probed rather than asserted in a comment:
  `test/LibreSCRS_OpenSslPtrTests.cpp` reads the released heap back for the
  pattern the `BIGNUM` held, against a plain `BN_free` control that says whether
  this allocator returns the chunk at all. Restores hardening that shipped in
  4.1.0.
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

- **The published macOS PKCS#11 archive.** The release no longer produces the
  `librescrs-pkcs11-*-macos-universal.zip` this module used to ship as, and
  nothing replaces it inside this project. (The Linux
  `librescrs-pkcs11-*-linux-x86_64.tar.gz` stopped publishing in the same
  release — see the entry above.) What was published was a *direct* module:
  it opened the card itself, took the PIN inside the loading application's
  address space, and its own instructions
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

### Security

- **The three statically bundled dependencies move to current releases:
  OpenSSL 3.5.8, curl 8.22.0 and miniz 3.1.2.** These are linked in, so a
  published vulnerability in any of them reaches this project without appearing
  in any distribution's security tracker — which is why the bill of materials
  ships beside every artefact and why this entry exists. What the three close, in
  terms of what this code actually reaches: two of the OpenSSL fixes are on paths
  driven by bytes nothing has authenticated — a heap overflow converting a
  multi-byte ASN.1 string, which happens for every certificate string read off a
  card, and a null dereference on a delta certificate revocation list with no
  list number, which happens on a body fetched over the network. The
  use-after-free in the PKCS#7 verification path is in the same release; it frees
  a buffer this project never passes, so it is fixed rather than reached here.
  curl 8.22.0 clears every published
  advisory affecting the previous pin, two of which are reachable from an
  HTTPS-only client that reuses one handle with client certificates — the shape
  the timestamp, revocation and trusted-list fetches have. miniz 3.1.2 restores
  a guard against an endless loop in the inflate path and replaces a
  central-directory bounds check that an archive could pass by overflowing it;
  that decoder reads the container a user drags into the signing wizard. A
  release cannot carry a partial move: the provenance check reads each bundled
  archive's own build stamp back and refuses a set where one platform's is
  older than the record claims.
- **A container or a card could make the reader allocate whatever it declared.**
  Two paths reserved a declared size before anything had authenticated the
  source. On the container path — the public re-signing entry point, reached by
  dragging a file into the wizard — a few hundred bytes declaring a
  multi-gigabyte entry reached the allocator, and the entry read first was the
  one with no ceiling on it at all. Every extraction now goes through one capped
  reader, and a container whose entry exceeds the ceiling is refused by name
  rather than quietly signed as if it were a new document.
- **A card could set a PIN length the encoding did not carry.** The directory
  parser accumulated an integer wider than the accumulator and then narrowed the
  result to the field it fed, so a card declaring 2^64 + 8 produced a minimum PIN
  length of eight and one declaring 2^32 + 5 produced five. Both widths are
  refused now, at the point where each one is.
- **A long-term signature could pass with no revocation evidence at all.** On a
  card with no Trusted List configured, the on-token certificate fallback
  returned every object with the signer moved to the front, and the revocation
  gate unconditionally exempted the last element of the chain — so the two
  together produced zero revocation evidence and reported zero gaps. A verdict
  4.2 reported as passing could not be relied on. Both halves are fixed: the
  fallback no longer reorders, and the exemption now applies only to a
  self-signed anchor.
- **An eMRTD authenticity badge could read PASSED from the SOD signature
  alone.** The document-signer chain check sat at NOT_PERFORMED while the badge
  already said the document was authentically issued — a verdict 4.2 reported as
  passing could not be relied on. The badge now requires both, and reports the
  chain state separately. Verified against a real document.
- **The expired-signer policy did not run on the append-signer path.** `sign()`
  routes an already-signed XAdES / JAdES / ASiC-E document into `appendSigner`,
  so a host that only ever calls `sign()` lost the check the moment its input was
  already signed. The policy now runs on both paths.
- **A PIN verify or change could spend the unblocking PIN's retry counter.** The
  verify, change-target and counter-read paths addressed the first PIN object in
  the directory without filtering out the unblocking / security-officer PIN, so
  on a card whose AODF lists its unblocking PIN before the user's, the operation
  consumed the wrong counter — and a PUK driven to zero takes the card's last
  recovery path with it. All three paths now classify the PIN before using it.
- **A malformed EF.CardAccess could send the reader into an endless loop.** Four
  private copies of the BER length decoder checked that the length OCTETS fit the
  buffer and never that the DECODED VALUE did, so `position + length` could
  overflow. EF.CardAccess is read before any key, PIN, CAN or MRZ is involved, so
  the bytes are entirely the chip's choice. Containment is now proved by
  subtraction and covered by self-tests.
- **A chip could make the reader allocate whatever its file header declared.**
  The chunked file read reserved the declared length before anything had
  authenticated the card; a header declaring 4 GiB reached the allocator. Reads
  now carry an explicit byte ceiling.
- **PIN-bearing APDU payloads were not wiped before their buffers were
  released.** Both the command payloads and their wire serialisations are now
  cleansed on every exit path.
- **A secure-messaging SELECT of DG3 killed the whole SM session on one card
  family.** The holder saw a read that "worked" minus their address, issuing data
  and annex — partial data silently presented as complete. The select is now
  driven so the session survives, and a read that cannot complete reports the
  failure instead of returning less.

### Known limitations

- **A document signature opens a second, short-lived PC/SC handle on the card
  it is signing with.** Signing loads the PKCS#11 module into the signing
  process and asks it for its slots, and answering that means probing the
  readers. On a reader whose session carries no live secure channel the module
  opens its own handle to the same card the caller is already talking to, and
  binds it. The handle is closed and the module unloaded before the call
  returns. A card protected by a secure channel is not **re-bound** this way —
  that session is adopted instead of reopened — but see the next item for what
  still reaches it.

  `test/pcsc_handle_census_test.cpp` records the counts. They are the counts of
  a signature whose bind fails, which is the path that test drives; a handle
  opened only where the bind succeeds would not move them.

- **The probe also touches readers the signature has nothing to do with.**
  Every reader the PC/SC layer reports gets a handle opened and closed during
  that same probe, including a reader holding a live secure channel: refusing
  to bind such a reader stops the bind, not the handle, because establishing a
  PC/SC context for any reader makes the bundled OpenSC enumerate all of them
  and read each one's features.

  What that costs differs by reader. On a reader **without** a live secure
  channel the module does not merely open a handle, it binds the card: that
  sends APDUs, so an operation running there can find card state it did not set
  — a different selected file, a changed security state — and, where the driver
  has to change protocol, a card that was unpowered under it. On a reader
  **with** a live secure channel only the enumeration reaches it, which by the
  reader driver's own source is a shared connect, one reader-level control call
  and a disconnect that leaves the card powered — a shape that driver hardcodes
  for this path, so no configuration turns it into a reset. On that reading the
  channel survives, but this has **not been confirmed on a card**, and no test in
  this release can confirm it. If a contactless session drops while you sign a
  document on another reader, this is the most likely cause: re-establish the
  session — you will be asked for the card access number again — and please
  report it.

  The counts and the reasoning above assume the reader driver's own defaults. A
  host that ships an `/etc/opensc.conf` with a `reader_driver pcsc` block can
  change the bind path itself: demanding exclusive access (signing then fails on
  a reader the agent holds), resetting or unpowering the card on disconnect, or
  replacing the PC/SC layer. This release ships no such file and sets no
  `OPENSC_CONF`.

- **The direct PKCS#11 module does not notice a card swapped in the same
  reader.** Each reader is probed exactly once for the life of the loaded
  module: there is no thread watching for removal, and `C_WaitForSlotEvent`
  reports `CKR_FUNCTION_NOT_SUPPORTED`, so the slots the first card published
  stay surfaced until `C_Finalize`.

  What stays surfaced is the first card's **identity**, not just its slot: the
  token label, the serial number and the certificate a host reads back are the
  ones the module learned from the card that has gone, while APDUs go to the one
  now in the reader. For two cards of the same family the object identifiers
  match, so the objects rebind silently and a PIN collected for the first card
  is presented to the second — spending its retry counter. Replace the card and
  reload the module, or use the agent, which owns the reader and does watch.
  This affects the `librescrs-pkcs11-direct` deployment only.

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
