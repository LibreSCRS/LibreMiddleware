# Contributing to a LibreSCRS Card Plugin

> **Scope (LM 4.0):** Plugins are an **internal modular-driver pattern**.
> They live in-tree under `LibreMiddleware/lib/<name>/` and
> `LibreMiddleware/lib/<name>-plugin/`, are built and tested as part of
> the LibreMiddleware build, and have direct access to the
> `LIBRESCRS_INTERNAL_BUILD`-gated APDU transmission helpers
> (`LibreSCRS::SmartCard::detail::unwrap`).
>
> **The LM 4.0 public C++ API does not include APDU transmission or
> low-level card session control.** Out-of-tree (third-party) plugin
> authoring is **not supported in 4.0**: the surface required to support
> it (a public APDU API and a stable plugin C++ ABI) is reserved for a
> future 4.x cycle, to be informed by a concrete real consumer rather
> than guessed pre-emptively.
>
> This document is therefore a **guide for in-tree contributors** —
> contributors adding support for additional national document types,
> applet families, or card platforms inside the LibreMiddleware tree.

This guide walks through adding support for a new smart card type to
LibreMiddleware. The process has three phases: investigating the card,
implementing the plugin, and submitting a pull request.

## Prerequisites

### Hardware

- A PC/SC-compatible smart card reader (contact or contactless, depending on
  the card)
- A physical smart card of the type you want to support

### Software

- CMake 3.24 or later
- A C++23-capable compiler (GCC 13+, Clang 16+, AppleClang 16+ with `-fexperimental-library`)
- PC/SC library (`pcsclite` on Linux, built-in on macOS)
- LibreMiddleware built from source (see top-level README)

### Knowledge

- Basic understanding of ISO 7816 APDUs (SELECT, READ BINARY, status words)
- Familiarity with TLV (Tag-Length-Value) encoding
- Comfort reading hex dumps

---

## Phase 1: Card Investigation

Start by scanning the card with `card_mapper` to discover its file system
structure and generate documentation scaffolding.

### Step 1: Discover the card

Insert the card into your reader and run:

```bash
./card_mapper --discover --scaffold <plugin-name> --verbose --output-dir docs/cards/
```

Replace `<plugin-name>` with a short identifier for your card type (e.g.,
`mynewcard`). This command:

1. Connects to the first available reader via PC/SC
2. Reads the card's ATR (Answer To Reset)
3. Probes known AIDs (from EF.DIR and existing `*_protocol.h` headers)
4. Walks the file system for each detected applet
5. Attempts TLV parsing of each file's contents

### Step 2: Review the generated output

The tool produces several files:

| Generated File | Location | Purpose |
|----------------|----------|---------|
| Applet doc(s) | `docs/cards/applets/<applet>-applet.md` | File system tree, data element tables, read procedure, APDU trace |
| Profile doc | `docs/cards/profiles/<profile>-profile.md` | ATR patterns, list of applets present on the card |
| Draft protocol header | `lib/<plugin-name>/src/<plugin_name>_protocol.h` | AID, FID, and TLV tag constants (generic names) |

The `--verbose` flag appends a full APDU trace section to each applet doc,
which is invaluable for debugging.

### Step 3: Refine the documentation

The auto-generated docs use generic names (e.g., `kTag_0x060A`, `kFile_0F02`).
You need to manually improve them:

- **Rename tags** to meaningful names based on card specifications or observed
  data (e.g., `kTag_0x060A` becomes `kTagSurname`)
- **Describe field semantics** in the data element tables (type, encoding,
  expected values)
- **Add card-specific notes** such as authentication requirements, card
  generations, or known quirks
- **Verify the file system tree** matches your understanding of the card's
  structure

### Step 4: Handle existing applets

If your card contains an applet that is already documented (e.g., CardEdge),
you do not need to create a new applet doc for it. Instead:

- Reference the existing applet doc from your profile doc
- Only create or update the **profile doc** to describe this particular
  combination of applets

See `docs/cards/applets/` for existing applet documentation examples, such as
`eid-serbian-applet.md`.

---

## Phase 2: Plugin Implementation

This phase covers the in-tree authoring flow: a pair of libraries under
`lib/`, wired into the LM build via `librescrs_add_plugin()`, with direct
access to the `LIBRESCRS_INTERNAL_BUILD`-gated APDU helpers.

### Directory structure

Create your plugin as a pair of libraries under `lib/`:

```
lib/<name>/                    # Core card logic (no plugin dependency)
├── CMakeLists.txt
├── src/
│   ├── <name>_protocol.h       # AID, FID, TLV tag constants
│   ├── <name>_card.h           # Card class declaration (internal header)
│   ├── <name>_card.cpp         # Card class implementation
│   └── <name>_types.h          # Data structs returned to the plugin

lib/<name>-plugin/             # CardPlugin adapter
├── CMakeLists.txt
├── manifest.json              # pluginId, displayName, abiVersion, capabilities, atrs
└── src/
    └── <name>_card_plugin.cpp # CardPlugin interface implementation
```

The separation between core logic (`lib/<name>/`) and plugin adapter
(`lib/<name>-plugin/`) keeps the card-reading code reusable without depending
on the plugin framework. Both directories are built as part of the
LibreMiddleware tree; the plugin target inherits `LIBRESCRS_INTERNAL_BUILD`
via the `librescrs_add_plugin()` CMake helper.

### Implement the CardPlugin interface

Your plugin must implement the `CardPlugin` interface defined in
`lib/plugin/include/plugin/card_plugin.h`. The key methods are:

```cpp
class CardPlugin {
public:
    // Identification — set ONCE in your derived ctor via the protected
    // setIdentity() helper; non-virtual accessors below.
    const std::string& pluginId() const noexcept;       // e.g., "mynewcard"
    const std::string& displayName() const noexcept;    // e.g., "My New Card"
    int probePriority() const noexcept;                 // lower = probed first

    // Capabilities — bitfield.
    virtual CardCapabilities capabilities() const = 0;
    // e.g. return CardCapabilities::PKI | CardCapabilities::PinManagement;

    // Manifest-driven ATR set. Plugins override this to expose the ATRs
    // declared in their manifest.json (the manifest2header codegen emits a
    // generated::<plugin>::kAtrs array — typical override is a one-liner
    // returning that span). Allocation-free; static lifetime.
    [[nodiscard]] virtual std::span<const Atr> supportedAtrs() const noexcept = 0;

    // Detection — fast path is non-virtual: canHandle() does an
    // allocation-free set-membership check against supportedAtrs(). Plugins
    // do NOT override canHandle(); they populate manifest.json:atrs instead.
    [[nodiscard]] bool canHandle(std::span<const std::uint8_t> atr) const noexcept;

    // Fallback for cards whose ATR is ambiguous or shared (e.g. PIV): probe
    // a live session via AID SELECT. The ATR is also passed in so plugins
    // can combine ATR and AID checks without re-reading the ATR. Default
    // implementation returns false.
    [[nodiscard]] virtual bool canHandleConnection(std::span<const std::uint8_t> atr,
                                                   LibreSCRS::SmartCard::CardSession& session) const;

    // Data reading — public NVI entry point. Returns ReadResult (status
    // classification + data). The wrapper observes a CancelToken and
    // short-circuits before dispatching to doReadCard(). Plugins do NOT
    // override readCard(); they override the protected doReadCard() seam.
    [[nodiscard]] ReadResult readCard(LibreSCRS::SmartCard::CardSession& session,
                                      GroupCallback onGroup = {},
                                      LibreSCRS::CancelToken token = {}) const;

protected:
    // Override seam for readCard(). Treated as atomic from a cancellation
    // standpoint — the only honest cancellation point is the pre-dispatch
    // short-circuit in the public wrapper.
    [[nodiscard]] virtual ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& session,
                                                GroupCallback onGroup) const = 0;

    // Derived constructors call this ONCE to fix identity.
    void setIdentity(std::string id, std::string name, int priority) noexcept;
};
```

> **NVI pattern:** the public `readCard()` is non-virtual; it observes the
> `CancelToken`, then dispatches to the protected virtual `doReadCard()`
> that derived classes override. The same idea applies to detection:
> `canHandle()` is non-virtual and derives its result from the
> `supportedAtrs()` override that plugins provide via their manifest.

> **APDU access:** `CardSession` is the opaque public handle for an
> active card connection. In-tree plugins built via the
> `librescrs_add_plugin()` CMake helper inherit the
> `LIBRESCRS_INTERNAL_BUILD` compile definition and obtain the raw
> `LibreSCRS::SmartCard::Internal::PCSCConnection&` via
> `LibreSCRS::SmartCard::detail::unwrap(session)` — this is the standard
> path for sending raw APDUs from a plugin.
>
> Translation units that do not carry `LIBRESCRS_INTERNAL_BUILD` cannot
> use `detail::unwrap`. There is no public alternative in LM 4.0; out-
> of-tree plugin authoring requires a public APDU API which is deferred
> to a future 4.x cycle.

**Detection strategy:** Populate the `atrs` array in `manifest.json` for fast
ATR-based matching (`canHandle()` derives its result from `supportedAtrs()`,
which the manifest codegen wires up automatically). If ATR alone is not
sufficient (e.g. multiple card types share an ATR), override
`canHandleConnection()` for AID-based detection on a live connection.

**PKI support:** If the card supports cryptographic operations (PIN
verification, certificate reading, digital signing), return the appropriate
`CardCapabilities` bits from `capabilities()` (typically
`CardCapabilities::PKI | CardCapabilities::PinManagement`) and override the
optional PKI methods: `readCertificates()`, `verifyPIN()`, `changePIN()`,
`getPINList()`, `getPINTriesLeft()`, `sign()`, `discoverKeyReferences()`.

PIN / PUK / CAN material is carried by `LibreSCRS::Secure::String` —
contents are `OPENSSL_cleanse`d on destruction. `verifyPIN`, `changePIN`,
`unblockPIN`, `setCredentials` all take `const Secure::String&` for secret
parameters; labels (PIN identifiers like `"UserPIN"`) are
`std::string_view` since they are not secrets.

`readCounters()` is the entry point for lifecycle counters: it returns a
`CredentialCounters` (retries / uses / unblocks, each `std::optional<int>` —
use `std::nullopt` for anything the card cannot report). `getPINTriesLeft()`
is superseded by `readCounters(session).retriesLeft` and retained only for
source compatibility. Cards with transport PINs or activatable signing keys
should also override `activateTransportPin()` and `activateSigningKey()`.

**Credentials:** If the card requires authentication before reading (e.g.,
PACE for eMRTD), override `setCredentials()` to accept key-value pairs
from the caller. The value parameter is `const Secure::String&`.

**Export functions:** Your plugin shared library must export two C-linkage
functions. The `LIBRESCRS_DECLARE_CARD_PLUGIN` macro emits both for you.

### Worked example: PIV plugin

The PIV plugin (US FIPS 201 / NIST SP 800-73) is a good worked example
because it is self-contained, internationally recognised, and exercises
the full in-tree authoring flow: a `lib/piv/` core library, a
`lib/piv-plugin/` adapter wired via `librescrs_add_plugin()`, a manifest
with capabilities and ABI version, and direct use of `detail::unwrap` to
reach the raw PC/SC connection.

#### Plugin CMake target

`lib/piv-plugin/CMakeLists.txt` (lines 4–11):

```cmake
librescrs_add_plugin(piv-plugin
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
    SOURCES  src/piv_card_plugin.cpp
    INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/lib/piv/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    LINK_LIBRARIES PIV
)
```

`librescrs_add_plugin()` sets `LIBRESCRS_INTERNAL_BUILD` on the target,
runs `manifest2header.py` over `manifest.json` to emit a generated
`manifest.h`, and links the loader-side glue. The `INCLUDE_DIRS` reach
into `lib/piv/src` and `lib/smartcard/src` — internal-only paths, by
design.

#### Manifest

`lib/piv-plugin/manifest.json` (lines 1–8):

```json
{
  "pluginId": "piv",
  "displayName": "PIV (NIST SP 800-73)",
  "abiVersion": 8,
  "capabilities": ["PKI", "PinManagement"],
  "preReadAuth": "None",
  "atrs": []
}
```

`abiVersion` must equal the current `LibreSCRS::Plugin::kCardPluginAbiVersion`
the plugin is built against; the manifest schema validates it at build time.
(The loader's runtime ABI gate compares the compiled `card_plugin_abi_version()`
symbol that `LIBRESCRS_DECLARE_CARD_PLUGIN` emits — not this JSON field.) The
`atrs` array
is intentionally empty for PIV because PIV cards have no distinguishing
ATR — detection runs through `canHandleConnection()` instead (see below).
The manifest is consumed by `manifest2header.py`, which generates the
`LibreSCRS::Plugin::generated::piv::k*` constants used in the adapter.

#### Plugin adapter — identity, capabilities, ATRs

`lib/piv-plugin/src/piv_card_plugin.cpp` (lines 60–75):

```cpp
PIVCardPlugin()
{
    setIdentity(std::string{LibreSCRS::Plugin::generated::piv::kPluginId},
                std::string{LibreSCRS::Plugin::generated::piv::kDisplayName},
                /*priority=*/700);
}

LibreSCRS::Plugin::CardCapabilities capabilities() const override
{
    return LibreSCRS::Plugin::generated::piv::kCapabilities;
}

std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
{
    return LibreSCRS::Plugin::generated::piv::kAtrs;
}
```

Identity, capabilities, and supported ATRs all flow from the manifest
through the generated header. The ctor's call to `setIdentity()` is the
once-per-instance handshake that fixes the public `pluginId()` /
`displayName()` / `probePriority()` accessors.

#### Plugin adapter — APDU access via `detail::unwrap`

`lib/piv-plugin/src/piv_card_plugin.cpp` (lines 77–87):

```cpp
bool canHandleConnection(std::span<const std::uint8_t> /*atr*/,
                         LibreSCRS::SmartCard::CardSession& session) const override
{
    auto& conn = LibreSCRS::SmartCard::detail::unwrap(session);
    try {
        piv::PIVCard card(conn);
        return card.probe();
    } catch (...) {
        return false;
    }
}
```

`LibreSCRS::SmartCard::detail::unwrap(session)` returns the underlying
`LibreSCRS::SmartCard::Internal::PCSCConnection&`. The unwrap header is gated by
`LIBRESCRS_INTERNAL_BUILD`, which the plugin target inherits from
`librescrs_add_plugin()`. Once the raw connection is in hand, the
plugin instantiates the in-tree `piv::PIVCard` core class
(`lib/piv/src/piv_card.h` lines 26–71) and drives it directly. The same
pattern is used in `doReadCard` (lines 89–180), `readCertificates`
(lines 182–202), `getPINList` (lines 204–234), `verifyPIN` (lines
236–252), `getPINTriesLeft` (lines 254–269), and `discoverKeyReferences`
(lines 271–285) — every entry point on the adapter unwraps to the raw
connection, opens a `LibreSCRS::SmartCard::Internal::CardTransaction`, and delegates to the
core `PIVCard` methods.

Note that `lib/piv/src/piv_card.h` itself starts with an
`#ifndef LIBRESCRS_INTERNAL_BUILD / #error` guard (lines 4–6) — the core
card class is internal too. Any consumer of the core library must also
be an in-tree target with the build flag granted.

#### Plugin adapter — the export macro

`lib/piv-plugin/src/piv_card_plugin.cpp` (line 290):

```cpp
LIBRESCRS_DECLARE_CARD_PLUGIN(PIVCardPlugin, LibreSCRS::Plugin::kCardPluginAbiVersion)
```

This macro (from `<LibreSCRS/Plugin/PluginExport.h>`) emits the two
`extern "C"` exports the loader looks up via `dlsym`: a factory function
returning a `std::unique_ptr<CardPlugin>` and an ABI-version accessor
returning the current `kCardPluginAbiVersion`. Pass your derived class
as the first argument; the second argument anchors the ABI handshake on
the loader side.

### Learn from existing plugins

Once the worked example is internalised, study these existing
implementations as a reference catalogue:

| Plugin | Card Type | Key Files |
|--------|-----------|-----------|
| `rs-eid` | Serbian eID | `lib/rs-eid/`, `lib/rs-eid-plugin/` |
| `eu-vrc` | EU Vehicle Registration (Directive 2003/127/EC) | `lib/eu-vrc/`, `lib/eu-vrc-plugin/` |
| `rs-health` | Serbian health card | `lib/rs-health/`, `lib/rs-health-plugin/` |
| `emrtd` | eMRTD / passport (ICAO 9303) | `lib/emrtd/`, `lib/emrtd-plugin/` |
| `cardedge` | CardEdge PKI applet | `lib/cardedge/`, `lib/cardedge-plugin/` |
| `pkcs15` | PKCS#15 generic applet | `lib/pkcs15/`, `lib/pkcs15-plugin/` |

### Write tests

Every plugin must include tests. Place them alongside your plugin code or in a
dedicated test directory.

**Unit tests (no hardware required):**

- TLV parsing of sample data buffers
- Protocol constant correctness
- Data conversion logic

These tests should always run, regardless of whether a card reader or card is
present.

**Hardware tests (card required):**

- Use `GTEST_SKIP()` to skip when the card is not present:

```cpp
TEST(MyNewCardTest, ReadCard)
{
    auto conn = connectToReader();
    if (!conn) {
        GTEST_SKIP() << "No card reader or card not present";
    }
    // ... test card reading ...
}
```

**PIN handling:**

Never hardcode PINs in test code. Use the `LIBRESCRS_TEST_PIN` environment
variable:

```cpp
TEST(MyNewCardTest, VerifyPIN)
{
    const char* pin = std::getenv("LIBRESCRS_TEST_PIN");
    if (!pin) {
        GTEST_SKIP() << "LIBRESCRS_TEST_PIN not set";
    }
    // ... test PIN verification with pin ...
}
```

PIN entry has a limited number of retries before the card is permanently
blocked (typically 3 attempts). Use the project's `g_pinFailed` flag and
`SKIP_IF_PIN_FAILED()` macro to abort remaining PIN tests after the first
failure.

---

## What This Doc Does NOT Cover

This guide is scoped to in-tree contribution. The following are **out
of scope for LM 4.0** and intentionally not documented here:

- **Third-party packaging or distribution** of plugins outside the
  LibreMiddleware source tree. Plugins are built as part of LM and
  ship in the same package.
- **ABI stability promises** for the `CardPlugin` C++ interface across
  LM versions. `kCardPluginAbiVersion` is a build-time handshake for
  in-tree plugins, not a stable contract for external binary plugins.
  In-tree plugins are recompiled with LM in lockstep.
- **Public APDU transmission from a non-`LIBRESCRS_INTERNAL_BUILD`
  translation unit.** The `detail::unwrap` gate is intentional. There
  is no public `CardSession::transmit` in 4.0.
- **`librescrs_add_plugin()` use from outside the LM source tree.**
  The CMake helper is part of the LM build system, not a published
  installable artefact.

When and if a real out-of-tree consumer materialises (a community
contributor with a named card platform, a partner program, or a
sandboxed extension like the future macOS CTK appex), a public APDU
surface and a stable plugin ABI will be designed in 4.x informed by
that consumer's actual shape.

---

## Phase 3: PR Submission

### PR checklist

Before submitting your pull request, verify that all of the following are
included:

- [ ] **Applet doc(s)** in `docs/cards/applets/<applet-name>-applet.md` —
  one per applet type on the card (skip if applet doc already exists)
- [ ] **Profile doc** in `docs/cards/profiles/<profile-name>-profile.md` —
  describing the applet combination on this card
- [ ] **Protocol header** (`*_protocol.h`) with finalized AID, FID, and TLV
  tag definitions (no generic names remaining)
- [ ] **Plugin implementation** implementing the `CardPlugin` interface
- [ ] **Tests** — both unit tests (no hardware) and hardware tests (with
  `GTEST_SKIP()` when card is not present)
- [ ] **SPDX license headers** on all new source files

### Reviewer verification

Reviewers will typically not have access to the physical card, so verification
is code-based:

1. **Protocol header review** — verify that `*_protocol.h` constants (AIDs,
   FIDs, TLV tags) are consistent with the applet doc
2. **Plugin code review** — verify that the read procedure in code matches the
   applet doc's documented read procedure
3. **Unit test review** — run unit tests (no hardware needed) to verify parsing
   and data conversion logic
4. **Live verification (optional)** — if the reviewer has access to the card,
   they can run `./card_mapper --plugin <name>` to compare tool output against
   the submitted applet doc

---

## Document Organization

LibreMiddleware uses a two-layer documentation structure for card mappings:

### Applet docs (`docs/cards/applets/`)

An **applet doc** is the full technical reference for a single applet type. It
contains:

- Application AID
- File system tree (ASCII + Mermaid diagram)
- Data element tables (tag, field key, name, type, example)
- Read procedure with APDU sequences
- APDU trace (if generated with `--verbose`)

Each applet is documented exactly once. Multiple cards that contain the same
applet (e.g., CardEdge) reference the same applet doc.

### Profile docs (`docs/cards/profiles/`)

A **profile doc** describes a physical card by listing which applets are
present on it. It contains:

- ATR patterns
- Table of applets with links to their applet docs
- Card-specific notes

Profiles are organized by **applet combination**, not by country. If two
countries' eID cards contain the same set of applets, they share a single
profile doc. Country-specific notes go in the card-specific notes section.

### Examples

See the existing documentation for reference:

- Applet doc: `docs/cards/applets/eid-serbian-applet.md`
- Profile docs: `docs/cards/profiles/` (when available)

---

## card_mapper Quick Reference

### Common commands

```bash
# Scan an unknown card, generate all docs
card_mapper --discover --output-dir docs/cards/

# Scan unknown card and scaffold a new plugin
card_mapper --discover --scaffold mynewcard --verbose --output-dir docs/cards/

# Map a known plugin's applet from a card in the reader
card_mapper --plugin eid --output docs/cards/applets/eid-serbian-applet.md

# Map with APDU trace for debugging
card_mapper --plugin eid --verbose --output docs/cards/applets/eid-serbian-applet.md

# Use a specific reader when multiple are connected
card_mapper --discover --reader "Alcor Micro AU9560"

# eMRTD with PACE-MRZ authentication
card_mapper --plugin emrtd --mrz "<MRZ-string>" --verbose

# eMRTD with PACE-CAN authentication
card_mapper --plugin emrtd --can <CAN>

# CardEdge with PIN (prompts interactively)
card_mapper --plugin cardedge --pin 0x80
```

### Authentication flags

| Flag | Purpose | Cards |
|------|---------|-------|
| `--mrz <MRZ>` | PACE authentication using Machine Readable Zone | eMRTD |
| `--can <CAN>` | PACE-CAN authentication | eMRTD |
| `--pin <ref>` | Interactive PIN prompt for the given reference | CardEdge, PKCS#15 |

Without authentication flags, protected files appear as `[AUTH REQUIRED]` in
the output.

### Output options

| Flag | Description |
|------|-------------|
| `--output <file>` | Write single applet doc to a file (`--plugin` mode) |
| `--output-dir <dir>` | Write all docs to a directory (`--discover` mode, default: `docs/cards/`) |
| `--verbose` | Append APDU trace section |
| No output flags | Print to stdout |

For full usage details, run `card_mapper --help`.
