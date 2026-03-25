# Contributing a New Card Plugin

This guide walks you through adding support for a new smart card type to
LibreMiddleware. The process has three phases: investigating the card,
implementing the plugin, and submitting a pull request.

## Prerequisites

### Hardware

- A PC/SC-compatible smart card reader (contact or contactless, depending on
  the card)
- A physical smart card of the type you want to support

### Software

- CMake 3.24 or later
- A C++20-capable compiler (GCC 12+, Clang 15+, MSVC 2022+)
- PC/SC library (`pcsclite` on Linux, built-in on macOS/Windows)
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

### Directory structure

Create your plugin as a pair of libraries under `lib/`:

```
lib/<name>/                    # Core card logic (no plugin dependency)
├── CMakeLists.txt
├── include/<name>/
│   └── <name>.h               # Public API header
└── src/
    ├── <name>_protocol.h       # AID, FID, TLV tag constants
    ├── <name>_reader.h         # Card reader class (reads data from card)
    ├── <name>_reader.cpp
    └── <name>.cpp              # High-level card API

lib/<name>-plugin/             # CardPlugin adapter
├── CMakeLists.txt
└── src/
    └── <name>_card_plugin.cpp  # CardPlugin interface implementation
```

The separation between core logic (`lib/<name>/`) and plugin adapter
(`lib/<name>-plugin/`) keeps the card-reading code reusable without depending
on the plugin framework.

### Implement the CardPlugin interface

Your plugin must implement the `CardPlugin` interface defined in
`lib/plugin/include/plugin/card_plugin.h`. The key methods are:

```cpp
class CardPlugin {
public:
    // Identification
    virtual std::string pluginId() const = 0;       // e.g., "mynewcard"
    virtual std::string displayName() const = 0;    // e.g., "My New Card"
    virtual int probePriority() const = 0;          // lower = probed first

    // Detection — return true if this plugin handles the given card
    virtual bool canHandle(const std::vector<uint8_t>& atr) const = 0;
    virtual bool canHandleConnection(smartcard::PCSCConnection& conn) const;

    // Data reading — read all data from the card
    virtual CardData readCard(smartcard::PCSCConnection& conn) const = 0;

    // Progressive reading — deliver data group by group (optional)
    virtual CardData readCardStreaming(
        smartcard::PCSCConnection& conn, GroupCallback onGroup) const;
};
```

**Detection strategy:** Implement `canHandle()` for fast ATR-based matching.
If ATR alone is not sufficient (e.g., multiple card types share an ATR),
implement `canHandleConnection()` for AID-based detection on a live connection.

**PKI support:** If the card supports cryptographic operations (PIN
verification, certificate reading, digital signing), override the optional PKI
methods: `supportsPKI()`, `readCertificates()`, `verifyPIN()`, `changePIN()`,
`getPINList()`, `getPINTriesLeft()`, `sign()`, `discoverKeyReferences()`.

**Credentials:** If the card requires authentication before reading (e.g.,
PACE for eMRTD), override `setCredentials()` to accept key-value pairs
from the caller.

**Export functions:** Your plugin shared library must export two C-linkage
functions:

```cpp
extern "C" std::unique_ptr<CardPlugin> create_card_plugin();
extern "C" uint32_t card_plugin_abi_version();
```

### Learn from existing plugins

Study these existing implementations as references:

| Plugin | Card Type | Key Files |
|--------|-----------|-----------|
| `eid` | Serbian eID | `lib/eidcard/`, `lib/eidcard-plugin/` |
| `eu-vrc` | EU Vehicle Registration (Directive 2003/127/EC) | `lib/eu-vrc/`, `lib/eu-vrc-plugin/` |
| `health` | Serbian health card | `lib/healthcard/`, `lib/healthcard-plugin/` |
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

## Phase 3: PR Submission

### PR checklist

Before submitting your pull request, verify that all of the following are
included:

- [ ] **Applet doc(s)** in `docs/cards/applets/<applet-name>-applet.md` --
  one per applet type on the card (skip if applet doc already exists)
- [ ] **Profile doc** in `docs/cards/profiles/<profile-name>-profile.md` --
  describing the applet combination on this card
- [ ] **Protocol header** (`*_protocol.h`) with finalized AID, FID, and TLV
  tag definitions (no generic names remaining)
- [ ] **Plugin implementation** implementing the `CardPlugin` interface
- [ ] **Tests** -- both unit tests (no hardware) and hardware tests (with
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
| `--pin <ref>` | Interactive PIN prompt for the given reference | CardEdge, PKS |

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
