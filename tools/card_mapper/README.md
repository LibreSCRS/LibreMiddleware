# card_mapper

Smart card file system mapper and documentation generator for LibreMiddleware.

Scans smart cards via PC/SC, generates Markdown documentation with ASCII tree diagrams, Mermaid diagrams, and TLV data element tables.

## Build

```bash
cd LibreMiddleware
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target card_mapper
```

The binary is at `build/tools/card_mapper/card_mapper`.

### Running Tests

```bash
cmake --build build --target card_mapper_tests
cd build/tools/card_mapper && ctest --output-on-failure
```

## Workflows

### I have a new card and want to document it

1. Insert the card into a reader.

2. Run discovery with scaffolding:

   ```bash
   ./card_mapper --discover --scaffold mynewcard --verbose --output-dir docs/cards/
   ```

3. Review generated files:
   - `docs/cards/applets/unknown-applet.md` -- applet documentation with file tree and data elements
   - `docs/cards/profiles/<profile>.md` -- profile linking to applet docs
   - `lib/mynewcard/src/mynewcard_protocol.h` -- draft protocol header with generic names

4. Rename generic tag names (`kTag_060A`) in the protocol header based on card specifications.

5. Refine the generated Markdown: add human-readable field names, notes about card generations, authentication details.

### I want to regenerate docs for an existing plugin

1. Insert the corresponding card into a reader.

2. Run in plugin mode:

   ```bash
   ./card_mapper --plugin eid --output docs/cards/applets/eid-serbian-applet.md --verbose
   ```

   Supported plugins: `eid`, `cardedge`, `health`, `eu-vrc`, `emrtd`.

3. Compare the output with the existing documentation:

   ```bash
   diff docs/cards/applets/eid-serbian-applet.md /tmp/eid-regenerated.md
   ```

4. Update the documentation if the tool reveals new fields or corrections.

### I want to verify a contributor's card map

1. Check out the contributor's branch.

2. Insert the same type of card used by the contributor.

3. Run the tool for their plugin:

   ```bash
   ./card_mapper --plugin <name> --verbose
   ```

4. Compare the tool's output with the submitted applet doc. Field names and tag counts should match. Example values will differ (personal data).

5. Verify the protocol header constants match the tool's discovered FIDs and tags.

### I want to scan an eMRTD (passport or eID with PACE)

eMRTD data groups are protected by PACE or BAC authentication. The card_mapper
reads credentials from environment variables so that secrets are never passed on
the command line.

**Passport (PACE-MRZ)**:

```bash
export LIBRESCRS_TEST_MRZ_DOC="014767289"     # document number from MRZ
export LIBRESCRS_TEST_MRZ_DOB="781207"         # date of birth YYMMDD
export LIBRESCRS_TEST_MRZ_EXPIRY="291028"      # expiry date YYMMDD
./card_mapper --plugin emrtd --verbose
```

**eID card (PACE-CAN)**:

```bash
export LIBRESCRS_TEST_CAN="123456"             # Card Access Number
./card_mapper --plugin emrtd --verbose
```

If no credentials are set, the tool prints static applet metadata only (no
authentication, no DG reads).

### Environment Variables (eMRTD)

| Variable | Description |
|----------|-------------|
| `LIBRESCRS_TEST_MRZ_DOC` | Document number from MRZ line 1 |
| `LIBRESCRS_TEST_MRZ_DOB` | Date of birth in YYMMDD format |
| `LIBRESCRS_TEST_MRZ_EXPIRY` | Expiry date in YYMMDD format |
| `LIBRESCRS_TEST_CAN` | Card Access Number (6-digit, printed on document) |

MRZ variables take precedence over CAN if both are set.

## Options

Run `card_mapper --help` for full usage information, or see the man page (`card_mapper.1`).
