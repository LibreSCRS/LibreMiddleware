# LibreSCRS shared-build CLI example

Minimal CLI demonstrating LibreSCRS consumption against the SHARED
`libLibreSCRS_*` artefacts.

## What it does

- Enumerates PC/SC readers via `LibreSCRS::SmartCard::MonitorService::listReaders`.
- Opens a `LibreSCRS::SmartCard::CardSession` against the first reader
  that has a card present.
- Prints the reader name + ATR hex on success; prints a per-reader error
  status otherwise.
- Exits gracefully (returns 0) when no readers are attached or no card
  is present in any reader.

## Build

Configure LibreMiddleware with shared libraries and example targets:

```sh
cmake -S . -B build-shared \
    -DLIBREMIDDLEWARE_BUILD_SHARED=ON \
    -DLIBRESCRS_BUILD_EXAMPLES=ON
cmake --build build-shared -j4 --target librescrs-example-shared-cli
```

## Run

In-tree (no install needed — CMake bakes the right RPATH into the
binary so it locates the sibling `libLibreSCRS_*.so` files):

```sh
./build-shared/examples/shared-cli/librescrs-example-shared-cli
```

After `cmake --install build-shared --prefix <dest>`, run with
`LD_LIBRARY_PATH` set so the dynamic loader finds the installed shared
libraries:

```sh
LD_LIBRARY_PATH=<dest>/lib ./build-shared/examples/shared-cli/librescrs-example-shared-cli
```

## Expected output

With no readers attached:

```
No PC/SC readers attached.
```

With one reader, no card present:

```
Detected 1 reader(s):
  - Identiv uTrust 4701 F Contactless Reader 00 00
  [Identiv uTrust 4701 F Contactless Reader 00 00] open failed: no card present

No reader produced an open session (likely no card inserted).
```

With a card inserted:

```
Detected 1 reader(s):
  - Identiv uTrust 4701 F Contactless Reader 00 00

Opened session against reader:
  Identiv uTrust 4701 F Contactless Reader 00 00
  ATR = 3BFE1800008031FE45...
```
