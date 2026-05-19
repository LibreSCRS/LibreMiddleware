<!--
SPDX-License-Identifier: LGPL-2.1-or-later
SPDX-FileCopyrightText: 2026 hirashix0
-->

# sdk-consumer

Minimal reference consumer that proves the LibreSCRS public API is
self-contained. Links against `LibreSCRS::All` only — none of the
private internal targets (`SmartCard_Impl`, `CardPlugin_Impl`, `LibreSign`,
etc.) and none of the private include directories (`lib/*/include`,
`lib/*/src`) are reachable.

Exercises one call per public target:

| # | Target              | Call                                             |
|---|---------------------|--------------------------------------------------|
| 1 | `LibreSCRS::Auth`   | `AuthRequirement::forSigning(LocalizedText{"", "PIN", {}}, 3)` |
| 2 | `LibreSCRS::Auth`   | `Secure::Buffer(8, 0x42)` (co-hosted in Auth lib)|
| 3 | `LibreSCRS::SmartCard` | `Monitor::listReaders()`                       |
| 4 | `LibreSCRS::Plugin` | `CardPluginService{path}`, `kCardPluginAbiVersion` |
| 5 | `LibreSCRS::Signing`| `SigningService(TrustConfig, TsaProvider)` ctor, `staticTsa(...)` |
| 6 | `LibreSCRS::Signing`| `SigningRequest::Builder` → build               |

If any future change makes a public header non-self-contained — e.g. a
`LibreSCRS/*.h` starts pulling an internal header onto its public surface
— `sdk-consumer` fails to build. That is the point.

## Build in-tree

```bash
cmake -B build -DLIBRESCRS_BUILD_EXAMPLES=ON
cmake --build build --target sdk-consumer -j4
./build/examples/sdk-consumer/sdk-consumer
```

Expected output: six lines, one per exercised call.

The option is `OFF` by default to keep normal `cmake -B build` builds
unaffected. Downstream CI should opt in explicitly.

## Consume as a downstream project (FetchContent)

```cmake
include(FetchContent)
FetchContent_Declare(
    LibreMiddleware
    GIT_REPOSITORY https://github.com/LibreSCRS/LibreMiddleware.git
    GIT_TAG        v4.0.0
)
FetchContent_MakeAvailable(LibreMiddleware)

add_executable(my-app main.cpp)
target_link_libraries(my-app PRIVATE LibreSCRS::All)
```

Individual component targets are also aliased:
`LibreSCRS::Auth`, `LibreSCRS::SmartCard`, `LibreSCRS::Plugin`,
`LibreSCRS::Signing`.

## Builder idiom

`SigningRequest::Builder::build()` is rvalue-qualified (`build() &&`),
so the chained `Builder{}.x().y().build()` form does NOT compile in this
codebase. Use a named builder and `std::move` into `build()`:

```cpp
LibreSCRS::Signing::SigningRequest::Builder sb;
sb.inputFile("/tmp/in.pdf");
sb.outputFile("/tmp/out.pdf");
sb.format(LibreSCRS::Signing::SignatureFormat::Pades);
sb.level(LibreSCRS::Signing::SignatureLevel::B_T);
auto sreq = std::move(sb).build();
```

## Related

The `LibreSCRS::*` umbrella and the private-header isolation rules this
example enforces are documented in the project's public API policy —
see `include/LibreSCRS/Export.h` for the in-tree summary and the
API-POLICY document on the project website for the normative text.
