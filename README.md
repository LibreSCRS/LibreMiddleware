# LibreMiddleware

**[librescrs.github.io](https://librescrs.github.io)**

Qt-free C++23 static libraries for reading smart cards via direct PC/SC APDU communication.

## Supported cards

**Full PKI through OpenSC.** OpenSC is the PKI engine. It works with every card OpenSC supports — the Serbian CardEdge cards (eID, qualified-signature/PKS, health) via the `srbeid` driver, plus IAS-ECC, CardOS, PIV, OpenPGP and more. Where OpenSC does not cover something, a built-in PKCS#15 plugin fills the gap (for example, on-card SHA-256 signing on the NAM card).

**Card data through plugins.** Built-in plugins read the document data: Serbian eID, Serbian health insurance, EU vehicle registration, and electronic passports (eMRTD, with PACE/BAC).

## Libraries

- **SmartCard** — PC/SC connection management, APDU, TLV/BER-TLV encoding
- **Card plugins** — data readers (Serbian eID, EU vehicle, Serbian health, eMRTD passport) and PKI backends (`opensc`, which drives OpenSC's driver chain; `pkcs15`, the generic gap-fill)
- **PKCS#11 module** — a standard PKCS#11 library for Firefox, Thunderbird, and other PKCS#11-aware applications
- **Signing / Trust** — AdES signing (XAdES, PAdES, CAdES, JAdES, ASiC-E), timestamping, and the async trust store

## Public C++ SDK (4.0)

LibreMiddleware exposes a stable public C++23 SDK under
`include/LibreSCRS/`, organised by namespace:

- `LibreSCRS::Auth` — credential providers, auth requirements
- `LibreSCRS::Certificate` — X.509 introspection (`ParsedCertificate`,
  `ObjectIdentifier`, `DistinguishedName`)
- `LibreSCRS::Plugin` — `CardPlugin` interface, `CardPluginService`,
  `AutoReaderService`, security checks
- `LibreSCRS::Secure` — cleansing `Buffer` / `String` for secret material
- `LibreSCRS::Signing` — `SigningService`, signing requests, TSA providers
- `LibreSCRS::SmartCard` — `CardSession`, `MonitorService`, low-level types
- `LibreSCRS::Trust` — unified async trust-store via `TrustStoreService`

Toolchain: GCC 13+ / Clang 16+ / AppleClang 16+. The build enforces
`std::expected` availability via a CMake `try_compile` probe at
`cmake/check-std-expected.cpp`.

### C++23 Idioms in 4.0

- **`std::expected<T, E>`** — every public fallible factory returns
  this shape (`ParsedCertificate::fromDer`, `CardSession::open`,
  `TrustStoreService::create`). See
  [developer-guide/sdk-reference/expected-result-handling][exp-doc] for
  the canonical consumption idioms.
- **`std::span<const std::uint8_t>`** — every byte-buffer parameter
  (ATR, DER, raw card data). See e.g. `CardPluginService::findPluginForCard`,
  `CardPlugin::canHandle`.
- **`std::format` / `std::print`** — diagnostic detail string
  composition inside Error types.
- **`std::variant` + tagged structs** — `LocalizedText::Placeholder`
  typed value payloads (Count / String / Hex / Date / Bool).
- **C++20 concepts** — `Auth::detail::SecretParameter` gates the
  credential-bearing overload set.
- **`[[nodiscard]]`** — every result type, factory, and accessor.

[exp-doc]: https://librescrs.github.io/developer-guide/sdk-reference/expected-result-handling/

A complete consumer example is at `examples/sdk-consumer/main.cpp`. See
the project documentation site for the full SDK reference and migration
guides.

### Consuming as an installed shared library

Set `-DLIBREMIDDLEWARE_BUILD_SHARED=ON` to produce versioned `.so`
libraries plus a CMake Config package so downstream projects can use
`find_package(LibreMiddleware 4.0 REQUIRED CONFIG)` and link against
namespaced `LibreMiddleware::*` imported targets. The full consumer
documentation is at
[`docs/SHARED-LIBRARY-CONSUMERS.md`](docs/SHARED-LIBRARY-CONSUMERS.md);
the self-contained worked example with end-to-end driver script is at
`examples/sdk-consumer-config/`.

### Quick build

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DSIGNING_BACKEND=both
cmake --build build -j4
(cd build && ctest --output-on-failure -j4)
```

`SIGNING_BACKEND=both` enables both the native libresign engine and the
DSS Java fallback. `-DLIBRESCRS_BUILD_EXAMPLES=ON` builds the SDK
consumer.

## API stability

The 4.x surface is locked by an ABI snapshot baseline at
`ci/abi/4.x-baseline.txt`. CI diffs every pull request against the
baseline and fails on any add / remove / signature change to the
public C++ surface. Intentional API changes require a baseline update
via `ci/scripts/abi-snapshot.sh --update build`, reviewed in the same
commit as the change.

The public surface follows the conventions documented in the
[LibreSCRS API Policy](https://LibreSCRS.github.io/developer-guide/sdk-reference/api-policy/):
named factories on closed-shape result types, append-only enums, pimpl
+ ABI version sentinel for plugin loading, thread-safety paragraph on
every `LIBRESCRS_PUBLIC_API` class.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for code-formatting expectations
(clang-format-21 pin), commit conventions, and the optional pre-commit
hook.

## License

LGPL-2.1-or-later — see [LICENSE](LICENSE) for details.

## Source availability

LibreMiddleware is licensed under LGPL-2.1-or-later. It links statically
against modified versions of LGPL-licensed components (notably OpenSC).

The complete corresponding source code for this software, including
all modified LGPL components, is publicly available at:

- https://github.com/LibreSCRS/LibreMiddleware
- https://github.com/LibreSCRS/LibreCelik

This offer is valid for as long as we distribute this software.
