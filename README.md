# LibreMiddleware

**[librescrs.github.io](https://librescrs.github.io)**

Qt-free C++23 static libraries for reading smart cards via direct PC/SC APDU communication.

## Supported Cards

- **eMRTD / ePassport** — ICAO 9303 compliant passports and national ID cards (PACE, BAC, Secure Messaging)
- **Serbian eID** — Gemalto 2014+, IF2020 Foreigner (personal data, photo, certificates)
- **Serbian Vehicle Registration (EU VRC)** — EU Directive 2003/127/EC (all mandatory and optional fields)
- **Serbian Health Insurance (RFZO)** — insured person, employer, insurance details
- **PIV (NIST SP 800-73)** — certificates, photo, fingerprints, PIN management
- **PKCS#15** — generic PKI card support (certificate discovery, PIN management, digital signing)

## Libraries

- **SmartCard** — PC/SC connection management, APDU, TLV/BER-TLV encoding
- **RsEId** — Serbian eID card protocol
- **EuVrc** — EU vehicle registration card protocol
- **RsHealth** — Serbian health insurance card protocol
- **eMRTD** — electronic travel document protocol with cryptographic authentication
- **PIV** — NIST PIV card protocol
- **PKCS15** — PKCS#15 token operations
- **CardEdge** — CardEdge applet operations (PIN management, signing, certificate discovery)
- **CardEdge PKCS#11** — shared library for Firefox, Thunderbird, and other PKCS#11-aware applications
- **CardEdge OpenSC Driver** — external OpenSC driver for CardEdge-based cards

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

The 4.0 surface is locked by an ABI snapshot baseline at
`ci/abi/4.0-baseline.txt`. The CI's `abi-stability-check` job diffs
every pull request against the baseline and fails on any add /remove /
signature change to the public C++ surface. Intentional API changes
require a baseline update via
`ci/scripts/abi-snapshot.sh --update build`.

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
