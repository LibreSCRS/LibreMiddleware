# LibreMiddleware

**[librescrs.github.io](https://librescrs.github.io)**

Middleware libraries for reading Serbian smart cards (eID, vehicle registration, health insurance, PKS qualified signature) via direct PC/SC APDU communication.

## Libraries

- **SmartCard** — PC/SC connection management, APDU command/response, TLV and BER-TLV encoding/decoding
- **EIdCard** — Serbian electronic ID card protocol (Apollo 2008, Gemalto 2014+, Foreigner IF2020)
- **VehicleCard** — Serbian vehicle registration document protocol
- **RsHealth** — Serbian health insurance card (RFZO/RFZO LBO)
- **PKSCard** — PKS qualified signature card (Chamber of Commerce of Serbia)
- **CardEdge** — Generic CardEdge/PKCS#15 applet operations (PIN management, signing, certificate discovery)
- **PKCS#11** — PKCS#11 module (`librescrs-pkcs11`) for use with Firefox, NSS, OpenSC tools, and other PKCS#11-aware applications

All libraries are Qt-free, use C++20, and produce static libraries (except the PKCS#11 module which is a shared library).

## Prerequisites

- CMake 3.24+
- C++20 compiler (GCC 11+, Clang 14+, Apple Clang 15+)
- PC/SC library (PCSC-Lite on Linux, built-in on macOS)
- OpenSSL 3.x (bundled as static library in `thirdparty/`)

## Building (standalone)

```bash
cmake -B build
cmake --build build
```

## Running tests

```bash
cmake --build build
cd build && ctest --output-on-failure
```

To disable tests: `cmake -B build -DBUILD_TESTING=OFF`

## PKCS#11 Module

The `librescrs-pkcs11` shared library allows PKCS#11-aware applications (Firefox, Thunderbird, OpenSC tools) to use Serbian smart cards for TLS client authentication and digital signing.

### Building the PKCS#11 module

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target librescrs-pkcs11
```

### Packaging

```bash
# Linux
scripts/linux/build-pkcs11-tar.sh build

# macOS
scripts/macos/build-pkcs11-zip.sh build
```

Pre-built packages are available on the [Releases](https://github.com/LibreSCRS/LibreMiddleware/releases) page.

### Firefox setup

1. Install the PKCS#11 module to `/usr/local/lib/librescrs-pkcs11.so` (Linux) or `/usr/local/lib/librescrs-pkcs11.dylib` (macOS)
2. In Firefox: `about:preferences#privacy` → Security Devices → Load → point to the library path
3. Insert your Serbian eID card — Firefox will offer it for TLS client authentication

## Using as a dependency (FetchContent)

```cmake
include(FetchContent)
FetchContent_Declare(LibreMiddleware
    GIT_REPOSITORY https://github.com/LibreSCRS/LibreMiddleware.git
    GIT_TAG 1.3.1
)
FetchContent_MakeAvailable(LibreMiddleware)

# Link against the libraries you need
target_link_libraries(YourTarget PRIVATE RsEId VehicleCard RsHealth PKSCard)

# Access certificates directory
message(STATUS "Certificates: ${LIBREMIDDLEWARE_CERTIFICATES_DIR}")
```

The `CMAKE_MODULE_PATH` is automatically extended to include `FindPCSC.cmake` and `FindUUID.cmake`.

## Bundled CA certificates

`thirdparty/certificates/all/` contains trusted CA certificates for verifying Serbian government smart cards:

- **MUP** (Ministry of Interior) — root and issuing CAs for eID cards (Generations 1–4)
- **PKS** (Chamber of Commerce of Serbia) — root and Class 1 CA for qualified signature cards

## License

LGPL-2.1-or-later — see [LICENSE](LICENSE) for details.
