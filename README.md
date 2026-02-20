# LibreMiddleware

Middleware libraries for reading Serbian smart cards (eID, vehicle registration, residence permits) via direct PC/SC APDU communication.

## Libraries

- **SmartCard** — PC/SC connection management, APDU command/response, TLV and BER-TLV encoding/decoding
- **EIdCard** — Serbian electronic ID card protocol (Apollo 2008, Gemalto 2014+, Foreigner IF2020)
- **VehicleCard** — Serbian vehicle registration document protocol

All libraries are Qt-free, use C++20, and produce static libraries.

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

## Using as a dependency (FetchContent)

```cmake
include(FetchContent)
FetchContent_Declare(LibreMiddleware
    GIT_REPOSITORY <repo-url>
    GIT_TAG main
)
FetchContent_MakeAvailable(LibreMiddleware)

# Link against the libraries
target_link_libraries(YourTarget PRIVATE EIdCard VehicleCard)

# Access certificates directory
message(STATUS "Certificates: ${LIBREMIDDLEWARE_CERTIFICATES_DIR}")
```

The `CMAKE_MODULE_PATH` is automatically extended to include `FindPCSC.cmake` and `FindUUID.cmake`.

## License

LGPL-2.1-or-later — see [LICENSE](LICENSE) for details.
