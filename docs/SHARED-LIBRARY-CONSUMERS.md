<!--
SPDX-License-Identifier: LGPL-2.1-or-later
SPDX-FileCopyrightText: 2026 hirashix0
-->

# Consuming LibreMiddleware as a shared library

Starting with LibreMiddleware 4.0, downstream projects (LibreKDE,
LibreLinux, third-party tools) can consume LM via CMake's
`find_package(LibreMiddleware ... CONFIG)`. This document covers
build options, version pinning, and the public target surface.

## Build options

| Option | Default | Effect |
|---|---|---|
| `LIBREMIDDLEWARE_BUILD_SHARED` | `OFF` | Builds public `LibreSCRS_*` archives as SHARED libraries with `SOVERSION = MAJOR`. |
| `LIBRESCRS_INSTALL_SDK_HEADERS` | `OFF` | Installs public headers under `include/LibreSCRS/`. Implicit ON when `LIBREMIDDLEWARE_BUILD_SHARED=ON`. |

LibreCelik's existing in-tree FetchContent build path uses the default
(STATIC). External consumers requiring `find_package` set
`LIBREMIDDLEWARE_BUILD_SHARED=ON`.

## Public targets

| In-tree | Installed | Purpose |
|---|---|---|
| `LibreSCRS::Auth` | `LibreMiddleware::Auth` | Auth requirements, secure string types, credential providers |
| `LibreSCRS::SmartCard` | `LibreMiddleware::SmartCard` | PCSC sessions, monitor service, reader enumeration |
| `LibreSCRS::Plugin` | `LibreMiddleware::Plugin` | `CardPlugin` interface, `CardPluginService` registry |
| `LibreSCRS::Signing` | `LibreMiddleware::Signing` | `SigningService`, `SigningRequest`, signature engine |
| `LibreSCRS::Trust` | `LibreMiddleware::Trust` | `TrustStore`, certificate validation |
| `LibreSCRS::Certificate` | `LibreMiddleware::Certificate` | X.509 utilities |
| `LibreSCRS::Secure` | `LibreMiddleware::Secure` | INTERFACE alias for secure-allocator-using types |
| `LibreSCRS::All` | `LibreMiddleware::All` | INTERFACE convenience aggregating the six archive targets |

The asymmetry between source namespace (`LibreSCRS::*`) and package
namespace (`LibreMiddleware::*`) is deliberate per the project naming
convention: `LibreSCRS` is the source/code namespace, `LibreMiddleware`
is the artefact/package namespace. Headers retain the `LibreSCRS::`
spelling under all build modes; only the CMake import names differ.

## Version pinning

`LibreMiddlewareConfigVersion.cmake` declares `SameMajorVersion`
compatibility. A consumer requesting
`find_package(LibreMiddleware 4.0 REQUIRED CONFIG)`:

- accepts any installed `4.x.y`;
- rejects `3.x.y` (older major) and `5.x.y` (newer major).

**This rule governs the source / CMake contract only.** It says which
package a build is willing to compile and link against. It is not what
the dynamic loader consults at run time, and it is not the SONAME — see
the next section.

## The SONAME is not the release version

The `LibreSCRS_*` shared objects carry a SONAME integer of their own
(`LIBRESCRS_ABI_SOVERSION` in the top-level `CMakeLists.txt`), decoupled
from `PROJECT_VERSION`. It is raised in any release where
`ci/scripts/abi-layout.sh` reports a non-additive change — a type whose
size moved, a member whose offset shifted, a virtual whose slot changed
occupant — **whether or not that release is a major**. Conversely, a new
major does not raise it by itself.

Packagers should therefore read the SONAME off the artefact rather than
deriving it from the version:

```sh
readelf -d libLibreSCRS_Plugin.so.* | grep SONAME
```

Consequently the file name and the SONAME need not agree: a build whose
`PROJECT_VERSION` is still `4.2.0` produces
`libLibreSCRS_Plugin.so.4.2.0` with `SONAME libLibreSCRS_Plugin.so.5`
once the shape has moved. That is the decoupling working as intended,
not a packaging error.

## Consumer example

`find_package(LibreMiddleware REQUIRED COMPONENTS Auth)` (per-component
selection) is **not** supported — the package does not declare
per-component found-variables. Always use the bare invocation and pick
imported targets via `target_link_libraries`. Consumers that need a
specific minor version pin can use the CMake 3.19+ `VERSION_RANGE` shape
(`find_package(LibreMiddleware 4.1...<5.0 REQUIRED CONFIG)`).

```cmake
cmake_minimum_required(VERSION 3.24)
project(my_consumer LANGUAGES CXX)

find_package(LibreMiddleware 4.0 REQUIRED CONFIG)

add_executable(my_consumer main.cpp)
target_compile_features(my_consumer PRIVATE cxx_std_23)
target_link_libraries(my_consumer
    PRIVATE LibreMiddleware::SmartCard LibreMiddleware::Plugin)
```

```cpp
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
```

A complete working example lives at `examples/sdk-consumer-config/`,
including a `build-and-run.sh` driver that exercises the full install →
configure → build → run flow against a temporary install prefix.

## Card plugins (runtime-loaded)

Card readers are reached through `LibreMiddleware::Plugin` —
`LibreSCRS::Plugin::CardPluginService` constructs a registry and
`dlopen()`s the `lib*-plugin.so` files inside the directory you pass it.
The plugins are independent `.so` artefacts (one per card family —
`libcardedge-plugin.so`, `libpkcs15-plugin.so`, `libemrtd-plugin.so`,
…); they are **not** linked into the public LibreMiddleware libraries.

### Install layout

When `LIBREMIDDLEWARE_BUILD_SHARED=ON`, `cmake --install` puts the
plugin `.so` files at:

    ${CMAKE_INSTALL_LIBDIR}/librescrs/plugins/lib<id>-plugin.so

and the per-plugin `manifest.json` (capabilities + supported-ATR
metadata) at:

    ${CMAKE_INSTALL_DATAROOTDIR}/librescrs/plugins/<id>/manifest.json

On a typical Linux distro this resolves to
`/usr/lib/librescrs/plugins/` and `/usr/share/librescrs/plugins/<id>/`.

### Discovering the plugin directory at runtime

Consumers should resolve the plugin path in this order:

1. **`LIBRESCRS_PLUGIN_PATH` environment variable** — explicit override,
   intended for development and per-user installs.
2. **Build-tree path** — when the consumer is co-built with LM via
   FetchContent, the CMake cache variable
   `LIBREMIDDLEWARE_PLUGIN_DIR` points at the build-tree plugins.
3. **Install-tree convention** —
   `${CMAKE_INSTALL_FULL_LIBDIR}/librescrs/plugins/` (i.e. matching the
   install location above).

Pass the resolved path to `CardPluginService`'s constructor:

```cpp
std::filesystem::path plugins =
    /* resolution per the order above */;
LibreSCRS::Plugin::CardPluginService registry{plugins};
```

## p11-kit integration — the agent proxy owns the registration

A host must expose exactly **one** LibreSCRS PKCS#11 provider, and it is the
agent proxy shipped by LibreLinux. The proxy collects the PIN in the agent's
prompter, behind an authorization prompt and a lease; this module collects it
inside whatever application dlopened it. Two registered providers for one card
are two independent security models, and the choice between them falls to
whichever dialog the user happens to type into.

`LIBREMIDDLEWARE_INSTALL_P11KIT_MODULE` is therefore **`OFF` by default**.
A default install places the library and no declaration at all:

    ${CMAKE_INSTALL_LIBDIR}/pkcs11/librescrs-pkcs11.so       (the .so)

Turning the option `ON` additionally installs

    ${CMAKE_INSTALL_DATADIR}/p11-kit/modules/librescrs.module (registration)

which is the escape hatch for a headless host that runs no agent, and for the
opt-in out-of-process deployment. It is not the supported desktop arrangement.

`librescrs.module` references the `.so` by bare filename; p11-kit resolves it
via its standard `${libdir}/pkcs11/` search path. Priority is 10 — well below
typical vendor middleware (50+) so proprietary middleware shipped with eID
hardware wins automatic resolution when both are installed.

### Packaging contract

This is the split this project **intends to ship**; no `librescrs-*` package has
been published yet, so nothing below describes an install base that exists
today. It is written down here because the invariant it protects is decided
here, and packaging only executes it.

    librescrs-middleware      usr/lib/pkcs11/librescrs-pkcs11.so          ← the .so only, NO .module
    librescrs-pkcs11-direct   usr/share/p11-kit/modules/librescrs.module  ← eight lines and nothing else
                              depends=('librescrs-middleware')
                              conflicts=('librescrs-agent')
    librescrs-agent           usr/lib/pkcs11/librescrs-pkcs11-agent.so
                              usr/share/p11-kit/modules/librescrs-agent.module
                              usr/lib/systemd/user/librescrs-p11-server.service
                              conflicts=('librescrs-pkcs11-direct')

Three things about it must not be lost in translation to a package recipe:

- The invariant is: *after installing any supported set of packages, the three
  directories p11-kit reads contain exactly one file naming a LibreSCRS
  provider, and it names the proxy.* By default that holds because nobody
  registers the direct module — which is **stronger than a conflict**, since
  there is nothing to conflict with.
- The conflict is declared from **both** sides deliberately. A one-sided
  conflict still permits coexistence when the side that was not named happens
  to be installed first.
- The name is `librescrs-pkcs11-direct`, **not** a bare `librescrs-pkcs11`.
  The bare name is what the released tarball was called and what the website
  still advertises, so reusing it for a package of the opposite meaning would
  let a stale link resolve to a different thing.

### Consumers

With the proxy registered by the agent, p11-kit-aware applications — Firefox,
Thunderbird, Chromium (via NSS), Evolution, KMail — discover the card with no
application-side configuration. The GnuPG stack (Kleopatra, `gpgsm`) is **not**
among them: it does not consume p11-kit at all, its card daemon speaks PC/SC
directly.

## Bundled dependencies

The SHARED `LibreSCRS_*` libraries bake in their own copies of the
LibreMiddleware-internal static archives that LibreCelik consumes
in-tree:

- bundled OpenSSL 3.5.5 (`thirdparty/openssl-3.5.5/{linux,macosx}`)
- `LibreSign` (private signing engine)
- `SmartCard_Impl`, `CardPlugin_Impl` (PC/SC + plugin runtime helpers)

Downstream consumers do **not** need to link these separately. The
exported `LibreMiddleware::*` imported targets do not propagate any
in-tree-only dep through `INSTALL_INTERFACE` (each in-source link uses
`$<BUILD_INTERFACE:>` to scope the propagation).

System dependencies that downstream consumers DO see via
`find_dependency` in `LibreMiddlewareConfig.cmake`:

- `OpenSSL 3.0` (`COMPONENTS Crypto`) — system OpenSSL; not the bundled
  one. Used at the consumer's own translation units if any reference
  OpenSSL types directly. The LibreMiddleware public headers do not
  expose OpenSSL types, so most consumers won't actually need it at
  compile time.
- `PCSC` — system PC/SC. `FindPCSC.cmake` is shipped next to the Config
  file so consumers don't need their own copy in `CMAKE_MODULE_PATH`.

## Distribution packaging

Linux distros with shared-library policies (Debian, Fedora, openSUSE,
Arch) build LibreMiddleware with `LIBREMIDDLEWARE_BUILD_SHARED=ON` and
ship:

- `libLibreSCRS_<Component>.so.5` — runtime soname (in `lib/`), from
  `LIBRESCRS_ABI_SOVERSION`, not from the release major
- `libLibreSCRS_<Component>.so.<PROJECT_VERSION>` — versioned binary (in
  `lib/`); the two numbers are independent, so do not assume the file
  name begins with the soname's integer
- Headers under `include/LibreSCRS/<Component>/...`
- Config package under `lib/cmake/LibreMiddleware/`

The runtime, development, and Config-package bits map to typical
`-runtime` / `-dev` / `-cmake` split packages per distro convention.

LibreCelik continues to ship a self-contained AppImage / DMG using the
static path; nothing changes for end-user binary downloads.
