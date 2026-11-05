<!--
SPDX-License-Identifier: LGPL-2.1-or-later
SPDX-FileCopyrightText: 2026 hirashix0
-->

# Consuming LibreMiddleware as a shared library

Starting with LibreMiddleware 4.0, downstream projects (LibreLinux,
LibreAgent, LibreDarwin, third-party tools) can consume LM via CMake's
`find_package(LibreMiddleware ... CONFIG)`. This document covers
build options, version pinning, and the public target surface.

## Build configuration

LibreMiddleware builds one way: every public `LibreSCRS_*` library is a
shared library, with the SONAME taken from `LIBRESCRS_ABI_SOVERSION` and
not from the release major (see below), and `cmake --install` always
installs the public headers under `include/LibreSCRS/` and the CMake
Config package. There is no static configuration: card plugins are
loaded at run time, and the process-wide state the libraries hold must
have exactly one definition per process.

## Public targets

| Target | Purpose |
|---|---|
| `LibreSCRS::Auth` | Auth requirements, secure string types, credential providers |
| `LibreSCRS::SmartCard` | PCSC sessions, monitor service, reader enumeration |
| `LibreSCRS::Plugin` | `CardPlugin` interface, `CardPluginService` registry |
| `LibreSCRS::Signing` | `SigningService`, `SigningRequest`, signature engine |
| `LibreSCRS::Trust` | `TrustStore`, certificate validation |
| `LibreSCRS::Certificate` | X.509 utilities |
| `LibreSCRS::Secure` | INTERFACE alias for secure-allocator-using types |

One spelling, in-tree and installed. `LibreMiddleware` names the package
a consumer asks `find_package` for; `LibreSCRS` names every target inside
it, matching the C++ namespace (`LibreSCRS::Foo::Bar`) and the header
paths (`<LibreSCRS/...>`). Up to 4.x the export carried the package name
and the source spelling was mirrored on top of it so either would link;
the mirror is gone and the source spelling is the export.

## Version pinning

`LibreMiddlewareConfigVersion.cmake` declares `SameMajorVersion`
compatibility. A consumer requesting
`find_package(LibreMiddleware 5.0 REQUIRED CONFIG)`:

- accepts any installed `5.x.y`;
- rejects `4.x.y` (older major) and `6.x.y` (newer major).

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

Consequently the file name and the SONAME need not agree. In this release
they happen to — `libLibreSCRS_Plugin.so.5.0.0` carries
`SONAME libLibreSCRS_Plugin.so.5` — only because the last layout break and
the last major landed together. They part company whenever one moves
without the other: a minor release that breaks layout keeps its file name
inside the current major line and raises the SONAME, and a new major that
breaks nothing moves the file name and leaves the SONAME where it is.
Either shape is the decoupling working as intended, not a packaging error.

Which releases each SONAME integer covers is recorded in exactly one place,
the `LIBRESCRS_ABI_SOVERSION` cache entry in the top-level `CMakeLists.txt`.
This document deliberately does not restate those numbers, so the two cannot
drift apart.

## Consumer example

`find_package(LibreMiddleware REQUIRED COMPONENTS Auth)` (per-component
selection) is **not** supported — the package does not declare
per-component found-variables. Always use the bare invocation and pick
imported targets via `target_link_libraries`. Consumers that want to state
both ends can use the CMake 3.19+ `VERSION_RANGE` shape
(`find_package(LibreMiddleware 5.0...<6.0 REQUIRED CONFIG)`). The lower
bound is a real floor and not a label: under `SameMajorVersion` a range
whose low end is above the installed version is refused before the majors
are compared at all, so `5.1...<6.0` against an installed 5.0.0 fails with
`no configuration file compatible with requested version range`. Name a
lower bound the release you build against actually reaches.

```cmake
cmake_minimum_required(VERSION 3.24)
project(my_consumer LANGUAGES CXX)

find_package(LibreMiddleware 5.0 REQUIRED CONFIG)

add_executable(my_consumer main.cpp)
target_compile_features(my_consumer PRIVATE cxx_std_23)
target_link_libraries(my_consumer
    PRIVATE LibreSCRS::SmartCard LibreSCRS::Plugin)
```

```cpp
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
```

A complete working example lives at `examples/sdk-consumer-config/`,
including a `build-and-run.sh` driver that exercises the full install →
configure → build → run flow against a temporary install prefix.

## Test support: `LibreSCRS::SmartCardTesting`

`LibreSCRS::SmartCardTesting` (`<LibreSCRS/SmartCard/testing/CardSessionTesting.h>`)
is a **static** archive in the development files, for the tests of projects
built on LibreSCRS. Unlike the shared libraries it is bound to one release,
not to a SONAME: it writes the private state of `CardSession`, whose layout
is not part of the ABI `LIBRESCRS_ABI_SOVERSION` tracks and may change in any
release, minor or patch.

- Link it only against the shared libraries of the **same** release. The
  package's `SameMajorVersion` rule cannot enforce that, and neither can the
  dynamic loader: a test binary linked against 5.0 starts against a later
  `libLibreSCRS_SmartCard.so.5` without complaint and misreads the session.
- **Rebuild your tests whenever LibreMiddleware is upgraded**, before running
  them. A build tree's test binaries are stale after an upgrade even when
  nothing in your sources changed.
- Packagers: tests that link this archive belong to the build (`%check`,
  `dh_auto_test`), run against the release being built — never in a package
  installed beside a different release of the runtime libraries.

## Card plugins (runtime-loaded)

Card readers are reached through `LibreSCRS::Plugin` —
`LibreSCRS::Plugin::CardPluginService` constructs a registry and
`dlopen()`s the `lib*-plugin.so` files inside the directory you pass it.
The plugins are independent `.so` artefacts (one per card family —
`librs-eid-plugin.so`, `libpkcs15-plugin.so`, `libemrtd-plugin.so`,
…); they are **not** linked into the public LibreMiddleware libraries.

### Install layout

`cmake --install` puts the plugin `.so` files at:

    ${CMAKE_INSTALL_LIBDIR}/librescrs/plugins/lib<id>-plugin.so

and the per-plugin `manifest.json` (capabilities + supported-ATR
metadata) at:

    ${CMAKE_INSTALL_DATAROOTDIR}/librescrs/plugins/<id>/manifest.json

On a typical Linux distro this resolves to
`/usr/lib/librescrs/plugins/` and `/usr/share/librescrs/plugins/<id>/`.

### Discovering the plugin directory at runtime

LibreMiddleware reads no environment variable for this: the host chooses the
directory and hands it to `CardPluginService`. (The LibreSCRS agent on Linux,
for example, honours `LIBRESCRS_PLUGIN_DIR` as its own override.) A host
should resolve the plugin path in this order:

1. **Its own override**, if it offers one — intended for development and
   per-user installs.
2. **Install-tree convention** —
   `${CMAKE_INSTALL_FULL_LIBDIR}/librescrs/plugins/` (i.e. matching the
   install location above).

Pass the resolved path to `CardPluginService`'s constructor:

```cpp
std::filesystem::path plugins =
    /* resolution per the order above */;
LibreSCRS::Plugin::CardPluginService registry{plugins};
```

## PKCS#11 — the agent's provider is the only one

LibreMiddleware ships no PKCS#11 module. The one LibreSCRS PKCS#11 provider a
host sees is the agent's, shipped and registered with p11-kit by the agent's
own package: it reaches the card through the agent, which owns the reader,
collects the PIN in its own prompter behind an authorization prompt and a
lease, and watches for card removal. A module that opened the card from inside
whatever application loaded it would be a second connection to the card beside
the agent's, and a second PIN-entry model.

### Packaging contract

    librescrs-agent           usr/lib/pkcs11/librescrs-pkcs11-agent.so
                              usr/share/p11-kit/modules/librescrs-agent.module

The invariant is: *after installing any supported set of packages, the three
directories p11-kit reads contain exactly one file naming a LibreSCRS provider,
and it names the agent's.* The middleware packages install no module and no
declaration.

The signing API does not use PKCS#11 at all: a document signature is made
through the card plugin on the session the caller already holds.

### Consumers

With the agent's provider registered, p11-kit-aware applications — Firefox,
Thunderbird, Chromium (via NSS), Evolution, KMail — discover the card with no
application-side configuration. The GnuPG stack (Kleopatra, `gpgsm`) is **not**
among them: it does not consume p11-kit at all, its card daemon speaks PC/SC
directly.

## Bundled dependencies

The SHARED `LibreSCRS_*` libraries bake in their own copies of the
LibreMiddleware-internal static archives that LibreCelik consumes
in-tree:

- bundled OpenSSL 3.5.8 (`thirdparty/openssl-3.5.8/{linux,macosx}`)
- `LibreSign` (private signing engine)
- `SmartCard_Impl`, `CardPlugin_Impl` (PC/SC + plugin runtime helpers)

Each of these is hidden inside the libraries that carry it. Every exported
function has exactly one owning library: the plugin layer
(`CardPluginService`, `CardPlugin`) is exported by `libLibreSCRS_Plugin`
alone, and `libLibreSCRS_Signing` links it rather than carrying a copy. A
consumer that constructs plugins links `LibreSCRS::Plugin`, whatever else it
links.

Downstream consumers do **not** need to link these separately. The
exported `LibreSCRS::*` imported targets do not propagate any
in-tree-only dep through `INSTALL_INTERFACE` (each in-source link uses
`$<BUILD_INTERFACE:>` to scope the propagation).

`LibreMiddlewareConfig.cmake` calls no `find_dependency`. The shared
libraries link OpenSSL and PC/SC privately, no public header names a type
of either, and the exported targets' link interface lists only
`LibreSCRS::*` targets, so a consumer needs neither's development headers.
A consumer that uses OpenSSL or PC/SC itself finds them itself.

## Distribution packaging

Linux distros with shared-library policies (Debian, Fedora, openSUSE,
Arch) ship:

- `libLibreSCRS_<Component>.so.<LIBRESCRS_ABI_SOVERSION>` — runtime soname
  (in `lib/`). The integer is the cache entry's, not the release major's, so
  read it off the artefact rather than deriving it from the version
- `libLibreSCRS_<Component>.so.<PROJECT_VERSION>` — versioned binary (in
  `lib/`); the two numbers are independent, so do not assume the file
  name begins with the soname's integer
- Headers under `include/LibreSCRS/<Component>/...`
- Config package under `lib/cmake/LibreMiddleware/`

The runtime, development, and Config-package bits map to typical
`-runtime` / `-dev` / `-cmake` split packages per distro convention.

LibreCelik continues to ship a self-contained AppImage / DMG using the
static path; nothing changes for end-user binary downloads.
