# Bundled OpenSSL 3.5.5 (static)
set(OPENSSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/openssl-3.5.5)
add_library(OpenSSL_Crypto STATIC IMPORTED GLOBAL)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_target_properties(OpenSSL_Crypto PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_ROOT}/macosx/lib/libcrypto.a
        INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_ROOT}/macosx/include
    )
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set_target_properties(OpenSSL_Crypto PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_ROOT}/linux/lib/libcrypto.a
        INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_ROOT}/linux/include
        INTERFACE_LINK_LIBRARIES "dl;pthread"
    )
endif()

# Bundled OpenSSL TLS (static). curl's TLS backend references SSL_* symbols
# that live in libssl.a, which is separate from libcrypto.a (OpenSSL_Crypto).
add_library(OpenSSL_Ssl STATIC IMPORTED GLOBAL)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_target_properties(OpenSSL_Ssl PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_ROOT}/macosx/lib/libssl.a
        INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_ROOT}/macosx/include
    )
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set_target_properties(OpenSSL_Ssl PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_ROOT}/linux/lib/libssl.a
        INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_ROOT}/linux/include
    )
endif()

# ──────────────────────────────────────────────────────────────────────────
# Vendored libcurl (pinned curl-8_11_1), built STATIC against the BUNDLED
# OpenSSL above.
#
# Rationale (consistency, not a bug-fix): a system libcurl.so drags the host
# distribution's libssl/libcrypto.so into every consuming process, so the
# LibreSign signing engine would run with TWO OpenSSL instances — the bundled
# static OpenSSL 3.5.5 AND the host's dynamic OpenSSL. The native engine
# registers a custom OpenSSL provider ("librescrs") in the bundled OpenSSL's
# default OSSL_LIB_CTX; a second, unrelated OpenSSL in the same address space
# is a latent hazard and a portability inconsistency (macOS universal builds
# have no system OpenSSL at all and already use the bundled one). Vendoring
# curl against the bundled OpenSSL guarantees exactly ONE OpenSSL per process
# on every platform. curl is reached only by the TSA / CRL / OCSP / Trusted-
# List HTTP paths (B-T and higher); B-B detached signing never calls it.
#
# See thirdparty/README.md for the pin rationale and update procedure.
# ──────────────────────────────────────────────────────────────────────────
option(LIBRESCRS_VENDOR_CURL
    "Build a static libcurl against the bundled OpenSSL so exactly one OpenSSL is loaded per process" ON)
if(LIBRESCRS_VENDOR_CURL)
    include(ExternalProject)
    # Resolve system zlib up front: the bundled static libcrypto.a references
    # zlib (COMP), so curl's static-OpenSSL symbol check needs ZLIB_LIBRARY
    # resolved during OpenSSL detection — before curl's own find_package(ZLIB).
    find_package(ZLIB REQUIRED)

    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(CURL_OPENSSL_DIR ${OPENSSL_ROOT}/macosx)
    else()
        set(CURL_OPENSSL_DIR ${OPENSSL_ROOT}/linux)
    endif()
    set(CURL_SOURCE_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/curl-source)
    set(CURL_BUILD_DIR   ${CMAKE_CURRENT_BINARY_DIR}/curl-build)
    set(CURL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/curl-install)
    set(CURL_STATIC_LIB  ${CURL_INSTALL_DIR}/lib/libcurl.a)
    # IMPORTED INTERFACE_INCLUDE_DIRECTORIES must exist at configure time even
    # though ExternalProject populates it at build time.
    file(MAKE_DIRECTORY ${CURL_INSTALL_DIR}/include)

    set(_curl_osx_args "")
    if(APPLE AND CMAKE_OSX_ARCHITECTURES)
        set(_curl_osx_args
            -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
            -DCMAKE_OSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET})
    endif()

    # Minimal HTTPS-only curl: OpenSSL TLS against the bundled tree, no extra
    # protocol/codec deps (no ldap/psl/ssh/nghttp2/brotli/zstd/idn2). zlib IS
    # enabled (system) — the bundled static libcrypto.a references zlib (COMP),
    # so the static archive pulls in libssl/libcrypto + system zlib + libc.
    ExternalProject_Add(curl_external
        SOURCE_DIR  ${CURL_SOURCE_DIR}
        BINARY_DIR  ${CURL_BUILD_DIR}
        INSTALL_DIR ${CURL_INSTALL_DIR}
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=${CURL_INSTALL_DIR}
            -DCMAKE_BUILD_TYPE=Release
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON
            -DBUILD_SHARED_LIBS=OFF
            -DBUILD_STATIC_LIBS=ON
            -DBUILD_CURL_EXE=OFF
            -DBUILD_TESTING=OFF
            -DBUILD_LIBCURL_DOCS=OFF
            -DENABLE_CURL_MANUAL=OFF
            -DCURL_USE_OPENSSL=ON
            -DOPENSSL_ROOT_DIR=${CURL_OPENSSL_DIR}
            -DOPENSSL_USE_STATIC_LIBS=ON
            # The baked CA default is the build host's; CURL_CA_FALLBACK lets a
            # target whose layout differs fall back to the bundled OpenSSL's
            # default store instead of hard-failing TLS. Cross-platform / macOS /
            # AppImage portability is completed by HttpClient honouring
            # SSL_CERT_FILE / SSL_CERT_DIR at runtime (a packager ships cacert.pem).
            -DCURL_CA_PATH=auto
            -DCURL_CA_BUNDLE=auto
            -DCURL_CA_FALLBACK=ON
            -DCURL_DISABLE_LDAP=ON
            -DCURL_DISABLE_LDAPS=ON
            -DCURL_USE_LIBPSL=OFF
            -DCURL_USE_LIBSSH2=OFF
            -DCURL_USE_LIBSSH=OFF
            -DCURL_USE_GSSAPI=OFF
            -DUSE_NGHTTP2=OFF
            -DUSE_NGTCP2=OFF
            -DCURL_BROTLI=OFF
            -DCURL_ZSTD=OFF
            # zlib (system) is REQUIRED: the bundled static libcrypto.a was
            # built with zlib (COMP) support, so curl's static-OpenSSL link
            # check needs -lz. zlib carries no OpenSSL dependency, so linking
            # the system zlib does NOT reintroduce a second OpenSSL.
            -DCURL_ZLIB=ON
            -DZLIB_LIBRARY=${ZLIB_LIBRARIES}
            -DZLIB_INCLUDE_DIR=${ZLIB_INCLUDE_DIRS}
            -DUSE_LIBIDN2=OFF
            ${_curl_osx_args}
        BUILD_BYPRODUCTS  ${CURL_STATIC_LIB}
        LOG_CONFIGURE         TRUE
        LOG_BUILD             TRUE
        LOG_INSTALL           TRUE
        LOG_OUTPUT_ON_FAILURE TRUE
    )

    add_library(curl_static STATIC IMPORTED GLOBAL)
    set_target_properties(curl_static PROPERTIES
        IMPORTED_LOCATION             ${CURL_STATIC_LIB}
        INTERFACE_INCLUDE_DIRECTORIES ${CURL_INSTALL_DIR}/include
    )
    add_dependencies(curl_static curl_external)

    # libcurl.a ↔ libssl.a ↔ libcrypto.a are mutually recursive at link time;
    # rescan group on GNU ld/lld, plain ordering on Apple ld64 (multi-pass by
    # default) — same strategy as opensc_static_with_deps below. ZLIB::ZLIB
    # (system, resolved above) sits inside the group: the bundled libcrypto.a's
    # COMP objects reference inflate/deflate, pulled mid-scan.
    add_library(curl_static_with_deps INTERFACE)
    if(APPLE)
        target_link_libraries(curl_static_with_deps INTERFACE
            curl_static OpenSSL_Ssl OpenSSL_Crypto ZLIB::ZLIB)
    else()
        target_link_libraries(curl_static_with_deps INTERFACE
            "$<LINK_GROUP:RESCAN,curl_static,OpenSSL_Ssl,OpenSSL_Crypto,ZLIB::ZLIB>")
    endif()
endif()

# ──────────────────────────────────────────────────────────────────────────
# Vendored OpenSC (LibreSCRS fork, pinned commit 1b2d5c5b).
#
# Built as a STATIC archive via ExternalProject_Add so the
# librescrs-opensc-pkcs11 SHARED library can link it without pulling a
# runtime dependency on the host distribution's libopensc.
#
# See thirdparty/README.md for the pin rationale and update procedure.
# ──────────────────────────────────────────────────────────────────────────
if(NOT LIBRESCRS_VENDOR_OPENSC)
    message(STATUS "Vendored OpenSC: disabled (LIBRESCRS_VENDOR_OPENSC=OFF)")
    return()
endif()

include(ExternalProject)

set(OPENSC_SOURCE_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/opensc-source)
set(OPENSC_BUILD_DIR   ${CMAKE_CURRENT_BINARY_DIR}/opensc-build)
set(OPENSC_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/opensc-install)
set(OPENSC_STATIC_LIB  ${OPENSC_INSTALL_DIR}/lib/libopensc.a)

# OpenSC does not install its libopensc/ public headers (treated as private
# upstream — system distros don't ship them either). Consumers like our
# `lib/cardedge-opensc-driver` add the source tree as the include root so
# `<libopensc/opensc.h>` resolves to `${SOURCE_DIR}/src/libopensc/opensc.h`.
# We follow the same pattern for the vendored fork.
#
# `config.h` is generated by autoconf in the build dir and is referenced via
# `#include "config.h"` from libopensc internals — needed only if downstream
# code includes private libopensc internals; for the public API exported via
# libopensc/opensc.h + libopensc/pkcs15.h it is not required.
set(OPENSC_INCLUDE_SRC   ${OPENSC_SOURCE_DIR}/src)
set(OPENSC_INCLUDE_BUILD ${OPENSC_BUILD_DIR})

# The vendored OpenSC tracks upstream directly (no downstream patches): the
# srbeid CardEdge driver, its RSA-2048 raw signing/decryption, and the G&D SCE7
# PIV support are all merged upstream. The stamp-invalidation guard below still
# tracks the vendored sources by mtime so a submodule bump re-links libopensc.a.
set(_opensc_any_patch_applied FALSE)

set(_opensc_stamp_dir
    ${CMAKE_CURRENT_BINARY_DIR}/opensc_external-prefix/src/opensc_external-stamp)

# ExternalProject_Add tracks step completion via stamp files. Once
# opensc_external-build exists, the build step is treated as done and not
# re-run even if the source tree changed after the stamp was written. Two
# things can change the vendored source after a stamp exists:
#
#   1. A freshly-applied patch (handled by _opensc_any_patch_applied).
#   2. A DIRECT edit to the vendored fork's own files — the parts we maintain
#      in-tree rather than via a .patch (e.g. src/libopensc/card-srbeid.c).
#      autoconf/ExternalProject has no dependency edge from these to the build
#      stamp, so an edited driver silently never reaches libopensc.a and the
#      built backend keeps running the stale object. (This is what hid the
#      256-byte PSO:DECIPHER fix: the srbeid driver carried the short-Lc
#      P2-stripping but libopensc.a predated the edit, so the agent kept
#      aborting the decipher before the PSO.)
#
# Guard against (2) by invalidating the build/install/done stamps whenever any
# of the directly-maintained vendored sources is newer than the build stamp.
# Build-only: it only controls WHEN `make` re-runs; it cannot change runtime
# behaviour or the produced code (so it cannot regress sign / NAM / AET).
set(_opensc_vendored_sources
    ${OPENSC_SOURCE_DIR}/src/libopensc/card-srbeid.c
    ${OPENSC_SOURCE_DIR}/src/libopensc/card-srbeid.h)
set(_opensc_sources_changed FALSE)
if(EXISTS ${_opensc_stamp_dir}/opensc_external-build)
    foreach(_src ${_opensc_vendored_sources})
        if(EXISTS ${_src} AND ${_src} IS_NEWER_THAN ${_opensc_stamp_dir}/opensc_external-build)
            set(_opensc_sources_changed TRUE)
        endif()
    endforeach()
endif()

if(_opensc_any_patch_applied OR _opensc_sources_changed)
    # Delete the build + install + done stamps so the next build pass re-runs
    # make → re-links libopensc.a with the current source.
    file(REMOVE
        ${_opensc_stamp_dir}/opensc_external-build
        ${_opensc_stamp_dir}/opensc_external-install
        ${_opensc_stamp_dir}/opensc_external-done)
    if(_opensc_any_patch_applied)
        message(STATUS "OpenSC: patch applied; invalidated build/install/done stamps")
    else()
        message(STATUS "OpenSC: vendored source newer than build stamp; invalidated build/install/done stamps")
    endif()
endif()

# PCSC strategy: vendored OpenSC owns its own PCSC session for the cards
# it claims (rs-eid via srbeid driver, etc.). Cross-process PCSC contention
# is left to the host PC/SC daemon's existing session arbitration; no
# explicit lock coordination across providers.
# libpcsclite is a system dep (autoconf detects it via --enable-pcsc).
# Presence is expected on Linux build hosts; consumers link it via the
# `opensc_static_with_deps` wrapper below.
set(OPENSC_CONFIGURE_FLAGS
    --prefix=${OPENSC_INSTALL_DIR}
    --disable-shared
    --enable-static
    --disable-tests
    --disable-doc
    --disable-man
    --enable-pcsc
    # Headless backend embedding has no use for OpenSC's desktop-notification
    # feature. Leaving it at autoconf's `detect` default makes notify.c pull in
    # GIO/GLib whenever the build host happens to ship gio-2.0, which then
    # leaves the static-archive consumers (OpenScPkcs11UnitTests, …) with
    # undefined g_application_*/g_notification_* references unless every
    # consuming environment also provides gio on its link line. Disabling it
    # outright keeps the link deterministic and drops the GIO/GLib edge.
    --disable-notify
    --with-pic
    # Redirect p11-kit module install into the staging dir; otherwise OpenSC
    # tries to write opensc.module into /usr/share/p11-kit/modules/ during
    # `make install` (system path detected via pkg-config p11-kit-1) and
    # fails with EACCES on non-root builds. We don't need the p11-kit
    # config file anyway — librescrs-opensc-pkcs11 statically links libopensc.
    --enable-p11_system_config_modules=${OPENSC_INSTALL_DIR}/share/p11-kit/modules
)

# CFLAGS for the vendored OpenSC build. Autoconf defaults to `-g -O2` when
# CFLAGS is unset, which produces a libopensc.a carrying full DWARF debug
# info (~7 MB of .debug_* sections) that propagates into every consuming
# shared library at link time. Mirror the consumer's build type instead:
#
#  - Release        → -O2 (no -g): drops DWARF from the static archive.
#  - RelWithDebInfo → -O2 -g
#  - Debug          → -O0 -g
#
# `-ffunction-sections -fdata-sections` lets the consuming `.so`'s linker
# `--gc-sections` drop unused OpenSC objects (drivers, helpers we never
# call). Net effect: `librescrs-pkcs11.so` Release shrinks from ~15 MB
# to ~8 MB, matching the size of the project's other static-linked plugins.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(OPENSC_CFLAGS "-O0 -g -ffunction-sections -fdata-sections")
elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(OPENSC_CFLAGS "-O2 -g -ffunction-sections -fdata-sections")
else()
    # Release and any other (including unset → autoconf would default `-g -O2`)
    set(OPENSC_CFLAGS "-O2 -ffunction-sections -fdata-sections")
endif()

# macOS universal binary: clang produces fat .o files when given multiple
# -arch flags, and autoconf's compile/link probes still pass because the
# host runs the slice matching its hardware. Same approach as upstream
# OpenSC's own packaging script (thirdparty/opensc-source/MacOSX/build).
# Point autoconf at the bundled fat libcrypto via -L/-l (not a direct .a
# path) so libtool treats it as a normal link target — passing the .a
# directly makes libtool repack the fat archive as a single member of
# every OpenSC module .dylib, which ranlib then rejects.
set(OPENSC_LDFLAGS "")
set(OPENSC_OPENSSL_CFLAGS "")
set(OPENSC_OPENSSL_LIBS "")
if(APPLE AND CMAKE_OSX_ARCHITECTURES)
    foreach(arch IN LISTS CMAKE_OSX_ARCHITECTURES)
        string(APPEND OPENSC_CFLAGS  " -arch ${arch}")
        string(APPEND OPENSC_LDFLAGS " -arch ${arch}")
    endforeach()
    set(OPENSC_OPENSSL_CFLAGS "-I${OPENSSL_ROOT}/macosx/include")
    set(OPENSC_OPENSSL_LIBS   "-L${OPENSSL_ROOT}/macosx/lib -lcrypto")
endif()

ExternalProject_Add(opensc_external
    SOURCE_DIR        ${OPENSC_SOURCE_DIR}
    BINARY_DIR        ${OPENSC_BUILD_DIR}
    INSTALL_DIR       ${OPENSC_INSTALL_DIR}
    # bootstrap regenerates configure/Makefile.in via autoreconf; must run
    # in the source tree before configure.
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E chdir ${OPENSC_SOURCE_DIR} ./bootstrap
              COMMAND ${CMAKE_COMMAND} -E env
                      "CFLAGS=${OPENSC_CFLAGS}"
                      "LDFLAGS=${OPENSC_LDFLAGS}"
                      "OPENSSL_CFLAGS=${OPENSC_OPENSSL_CFLAGS}"
                      "OPENSSL_LIBS=${OPENSC_OPENSSL_LIBS}"
                      "MACOSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}"
                      ${OPENSC_SOURCE_DIR}/configure ${OPENSC_CONFIGURE_FLAGS}
    BUILD_COMMAND     make -j4
    INSTALL_COMMAND   make install
    BUILD_BYPRODUCTS  ${OPENSC_STATIC_LIB}
    BUILD_IN_SOURCE   FALSE
    LOG_CONFIGURE         TRUE
    LOG_BUILD             TRUE
    LOG_INSTALL           TRUE
    LOG_OUTPUT_ON_FAILURE TRUE
)

add_library(opensc_static STATIC IMPORTED GLOBAL)
set_target_properties(opensc_static PROPERTIES
    IMPORTED_LOCATION             ${OPENSC_STATIC_LIB}
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSC_INCLUDE_SRC};${OPENSC_INCLUDE_BUILD}"
)
add_dependencies(opensc_static opensc_external)

# Convenience wrapper bundling opensc_static with its transitive runtime
# deps. libopensc.a references zlib (compression.o, pkcs15-actalis.o) and
# PC/SC (SCard* via --enable-pcsc). Consumers linking the static archive
# into a SHARED library must satisfy these symbols; depending on this
# INTERFACE target does it once for the whole tree. (The notify backend is
# built with --disable-notify, so there is no GIO/GLib link edge.)
add_library(opensc_static_with_deps INTERFACE)
# libopensc.a and libcrypto.a are mutually recursive at link time
# (libopensc → ERR_*, X509_*, BIO_*; libcrypto pulled fresh by libopensc
# objects discovered later). When consumers also drag OpenSSL_Crypto in
# earlier (via e.g. SmartCard_Impl), CMake deduplicates and the late
# OpenSSL_Crypto reference is dropped — leaving libopensc.a's undefined
# symbols unresolved.
#
# On GNU ld / lld we force --start-group/--end-group rescan via
# `$<LINK_GROUP:RESCAN,...>` so the archives are scanned until the symbol
# set converges. Apple ld64 performs multi-pass archive linking on its own
# (CMake's `$<LINK_GROUP>` is documented as not supported for the 'CXX'
# link language on Apple), so the plain target ordering is sufficient —
# ld64 will rescan both archives until no more symbols are pulled.
#
# ZLIB::ZLIB MUST sit inside the rescan group, not after it: libopensc.a's
# compression.o / pkcs15-actalis.o reference inflate/uncompress/inflateInit2_
# /inflateEnd, and those objects are pulled in mid-scan. With zlib appended
# *after* --end-group the resolution only works by luck of link ordering
# (e.g. when CMake happens to emit libz.so before the group, where a shared
# lib's symbols stay available). Under a different consumer/link order — as
# CodeQL's traced build produced for OpenScPkcs11UnitTests — the trailing
# libz lands past the closed group and the zlib refs go undefined. Folding
# zlib into the group makes the link order-independent and correct on every
# consumer.
find_package(ZLIB REQUIRED)
if(APPLE)
    target_link_libraries(opensc_static_with_deps INTERFACE
        opensc_static OpenSSL_Crypto ZLIB::ZLIB
    )
else()
    target_link_libraries(opensc_static_with_deps INTERFACE
        "$<LINK_GROUP:RESCAN,opensc_static,OpenSSL_Crypto,ZLIB::ZLIB>"
    )
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    pkg_check_modules(LIBRESCRS_OPENSC_PCSC QUIET IMPORTED_TARGET libpcsclite)
    if(LIBRESCRS_OPENSC_PCSC_FOUND)
        target_link_libraries(opensc_static_with_deps INTERFACE PkgConfig::LIBRESCRS_OPENSC_PCSC)
    endif()
endif()
