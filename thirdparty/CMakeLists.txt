# Bundled OpenSSL 3.5.8 (static)
set(OPENSSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/openssl-3.5.8)
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
# Vendored libcurl (pinned curl-8_22_0), built STATIC against the BUNDLED
# OpenSSL above.
#
# Rationale (consistency, not a bug-fix): a system libcurl.so drags the host
# distribution's libssl/libcrypto.so into every consuming process, so the
# LibreSign signing engine would run with TWO OpenSSL instances — the bundled
# static OpenSSL 3.5.8 AND the host's dynamic OpenSSL. The native engine
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
    # curl's own CMakeCache.txt outlives a change of either bundled version:
    # -DOPENSSL_ROOT_DIR does not reset the OPENSSL_*_LIBRARY and
    # OPENSSL_INCLUDE_DIR it cached, so after a switch the configure step
    # looks for a tree that no longer exists. Key the build tree by both
    # versions, so each pair configures in a tree of its own, and re-run
    # this configure when the curl checkout moves.
    set(_curl_version_header ${CURL_SOURCE_DIR}/include/curl/curlver.h)
    file(STRINGS ${_curl_version_header} _curl_version_line
        REGEX "^#define LIBCURL_VERSION \"[^\"]+\"")
    string(REGEX REPLACE "^#define LIBCURL_VERSION \"([^\"]+)\".*" "\\1"
        _curl_version "${_curl_version_line}")
    if(NOT _curl_version)
        message(FATAL_ERROR "No LIBCURL_VERSION in ${_curl_version_header}")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${_curl_version_header})
    get_filename_component(_curl_openssl_name ${OPENSSL_ROOT} NAME)
    set(CURL_BUILD_DIR   ${CMAKE_CURRENT_BINARY_DIR}/curl-build-${_curl_version}-${_curl_openssl_name})
    set(CURL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/curl-install)
    set(CURL_STATIC_LIB  ${CURL_INSTALL_DIR}/lib/libcurl.a)
    # IMPORTED INTERFACE_INCLUDE_DIRECTORIES must exist at configure time even
    # though ExternalProject populates it at build time.
    file(MAKE_DIRECTORY ${CURL_INSTALL_DIR}/include)

    set(_curl_osx_args "")
    if(APPLE AND CMAKE_OSX_ARCHITECTURES)
        # CMAKE_OSX_ARCHITECTURES is a ;-list ("x86_64;arm64"). Passed verbatim
        # through ExternalProject_Add's CMAKE_ARGS, the ';' is taken as an
        # argument separator, so curl's sub-CMake would see only the first arch
        # and build a NON-universal libcurl.a (undefined _curl_* for the dropped
        # slice). Re-encode the list with '|' and declare LIST_SEPARATOR below so
        # the full arch list reaches curl intact.
        string(REPLACE ";" "|" _curl_osx_arch "${CMAKE_OSX_ARCHITECTURES}")
        set(_curl_osx_args
            -DCMAKE_OSX_ARCHITECTURES=${_curl_osx_arch}
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
        # '|' carries the ;-separated CMAKE_OSX_ARCHITECTURES list into the
        # sub-CMake without it being split as an argument separator (see above).
        LIST_SEPARATOR |
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=${CURL_INSTALL_DIR}
            # curl's own GNUInstallDirs picks lib64 on a 64-bit RPM target,
            # while CURL_STATIC_LIB above names lib/libcurl.a unconditionally.
            # Pin the producer, not the consumer: changing CURL_STATIC_LIB to
            # lib64 would fix Fedora and break Debian.
            -DCMAKE_INSTALL_LIBDIR=lib
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
            # Named, not searched: a hit elsewhere on the host would be a
            # second OpenSSL in the process.
            -DOPENSSL_INCLUDE_DIR=${CURL_OPENSSL_DIR}/include
            -DOPENSSL_SSL_LIBRARY=${CURL_OPENSSL_DIR}/lib/libssl.a
            -DOPENSSL_CRYPTO_LIBRARY=${CURL_OPENSSL_DIR}/lib/libcrypto.a
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
            # curl's OpenSSL init otherwise asks for OPENSSL_INIT_LOAD_CONFIG,
            # which reads openssl.cnf from the bundled libcrypto's compiled-in
            # OPENSSLDIR. Defence in depth only: libcrypto still loads that
            # file itself on its first fetch, often before curl initialises,
            # so what keeps a planted openssl.cnf out is an OPENSSLDIR no user
            # can create, not this flag.
            -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG=ON
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
        # curl's macOS backend (Curl_macos_init) calls SCDynamicStoreCopyProxies
        # (SystemConfiguration) for system-proxy discovery and CFRelease
        # (CoreFoundation); a static libcurl.a does not carry those frameworks,
        # so every consumer of curl must link them explicitly.
        target_link_libraries(curl_static_with_deps INTERFACE
            curl_static OpenSSL_Ssl OpenSSL_Crypto ZLIB::ZLIB
            "-framework CoreFoundation" "-framework SystemConfiguration")
    else()
        target_link_libraries(curl_static_with_deps INTERFACE
            "$<LINK_GROUP:RESCAN,curl_static,OpenSSL_Ssl,OpenSSL_Crypto,ZLIB::ZLIB>")
    endif()
endif()

# ──────────────────────────────────────────────────────────────────────────
# Vendored OpenSC (upstream OpenSC/OpenSC, pinned commit 07d0d40b).
#
# Built as STATIC archives via ExternalProject_Add so the
# librescrs-opensc-pkcs11 SHARED library and the OpenSC card plugin can link
# it without pulling a runtime dependency on the host distribution's
# libopensc. The two get separate builds of the one source: the plugin's has
# no PC/SC reader driver (opensc_external_plugin below).
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

# The same source is built a second time for the OpenSC card plugin, without
# the PC/SC reader driver (see opensc_external_plugin below).
set(OPENSC_PLUGIN_BUILD_DIR   ${CMAKE_CURRENT_BINARY_DIR}/opensc-plugin-build)
set(OPENSC_PLUGIN_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/opensc-plugin-install)
set(OPENSC_PLUGIN_STATIC_LIB  ${OPENSC_PLUGIN_INSTALL_DIR}/lib/libopensc.a)

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

# Both builds of the source are guarded, each against its own build stamp: a
# stale plugin archive would hide an edit exactly as a stale module archive did.
foreach(_opensc_project opensc_external opensc_external_plugin)
    set(_opensc_stamp_dir ${CMAKE_CURRENT_BINARY_DIR}/${_opensc_project}-prefix/src/${_opensc_project}-stamp)
    set(_opensc_sources_changed FALSE)
    if(EXISTS ${_opensc_stamp_dir}/${_opensc_project}-build)
        foreach(_src ${_opensc_vendored_sources})
            if(EXISTS ${_src} AND ${_src} IS_NEWER_THAN ${_opensc_stamp_dir}/${_opensc_project}-build)
                set(_opensc_sources_changed TRUE)
            endif()
        endforeach()
    endif()

    if(_opensc_any_patch_applied OR _opensc_sources_changed)
        # Delete the build + install + done stamps so the next build pass re-runs
        # make → re-links libopensc.a with the current source.
        file(REMOVE
            ${_opensc_stamp_dir}/${_opensc_project}-build
            ${_opensc_stamp_dir}/${_opensc_project}-install
            ${_opensc_stamp_dir}/${_opensc_project}-done)
        if(_opensc_any_patch_applied)
            message(STATUS "OpenSC (${_opensc_project}): patch applied; invalidated build/install/done stamps")
        else()
            message(STATUS "OpenSC (${_opensc_project}): vendored source newer than build stamp; "
                           "invalidated build/install/done stamps")
        endif()
    endif()
endforeach()

# libopensc compiles OPENSC_CONF_PATH="$(sysconfdir)/opensc.conf" in as the
# configuration it reads when OPENSC_CONF is unset, and opensc.conf can name an
# OpenSSL configuration and modules to load. Left at the default, sysconfdir is
# ${OPENSC_INSTALL_DIR}/etc: a directory in the build tree, writable by whoever
# built it, and the file make install puts there was then read by every process
# loading the module on that host. Point it at a root-owned directory that
# nothing installs -- on macOS one under /System/Library, which System
# Integrity Protection keeps anyone from creating -- so the module runs without
# a configuration file, as it already did on every machine but the build host.
# make install gets sysconfdir back as the staging directory (see
# INSTALL_COMMAND), so nothing is written to the compiled-in path.
if(APPLE)
    set(OPENSC_SYSCONFDIR /System/Library/LibreSCRS/opensc)
else()
    set(OPENSC_SYSCONFDIR /usr/lib/librescrs/opensc)
endif()

# Reader drivers. The copy linked into the PKCS#11 module is a PC/SC client of
# its own: it opens the readers it serves through the host PC/SC daemon, and
# cross-process contention is left to that daemon's session arbitration.
# libpcsclite is a system dep (autoconf detects it via --enable-pcsc); consumers
# link it via the `opensc_static_with_deps` wrapper below.
#
# The copy linked into the OpenSC card plugin has no PC/SC driver. The plugin
# reaches the card only through the bridge reader it installs over the session
# it is handed, yet a context with the PC/SC driver enumerates every reader on
# the host and connects to each one the moment it is created. OpenSC needs
# exactly one reader driver (configure refuses none, and the context
# dereferences it unconditionally), so the CT-API driver stands in: with no
# module named in a configuration it loads nothing, and it has no reader
# detection at all. This is a configuration of upstream OpenSC, not a patch.
set(OPENSC_PCSC_READER_FLAGS --enable-pcsc)
set(OPENSC_PLUGIN_READER_FLAGS --disable-pcsc --disable-cryptotokenkit --enable-ctapi)

# _opensc_configure_flags(<out> <install-dir> <reader-flags>...)
function(_opensc_configure_flags out install_dir)
    set(_flags
        --prefix=${install_dir}
        --sysconfdir=${OPENSC_SYSCONFDIR}
        # Defaults to ${sysconfdir}/bash_completion.d, or to the host's own
        # bash-completion directory when pkg-config finds one; keep the tools'
        # completion files in the staging tree either way.
        --with-completiondir=${install_dir}/etc/bash_completion.d
        --disable-shared
        --enable-static
        --disable-tests
        --disable-doc
        --disable-man
        ${ARGN}
        # Headless backend embedding has no use for OpenSC's desktop-notification
        # feature. Leaving it at autoconf's `detect` default makes notify.c pull in
        # GIO/GLib whenever the build host happens to ship gio-2.0, which then
        # leaves the static-archive consumers (OpenScPkcs11UnitTests, …) with
        # undefined g_application_*/g_notification_* references unless every
        # consuming environment also provides gio on its link line. Disabling it
        # outright keeps the link deterministic and drops the GIO/GLib edge.
        --disable-notify
        # OpenSC auto-detects libeac/openpace (EAC / PACE) whenever the build host
        # ships its headers — Arch's `opensc` package pulls them in, Ubuntu's does
        # not — which makes libopensc.a reference CVC_*/EAC_*/PACE_*/TA_* and leaves
        # the static-archive consumers (librescrs-opensc-pkcs11, …) with undefined
        # references unless every consuming environment also links -leac. LibreSCRS
        # performs its own PACE, so disable it outright to keep the link
        # deterministic and drop the libeac edge (same reasoning as --disable-notify).
        --disable-openpace
        --with-pic
        # Redirect p11-kit module install into the staging dir; otherwise OpenSC
        # tries to write opensc.module into /usr/share/p11-kit/modules/ during
        # `make install` (system path detected via pkg-config p11-kit-1) and
        # fails with EACCES on non-root builds. We don't need the p11-kit
        # config file anyway — librescrs-opensc-pkcs11 statically links libopensc.
        --enable-p11_system_config_modules=${install_dir}/share/p11-kit/modules
    )
    set(${out} ${_flags} PARENT_SCOPE)
endfunction()

_opensc_configure_flags(OPENSC_CONFIGURE_FLAGS ${OPENSC_INSTALL_DIR} ${OPENSC_PCSC_READER_FLAGS})
_opensc_configure_flags(OPENSC_PLUGIN_CONFIGURE_FLAGS ${OPENSC_PLUGIN_INSTALL_DIR} ${OPENSC_PLUGIN_READER_FLAGS})

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
    # The deployment target goes to the compile as well: clang reads it from
    # the environment of each compile, and configure does not turn it into a
    # flag, so without it here every object carries the SDK's own version.
    BUILD_COMMAND     ${CMAKE_COMMAND} -E env
                      "MACOSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}"
                      make -j4
    # With autostart off and the completion directory pinned above, only
    # opensc.conf is installed under sysconfdir. The objects were
    # compiled by BUILD_COMMAND with the configured value, and install only
    # copies them, so overriding it here moves the file and not the path.
    INSTALL_COMMAND   make install sysconfdir=${OPENSC_INSTALL_DIR}/etc
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

# The card plugin's copy: the same source, flags and build type, configured
# without the PC/SC reader driver (OPENSC_PLUGIN_READER_FLAGS above). The price
# is a second OpenSC build in every configuration that vendors it.
#
# bootstrap rewrites configure and the Makefile.in files in the shared source
# tree, so it runs once, in opensc_external's configure step; this build's
# configure waits for that step and does not run it again. Its make also waits
# for the other make: automake's rebuild rules write into the shared source
# tree as well, and two make -j4 at once would double the job count. The price
# is that the two OpenSC builds run one after the other.
ExternalProject_Add(opensc_external_plugin
    SOURCE_DIR        ${OPENSC_SOURCE_DIR}
    BINARY_DIR        ${OPENSC_PLUGIN_BUILD_DIR}
    INSTALL_DIR       ${OPENSC_PLUGIN_INSTALL_DIR}
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env
                      "CFLAGS=${OPENSC_CFLAGS}"
                      "LDFLAGS=${OPENSC_LDFLAGS}"
                      "OPENSSL_CFLAGS=${OPENSC_OPENSSL_CFLAGS}"
                      "OPENSSL_LIBS=${OPENSC_OPENSSL_LIBS}"
                      "MACOSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}"
                      ${OPENSC_SOURCE_DIR}/configure ${OPENSC_PLUGIN_CONFIGURE_FLAGS}
    BUILD_COMMAND     ${CMAKE_COMMAND} -E env
                      "MACOSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}"
                      make -j4
    INSTALL_COMMAND   make install sysconfdir=${OPENSC_PLUGIN_INSTALL_DIR}/etc
    BUILD_BYPRODUCTS  ${OPENSC_PLUGIN_STATIC_LIB}
    BUILD_IN_SOURCE   FALSE
    # Built only when the plugin or a test of it is: a configuration without
    # the plugins does not pay for it.
    EXCLUDE_FROM_ALL  TRUE
    LOG_CONFIGURE         TRUE
    LOG_BUILD             TRUE
    LOG_INSTALL           TRUE
    LOG_OUTPUT_ON_FAILURE TRUE
)
ExternalProject_Add_StepTargets(opensc_external configure build)
ExternalProject_Add_StepDependencies(opensc_external_plugin configure opensc_external-configure)
ExternalProject_Add_StepDependencies(opensc_external_plugin build opensc_external-build)

add_library(opensc_plugin_static STATIC IMPORTED GLOBAL)
set_target_properties(opensc_plugin_static PROPERTIES
    IMPORTED_LOCATION             ${OPENSC_PLUGIN_STATIC_LIB}
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSC_INCLUDE_SRC};${OPENSC_PLUGIN_BUILD_DIR}"
)
add_dependencies(opensc_plugin_static opensc_external_plugin)

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

# The same wrapper for the plugin's copy: the same rescan group, and no PC/SC
# library, because that copy has nothing that calls one.
add_library(opensc_plugin_static_with_deps INTERFACE)
if(APPLE)
    target_link_libraries(opensc_plugin_static_with_deps INTERFACE
        opensc_plugin_static OpenSSL_Crypto ZLIB::ZLIB
    )
else()
    target_link_libraries(opensc_plugin_static_with_deps INTERFACE
        "$<LINK_GROUP:RESCAN,opensc_plugin_static,OpenSSL_Crypto,ZLIB::ZLIB>"
    )
endif()
