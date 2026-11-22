# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# Public headers collected per public-target namespace. Listed here so IDEs
# (QtCreator, CLion, VS Code CMake Tools) show them in the project tree.
# CONFIGURE_DEPENDS asks CMake to re-glob on each build so new headers get
# picked up without a manual re-configure — adequate for IDE visibility;
# the actual build-correctness contract still lives in the .cpp target
# source lists below.
file(GLOB LIBRESCRS_AUTH_PUBLIC_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/Auth/*.h"
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/Secure/*.h"
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/Export.h"
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/LocalizedText.h"
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/Logging.h"
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/SyncProvider.h"
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/CancelToken.h"
)
file(GLOB LIBRESCRS_SMARTCARD_PUBLIC_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/SmartCard/*.h"
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/SmartCard/detail/*.h"
)
file(GLOB LIBRESCRS_PLUGIN_PUBLIC_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/Plugin/*.h"
)
file(GLOB LIBRESCRS_SIGNING_PUBLIC_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/Signing/*.h"
)
file(GLOB LIBRESCRS_SIGNING_DETAIL_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/Signing/detail/*.h"
)
file(GLOB LIBRESCRS_TRUST_PUBLIC_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/Trust/*.h"
)

# Auth: header-only types + compiled factory functions.
add_library(LibreSCRS_Auth SHARED
    Auth/AuthRequirementFactory.cpp
    CancelToken.cpp
    # Logging.cpp lives in the lowest public target on purpose: LibreSCRS_Auth
    # is the one every other LibreSCRS_* target links PUBLIC (directly or via
    # LibreSCRS_SmartCard), so the facade's process-global sink has exactly one
    # home rather than one per archive.
    Logging.cpp
    Secure/Buffer.cpp
    Secure/String.cpp
    ${LIBRESCRS_AUTH_PUBLIC_HEADERS}
)
target_compile_definitions(LibreSCRS_Auth PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
# LIBRESCRS_INTERNAL_BUILD kept uniform across all four public LibreSCRS_*
# targets for sibling consistency — prophylactic so future Auth/Secure
# detail/*.h headers don't trip the #error guard later.
target_include_directories(LibreSCRS_Auth PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# <LibreSCRS_internal/Secure/secure_allocator.h>, shared with SmartCard_Impl.
target_include_directories(LibreSCRS_Auth PRIVATE ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_features(LibreSCRS_Auth PUBLIC cxx_std_23)
# OpenSSL_Crypto is the bundled static archive (thirdparty/openssl-3.5.8);
# baked into the .so / .a so downstream consumers don't need to link it.
# BUILD_INTERFACE-only keeps Config-package consumers from seeing the
# unresolved `-lOpenSSL_Crypto` reference at link time.
target_link_libraries(LibreSCRS_Auth PUBLIC $<BUILD_INTERFACE:OpenSSL_Crypto>)
# Plugins (card-*, eu-vrc-*, emrtd-*, rs-*, etc.) link LibreSCRS_Auth
# transitively via LibreSCRS_SmartCard PUBLIC into dynamic .so artefacts, so
# the static archive must be position-independent. Sibling targets
# (LibreSCRS_SmartCard) already set this; required once AuthRequirementFactory
# emits typeinfo relocations (e.g. throw std::invalid_argument from §5.1
# factory input validation).
set_target_properties(LibreSCRS_Auth PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(LibreSCRS_Auth PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)
set_target_properties(LibreSCRS_Auth PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${LIBRESCRS_ABI_SOVERSION}
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# Trust: public types + internal providers + composer + async lifecycle owner.
add_library(LibreSCRS_Trust SHARED
    Trust/CscaMasterList.cpp
    Trust/TrustStore.cpp
    Trust/TrustStoreService.cpp
    Trust/TrustStoreServiceEntry.cpp
    Trust/internal/BundledCertsProvider.cpp
    Trust/internal/TrustStoreInternalAccess.cpp
    ${LIBRESCRS_TRUST_PUBLIC_HEADERS}
)
target_compile_definitions(LibreSCRS_Trust PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_CERTIFICATES_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}"
    LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR="${LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR}")
target_include_directories(LibreSCRS_Trust PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# Trust subsystem: TrustStoreService.cpp drives eager TL
# fetches by calling libresign internals (fetch_and_verify_tl, the anchor-
# extraction helper inside trust/TrustedListProvider.cpp). PRIVATE-include
# the libresign src root so those headers resolve; LIBRESCRS_INTERNAL_BUILD
# is already set so their #error guards let us through.
target_include_directories(LibreSCRS_Trust PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/libresign/src
    ${PROJECT_SOURCE_DIR}/lib
    # The shared internal Crypto handle aliases: this subsystem had written its
    # own borrowing X509-stack deleter, one of five copies of it in this tree.
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_features(LibreSCRS_Trust PUBLIC cxx_std_23)
# LibreSign already PRIVATE-links LibreSCRS_Trust (TrustStore::Impl friend
# access for the lazy-fetch merge path). Adding a reverse PRIVATE link here
# closes the loop used by TrustStoreService eager fetches; static archives
# tolerate the cycle because the linker re-emits both archives in one pass.
# ${CMAKE_DL_LIBS}: BundledCertsProvider.cpp uses dladdr to derive the
# certificate bundle from the location of this library rather than the host
# executable's.
# EMRTDCrypto: Trust/CscaMasterList.cpp is a facade over the CSCA
# master-list reader that lives beside passive authentication. PRIVATE and
# BUILD_INTERFACE-only, exactly like the two above — EMRTDCrypto is a static
# archive that is never installed and never exported, so a Config-package
# consumer must not see the link edge. What the consumer sees is the three
# LibreSCRS::Trust symbols, promoted by LIBRESCRS_PUBLIC_API through the
# version-script allowlist; `emrtd::crypto::*` mentions no LibreSCRS type, so
# the allowlist leaves it local and the internal surface stays inside the .so.
target_link_libraries(LibreSCRS_Trust PRIVATE
    $<BUILD_INTERFACE:OpenSSL_Crypto>
    $<BUILD_INTERFACE:LibreSign>
    $<BUILD_INTERFACE:EMRTDCrypto>
    ${CMAKE_DL_LIBS})
set_target_properties(LibreSCRS_Trust PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(LibreSCRS_Trust PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections>
)
# Drop libresign sources Trust does not reference. Trust pulls in LibreSign
# for TL fetch/verify/anchor helpers only; without dead-stripping the entire
# static archive (PAdES, CAdES, …) is mirrored into the .so.
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_options(LibreSCRS_Trust PRIVATE "LINKER:-dead_strip")
else()
    target_link_options(LibreSCRS_Trust PRIVATE "LINKER:--gc-sections")
endif()
set_target_properties(LibreSCRS_Trust PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${LIBRESCRS_ABI_SOVERSION}
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# Certificate: ParsedCertificate public types + OID name database.
# OID database codegen: merges OpenSSL objects.txt + curated TSVs into a
# sorted constexpr table for O(log N) binary-search lookup. Target is the
# superset of OpenSSL + Rust oid-registry + BouncyCastle + ETSI eIDAS +
# ICAO 9303 + Serbian-curated entries.
find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(LIBRESCRS_OID_DB_INPUTS
    "${PROJECT_SOURCE_DIR}/thirdparty/oid-database/openssl-objects.txt"
    "${PROJECT_SOURCE_DIR}/data/oid-database/eidas-pkix.tsv"
    "${PROJECT_SOURCE_DIR}/data/oid-database/etsi-tsl.tsv"
    "${PROJECT_SOURCE_DIR}/data/oid-database/icao-9303.tsv"
    "${PROJECT_SOURCE_DIR}/data/oid-database/extras-oid-registry.tsv"
    "${PROJECT_SOURCE_DIR}/data/oid-database/extras-bouncycastle.tsv"
    "${PROJECT_SOURCE_DIR}/data/oid-database/serbian.tsv"
)
set(LIBRESCRS_OID_DB_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/OidDatabaseGenerated.cpp")
add_custom_command(
    OUTPUT  ${LIBRESCRS_OID_DB_GENERATED}
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/generate_oid_table.py
            --output ${LIBRESCRS_OID_DB_GENERATED}
            ${LIBRESCRS_OID_DB_INPUTS}
    DEPENDS ${LIBRESCRS_OID_DB_INPUTS}
            ${PROJECT_SOURCE_DIR}/tools/generate_oid_table.py
    COMMENT "Generating OID name database (~superset of OpenSSL + Rust + BC + ETSI + ICAO + Serbian)"
    VERBATIM
)

add_library(LibreSCRS_Certificate SHARED
    Certificate/ObjectIdentifier.cpp
    Certificate/DistinguishedName.cpp
    Certificate/ParsedCertificate.cpp
    Certificate/internal/OidLookup.cpp
    ${LIBRESCRS_OID_DB_GENERATED}
)
target_compile_definitions(LibreSCRS_Certificate PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
target_include_directories(LibreSCRS_Certificate PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_include_directories(LibreSCRS_Certificate PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/Certificate/internal
    # The shared internal Crypto handle aliases, on the same terms as
    # LibreSCRS_Trust above: header-only deleters, no link edge. The serial
    # number reader used to own its own BIGNUM deleter, which is how a
    # non-cleansing one lived here after the shared one was fixed.
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_features(LibreSCRS_Certificate PUBLIC cxx_std_23)
target_link_libraries(LibreSCRS_Certificate PRIVATE $<BUILD_INTERFACE:OpenSSL_Crypto>)
set_target_properties(LibreSCRS_Certificate PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(LibreSCRS_Certificate PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)
set_target_properties(LibreSCRS_Certificate PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${LIBRESCRS_ABI_SOVERSION}
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# SmartCard: CardSession, the monitor and the PC/SC connection, plus the
# secure channels (ISecureChannel with the plain, PACE, BAC and Chip
# Authentication implementations) CardSession owns. The channels have no
# consumer outside CardSession and the card plugins that reach them through
# it, so they live in the same library.
#
# Public SecureChannel headers (BacParams.h, ChannelErrors.h) live under
# `include/LibreSCRS/SecureChannel/`, because CardSession.h names their
# types. Implementation-private headers (ISecureChannel.h, PlainChannel.h,
# PaceChannel.h, PaceParams.h, BacChannel.h, SessionKeys.h,
# detail/ChannelStateMutator.h) live under
# `lib/SecureChannel/include/LibreSCRS_internal/SecureChannel/` and are
# guarded by `#ifndef LIBRESCRS_INTERNAL_BUILD #error`. Only the public
# subset is installed; the internal subset is on the BUILD_INTERFACE for
# in-tree consumers.
file(GLOB LIBRESCRS_SECURECHANNEL_PUBLIC_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/SecureChannel/*.h"
)
file(GLOB LIBRESCRS_SECURECHANNEL_INTERNAL_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/lib/SecureChannel/include/LibreSCRS_internal/SecureChannel/*.h"
    "${PROJECT_SOURCE_DIR}/lib/SecureChannel/include/LibreSCRS_internal/SecureChannel/detail/*.h"
)
file(GLOB LIBRESCRS_SMARTCARD_INTERNAL_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/lib/SmartCard/include/LibreSCRS_internal/SmartCard/*.h"
)
add_library(LibreSCRS_SmartCard SHARED
    SmartCard/ActiveChannelHolder.cpp
    SmartCard/CardSession.cpp
    SmartCard/DefaultScanProvider.cpp
    SmartCard/MonitorService.cpp
    SmartCard/open_error.cpp
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_classify.cpp
    # The connection holds process-wide card state, so it is defined here and
    # only here; every other image imports it from this library. macOS reaches
    # the card through one held CryptoTokenKit session, everything else
    # through PC/SC.
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_connection.cpp
    $<$<PLATFORM_ID:Darwin>:${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_connection_ctk.cpp>
    $<$<PLATFORM_ID:Darwin>:${PROJECT_SOURCE_DIR}/lib/smartcard/src/ctk_smartcard.mm>
    $<$<PLATFORM_ID:Darwin>:${PROJECT_SOURCE_DIR}/lib/smartcard/src/ctk_scan_provider.cpp>
    $<$<NOT:$<PLATFORM_ID:Darwin>>:${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_connection_pcsc.cpp>
    SecureChannel/pace_channel.cpp
    SecureChannel/pace_params.cpp
    SecureChannel/bac_channel.cpp
    SecureChannel/chip_auth_channel.cpp
    ${LIBRESCRS_SMARTCARD_PUBLIC_HEADERS}
    ${LIBRESCRS_SMARTCARD_INTERNAL_HEADERS}
    ${LIBRESCRS_SECURECHANNEL_PUBLIC_HEADERS}
    ${LIBRESCRS_SECURECHANNEL_INTERNAL_HEADERS}
)
target_include_directories(LibreSCRS_SmartCard PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# Internal header tree under lib/<target>/include/LibreSCRS_internal/<Target>/
# (per API-POLICY §6): exposes the LIBRESCRS_INTERNAL_BUILD-only friend-accessor
# surface (ActiveChannelHolderInternal.h) to in-tree consumers on the
# BUILD_INTERFACE only. External SDK consumers do not see this path.
target_include_directories(LibreSCRS_SmartCard PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/SmartCard/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/SecureChannel/include>)
# PRIVATE: needed because MonitorService.cpp includes the internal
# <smartcard/ipcsc_scan_provider.h> (lives under lib/smartcard/src) and
# because <smartcard/pcsc_connection.h>/<smartcard/monitor.h> transitively
# pull "apdu.h"/"ipcsc_scan_provider.h" from the same directory.
# The channel implementations operate on the internal APDUCommand /
# APDUResponse types and the eMRTD protocol code directly.
target_include_directories(LibreSCRS_SmartCard PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include
    ${PROJECT_SOURCE_DIR}/lib/emrtd-crypto/src
    # <LibreSCRS_internal/LogNoexcept.h>
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_features(LibreSCRS_SmartCard PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_SmartCard PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
if(APPLE)
    set_source_files_properties(${PROJECT_SOURCE_DIR}/lib/smartcard/src/ctk_smartcard.mm
        PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    target_link_libraries(LibreSCRS_SmartCard PRIVATE "-framework CryptoTokenKit" "-framework Foundation")
endif()
# Plugins link CardPlugin_Impl (which now pulls LibreSCRS_SmartCard via PUBLIC)
# into dynamic .so artefacts, so the static archive must be position-independent.
set_target_properties(LibreSCRS_SmartCard PROPERTIES POSITION_INDEPENDENT_CODE ON)
# LIBRESCRS_INTERNAL_BUILD lets the sources include the internal smartcard/*
# headers, and MonitorService.cpp include detail/MonitorInjection.h.
target_link_libraries(LibreSCRS_SmartCard
    PUBLIC  LibreSCRS_Auth
    PRIVATE $<BUILD_INTERFACE:SmartCard_Impl>
            $<BUILD_INTERFACE:EMRTDCrypto>
)
target_compile_options(LibreSCRS_SmartCard PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)
set_target_properties(LibreSCRS_SmartCard PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${LIBRESCRS_ABI_SOVERSION}
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# Plugin: the public plugin surface over the internal CardPluginService.
add_library(LibreSCRS_Plugin SHARED
    Plugin/SecurityCheck.cpp
    ${LIBRESCRS_PLUGIN_PUBLIC_HEADERS}
)
target_include_directories(LibreSCRS_Plugin PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_include_directories(LibreSCRS_Plugin PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/plugin/src>)
target_compile_features(LibreSCRS_Plugin PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_Plugin PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
# LIBRESCRS_INTERNAL_BUILD: sibling-consistent with SmartCard + Signing, so
# future detail/ additions work without a CMake edit.
target_link_libraries(LibreSCRS_Plugin
    PUBLIC  LibreSCRS_Auth LibreSCRS_SmartCard LibreSCRS_Trust
    PRIVATE $<BUILD_INTERFACE:CardPlugin_Impl>
)
target_compile_options(LibreSCRS_Plugin PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)
set_target_properties(LibreSCRS_Plugin PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${LIBRESCRS_ABI_SOVERSION}
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# Signing: opaque-pimpl request/response types + builders.
add_library(LibreSCRS_Signing SHARED
    Signing/SigningRequest.cpp
    Signing/VisualSignatureParams.cpp
    Signing/TsaProvider.cpp
    Signing/SigningService.cpp
    Signing/detail/RequestBridge.cpp
    ${LIBRESCRS_SIGNING_PUBLIC_HEADERS}
    ${LIBRESCRS_SIGNING_DETAIL_HEADERS}
)
target_compile_definitions(LibreSCRS_Signing PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_CERTIFICATES_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}"
    LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR="${LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR}")
# LIBRESCRS_INTERNAL_BUILD lets SigningService.cpp include the local
# detail/ErrorClassifier.h (guarded) and transitively pull the internal
# apdu.h (still referenced by smartcard/pcsc_connection.h) through the
# include graph of the SmartCard_Impl headers.
target_include_directories(LibreSCRS_Signing PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# libresign has no PUBLIC include directory; its internal headers
# (signing_service.h, native/native_signing_service.h, types.h) live in
# lib/libresign/src/. The bridge SigningService.cpp needs them to translate
# libresign:: types into LibreSCRS:: types, so opt in via a PRIVATE include
# of the src root. The lifecycle role of the trust store lives on
# LibreSCRS::Trust::TrustStoreService.
target_include_directories(LibreSCRS_Signing PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/libresign/src)
target_compile_features(LibreSCRS_Signing PUBLIC cxx_std_23)
# Signing calls a card plugin through the NVI entry points
# libLibreSCRS_Plugin exports, so it links that library and does not absorb
# CardPlugin_Impl: absorbing it made this library export the whole plugin
# layer a second time. PRIVATE, because SigningService.h only forward-declares
# LibreSCRS::Plugin::CardPlugin; a consumer that constructs plugins links
# LibreSCRS::Plugin itself. abi-snapshot.sh refuses a function exported by two
# libraries. The card-plugin signing key comes in LibreSignPluginKey, which
# carries LibreSign and the plugin library with it.
target_link_libraries(LibreSCRS_Signing
    PUBLIC  LibreSCRS_Auth LibreSCRS_Trust
    PRIVATE
        $<BUILD_INTERFACE:LibreSignPluginKey>
        LibreSCRS_Plugin
        $<BUILD_INTERFACE:SmartCard_Impl>
        $<BUILD_INTERFACE:OpenSSL_Crypto>)
target_compile_options(LibreSCRS_Signing PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)
set_target_properties(LibreSCRS_Signing PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${LIBRESCRS_ABI_SOVERSION}
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# ──────────────────────────────────────────────────────────────────────────
# SHARED-build symbol hygiene: namespace-allowlist version script.
#
# Without this, bundled OpenSSL (thirdparty/openssl-3.5.8/libcrypto.a) and
# vendored nlohmann::json / miniz (carried in LibreSign.a) leak ~4400
# default-visibility symbols (OPENSSL_*, EVP_*, X509_*, BN_*, ossl_*,
# nlohmann::json_abi_v3_11_3::*, mz_*, …) into the public dynamic symbol
# table — broadening the LibreMiddleware ABI to OpenSSL's surface,
# letting any consumer dlsym() bundled OpenSSL helpers, and risking
# symbol-interposition collisions against a host process's system OpenSSL.
#
# A namespace-allowlist version script is the cleanest fix:
#   * Whitelist `LibreSCRS::*`     — the entities declared in that
#                                    namespace; what is not public API is
#                                    hidden at its declaration, and card
#                                    plugins reach the libraries through
#                                    public API only.
#   * Local everything else        — OpenSSL, libresign::, nlohmann::,
#                                    miniz, pugixml, std-template
#                                    instantiations (on LibreSCRS types
#                                    too: the patterns match the mangled
#                                    name, rooted in the namespace).
#
# `--exclude-libs` was tried and rejected: the public
# `LibreSCRS::Signing::layoutVisualSignature` lives in libresign source
# (lib/libresign/src/native/visual_signature_layout.cpp), so a
# `--exclude-libs libLibreSign.a` would have hidden a documented public
# symbol. Namespace-allowlist routes around that confusion by working in
# C++-namespace space, not archive space.
# ──────────────────────────────────────────────────────────────────────────
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(_lm_export_filter "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/librescrs-public-exports.map")
    set(_lm_export_link_opt
        "LINKER:--version-script=${_lm_export_filter}")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # Apple ld counterpart — same allowlist intent, different syntax.
    # Itanium-ABI mangled names with the leading Darwin `_` prefix
    # (i.e. `__ZN9LibreSCRS…` / `__ZN9smartcard…`).
    set(_lm_export_filter "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/librescrs-public-exports.darwin.list")
    set(_lm_export_link_opt
        "LINKER:-exported_symbols_list,${_lm_export_filter}")
else()
    set(_lm_export_filter "")
endif()

if(_lm_export_filter)
    foreach(_lm_target Auth Trust Certificate SmartCard Plugin Signing)
        target_link_options(LibreSCRS_${_lm_target} PRIVATE
            "${_lm_export_link_opt}")
        set_property(TARGET LibreSCRS_${_lm_target} APPEND PROPERTY
            LINK_DEPENDS "${_lm_export_filter}")
    endforeach()
endif()


# ──────────────────────────────────────────────────────────────────────────
# Declared test support: LibreSCRS::SmartCardTesting.
#
# <LibreSCRS/SmartCard/testing/CardSessionTesting.h> — detached card sessions
# and stand-in secure channels for the tests of projects built on LibreSCRS
# (and for LibreMiddleware's own). A static archive, installed with the
# development files, so no shipped shared library exports a test seam. It
# also carries detail::ChannelInjector::installForTesting, the one path that
# installs a channel double, which the stand-in goes through.
#
# The archive writes CardSession's private state (CardSessionImpl.h), so it
# is built from the internal headers but links nothing of the internals: it
# calls only what libLibreSCRS_SmartCard exports.
# ──────────────────────────────────────────────────────────────────────────
add_library(LibreSCRS_SmartCardTesting STATIC
    SmartCard/testing/card_session_testing.cpp
    SmartCard/testing/channel_injector.cpp
)
target_link_libraries(LibreSCRS_SmartCardTesting PUBLIC LibreSCRS_SmartCard)
target_include_directories(LibreSCRS_SmartCardTesting PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include
    $<TARGET_PROPERTY:PCSC::PCSC,INTERFACE_INCLUDE_DIRECTORIES>)
target_compile_features(LibreSCRS_SmartCardTesting PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_SmartCardTesting PRIVATE LIBRESCRS_INTERNAL_BUILD)
# libLibreSCRSTesting_SmartCard.a: outside the libLibreSCRS_* name the
# core libraries share, which packaging globs and the impl-visibility gate's
# archive count rely on.
set_target_properties(LibreSCRS_SmartCardTesting PROPERTIES
    OUTPUT_NAME LibreSCRSTesting_SmartCard
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# ──────────────────────────────────────────────────────────────────────────
# Test-only helper archive.
#
# The test-injection helpers (detail::makeMonitorWithProvider,
# detail::makeSubscriptionIdForTest, the MonitorService dispatch seams
# detail::publishForTest / publishReaderListForTest / coalesceStateSizeForTest)
# live here rather than in the production libLibreSCRS_SmartCard so consumers
# of the released SDK never see the helper symbols at link or runtime. Test
# executables that need the helpers link this archive alongside the production
# target; it brings the declared LibreSCRS_SmartCardTesting archive with it.
#
# The members that arm a PCSCConnection test seam (setTransmitFilter,
# setDetachedAtr, ...) are not here: they are members of a class whose
# typeinfo the library hides, so they come with the test copies of that class
# (LibreSCRS_SmartCard_RawDiagnostic and its siblings below). Here they would
# make every consumer of this archive reference the hidden typeinfo in a
# sanitizer build.
#
# The archive is OBJECT (not STATIC) so its symbols merge directly into
# every test executable that links it, with no archive-level
# whole-archive opt-in needed. Default visibility on the archive
# (overriding the production target's hidden default) keeps the helper
# symbols linkable from test executables. Should a definition ever find its
# way into the production library, the version script's `local:` block
# strips it on Linux; on Darwin, whose export list is an allowlist glob with
# no per-symbol exclusions, the LIBRESCRS_INTERNAL attribute on each
# declaration is the only guard.
#
# Not installed (no install(TARGETS …) rule). Build-tree-only.
# ──────────────────────────────────────────────────────────────────────────
add_library(LibreSCRS_SmartCard_TestHelpers OBJECT
    SmartCard/test_helpers/monitor_test_helpers.cpp
)
target_link_libraries(LibreSCRS_SmartCard_TestHelpers
    PUBLIC LibreSCRS_SmartCard LibreSCRS_SmartCardTesting
    PRIVATE $<BUILD_INTERFACE:SmartCard_Impl>
)
# SmartCard/testing: session_access.h, the friend of CardSession that test
# support uses (header-only, shared with the declared test archive).
target_include_directories(LibreSCRS_SmartCard_TestHelpers
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/SmartCard/test_helpers ${CMAKE_CURRENT_SOURCE_DIR}/SmartCard/testing
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/smartcard/src)
target_compile_features(LibreSCRS_SmartCard_TestHelpers PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_SmartCard_TestHelpers PRIVATE
    LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
set_target_properties(LibreSCRS_SmartCard_TestHelpers PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
)

# ──────────────────────────────────────────────────────────────────────────
# Raw PC/SC open for hardware probes and diagnostic tools.
#
# Production code opens a card through CardSession::open, which keeps one
# session per reader. Probes under test/ and tools/ that talk to a card
# below that layer call Internal::openRawDiagnostic(), whose declaration
# (raw_diagnostic/pcsc_raw_diagnostic.h) is on the include path of this
# archive's consumers only and whose definition is in this archive only. No
# library links it, so a library source that declares the function itself
# leaves an undefined symbol: the executables that link a core library, and
# the plugin loader's RTLD_NOW, both refuse it.
#
# OBJECT, like the test helpers above: the object lands in the executable
# ahead of SmartCard_Impl, so archive order cannot drop the reference.
#
# It carries its own copy of the connection, because libLibreSCRS_SmartCard
# exports none of it: no member and not its typeinfo. The executables that
# link this -- hardware probes, card_mapper and the tests that list readers,
# keep a detached connection of their own or arm a seam of a session's
# connection -- talk to the card through this copy and to CardSession through
# the library's. Both copies are the real PC/SC (or, on macOS, CryptoTokenKit)
# connection; nothing is stubbed. The copy also brings the class's typeinfo,
# which a sanitizer build (-fsanitize=vptr) references from every member call,
# and the definitions of the members that ARM a test seam
# (test_helpers/pcsc_connection_test_helpers.cpp) -- members of this class, so
# they come with a copy of it and with nothing else.
#
# Not installed (no install(TARGETS …) rule). Build-tree-only.
# ──────────────────────────────────────────────────────────────────────────
add_library(LibreSCRS_SmartCard_RawDiagnostic OBJECT
    SmartCard/raw_diagnostic/pcsc_raw_diagnostic.cpp
    SmartCard/open_error.cpp
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_classify.cpp
    SmartCard/test_helpers/pcsc_connection_test_helpers.cpp
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_connection.cpp
    $<$<PLATFORM_ID:Darwin>:${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_connection_ctk.cpp>
    $<$<PLATFORM_ID:Darwin>:${PROJECT_SOURCE_DIR}/lib/smartcard/src/ctk_smartcard.mm>
    $<$<NOT:$<PLATFORM_ID:Darwin>>:${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_connection_pcsc.cpp>
)
target_link_libraries(LibreSCRS_SmartCard_RawDiagnostic
    PUBLIC LibreSCRS_SmartCard $<BUILD_INTERFACE:SmartCard_Impl>
)
if(APPLE)
    set_source_files_properties(${PROJECT_SOURCE_DIR}/lib/smartcard/src/ctk_smartcard.mm
        TARGET_DIRECTORY LibreSCRS_SmartCard_RawDiagnostic PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    target_link_libraries(LibreSCRS_SmartCard_RawDiagnostic PUBLIC "-framework CryptoTokenKit" "-framework Foundation")
    # The executables load the library's copy of the Objective-C classes too.
    target_compile_definitions(LibreSCRS_SmartCard_RawDiagnostic PRIVATE LIBRESCRS_CTK_SECOND_COPY)
endif()
# PC/SC itself comes with SmartCard_Impl on every other platform.
target_include_directories(LibreSCRS_SmartCard_RawDiagnostic
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/SmartCard/raw_diagnostic ${PROJECT_SOURCE_DIR}/lib/smartcard/src)
target_compile_features(LibreSCRS_SmartCard_RawDiagnostic PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_SmartCard_RawDiagnostic PUBLIC LIBRESCRS_INTERNAL_BUILD)
set_target_properties(LibreSCRS_SmartCard_RawDiagnostic PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ──────────────────────────────────────────────────────────────────────────
# Test-only copy of the PC/SC connection.
#
# A test executable that replaces the PC/SC entry points with its own stubs
# (SCardTransmit, SCardReconnect, ...) needs the connection compiled into the
# executable itself: on macOS the connection inside libLibreSCRS_SmartCard
# binds to the PCSC framework at link time and never reaches a stub the
# executable defines. Executables that link this define their own PC/SC entry
# points; they must not call CardSession::open — on macOS the library keeps
# its own copy of the connection. ci/scripts/check-impl-visibility.sh fails
# when one of their sources does.
#
# Not installed (no install(TARGETS …) rule). Build-tree-only.
# ──────────────────────────────────────────────────────────────────────────
# macOS has no PC/SC body to stub.
if(NOT APPLE)
    add_library(LibreSCRS_SmartCard_PcscForTests OBJECT
        SmartCard/test_helpers/pcsc_connection_test_helpers.cpp
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_classify.cpp
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_connection.cpp
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_connection_pcsc.cpp
    )
    target_link_libraries(LibreSCRS_SmartCard_PcscForTests
        PUBLIC LibreSCRS_SmartCard
        PRIVATE $<BUILD_INTERFACE:SmartCard_Impl>
    )
    target_include_directories(LibreSCRS_SmartCard_PcscForTests
        PRIVATE ${PROJECT_SOURCE_DIR}/lib/smartcard/src)
    target_compile_features(LibreSCRS_SmartCard_PcscForTests PUBLIC cxx_std_23)
    target_compile_definitions(LibreSCRS_SmartCard_PcscForTests PRIVATE
        LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
    set_target_properties(LibreSCRS_SmartCard_PcscForTests PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        CXX_VISIBILITY_PRESET default
        VISIBILITY_INLINES_HIDDEN OFF
    )
endif()

# ──────────────────────────────────────────────────────────────────────────
# Test-only copy of the secure channels libLibreSCRS_SmartCard keeps hidden.
#
# The PACE, BAC, Chip Authentication and plain channels are not exported:
# CardSession, their caller, is in the same library. Tests that construct a
# channel or call its members compile these sources into the executable
# instead of reaching an export. A channel built here may be handed to a
# CardSession in the library: the session matches channels by the protocol it
# recorded, never by RTTI, so the two copies' typeinfo never meet. The state
# mutator is header-only, so it is not copied.
#
# Not installed (no install(TARGETS …) rule). Build-tree-only.
# ──────────────────────────────────────────────────────────────────────────
add_library(LibreSCRS_SecureChannel_ForTests OBJECT
    SecureChannel/pace_channel.cpp
    SecureChannel/pace_params.cpp
    SecureChannel/bac_channel.cpp
    SecureChannel/chip_auth_channel.cpp
)
target_link_libraries(LibreSCRS_SecureChannel_ForTests
    PUBLIC LibreSCRS_SmartCard
    PRIVATE $<BUILD_INTERFACE:SmartCard_Impl> $<BUILD_INTERFACE:EMRTDCrypto>
)
target_include_directories(LibreSCRS_SecureChannel_ForTests PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include
    ${PROJECT_SOURCE_DIR}/lib/emrtd-crypto/src
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_features(LibreSCRS_SecureChannel_ForTests PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_SecureChannel_ForTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
set_target_properties(LibreSCRS_SecureChannel_ForTests PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ──────────────────────────────────────────────────────────────────────────
# Test-only copy of the connection over CryptoTokenKit, compiled against the
# scripted CryptoTokenKit facade (test/ctk_fake.cpp) instead of the system
# one, so the CryptoTokenKit body is judged on every platform. Executables
# that link it must not link libLibreSCRS_SmartCard and must not call
# CardSession::open: the class has another layout in this copy.
# LIBRESCRS_BUILDING is deliberately absent: pcsc_connection.h refuses the
# fake in anything that defines it, which every shipped library does.
#
# Not installed (no install(TARGETS …) rule). Build-tree-only.
# ──────────────────────────────────────────────────────────────────────────
add_library(LibreSCRS_SmartCard_CtkForTests OBJECT
    SmartCard/test_helpers/pcsc_connection_test_helpers.cpp
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_classify.cpp
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_connection.cpp
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src/pcsc_connection_ctk.cpp
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src/ctk_scan_provider.cpp
    ${PROJECT_SOURCE_DIR}/test/ctk_fake.cpp
    # The raw open again, compiled against this copy's class layout.
    SmartCard/raw_diagnostic/pcsc_raw_diagnostic.cpp
)
# LibreSCRS_Auth: the connection traces through the logging facade.
target_link_libraries(LibreSCRS_SmartCard_CtkForTests PUBLIC $<BUILD_INTERFACE:SmartCard_Impl> LibreSCRS_Auth)
target_include_directories(LibreSCRS_SmartCard_CtkForTests
    PUBLIC ${PROJECT_SOURCE_DIR}/lib/smartcard/src ${PROJECT_SOURCE_DIR}/test
           ${CMAKE_CURRENT_SOURCE_DIR}/SmartCard/raw_diagnostic)
target_compile_features(LibreSCRS_SmartCard_CtkForTests PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_SmartCard_CtkForTests PUBLIC
    LIBRESCRS_SMARTCARD_CTK_FAKE LIBRESCRS_INTERNAL_BUILD)
set_target_properties(LibreSCRS_SmartCard_CtkForTests PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ──────────────────────────────────────────────────────────────────────────
# Test-only copy of the trust store service, and of the signing service that
# drives it.
#
# The service's tests serve signed Trusted Lists on loopback, under a test
# certificate no pinned one covers. libLibreSCRS_Trust has no way to replace
# the certificate a list is verified against, so this copy carries one:
# test_helpers/trust_service_test_seam.cpp stands in for
# TrustStoreServiceEntry.cpp, every other source is the shipped one. The
# signing service comes too, because one test drives the service through a
# signature and it must reach this copy. An executable that links this calls
# both services here; the shipped libraries, which the plugin and smart-card
# libraries still load, keep their own copies of the same layout.
#
# Not installed (no install(TARGETS …) rule). Build-tree-only.
# ──────────────────────────────────────────────────────────────────────────
add_library(LibreSCRS_TrustService_ForTests OBJECT
    Trust/CscaMasterList.cpp
    Trust/TrustStore.cpp
    Trust/TrustStoreService.cpp
    Trust/internal/BundledCertsProvider.cpp
    Trust/internal/TrustStoreInternalAccess.cpp
    Trust/test_helpers/trust_service_test_seam.cpp
    Signing/SigningRequest.cpp
    Signing/VisualSignatureParams.cpp
    Signing/TsaProvider.cpp
    Signing/SigningService.cpp
    Signing/detail/RequestBridge.cpp
)
target_link_libraries(LibreSCRS_TrustService_ForTests
    PUBLIC LibreSCRS_Auth LibreSCRS_Plugin
    PRIVATE $<BUILD_INTERFACE:LibreSignPluginKey> $<BUILD_INTERFACE:LibreSign> $<BUILD_INTERFACE:EMRTDCrypto>
            $<BUILD_INTERFACE:SmartCard_Impl> $<BUILD_INTERFACE:OpenSSL_Crypto> ${CMAKE_DL_LIBS}
)
target_include_directories(LibreSCRS_TrustService_ForTests
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Trust/test_helpers
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Trust ${PROJECT_SOURCE_DIR}/lib/libresign/src ${PROJECT_SOURCE_DIR}/lib
            ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_features(LibreSCRS_TrustService_ForTests PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_TrustService_ForTests PRIVATE LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_CERTIFICATES_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}"
    LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR="${LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR}")
set_target_properties(LibreSCRS_TrustService_ForTests PROPERTIES POSITION_INDEPENDENT_CODE ON)

# The shipped libraries. LibreSCRS_Secure is an INTERFACE target with no
# sources of its own, and LibreSCRS_SmartCard_TestHelpers and
# LibreSCRS_SmartCard_PcscForTests are build-tree-only test scaffolding — none
# of the three is listed. LibreSCRS_SmartCardTesting ships in the development
# files, so it is.
librescrs_warnings_as_errors(
    LibreSCRS_Auth
    LibreSCRS_Trust
    LibreSCRS_Certificate
    LibreSCRS_SmartCard
    LibreSCRS_Plugin
    LibreSCRS_Signing
    LibreSCRS_SmartCardTesting
)

# Public aliases — consumers use these.
add_library(LibreSCRS::Auth      ALIAS LibreSCRS_Auth)
add_library(LibreSCRS::SmartCard ALIAS LibreSCRS_SmartCard)
add_library(LibreSCRS::Plugin    ALIAS LibreSCRS_Plugin)
add_library(LibreSCRS::Signing   ALIAS LibreSCRS_Signing)
add_library(LibreSCRS::Trust     ALIAS LibreSCRS_Trust)
add_library(LibreSCRS::Certificate ALIAS LibreSCRS_Certificate)
add_library(LibreSCRS::SmartCardTesting ALIAS LibreSCRS_SmartCardTesting)

# Secure namespace lives inside LibreSCRS_Auth (no separate compilation unit
# cost; see Buffer.cpp being compiled into LibreSCRS_Auth target). A pure
# INTERFACE alias exposes the namespace as an addressable public target so
# consumers can link LibreSCRS::Secure explicitly for the cleansing buffer.
add_library(LibreSCRS_Secure INTERFACE)
target_link_libraries(LibreSCRS_Secure INTERFACE LibreSCRS_Auth)
add_library(LibreSCRS::Secure ALIAS LibreSCRS_Secure)

# ──────────────────────────────────────────────────────────────────────────
# CMake Config-package export for downstream find_package consumers.
#
# Each of the six public shared targets plus the LibreSCRS_Secure INTERFACE
# aggregator is exported under EXPORT LibreMiddlewareTargets, with
# EXPORT_NAME remapping the in-tree LibreSCRS_X spelling to the
# downstream LibreSCRS::X spelling — the same spelling the headers and
# the in-tree alias targets use. The final install(EXPORT ...)
# materialises Targets.cmake into the same dir as the Config + Version
# files generated by the root CMakeLists.txt.
# ──────────────────────────────────────────────────────────────────────────
include(GNUInstallDirs)

set_target_properties(LibreSCRS_Auth        PROPERTIES EXPORT_NAME Auth)
set_target_properties(LibreSCRS_Trust       PROPERTIES EXPORT_NAME Trust)
set_target_properties(LibreSCRS_Certificate PROPERTIES EXPORT_NAME Certificate)
set_target_properties(LibreSCRS_SmartCard   PROPERTIES EXPORT_NAME SmartCard)
set_target_properties(LibreSCRS_Plugin      PROPERTIES EXPORT_NAME Plugin)
set_target_properties(LibreSCRS_Signing     PROPERTIES EXPORT_NAME Signing)
set_target_properties(LibreSCRS_Secure      PROPERTIES EXPORT_NAME Secure)
set_target_properties(LibreSCRS_SmartCardTesting PROPERTIES EXPORT_NAME SmartCardTesting)

foreach(_lm_target Auth Trust Certificate SmartCard Plugin Signing)
    install(TARGETS LibreSCRS_${_lm_target}
        EXPORT   LibreMiddlewareTargets
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endforeach()

install(TARGETS LibreSCRS_Secure
    EXPORT   LibreMiddlewareTargets
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Development files only: the declared test support archive.
install(TARGETS LibreSCRS_SmartCardTesting
    EXPORT   LibreMiddlewareTargets
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT LibreMiddlewareTargets
    FILE      LibreMiddlewareTargets.cmake
    NAMESPACE LibreSCRS::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibreMiddleware
)
