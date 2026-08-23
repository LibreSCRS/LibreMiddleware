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
add_library(LibreSCRS_Auth ${LIBREMIDDLEWARE_LIB_TYPE}
    Auth/AuthRequirementFactory.cpp
    CancelToken.cpp
    LocalizedText.cpp
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
target_compile_features(LibreSCRS_Auth PUBLIC cxx_std_23)
# OpenSSL_Crypto is the bundled static archive (thirdparty/openssl-3.5.5);
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
if(LIBREMIDDLEWARE_BUILD_SHARED)
    set_target_properties(LibreSCRS_Auth PROPERTIES
        VERSION   ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
endif()

# Trust: public types + internal providers + composer + async lifecycle owner.
add_library(LibreSCRS_Trust ${LIBREMIDDLEWARE_LIB_TYPE}
    Trust/TrustConfig.cpp
    Trust/TrustStore.cpp
    Trust/TrustStoreService.cpp
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
    ${PROJECT_SOURCE_DIR}/lib)
target_compile_features(LibreSCRS_Trust PUBLIC cxx_std_23)
# LibreSign already PRIVATE-links LibreSCRS_Trust (TrustStore::Impl friend
# access for the lazy-fetch merge path). Adding a reverse PRIVATE link here
# closes the loop used by TrustStoreService eager fetches; static archives
# tolerate the cycle because the linker re-emits both archives in one pass.
# ${CMAKE_DL_LIBS}: BundledCertsProvider.cpp uses dladdr to derive the
# certificate bundle from the location of this library rather than the host
# executable's.
target_link_libraries(LibreSCRS_Trust PRIVATE
    $<BUILD_INTERFACE:OpenSSL_Crypto>
    $<BUILD_INTERFACE:LibreSign>
    ${CMAKE_DL_LIBS})
set_target_properties(LibreSCRS_Trust PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(LibreSCRS_Trust PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections>
)
# Drop libresign sources Trust does not reference. Trust pulls in LibreSign
# for TL fetch/verify/anchor helpers only; without dead-stripping the entire
# static archive (Pkcs11Token, PAdES, CAdES, …) is mirrored into the .so.
if(LIBREMIDDLEWARE_BUILD_SHARED)
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options(LibreSCRS_Trust PRIVATE "LINKER:-dead_strip")
    else()
        target_link_options(LibreSCRS_Trust PRIVATE "LINKER:--gc-sections")
    endif()
endif()
if(LIBREMIDDLEWARE_BUILD_SHARED)
    set_target_properties(LibreSCRS_Trust PROPERTIES
        VERSION   ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
endif()

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

add_library(LibreSCRS_Certificate ${LIBREMIDDLEWARE_LIB_TYPE}
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
target_include_directories(LibreSCRS_Certificate PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Certificate/internal)
target_compile_features(LibreSCRS_Certificate PUBLIC cxx_std_23)
target_link_libraries(LibreSCRS_Certificate PRIVATE $<BUILD_INTERFACE:OpenSSL_Crypto>)
set_target_properties(LibreSCRS_Certificate PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(LibreSCRS_Certificate PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)
if(LIBREMIDDLEWARE_BUILD_SHARED)
    set_target_properties(LibreSCRS_Certificate PROPERTIES
        VERSION   ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
endif()

# SecureChannel: ISecureChannel abstraction + PlainChannel/PaceChannel/
# BacChannel implementations. Hosts the cross-plugin secure-channel
# coordination surface owned by CardSession. Declared before SmartCard
# because SmartCard PUBLIC-links it for the CardSession.h surface.
#
# Public headers (BacParams.h, PaceParams.h, ChannelErrors.h) live under
# `include/LibreSCRS/SecureChannel/`. Implementation-private headers
# (ISecureChannel.h, PlainChannel.h, PaceChannel.h, BacChannel.h,
# SessionKeys.h, detail/ChannelStateMutator.h) live under
# `lib/SecureChannel/include/LibreSCRS_internal/SecureChannel/` and are
# guarded by `#ifndef LIBRESCRS_INTERNAL_BUILD #error`. Only the public
# subset is installed; the internal subset is on the target's PRIVATE
# include path for in-tree consumers.
file(GLOB LIBRESCRS_SECURECHANNEL_PUBLIC_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/SecureChannel/*.h"
)
file(GLOB LIBRESCRS_SECURECHANNEL_INTERNAL_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/lib/SecureChannel/include/LibreSCRS_internal/SecureChannel/*.h"
    "${PROJECT_SOURCE_DIR}/lib/SecureChannel/include/LibreSCRS_internal/SecureChannel/detail/*.h"
)
add_library(LibreSCRS_SecureChannel ${LIBREMIDDLEWARE_LIB_TYPE}
    SecureChannel/plain_channel.cpp
    SecureChannel/pace_channel.cpp
    SecureChannel/pace_params.cpp
    SecureChannel/bac_channel.cpp
    SecureChannel/chip_auth_channel.cpp
    SecureChannel/channel_state_mutator.cpp
    ${LIBRESCRS_SECURECHANNEL_PUBLIC_HEADERS}
    ${LIBRESCRS_SECURECHANNEL_INTERNAL_HEADERS}
)
target_include_directories(LibreSCRS_SecureChannel PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# Internal header tree under lib/<target>/include/LibreSCRS_internal/<Target>/
# (per API-POLICY §6): on the BUILD_INTERFACE only. Consumers under
# LIBRESCRS_INTERNAL_BUILD reach <LibreSCRS_internal/SecureChannel/...>
# through this path; external SDK consumers never see it.
target_include_directories(LibreSCRS_SecureChannel PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/SecureChannel/include>)
# The internal APDUCommand/APDUResponse types live in lib/smartcard/src/.
# The channel implementations operate on those types directly (matching
# IConnection::transmit's signature), so the internal include path is a
# private build-time dependency.
target_include_directories(LibreSCRS_SecureChannel PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include
    ${PROJECT_SOURCE_DIR}/lib/emrtd-crypto/src)
target_compile_features(LibreSCRS_SecureChannel PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_SecureChannel PRIVATE
    LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
target_link_libraries(LibreSCRS_SecureChannel
    PUBLIC  LibreSCRS_Auth LibreSCRS::Secure
    PRIVATE $<BUILD_INTERFACE:EMRTDCrypto>
            $<BUILD_INTERFACE:SmartCard_Impl>
)
set_target_properties(LibreSCRS_SecureChannel PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(LibreSCRS_SecureChannel PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)
if(LIBREMIDDLEWARE_BUILD_SHARED)
    set_target_properties(LibreSCRS_SecureChannel PROPERTIES
        VERSION   ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
endif()

file(GLOB LIBRESCRS_SMARTCARD_INTERNAL_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/lib/SmartCard/include/LibreSCRS_internal/SmartCard/*.h"
)
add_library(LibreSCRS_SmartCard ${LIBREMIDDLEWARE_LIB_TYPE}
    SmartCard/ActiveChannelHolder.cpp
    SmartCard/CardMap.cpp
    SmartCard/CardSession.cpp
    SmartCard/MonitorService.cpp
    SmartCard/SessionPresence.cpp
    SmartCard/SmartCardServices.cpp
    ${LIBRESCRS_SMARTCARD_PUBLIC_HEADERS}
    ${LIBRESCRS_SMARTCARD_INTERNAL_HEADERS}
)
target_include_directories(LibreSCRS_SmartCard PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# Internal header tree under lib/<target>/include/LibreSCRS_internal/<Target>/
# (per API-POLICY §6): exposes the LIBRESCRS_INTERNAL_BUILD-only friend-accessor
# surface (ActiveChannelHolderInternal.h) to in-tree consumers on the
# BUILD_INTERFACE only. External SDK consumers do not see this path.
target_include_directories(LibreSCRS_SmartCard PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/SmartCard/include>)
# PRIVATE: needed because MonitorService.cpp includes the internal
# <smartcard/ipcsc_scan_provider.h> (lives under lib/smartcard/src) and
# because <smartcard/pcsc_connection.h>/<smartcard/monitor.h> transitively
# pull "apdu.h"/"ipcsc_scan_provider.h" from the same directory.
target_include_directories(LibreSCRS_SmartCard PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src)
target_compile_features(LibreSCRS_SmartCard PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_SmartCard PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
# Plugins link CardPlugin_Impl (which now pulls LibreSCRS_SmartCard via PUBLIC)
# into dynamic .so artefacts, so the static archive must be position-independent.
set_target_properties(LibreSCRS_SmartCard PROPERTIES POSITION_INDEPENDENT_CODE ON)
# LIBRESCRS_INTERNAL_BUILD lets CardSession.cpp include detail/Unwrap.h, and
# MonitorService.cpp include detail/MonitorInjection.h and internal smartcard/* headers.
target_link_libraries(LibreSCRS_SmartCard
    PUBLIC  LibreSCRS_Auth LibreSCRS_SecureChannel
    PRIVATE $<BUILD_INTERFACE:SmartCard_Impl>
)
target_compile_options(LibreSCRS_SmartCard PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)
if(LIBREMIDDLEWARE_BUILD_SHARED)
    set_target_properties(LibreSCRS_SmartCard PROPERTIES
        VERSION   ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
endif()

# Plugin: public AutoReaderService wrapper over the internal CardPluginService.
add_library(LibreSCRS_Plugin ${LIBREMIDDLEWARE_LIB_TYPE}
    Plugin/AutoReaderService.cpp
    Plugin/CardDataAccess.cpp
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
# LIBRESCRS_INTERNAL_BUILD: sibling-consistent with SmartCard + Signing.
# AutoReaderService.cpp does not yet include any Plugin/detail/*.h, but making
# this uniform across all four public targets removes the silent-design-
# inconsistency surfaced during 4.0 arch review and ensures future
# detail/ additions work without a CMake edit.
target_link_libraries(LibreSCRS_Plugin
    PUBLIC  LibreSCRS_Auth LibreSCRS_SmartCard LibreSCRS_Trust
    PRIVATE $<BUILD_INTERFACE:CardPlugin_Impl>
)
target_compile_options(LibreSCRS_Plugin PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)
if(LIBREMIDDLEWARE_BUILD_SHARED)
    set_target_properties(LibreSCRS_Plugin PROPERTIES
        VERSION   ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
endif()

# Signing: opaque-pimpl request/response types + builders.
add_library(LibreSCRS_Signing ${LIBREMIDDLEWARE_LIB_TYPE}
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
# include graph of CardPlugin_Impl/SmartCard_Impl headers.
target_include_directories(LibreSCRS_Signing PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# libresign has no PUBLIC include directory; its internal headers
# (signing_service.h, signing_service_factory.h, types.h) live in
# lib/libresign/src/. The bridge SigningService.cpp needs them to translate
# libresign:: types into LibreSCRS:: types, so opt in via a PRIVATE include
# of the src root. The lifecycle role of the trust store lives on
# LibreSCRS::Trust::TrustStoreService.
target_include_directories(LibreSCRS_Signing PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/libresign/src)
target_compile_features(LibreSCRS_Signing PUBLIC cxx_std_23)
# CardPlugin_Impl kept PRIVATE so consumers of LibreSCRS::Signing don't
# transitively pull the internal archive's include graph. SigningService.h's
# forward declaration of LibreSCRS::Plugin::CardPlugin is sufficient for
# consumers; to actually construct a shared_ptr<CardPlugin> they must link
# LibreSCRS::Plugin separately.
target_link_libraries(LibreSCRS_Signing
    PUBLIC  LibreSCRS_Auth LibreSCRS_Trust
    PRIVATE
        $<BUILD_INTERFACE:CardPlugin_Impl>
        $<BUILD_INTERFACE:LibreSign>
        $<BUILD_INTERFACE:SmartCard_Impl>
        $<BUILD_INTERFACE:OpenSSL_Crypto>)
target_compile_options(LibreSCRS_Signing PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)
if(LIBREMIDDLEWARE_BUILD_SHARED)
    set_target_properties(LibreSCRS_Signing PROPERTIES
        VERSION   ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
endif()

# ──────────────────────────────────────────────────────────────────────────
# SHARED-build symbol hygiene: namespace-allowlist version script.
#
# Without this, bundled OpenSSL (thirdparty/openssl-3.5.5/libcrypto.a) and
# vendored nlohmann::json / miniz (carried in LibreSign.a) leak ~4400
# default-visibility symbols (OPENSSL_*, EVP_*, X509_*, BN_*, ossl_*,
# nlohmann::json_abi_v3_11_3::*, mz_*, …) into the public dynamic symbol
# table — broadening the LibreMiddleware ABI to OpenSSL's surface,
# letting any consumer dlsym() bundled OpenSSL helpers, and risking
# symbol-interposition collisions against a host process's system OpenSSL.
#
# A namespace-allowlist version script is the cleanest fix:
#   * Whitelist `LibreSCRS::*`     — public LM C++ API, including the
#                                    cross-`.so` LibreSCRS::SmartCard::Internal::*
#                                    helpers consumed by every card plugin
#                                    via the DT_NEEDED edge on
#                                    libLibreSCRS_SmartCard.so.
#   * Local everything else        — OpenSSL, libresign::, nlohmann::,
#                                    miniz, pugixml, std-template
#                                    instantiations on internal types.
#
# `--exclude-libs` was tried and rejected: the public
# `LibreSCRS::Signing::layoutVisualSignature` lives in libresign source
# (lib/libresign/src/native/visual_signature_layout.cpp), so a
# `--exclude-libs libLibreSign.a` would have hidden a documented public
# symbol. Namespace-allowlist routes around that confusion by working in
# C++-namespace space, not archive space.
# ──────────────────────────────────────────────────────────────────────────
if(LIBREMIDDLEWARE_BUILD_SHARED)
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
        foreach(_lm_target Auth Trust Certificate SmartCard SecureChannel Plugin Signing)
            target_link_options(LibreSCRS_${_lm_target} PRIVATE
                "${_lm_export_link_opt}")
            set_property(TARGET LibreSCRS_${_lm_target} APPEND PROPERTY
                LINK_DEPENDS "${_lm_export_filter}")
        endforeach()
    endif()

endif()

# ──────────────────────────────────────────────────────────────────────────
# Test-only helper archive.
#
# The three test-injection helpers (detail::makeMonitorWithProvider,
# detail::makeSubscriptionIdForTest, detail::ChannelInjector::
# installForTesting) live here rather than in the production
# libLibreSCRS_SmartCard so consumers of the released SDK never see the
# helper symbols at link or runtime. Test executables that need the
# helpers link this archive alongside the production target.
#
# The archive is OBJECT (not STATIC) so its symbols merge directly into
# every test executable that links it, with no archive-level
# whole-archive opt-in needed. Default visibility on the archive
# (overriding the production target's hidden default) keeps the helper
# symbols linkable from test executables; the production library's
# version-script `local:` block on Linux and `-unexported_symbol` globs
# on Darwin strip any stray definition that ever finds its way into the
# .so / .dylib.
#
# Not installed (no install(TARGETS …) rule). Build-tree-only.
# ──────────────────────────────────────────────────────────────────────────
add_library(LibreSCRS_SmartCard_TestHelpers OBJECT
    SmartCard/test_helpers/monitor_test_helpers.cpp
    SmartCard/test_helpers/channel_test_helpers.cpp
    SmartCard/test_helpers/session_presence_test_helpers.cpp
)
target_link_libraries(LibreSCRS_SmartCard_TestHelpers
    PUBLIC LibreSCRS_SmartCard
    PRIVATE $<BUILD_INTERFACE:SmartCard_Impl>
)
target_include_directories(LibreSCRS_SmartCard_TestHelpers
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/SmartCard/test_helpers
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/smartcard/src)
target_compile_features(LibreSCRS_SmartCard_TestHelpers PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_SmartCard_TestHelpers PRIVATE
    LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
set_target_properties(LibreSCRS_SmartCard_TestHelpers PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
)

# The shipped libraries. LibreSCRS_Secure and LibreSCRS_All are INTERFACE
# targets with no sources of their own, and LibreSCRS_SmartCard_TestHelpers is
# build-tree-only test scaffolding — none of the three is listed.
librescrs_warnings_as_errors(
    LibreSCRS_Auth
    LibreSCRS_Trust
    LibreSCRS_Certificate
    LibreSCRS_SecureChannel
    LibreSCRS_SmartCard
    LibreSCRS_Plugin
    LibreSCRS_Signing
)

# Public aliases — consumers use these.
add_library(LibreSCRS::Auth      ALIAS LibreSCRS_Auth)
add_library(LibreSCRS::SmartCard ALIAS LibreSCRS_SmartCard)
add_library(LibreSCRS::Plugin    ALIAS LibreSCRS_Plugin)
add_library(LibreSCRS::Signing   ALIAS LibreSCRS_Signing)
add_library(LibreSCRS::Trust     ALIAS LibreSCRS_Trust)
add_library(LibreSCRS::Certificate ALIAS LibreSCRS_Certificate)
add_library(LibreSCRS::SecureChannel ALIAS LibreSCRS_SecureChannel)

# Secure namespace lives inside LibreSCRS_Auth (no separate compilation unit
# cost; see Buffer.cpp being compiled into LibreSCRS_Auth target). A pure
# INTERFACE alias exposes the namespace as an addressable public target so
# consumers can link LibreSCRS::Secure explicitly for the cleansing buffer.
add_library(LibreSCRS_Secure INTERFACE)
target_link_libraries(LibreSCRS_Secure INTERFACE LibreSCRS_Auth)
add_library(LibreSCRS::Secure ALIAS LibreSCRS_Secure)

# Umbrella for consumers who don't want to reason about component boundaries.
add_library(LibreSCRS_All INTERFACE)
target_link_libraries(LibreSCRS_All INTERFACE
    LibreSCRS::Auth LibreSCRS::SmartCard LibreSCRS::SecureChannel LibreSCRS::Plugin LibreSCRS::Signing LibreSCRS::Trust LibreSCRS::Certificate)
add_library(LibreSCRS::All ALIAS LibreSCRS_All)

# ──────────────────────────────────────────────────────────────────────────
# CMake Config-package export for downstream find_package consumers.
#
# Active when LIBREMIDDLEWARE_BUILD_SHARED=ON. Each of the six public
# archive-or-shared targets plus the LibreSCRS_Secure INTERFACE
# aggregator is exported under EXPORT LibreMiddlewareTargets, with
# EXPORT_NAME remapping the in-tree LibreSCRS_X spelling to the
# downstream LibreMiddleware::X spelling. The final install(EXPORT ...)
# materialises Targets.cmake into the same dir as the Config + Version
# files generated by the root CMakeLists.txt.
# ──────────────────────────────────────────────────────────────────────────
if(LIBREMIDDLEWARE_BUILD_SHARED)
    include(GNUInstallDirs)

    set_target_properties(LibreSCRS_Auth        PROPERTIES EXPORT_NAME Auth)
    set_target_properties(LibreSCRS_Trust       PROPERTIES EXPORT_NAME Trust)
    set_target_properties(LibreSCRS_Certificate PROPERTIES EXPORT_NAME Certificate)
    set_target_properties(LibreSCRS_SmartCard   PROPERTIES EXPORT_NAME SmartCard)
    set_target_properties(LibreSCRS_SecureChannel PROPERTIES EXPORT_NAME SecureChannel)
    set_target_properties(LibreSCRS_Plugin      PROPERTIES EXPORT_NAME Plugin)
    set_target_properties(LibreSCRS_Signing     PROPERTIES EXPORT_NAME Signing)
    set_target_properties(LibreSCRS_Secure      PROPERTIES EXPORT_NAME Secure)

    foreach(_lm_target Auth Trust Certificate SmartCard SecureChannel Plugin Signing)
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

    install(EXPORT LibreMiddlewareTargets
        FILE      LibreMiddlewareTargets.cmake
        NAMESPACE LibreMiddleware::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibreMiddleware
    )
endif()
