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
    "${PROJECT_SOURCE_DIR}/include/LibreSCRS/Plugin/detail/*.h"
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
add_library(LibreSCRS_Auth STATIC
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
    ${PROJECT_SOURCE_DIR}/include)
target_compile_features(LibreSCRS_Auth PUBLIC cxx_std_23)
target_link_libraries(LibreSCRS_Auth PUBLIC OpenSSL_Crypto)
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

# Trust: public types + internal providers + composer + async lifecycle owner.
add_library(LibreSCRS_Trust STATIC
    Trust/TrustConfig.cpp
    Trust/TrustStore.cpp
    Trust/TrustStoreService.cpp
    Trust/internal/BundledCertsProvider.cpp
    Trust/internal/TrustStoreInternalAccess.cpp
    ${LIBRESCRS_TRUST_PUBLIC_HEADERS}
)
target_compile_definitions(LibreSCRS_Trust PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_CERTIFICATES_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}")
target_include_directories(LibreSCRS_Trust PUBLIC ${PROJECT_SOURCE_DIR}/include)
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
target_link_libraries(LibreSCRS_Trust PRIVATE OpenSSL_Crypto LibreSign)
set_target_properties(LibreSCRS_Trust PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(LibreSCRS_Trust PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
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

add_library(LibreSCRS_Certificate STATIC
    Certificate/ObjectIdentifier.cpp
    Certificate/DistinguishedName.cpp
    Certificate/ParsedCertificate.cpp
    Certificate/internal/OidLookup.cpp
    ${LIBRESCRS_OID_DB_GENERATED}
)
target_compile_definitions(LibreSCRS_Certificate PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
target_include_directories(LibreSCRS_Certificate PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(LibreSCRS_Certificate PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Certificate/internal)
target_compile_features(LibreSCRS_Certificate PUBLIC cxx_std_23)
target_link_libraries(LibreSCRS_Certificate PRIVATE OpenSSL_Crypto)
set_target_properties(LibreSCRS_Certificate PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(LibreSCRS_Certificate PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)

add_library(LibreSCRS_SmartCard STATIC
    SmartCard/CardMap.cpp
    SmartCard/CardSession.cpp
    SmartCard/MonitorService.cpp
    ${LIBRESCRS_SMARTCARD_PUBLIC_HEADERS}
)
target_include_directories(LibreSCRS_SmartCard PUBLIC ${PROJECT_SOURCE_DIR}/include)
# PRIVATE: needed because MonitorService.cpp includes <smartcard/ipcsc_scan_provider.h>
# (bucket-B, relocated to lib/smartcard/src in Chunk E) and because
# <smartcard/pcsc_connection.h>/<smartcard/monitor.h> (bucket-C) transitively
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
    PUBLIC  LibreSCRS_Auth
    PRIVATE SmartCard_Impl
)
target_compile_options(LibreSCRS_SmartCard PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)

# Plugin: public AutoReaderService wrapper over the internal CardPluginService.
add_library(LibreSCRS_Plugin STATIC
    Plugin/AutoReaderService.cpp
    Plugin/SecurityCheck.cpp
    ${LIBRESCRS_PLUGIN_PUBLIC_HEADERS}
)
target_include_directories(LibreSCRS_Plugin PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_features(LibreSCRS_Plugin PUBLIC cxx_std_23)
target_compile_definitions(LibreSCRS_Plugin PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)
# LIBRESCRS_INTERNAL_BUILD: sibling-consistent with SmartCard + Signing.
# AutoReaderService.cpp does not yet include any Plugin/detail/*.h, but making
# this uniform across all four public targets removes the silent-design-
# inconsistency surfaced during 4.0 arch review and ensures future
# detail/ additions work without a CMake edit.
target_link_libraries(LibreSCRS_Plugin
    PUBLIC  LibreSCRS_Auth LibreSCRS_SmartCard LibreSCRS_Trust
    PRIVATE CardPlugin_Impl
)
target_compile_options(LibreSCRS_Plugin PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)

# Signing: opaque-pimpl request/response types + builders.
add_library(LibreSCRS_Signing STATIC
    Signing/SigningRequest.cpp
    Signing/VisualSignatureParams.cpp
    Signing/TsaProvider.cpp
    Signing/SigningService.cpp
    Signing/detail/RequestBridge.cpp
    ${LIBRESCRS_SIGNING_PUBLIC_HEADERS}
    ${LIBRESCRS_SIGNING_DETAIL_HEADERS}
)
target_compile_definitions(LibreSCRS_Signing PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_CERTIFICATES_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}")
# LIBRESCRS_INTERNAL_BUILD lets SigningService.cpp include the local
# detail/ErrorClassifier.h (guarded) and transitively pull apdu.h (bucket-B
# still referenced by smartcard/pcsc_connection.h) through the include graph
# of CardPlugin_Impl/SmartCard_Impl headers.
target_include_directories(LibreSCRS_Signing PUBLIC
    ${PROJECT_SOURCE_DIR}/include)
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
    PRIVATE CardPlugin_Impl LibreSign SmartCard_Impl OpenSSL_Crypto)
target_compile_options(LibreSCRS_Signing PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fvisibility=hidden -fvisibility-inlines-hidden>
)

# Public aliases — consumers use these.
add_library(LibreSCRS::Auth      ALIAS LibreSCRS_Auth)
add_library(LibreSCRS::SmartCard ALIAS LibreSCRS_SmartCard)
add_library(LibreSCRS::Plugin    ALIAS LibreSCRS_Plugin)
add_library(LibreSCRS::Signing   ALIAS LibreSCRS_Signing)
add_library(LibreSCRS::Trust     ALIAS LibreSCRS_Trust)
add_library(LibreSCRS::Certificate ALIAS LibreSCRS_Certificate)

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
    LibreSCRS::Auth LibreSCRS::SmartCard LibreSCRS::Plugin LibreSCRS::Signing LibreSCRS::Trust LibreSCRS::Certificate)
add_library(LibreSCRS::All ALIAS LibreSCRS_All)
