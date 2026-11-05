# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()

add_executable(LibreMiddlewareTests
    smartcard_test.cpp
    eu_vrc_test.cpp
    healthcard_test.cpp
)

target_link_libraries(LibreMiddlewareTests
    GTest::gtest_main
    RsEId
    EuVrc
    RsHealth
    SmartCard_Impl
    LibreSCRS_SmartCard_TestHelpers
)

target_include_directories(LibreMiddlewareTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-eid/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-health/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-health-plugin/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/eu-vrc/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
)
# LM-internal test: includes internal headers via lib/*/src/; advertise the
# internal-build marker to satisfy the #error guard on those headers.
target_compile_definitions(LibreMiddlewareTests PRIVATE LIBRESCRS_INTERNAL_BUILD
    # The chunked-read cap cases read the SAME file the fuzz harness seeds
    # from, so a corpus entry and its regression case cannot drift apart.
    LIBRESCRS_FUZZ_CORPUS_DIR="${PROJECT_SOURCE_DIR}/fuzz/corpus")

include(GoogleTest)
gtest_discover_tests(LibreMiddlewareTests)

# EF.DIR parser: selection-by-verification depends on getting every
# application template back, including ones sharing an AID with another.
add_executable(EfDirTests ef_dir_test.cpp)
# SmartCard_Impl, ne LibreSCRS::SmartCard: alias je SHARED sa -fvisibility=hidden
# i ne izvozi interne simbole, pa bi parseEfDir bio undefined reference.
# Obrazac postoji: test/CMakeLists.txt:33,65.
target_link_libraries(EfDirTests GTest::gtest_main SmartCard_Impl)
target_include_directories(EfDirTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
)
target_compile_definitions(EfDirTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(EfDirTests)

# PKCS15Card::probeViaEfDir integration coverage: proves the selection
# loop picks the candidate under which EF.ODF actually selects, not the
# first EF.DIR entry whose AID matches. ef_dir_test.cpp above only covers
# the parser, which never selects anything on the wire. Drives the real
# PKCS15Card against a scripted card behind a detached PCSCConnection, so
# it links PKCS15 (not just SmartCard_Impl) plus the public smartcard/
# secure-channel libraries pkcs15_card.h transitively needs -- same
# include/link combination lib/pkcs15-plugin/CMakeLists.txt already uses
# for the equivalent non-plugin PKCS15Card probe path.
add_executable(Pkcs15ProbeEfDirTests Pkcs15ProbeEfDirTests.cpp)
target_link_libraries(Pkcs15ProbeEfDirTests GTest::gtest_main PKCS15 LibreSCRS_SmartCard SmartCard_Impl LibreSCRS_SmartCard_TestHelpers)
target_include_directories(Pkcs15ProbeEfDirTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/pkcs15/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(Pkcs15ProbeEfDirTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(Pkcs15ProbeEfDirTests)

# rs-eid driver unit tests (flagship Serbian eID coverage).
# Drives CardReaderApollo / CardReaderGemalto / CardVerifier through a
# detached PCSCConnection with a TransmitFilter intercepting every APDU.
add_executable(RsEidDriverTests
    rs-eid/protocol_test.cpp
    rs-eid/card_reader_apollo_test.cpp
    rs-eid/card_reader_gemalto_test.cpp
    rs-eid/card_verifier_test.cpp
    rs-eid/card_verifier_pin_test.cpp
)
target_link_libraries(RsEidDriverTests
    GTest::gtest_main
    RsEId
    SmartCard_Impl
    OpenSSL_Crypto
    LibreSCRS_SmartCard_TestHelpers
)
target_include_directories(RsEidDriverTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-eid/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-eid-core/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include
)
target_compile_definitions(RsEidDriverTests PRIVATE
    LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_TEST_DATA_DIR="${PROJECT_SOURCE_DIR}/test/test-data"
)
gtest_discover_tests(RsEidDriverTests)

# rs-eid-core unit tests. The core is card-free by construction, so these run
# entirely on synthetic fixtures -- no card bytes enter this repository.
add_executable(RsEidCoreTests
    rs-eid-core/rs_container_test.cpp
    rs-eid-core/rs_digest_binding_test.cpp
    rs-eid-core/document_signer_policy_test.cpp
    rs-eid-core/rs_signed_object_test.cpp
    rs-eid-core/rs_trust_store_test.cpp
    rs-eid-core/synthetic_annex.cpp
)
target_link_libraries(RsEidCoreTests
    GTest::gtest_main
    RsEIdCore
    SmartCard_Impl
    OpenSSL_Crypto
)
target_include_directories(RsEidCoreTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-eid-core/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include
)
target_compile_definitions(RsEidCoreTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(RsEidCoreTests)

# rs-eid plugin test: drives the real, dlopen'd rs-eid-plugin.so through
# CardPluginService against a detached PCSCConnection (Apollo protocol,
# scripted via TransmitFilter + the test-only setDetachedAtr seam). Covers
# readCard()'s CardData shape end to end -- unlike RsEidDriverTests above,
# which exercises the CardReaderApollo/CardVerifier drivers directly.
add_executable(RsEidPluginTests
    rs-eid/eid_card_plugin_verification_test.cpp
)
# LibreSCRS_SmartCard_TestHelpers supplies PCSCConnection::setDetachedAtr:
# the setter's definition lives in that build-tree-only archive so the
# shipped libLibreSCRS_SmartCard exports no way to arm the detached-ATR
# seam (see lib/LibreSCRS/CMakeLists.txt). SmartCard_Impl carries the rest
# of PCSCConnection, so both are needed.
target_link_libraries(RsEidPluginTests
    GTest::gtest_main
    CardPlugin_Impl
    SmartCard_Impl
    LibreSCRS_SmartCard_TestHelpers
)
target_include_directories(RsEidPluginTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-eid/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-eid-core/src
)
target_compile_definitions(RsEidPluginTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
    LIBRESCRS_INTERNAL_BUILD
)
add_dependencies(RsEidPluginTests rs-eid-plugin)
gtest_discover_tests(RsEidPluginTests)

# Annex mechanism unit tests. The mechanism lives in its own static library
# precisely so a test can link it -- the plugin itself is only reachable by dlopen.
add_executable(AnnexTests
    annex_registry_test.cpp
    annex_reader_test.cpp
    rs-eid-core/synthetic_annex.cpp
)
target_link_libraries(AnnexTests
    GTest::gtest_main
    CardAnnex
    LibreSCRS::SmartCard
    SmartCard_Impl
    RsEIdCore
    EMRTDCrypto
)
target_include_directories(AnnexTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/card-annex/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-eid-core/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/SecureChannel/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd-crypto/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include
)
target_compile_definitions(AnnexTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(AnnexTests)

add_executable(LibreSCRS_AuthTests LibreSCRS_Auth_test.cpp)
target_link_libraries(LibreSCRS_AuthTests GTest::gtest_main LibreSCRS_Auth CardPlugin_Impl SmartCard_Impl)
# ABI v6 removed LibreSCRS::Plugin::detail::ChangePinAdapter — the auth test
# no longer touches any internal detail/ header, so it builds against the
# public API without the LIBRESCRS_INTERNAL_BUILD marker.
gtest_discover_tests(LibreSCRS_AuthTests)

# The scope guard that wipes key material. Header-only and internal, so this
# needs the internal include root and nothing else -- it links LibreSCRS_Auth
# only for the OpenSSL it already carries (OPENSSL_cleanse).
# The two X509-stack pointers whose predecessors shared one name and did
# opposite things. Header-only and internal, like the guard below.
add_executable(LibreSCRS_OpenSslPtrTests LibreSCRS_OpenSslPtrTests.cpp)
target_link_libraries(LibreSCRS_OpenSslPtrTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
target_compile_definitions(LibreSCRS_OpenSslPtrTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(LibreSCRS_OpenSslPtrTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include
)
gtest_discover_tests(LibreSCRS_OpenSslPtrTests)

add_executable(LibreSCRS_CleanseGuardTests LibreSCRS_CleanseGuardTests.cpp)
target_link_libraries(LibreSCRS_CleanseGuardTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
target_compile_definitions(LibreSCRS_CleanseGuardTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(LibreSCRS_CleanseGuardTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include
)
gtest_discover_tests(LibreSCRS_CleanseGuardTests)

add_executable(LibreSCRS_CancelTokenTests LibreSCRS_CancelTokenTests.cpp)
target_link_libraries(LibreSCRS_CancelTokenTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
target_compile_definitions(LibreSCRS_CancelTokenTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(LibreSCRS_CancelTokenTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib
)
gtest_discover_tests(LibreSCRS_CancelTokenTests)

# Logging — the public sink-injected facade. Links LibreSCRS_Auth because that
# is where Logging.cpp lives (the lowest target every other one links PUBLIC,
# so the process-global sink has exactly one home).
add_executable(LibreSCRS_LoggingTests LibreSCRS_LoggingTests.cpp)
target_link_libraries(LibreSCRS_LoggingTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
gtest_discover_tests(LibreSCRS_LoggingTests)

add_executable(LibreSCRS_CredentialProviderTests LibreSCRS_CredentialProvider_test.cpp)
target_link_libraries(LibreSCRS_CredentialProviderTests GTest::gtest_main LibreSCRS_Auth)
gtest_discover_tests(LibreSCRS_CredentialProviderTests)

# PlainChannel — pass-through implementation of ISecureChannel; exercises
# the FakePCSCConnection IConnection seam used by all SecureChannel tests.
add_executable(LibreSCRS_PlainChannelTests LibreSCRS_PlainChannelTests.cpp)
target_link_libraries(LibreSCRS_PlainChannelTests
    GTest::gtest_main
    LibreSCRS::SmartCard
    SmartCard_Impl)
target_include_directories(LibreSCRS_PlainChannelTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include)
target_compile_definitions(LibreSCRS_PlainChannelTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_PlainChannelTests)

# AET SafeSign QSCD attestation unlock — verifies selectApplet() replies to
# the lock prompt with the fixed PUT DATA attestation, exactly once, and stays
# inert for unlocked / generic cards. Links PKCS15 for pkcs15::PKCS15Card.
add_executable(LibreSCRS_AetAttestationTests LibreSCRS_AetAttestationTests.cpp)
target_link_libraries(LibreSCRS_AetAttestationTests
    GTest::gtest_main
    PKCS15
    LibreSCRS::SmartCard
    SmartCard_Impl)
target_include_directories(LibreSCRS_AetAttestationTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/pkcs15/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/SecureChannel/include)
target_compile_definitions(LibreSCRS_AetAttestationTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_AetAttestationTests)

# PaceChannel + BacChannel — SM-wrapping channels. Tests exercise state
# transitions, sentinel SW codes, and SW 6987/6988 external-invalidation
# detection. Full PACE/BAC handshake test vectors require BSI TR-03110 /
# ICAO Doc 9303 documents and are deferred.
add_executable(LibreSCRS_SmChannelTests LibreSCRS_SmChannelTests.cpp)
target_link_libraries(LibreSCRS_SmChannelTests
    GTest::gtest_main
    LibreSCRS::SmartCard
    SmartCard_Impl)
target_include_directories(LibreSCRS_SmChannelTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include)
target_compile_definitions(LibreSCRS_SmChannelTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_SmChannelTests)

# ChipAuthChannel: flags, AES-SM round-trip against a card-side oracle, and the
# confirmSmAfterKeyChange proof exchange. The oracle needs the emrtd-crypto
# AES/CMAC primitives, so EMRTDCrypto and its src dir join the link/include set.
add_executable(LibreSCRS_ChipAuthChannelTests LibreSCRS_ChipAuthChannelTests.cpp)
target_link_libraries(LibreSCRS_ChipAuthChannelTests
    GTest::gtest_main
    LibreSCRS::SmartCard
    SmartCard_Impl
    EMRTDCrypto)
target_include_directories(LibreSCRS_ChipAuthChannelTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd-crypto/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include)
target_compile_definitions(LibreSCRS_ChipAuthChannelTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_ChipAuthChannelTests)

# CA/AA crypto verdicts + ChipAuthChannel::establish. Uses a synthetic EC chip
# (DG14/DG15 + card-side ECDH), so it links EMRTDCrypto and needs the crypto
# src include path plus OpenSSL (pulled transitively by EMRTDCrypto).
add_executable(LibreSCRS_ChipAuthCryptoTests LibreSCRS_ChipAuthCryptoTests.cpp)
target_link_libraries(LibreSCRS_ChipAuthCryptoTests
    GTest::gtest_main
    LibreSCRS::SmartCard
    SmartCard_Impl
    EMRTDCrypto)
target_include_directories(LibreSCRS_ChipAuthCryptoTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd-crypto/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include)
target_compile_definitions(LibreSCRS_ChipAuthCryptoTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_ChipAuthCryptoTests)

# CardSession control flow for the CA channel (installSmChannel seam, the
# reuse-only ChipAuthRequest guard, cross-applet wrapped-SELECT reuse). Needs
# the test archives (ChannelInjector, Testing::makeDetachedCardSession) and the
# EMRTDCrypto primitives behind the SM oracle.
add_executable(LibreSCRS_ChipAuthSessionTests LibreSCRS_ChipAuthSessionTests.cpp)
target_link_libraries(LibreSCRS_ChipAuthSessionTests
    GTest::gtest_main
    LibreSCRS::SmartCard
    LibreSCRS_SmartCard_TestHelpers
    LibreSCRS::Secure
    SmartCard_Impl
    EMRTDCrypto
    PCSC::PCSC)
target_include_directories(LibreSCRS_ChipAuthSessionTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/SecureChannel/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd-crypto/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include)
target_compile_definitions(LibreSCRS_ChipAuthSessionTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_ChipAuthSessionTests)

# CardTransaction static contract — move-only, release() noexcept, owns()
# accessor present, PCSCConnection::isTransactionHeld() visible. Behavioural
# tests against a real reader live in the hardware suite.
add_executable(LibreSCRS_CardTransactionTests LibreSCRS_CardTransactionTests.cpp)
target_link_libraries(LibreSCRS_CardTransactionTests GTest::gtest_main SmartCard_Impl)
target_include_directories(LibreSCRS_CardTransactionTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
target_compile_definitions(LibreSCRS_CardTransactionTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_CardTransactionTests)

# AuthRequirement::forPaceSecret — PACE/BAC credential prompt factory.
add_executable(LibreSCRS_AuthRequirementPaceTests LibreSCRS_AuthRequirementPaceTests.cpp)
target_link_libraries(LibreSCRS_AuthRequirementPaceTests GTest::gtest_main LibreSCRS::Auth)
gtest_discover_tests(LibreSCRS_AuthRequirementPaceTests)

# OID database lookup tests — superset of OpenSSL/Rust/BC/ETSI/ICAO/Serbian.
add_executable(OidDatabaseTests oid_database_test.cpp)
target_link_libraries(OidDatabaseTests GTest::gtest_main LibreSCRS_Certificate)
gtest_discover_tests(OidDatabaseTests)

# ParsedCertificate public-API tests.
add_executable(ParsedCertificateTests parsed_certificate_test.cpp)
target_link_libraries(ParsedCertificateTests GTest::gtest_main LibreSCRS_Certificate)
target_compile_definitions(ParsedCertificateTests PRIVATE
    LIBREMIDDLEWARE_TEST_DATA_DIR="${PROJECT_SOURCE_DIR}/test/test-data")
gtest_discover_tests(ParsedCertificateTests)

# ParsedCertificate::fromDer std::expected error-shape regression tests
# (locks the fallible-factory invariant: the factory returns
# std::expected<T, E>; failure E carries Kind + LocalizedText + diag).
add_executable(ParsedCertificateExpectedTests
    ${CMAKE_CURRENT_SOURCE_DIR}/cert/parsed_certificate_expected_test.cpp)
target_link_libraries(ParsedCertificateExpectedTests GTest::gtest_main LibreSCRS_Certificate)
gtest_discover_tests(ParsedCertificateExpectedTests)

# TrustStoreService — lifecycle and fetch tests.
add_executable(TrustStoreServiceTests trust_store_service_test.cpp)
target_link_libraries(TrustStoreServiceTests PRIVATE
    GTest::gtest_main
    LibreSCRS::Trust
    LibreSCRS::Signing
    OpenSSL_Crypto
)
gtest_discover_tests(TrustStoreServiceTests)

# TrustStoreService::create std::expected error-shape regression tests
# (locks the same fallible-factory invariant; mirrors
# ParsedCertificateExpectedTests).
add_executable(TrustStoreServiceCreateExpectedTests
    ${CMAKE_CURRENT_SOURCE_DIR}/trust/trust_store_service_create_expected_test.cpp)
target_link_libraries(TrustStoreServiceCreateExpectedTests PRIVATE
    GTest::gtest_main
    LibreSCRS::Trust
)
gtest_discover_tests(TrustStoreServiceCreateExpectedTests)

# PCSCConnection TransmitFilter tests
add_executable(pcsc_connection_filter_test pcsc_connection_filter_test.cpp)
target_link_libraries(pcsc_connection_filter_test SmartCard_Impl GTest::gtest_main)
target_include_directories(pcsc_connection_filter_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
# LM-internal test: reaches directly into lib/smartcard/src; must advertise
# the internal-build marker so the #error guard in apdu.h lets it in.
target_compile_definitions(pcsc_connection_filter_test PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(pcsc_connection_filter_test)

# T=0 SW=6C retry semantics — drives the real PCSCConnection::transmit()
# against link-time SCardTransmit/SCardReconnect stubs defined in the test
# binary itself (the executable's definitions take precedence over
# libpcsclite's), so no PC/SC daemon or card I/O is involved. Own binary:
# the stubs interpose for the whole executable. The connection comes from
# LibreSCRS_SmartCard_PcscForTests, compiled into the binary, because the copy
# inside libLibreSCRS_SmartCard does not see the stubs on macOS.
# macOS has no PC/SC body to stub; the CryptoTokenKit body has its own tests.
if(NOT APPLE)
    add_executable(pcsc_6c_retry_test pcsc_6c_retry_test.cpp)
    target_link_libraries(pcsc_6c_retry_test SmartCard_Impl LibreSCRS_SmartCard_PcscForTests GTest::gtest_main)
    target_include_directories(pcsc_6c_retry_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
    # LM-internal test: reaches directly into lib/smartcard/src; must advertise
    # the internal-build marker so the #error guard in apdu.h lets it in.
    target_compile_definitions(pcsc_6c_retry_test PRIVATE LIBRESCRS_INTERNAL_BUILD)
    gtest_discover_tests(pcsc_6c_retry_test)

    # The PC/SC trace channel against a stubbed SCardTransmit: off by default,
    # and a card's answer is traced as its length and status word only.
    add_executable(pcsc_trace_test pcsc_trace_test.cpp)
    target_link_libraries(pcsc_trace_test SmartCard_Impl LibreSCRS_SmartCard_PcscForTests GTest::gtest_main)
    target_include_directories(pcsc_trace_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
    target_compile_definitions(pcsc_trace_test PRIVATE LIBRESCRS_INTERNAL_BUILD)
    gtest_discover_tests(pcsc_trace_test)
endif()

# CardSession::open classifies a failure by the PC/SC code: this executable
# defines the PC/SC entry points the SmartCard library's references resolve to.
if(NOT APPLE)
    add_executable(CardSessionOpenTests card_session_open_test.cpp)
    target_link_libraries(CardSessionOpenTests LibreSCRS_SmartCard GTest::gtest_main)
    target_include_directories(CardSessionOpenTests SYSTEM PRIVATE
        $<TARGET_PROPERTY:PCSC::PCSC,INTERFACE_INCLUDE_DIRECTORIES>)
    set_target_properties(CardSessionOpenTests PROPERTIES ENABLE_EXPORTS ON)
    gtest_discover_tests(CardSessionOpenTests)
endif()

# eMRTD file reading against a scripted chip: the odd-INS READ BINARY past
# offset 0x7FFF, and a file cut short is no file.
add_executable(EmrtdCardReadTests emrtd_card_read_test.cpp)
target_link_libraries(EmrtdCardReadTests EMRTD LibreSCRS_SmartCard_TestHelpers GTest::gtest_main)
target_include_directories(EmrtdCardReadTests PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/emrtd/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src)
target_compile_definitions(EmrtdCardReadTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(EmrtdCardReadTests)

# The CryptoTokenKit body of the connection against a scripted CryptoTokenKit:
# one held session per connection, session loss, and the PC/SC codes it maps
# to. Runs everywhere; links no LibreSCRS library.
add_executable(CtkConnectionTests ctk_connection_test.cpp)
target_link_libraries(CtkConnectionTests LibreSCRS_SmartCard_CtkForTests GTest::gtest_main)
gtest_discover_tests(CtkConnectionTests)

# Reader events from CryptoTokenKit's slots, in PC/SC terms, against the
# scripted CryptoTokenKit. Runs everywhere; links no LibreSCRS library.
add_executable(CtkScanProviderTests ctk_scan_provider_test.cpp)
target_link_libraries(CtkScanProviderTests LibreSCRS_SmartCard_CtkForTests GTest::gtest_main)
gtest_discover_tests(CtkScanProviderTests)

if(APPLE)
    # The CryptoTokenKit facade against Objective-C objects answering the same
    # selectors; it never reaches the system's CryptoTokenKit.
    add_executable(CtkSmartCardTests ctk_smartcard_test.mm
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src/ctk_smartcard.mm)
    set_source_files_properties(ctk_smartcard_test.mm ${PROJECT_SOURCE_DIR}/lib/smartcard/src/ctk_smartcard.mm
        TARGET_DIRECTORY CtkSmartCardTests PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    target_include_directories(CtkSmartCardTests PRIVATE ${PROJECT_SOURCE_DIR}/lib/smartcard/src ${PROJECT_SOURCE_DIR}/include)
    target_compile_definitions(CtkSmartCardTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
    target_link_libraries(CtkSmartCardTests SmartCard_Impl GTest::gtest_main "-framework CryptoTokenKit" "-framework Foundation")
    gtest_discover_tests(CtkSmartCardTests)

    # The shipped library in a process without the smart-card entitlement:
    # opening a card fails and says why. Runs unsigned: the one name in
    # LIBRESCRS_UNSIGNED_EXECUTABLES (top-level CMakeLists.txt).
    add_executable(CardSessionMacTests cardsession_mac_test.cpp)
    target_include_directories(CardSessionMacTests PRIVATE ${PROJECT_SOURCE_DIR}/lib/smartcard/src)
    target_compile_definitions(CardSessionMacTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
    target_link_libraries(CardSessionMacTests LibreSCRS_SmartCard SmartCard_Impl GTest::gtest_main)
    gtest_discover_tests(CardSessionMacTests)

    # Hardware checks of the held CryptoTokenKit session against real cards and
    # readers. Every case skips unless LIBRESCRS_HW_CTK=1; the person at the
    # readers runs them one by one (see the header of the source). It also
    # carries the one check that never skips: the binary holds the smart-card
    # entitlement every executable of this build is signed with, so a card
    # case cannot skip for want of it.
    add_executable(CtkSessionHardwareTests ctk_session_hw_test.cpp ctk_hw_probe.mm smartcard_entitlement_check.cpp)
    set_source_files_properties(ctk_hw_probe.mm PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    target_include_directories(CtkSessionHardwareTests PRIVATE
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(CtkSessionHardwareTests PRIVATE
        LIBRESCRS_INTERNAL_BUILD
        PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}")
    target_link_libraries(CtkSessionHardwareTests
        CardPlugin_Impl PKCS15 LibreSCRS_SmartCard SmartCard_Impl LibreSCRS_SmartCard_RawDiagnostic GTest::gtest_main
        "-framework CryptoTokenKit" "-framework Foundation" "-framework Security" "-framework CoreFoundation")
    foreach(plugin rs-eid-plugin pkcs15-plugin opensc-plugin emrtd-plugin)
        if(TARGET ${plugin})
            add_dependencies(CtkSessionHardwareTests ${plugin})
        endif()
    endforeach()
    # gtest_discover_tests gives every case a SKIP_REGULAR_EXPRESSION, so a
    # case without LIBRESCRS_HW_CTK reads as Skipped, not Passed. The pattern
    # matches anywhere in the output and cannot be replaced from here, so no
    # case in the source skips after a failure.
    gtest_discover_tests(CtkSessionHardwareTests PROPERTIES LABELS "HARDWARE")

    # Hardware checks of MonitorService's CryptoTokenKit events with real
    # readers. Every case skips unless LIBRESCRS_HW_MONITOR=1 (see the header of
    # the source); the entitlement check never skips, as above.
    add_executable(MonitorCtkHardwareTests monitor_ctk_hw_test.cpp ctk_hw_probe.mm smartcard_entitlement_check.cpp)
    target_link_libraries(MonitorCtkHardwareTests
        LibreSCRS_SmartCard GTest::gtest_main
        "-framework CryptoTokenKit" "-framework Foundation" "-framework Security" "-framework CoreFoundation")
    gtest_discover_tests(MonitorCtkHardwareTests PROPERTIES LABELS "HARDWARE")
endif()

# selectByFileId P2 parameter test
add_executable(apdu_select_p2_test apdu_select_p2_test.cpp)
target_link_libraries(apdu_select_p2_test SmartCard_Impl GTest::gtest_main)
target_include_directories(apdu_select_p2_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
# LM-internal test: reaches directly into lib/smartcard/src; must advertise
# the internal-build marker so the #error guard in apdu.h lets it in.
target_compile_definitions(apdu_select_p2_test PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(apdu_select_p2_test)

# Plugin tests (CardData model + Registry + dlopen loading)
add_subdirectory(mock_card_plugin)

add_executable(PluginTests
    card_data_test.cpp
    card_plugin_registry_test.cpp
)
target_link_libraries(PluginTests
    GTest::gtest_main
    CardPlugin_Impl
)
target_compile_definitions(PluginTests PRIVATE
    MOCK_PLUGIN_DIR="$<TARGET_FILE_DIR:mock-card-plugin>"
)
add_dependencies(PluginTests mock-card-plugin)
gtest_discover_tests(PluginTests)

# SmartCard secure-wipe primitive (openssl confined to secure_wipe.cpp).
add_executable(SecureWipeTests secure_wipe_test.cpp)
target_link_libraries(SecureWipeTests GTest::gtest_main SmartCard_Impl)
gtest_discover_tests(SecureWipeTests)

# Integration test: loads all 4 real card plugins
add_executable(PluginIntegrationTests
    plugin_integration_test.cpp
)
target_link_libraries(PluginIntegrationTests
    GTest::gtest_main
    CardPlugin_Impl
)
target_compile_definitions(PluginIntegrationTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
add_dependencies(PluginIntegrationTests
    rs-eid-plugin
    eu-vrc-plugin
    rs-health-plugin
)

if(TARGET emrtd-plugin)
    add_dependencies(PluginIntegrationTests emrtd-plugin)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_EMRTD_PLUGIN=1)
endif()

if(TARGET pkcs15-plugin)
    add_dependencies(PluginIntegrationTests pkcs15-plugin)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_PKCS15_PLUGIN=1)
endif()

if(LIBRESCRS_VENDOR_OPENSC)
    add_dependencies(PluginIntegrationTests opensc-plugin)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_OPENSC_PLUGIN=1)
endif()

gtest_discover_tests(PluginIntegrationTests)

# eMRTD plugin tests
add_executable(EMRTDPluginTests
    emrtd_plugin_test.cpp
    # The synthetic CSCA/SOD generator, so a scripted card can serve a REAL
    # EF.SOD: without one no plugin test reaches the passive-authentication
    # path at all, and the CSCA verdict the plugin publishes would be pinned
    # nowhere.
    emrtd-crypto/synthetic_masterlist.cpp
)
target_link_libraries(EMRTDPluginTests
    GTest::gtest_main
    CardPlugin_Impl
    SmartCard_Impl
    EMRTDCrypto
    LibreSCRS_SmartCard_TestHelpers
)
target_include_directories(EMRTDPluginTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd-crypto/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/plugin/include)
target_compile_definitions(EMRTDPluginTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
    LIBRESCRS_INTERNAL_BUILD
)
add_dependencies(EMRTDPluginTests emrtd-plugin)
# Mixed target: only the EMRTDHardwareTest suite (7 cases) is card-gated;
# the other suites in this binary (EMRTDPluginTest, EmrtdPluginSessionKeying,
# EmrtdInterfaceActivation, EmrtdPreReadAuth, PaceDowngradeVerdict,
# BacDowngradeGuard) run with no card. `PROPERTIES LABELS` applies to the
# whole target, so it is not added here — it would mislabel the rest.
gtest_discover_tests(EMRTDPluginTests)

# eMRTD crypto tests
add_executable(EMRTDCryptoTests
    bac_test.cpp
    secure_messaging_test.cpp
    pace_test.cpp
    emrtd_crypto_test.cpp
    emrtd-crypto/synthetic_masterlist.cpp
)
target_link_libraries(EMRTDCryptoTests
    GTest::gtest_main
    EMRTDCrypto
    CardPlugin_Impl
    LibreSCRS_Plugin
)
target_include_directories(EMRTDCryptoTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd-crypto/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include
    # The PACE fake chip is an IConnection.
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include
)
target_compile_definitions(EMRTDCryptoTests PRIVATE LIBRESCRS_INTERNAL_BUILD
    # The bounds cases read the SAME files the fuzz harnesses seed from, so a
    # corpus entry and its regression case cannot drift apart.
    LIBRESCRS_FUZZ_CORPUS_DIR="${PROJECT_SOURCE_DIR}/fuzz/corpus")
gtest_discover_tests(EMRTDCryptoTests)

add_executable(EMRTDTests
    mrz_parse_test.cpp
    data_group_test.cpp
    pace_hardware_test.cpp
)
target_link_libraries(EMRTDTests
    GTest::gtest_main
    EMRTD
    LibreSCRS_SmartCard
    LibreSCRS_SmartCard_RawDiagnostic
)
target_include_directories(EMRTDTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd-crypto/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
)
target_compile_definitions(EMRTDTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
# Mixed target: only the PACEHardwareTest suite (4 cases, from
# pace_hardware_test.cpp) is card-gated; MRZParseTest and DataGroupTest
# (from mrz_parse_test.cpp / data_group_test.cpp) need no card.
# `PROPERTIES LABELS` applies to the whole target, so it is not added here.
gtest_discover_tests(EMRTDTests)

# PKCS#15 parser tests
add_executable(PKCS15ParserTests pkcs15_parser_test.cpp)
target_link_libraries(PKCS15ParserTests GTest::gtest_main PKCS15)
target_include_directories(PKCS15ParserTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/pkcs15/src
)
target_compile_definitions(PKCS15ParserTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(PKCS15ParserTests)

# ECDSA reply reading: DER, fixed-width INTEGERs or raw r||s from a card ->
# the plugin contract's fixed-width r||s, only when it verifies. No card I/O;
# OpenSSL makes the keys and the signatures.
add_executable(Pkcs15EcdsaSignatureTests pkcs15_ecdsa_signature_test.cpp)
target_link_libraries(Pkcs15EcdsaSignatureTests PRIVATE GTest::gtest_main PKCS15 OpenSSL_Crypto)
target_include_directories(Pkcs15EcdsaSignatureTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/pkcs15/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(Pkcs15EcdsaSignatureTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(Pkcs15EcdsaSignatureTests)

# DOCP counter parser tests — pure TLV walker over a GET DATA (ODD)
# response, no card I/O. Links PKCS15 only for the docp_parser.cpp TU.
add_executable(DocpParserTests DocpParserTests.cpp)
target_link_libraries(DocpParserTests GTest::gtest_main PKCS15)
target_include_directories(DocpParserTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/pkcs15/src
)
target_compile_definitions(DocpParserTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(DocpParserTests)

# PKCS#15 plugin tests
add_executable(PKCS15PluginTests pkcs15_plugin_test.cpp)
target_link_libraries(PKCS15PluginTests GTest::gtest_main CardPlugin_Impl LibreSCRS::SmartCard LibreSCRS::Auth)
target_compile_definitions(PKCS15PluginTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
add_dependencies(PKCS15PluginTests pkcs15-plugin)
gtest_discover_tests(PKCS15PluginTests)

# OpenSC plugin unit tests that need no card and no plugin instance: how the
# plugin reads OpenSC's VERIFY answer.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenScPluginUnitTests
        opensc-plugin/pin_verdict_test.cpp
    )
    target_link_libraries(OpenScPluginUnitTests PRIVATE
        GTest::gtest_main
        opensc_plugin_static_with_deps
    )
    target_include_directories(OpenScPluginUnitTests PRIVATE
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src
    )
    target_compile_definitions(OpenScPluginUnitTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
    gtest_discover_tests(OpenScPluginUnitTests)
endif()

# OpenSC fallback plugin tests (conditional on vendored OpenSC availability)
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenSCPluginTests
        opensc_plugin_test.cpp
    )
    target_link_libraries(OpenSCPluginTests
        GTest::gtest_main
        CardPlugin_Impl
        LibreSCRS_SmartCard
        LibreSCRS_SmartCardTesting
        SmartCard_Impl
        opensc_plugin_static_with_deps
    )
    target_compile_definitions(OpenSCPluginTests PRIVATE
        PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
        LIBRESCRS_INTERNAL_BUILD
    )
    add_dependencies(OpenSCPluginTests opensc-plugin)
    gtest_discover_tests(OpenSCPluginTests)
endif()

# Single-session bridge unit tests (no hardware): sc_apdu<->APDUCommand
# mapping + lock-nesting against a DetachedTag PCSCConnection. Compiles the
# bridge source directly so the ops/helpers can be driven in isolation.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenScBridgeTests
        opensc_bridge_test.cpp
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src/opensc_reader_bridge.cpp
    )
    target_include_directories(OpenScBridgeTests PRIVATE
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
    )
    target_link_libraries(OpenScBridgeTests
        GTest::gtest_main
        LibreSCRS_SmartCard
        # fake_channel.h (tunnel-branch channel double) + its include dir.
        LibreSCRS_SmartCard_TestHelpers
        SmartCard_Impl
        opensc_plugin_static_with_deps
    )
    target_compile_definitions(OpenScBridgeTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
    gtest_discover_tests(OpenScBridgeTests)
endif()

# OpenSC fallback hardware integration test.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenSCFallbackIntegrationTest
        opensc_fallback_integration_test.cpp
    )
    # Link list mirrors the canonical sibling target OpenSCPluginTests.
    # LibreSCRS_Plugin is not needed: registry symbols come from CardPlugin_Impl.
    # LibreSCRS_Secure is not needed: Secure::String symbols come transitively
    # via CardPlugin_Impl → LibreSCRS_Auth.
    target_link_libraries(OpenSCFallbackIntegrationTest PRIVATE
        GTest::gtest_main
        CardPlugin_Impl
        LibreSCRS_SmartCard
        SmartCard_Impl
        opensc_plugin_static_with_deps
        OpenSSL_Crypto
    )
    # LIBRESCRS_INTERNAL_BUILD and lib/smartcard/src: the reader list comes
    # from the internal PC/SC connection, as in the other hardware tests.
    target_compile_definitions(OpenSCFallbackIntegrationTest PRIVATE
        PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
        LIBRESCRS_INTERNAL_BUILD
    )
    # Shared PIN-guard header (single source of truth across real-card
    # test binaries).
    target_include_directories(OpenSCFallbackIntegrationTest PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    )
    add_dependencies(OpenSCFallbackIntegrationTest opensc-plugin)
    gtest_discover_tests(OpenSCFallbackIntegrationTest
        PROPERTIES LABELS "HARDWARE"
    )
endif()

# Second-generation Serbian eID contactless hardware test. Drives the full
# opensc-plugin tunnel path (CAN prompt -> PACE -> deferred bind ->
# CAN-hidden enumeration -> PIN verify -> pre-hashed ECDSA) against a real
# card; SKIPs without LIBRESCRS_TEST_CAN / LIBRESCRS_TEST_PIN or the card.
# Link list mirrors OpenSCFallbackIntegrationTest.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenScSrbEid2HwTest
        opensc_srbeid2_hw_test.cpp
    )
    target_link_libraries(OpenScSrbEid2HwTest PRIVATE
        GTest::gtest_main
        CardPlugin_Impl
        LibreSCRS_SmartCard
        SmartCard_Impl
        opensc_plugin_static_with_deps
        OpenSSL_Crypto
    )
    target_compile_definitions(OpenScSrbEid2HwTest PRIVATE
        PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
        LIBRESCRS_INTERNAL_BUILD
    )
    target_include_directories(OpenScSrbEid2HwTest PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    )
    add_dependencies(OpenScSrbEid2HwTest opensc-plugin)
    gtest_discover_tests(OpenScSrbEid2HwTest
        PROPERTIES LABELS "HARDWARE"
    )
endif()

# Downstream-patch presence guard for vendored OpenSC. Pure source-text
# inspection: no card, no opensc-static link; safe to run on every build.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(PivAidPatchTest opensc-fallback/piv_aid_test.cpp)
    target_link_libraries(PivAidPatchTest PRIVATE GTest::gtest_main)
    target_compile_definitions(PivAidPatchTest PRIVATE
        LIBRESCRS_OPENSC_CARD_PIV_C="${PROJECT_SOURCE_DIR}/thirdparty/opensc-source/src/libopensc/card-piv.c"
    )
    # Auto-apply hook runs at configure time on the source tree itself, so
    # the source file is already patched before this test compiles.
    gtest_discover_tests(PivAidPatchTest)
endif()

# SmartCard Monitor tests
add_executable(MonitorTests monitor_test.cpp)
find_package(Threads REQUIRED)
target_link_libraries(MonitorTests PRIVATE SmartCard_Impl GTest::gtest_main Threads::Threads)
# <smartcard/monitor.h> transitively pulls "ipcsc_scan_provider.h" /
# "monitor_event.h" — ipcsc_scan_provider.h now lives in lib/smartcard/src/.
target_include_directories(MonitorTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
target_compile_definitions(MonitorTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(MonitorTests)

option(BUILD_DSS_ORACLE "Build DSS validation oracle for testing (requires Java + DSS JAR)" ON)

# Which engines the signing tests sign through. `native` is the one the signing
# library carries; `both` also builds the DSS Java reference as a second engine
# (test/dss_oracle) for the cross-backend cases.
set(SIGNING_BACKEND "native" CACHE STRING "Signing tests: native, or both (also sign through the DSS cross-verification oracle)")
set_property(CACHE SIGNING_BACKEND PROPERTY STRINGS "native" "both")
if(NOT SIGNING_BACKEND MATCHES "^(native|both)$")
    message(FATAL_ERROR "SIGNING_BACKEND must be `native` or `both`, not `${SIGNING_BACKEND}`.")
endif()

# Digital signing tests
add_executable(LibreSignTests libresign_test.cpp)
target_link_libraries(LibreSignTests PRIVATE LibreSign GTest::gtest_main OpenSSL_Crypto)
# libresign has no PUBLIC include/. Tests reach types.h / signing_service.h
# via the PRIVATE src/ root plus LIBRESCRS_INTERNAL_BUILD to satisfy the
# #error guards.
target_include_directories(LibreSignTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(LibreSignTests PRIVATE
    LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSignTests)

# The DSS Java service as the tests' validation oracle (and, under
# SIGNING_BACKEND=both, as a second signing engine). Test code only: the
# process management and the HTTP over a Unix socket it needs have no place
# in the library that ships. POSIX-only (fork/exec).
add_library(LibreSignDssOracle STATIC
    dss_oracle/dss_http.cpp
    dss_oracle/dss_path_resolver.cpp
    dss_oracle/dss_service_manager.cpp
    dss_oracle/dss_validation_client.cpp)
if(SIGNING_BACKEND STREQUAL "both")
    target_sources(LibreSignDssOracle PRIVATE dss_oracle/dss_signing_service.cpp)
    # Exhaustive switches over the engine's enums: a new format or
    # level must not map silently to a wrong wire value.
    set_source_files_properties(dss_oracle/dss_signing_service.cpp
        PROPERTIES COMPILE_OPTIONS "-Werror=switch-enum")
    target_compile_definitions(LibreSignDssOracle PUBLIC LIBRESIGN_HAS_DSS=1)
endif()
target_include_directories(LibreSignDssOracle PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include
    ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann)
target_compile_definitions(LibreSignDssOracle PUBLIC LIBRESCRS_INTERNAL_BUILD)
target_link_libraries(LibreSignDssOracle PUBLIC LibreSign OpenSSL_Crypto
    PRIVATE curl_static_with_deps)

# Shared test support library (must be defined before tests that use it)
add_library(SigningTestSupport STATIC
    signing_test_support/signing_test_support.cpp
    signing_test_support/signing_keys.cpp
    signing_test_support/loopback_http_server.cpp
    signing_test_support/mock_trusted_list_server.cpp
    signing_test_support/mock_tsa_server.cpp)
# LibreSign's bucket-B internal headers (http_client.h, native/*)
# live in src/. Tests reach them via this PUBLIC include root so they
# propagate to every target that links SigningTestSupport.
target_include_directories(SigningTestSupport PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/signing_test_support
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include
    # native/der_utils.h encodes through <ber.h>.
    ${LibreMiddleware_SOURCE_DIR}/lib/smartcard/src
    ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann)
# mock_tsa_server.cpp drives OpenSSL's RFC 3161 responder API
# (TS_RESP_CTX) and mints its own signing certificate, so the support
# library needs libcrypto directly rather than transitively.
target_link_libraries(SigningTestSupport PUBLIC
    GTest::gtest GTest::gmock LibreSign OpenSSL_Crypto)
# Support library reaches into bucket-B libresign internals (native/*). Propagate the internal-build marker to every consumer so the
# #error guard lets them through.
target_compile_definitions(SigningTestSupport PUBLIC
    CMAKE_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
    LIBRESCRS_INTERNAL_BUILD)

if(TARGET LibreSignDssOracle)
    target_link_libraries(SigningTestSupport PUBLIC LibreSignDssOracle)
    if(BUILD_DSS_ORACLE)
        target_compile_definitions(SigningTestSupport PUBLIC LIBRESIGN_HAS_DSS_ORACLE=1)
    endif()
endif()

# A real card's signing key, reached through the card's plugin on a
# session for the reader. Kept out of SigningTestSupport so the tests that
# sign in memory carry no plugin registry and no card stack.
add_library(CardSigningKeySupport STATIC signing_test_support/card_signing_key.cpp)
target_link_libraries(CardSigningKeySupport PUBLIC
    SigningTestSupport LibreSignPluginKey CardPlugin_Impl LibreSCRS_SmartCard SmartCard_Impl)
target_compile_definitions(CardSigningKeySupport PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}")

# Unified signing E2E tests (parameterized by backend, custom main)
add_executable(SigningE2ETests signing_e2e_test.cpp)
target_link_libraries(SigningE2ETests PRIVATE CardSigningKeySupport)
# Mixed target: only the AllBackends/SigningE2ETest and SigningHwNativeBLT
# instantiations are card-gated; the InMemory/SigningE2ETest instantiation
# of the SAME parameterized fixture signs with a key held in memory, not a
# card. `PROPERTIES LABELS` applies to the whole target (and cannot
# distinguish instantiations of one suite), so it is not added here.
gtest_discover_tests(SigningE2ETests DISCOVERY_TIMEOUT 30)

# ETSI conformance suite: every case signs against the software token and
# is graded by the independent validator. Its own main registers the
# SigningTestEnvironment, which is where the oracle lives.
add_executable(SigningConformanceTests signing_conformance_test.cpp)
target_link_libraries(SigningConformanceTests PRIVATE SigningTestSupport GTest::gmock)
gtest_discover_tests(SigningConformanceTests DISCOVERY_TIMEOUT 30)

# The OpenSSL provider signing through a key held in memory: no card.
add_executable(SigningProviderKeymgmtTests signing_provider_keymgmt_test.cpp)
target_link_libraries(SigningProviderKeymgmtTests PRIVATE SigningTestSupport OpenSSL_Crypto GTest::gtest_main)
gtest_discover_tests(SigningProviderKeymgmtTests)

# The key that signs through a card plugin on a held session, against a
# plugin that records every deposit and sign: no card.
add_executable(PluginSigningKeyTests PluginSigningKeyTests.cpp)
target_link_libraries(PluginSigningKeyTests PRIVATE SigningTestSupport LibreSignPluginKey CardPlugin_Impl
    LibreSCRS_SmartCard LibreSCRS_SmartCardTesting SmartCard_Impl OpenSSL_Crypto GTest::gtest_main)
target_include_directories(PluginSigningKeyTests PRIVATE ${LibreMiddleware_SOURCE_DIR}/lib/smartcard/src)
gtest_discover_tests(PluginSigningKeyTests)

# HttpClient is core (used by both backends)
add_executable(HttpClientTests http_client_test.cpp)
target_link_libraries(HttpClientTests PRIVATE LibreSign GTest::gtest_main)
target_include_directories(HttpClientTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(HttpClientTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(HttpClientTests)

# DSS backend tests
if(SIGNING_BACKEND STREQUAL "both" AND TARGET LibreSignDssOracle)
    add_executable(DSSServiceManagerTests dss_service_manager_test.cpp)
    target_link_libraries(DSSServiceManagerTests PRIVATE LibreSignDssOracle GTest::gmock GTest::gtest_main)
    gtest_discover_tests(DSSServiceManagerTests)

    add_executable(DSSSigningServiceTests dss_signing_service_test.cpp)
    target_link_libraries(DSSSigningServiceTests PRIVATE SigningTestSupport GTest::gtest_main)
    gtest_discover_tests(DSSSigningServiceTests)

    # DSS integration tests (require JAR + Java on PATH)
    add_executable(DSSIntegrationTests dss_integration_test.cpp)
    target_link_libraries(DSSIntegrationTests PRIVATE LibreSignDssOracle GTest::gtest_main)
    target_compile_definitions(DSSIntegrationTests PRIVATE
        CMAKE_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
    gtest_discover_tests(DSSIntegrationTests)

    # Signing integration tests (trust store + DSS service + optional real card)
    add_executable(SigningIntegrationTests signing_integration_test.cpp)
    target_link_libraries(SigningIntegrationTests PRIVATE SigningTestSupport GTest::gtest_main OpenSSL_Crypto)
    target_compile_definitions(SigningIntegrationTests PRIVATE
        CMAKE_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
    gtest_discover_tests(SigningIntegrationTests)
endif()

# Native backend tests
# Internal-utility unit tests (derEncodeLength, sha256Base64 parity).
# Includes internal headers from lib/libresign/src/native/, so links
# LibreSign + OpenSSL directly.
add_executable(NativeUtilsTests native_utils_test.cpp)
target_link_libraries(NativeUtilsTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto)
target_include_directories(NativeUtilsTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/thirdparty/miniz
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include
    ${LibreMiddleware_SOURCE_DIR}/lib/smartcard/src)
target_compile_definitions(NativeUtilsTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
# Mixed target, at a finer grain than most: nine of the ten suites in
# this binary need no card, and even the tenth (BuildOrderedChain)
# mixes GRAIN — only its HwCompletesRealCardLeafToTrustedListCa case
# is card-gated; the other six BuildOrderedChain cases use synthetic
# certs. `PROPERTIES LABELS` applies to the whole target (or nothing
# finer than a whole gtest suite), so it cannot express this and is
# not added here.
gtest_discover_tests(NativeUtilsTests)

add_executable(TSAClientTests tsa_client_test.cpp)
target_link_libraries(TSAClientTests PRIVATE GTest::gtest_main LibreSign SigningTestSupport)
target_include_directories(TSAClientTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(TSAClientTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(TSAClientTests)

# TSA / OCSP failure-mode coverage. Exercises body-parse rejection,
# unreachable endpoint, timeout, plus module-level "B-T requires TSA"
# contract via CAdES::addTimestamp throw site.
add_executable(TsaFailureModesTests tsa_failure_modes_test.cpp)
target_link_libraries(TsaFailureModesTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
target_include_directories(TsaFailureModesTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(TsaFailureModesTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(TsaFailureModesTests)

add_executable(RevocationClientTests revocation_client_test.cpp)
target_link_libraries(RevocationClientTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto)
target_include_directories(RevocationClientTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(RevocationClientTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(RevocationClientTests)

add_executable(CAdESModuleTests cades_module_test.cpp)
target_link_libraries(CAdESModuleTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
gtest_discover_tests(CAdESModuleTests)

# Service-level policy — covers the sign() entry point and its dispatch,
# not the format modules.
add_executable(NativeSigningServiceTests native_signing_service_test.cpp)
target_link_libraries(NativeSigningServiceTests
    PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
gtest_discover_tests(NativeSigningServiceTests)

add_executable(PAdESModuleTests pades_module_test.cpp)
target_link_libraries(PAdESModuleTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
gtest_discover_tests(PAdESModuleTests)

add_executable(PAdESUnicodeE2ETests pades_unicode_e2e_test.cpp)
target_link_libraries(PAdESUnicodeE2ETests PRIVATE
    GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
gtest_discover_tests(PAdESUnicodeE2ETests)

# Visual-signature FILL_BOX cross-backend oracle. Self-
# consistency (native emitter vs layoutVisualSignature) runs
# under SIGNING_BACKEND=native|both. Full DSS oracle skips
# silently unless SIGNING_BACKEND=both AND the DSS Java service is
# reachable.
add_executable(PAdESDssOracleTests pades_dss_oracle_test.cpp)
target_link_libraries(PAdESDssOracleTests
    PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
gtest_discover_tests(PAdESDssOracleTests)

add_executable(TtfParserTests ttf_parser_test.cpp)
target_link_libraries(TtfParserTests PRIVATE GTest::gtest_main LibreSign)
target_include_directories(TtfParserTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(TtfParserTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(TtfParserTests)

add_executable(TtfSubsetTests ttf_subset_test.cpp)
target_link_libraries(TtfSubsetTests PRIVATE GTest::gtest_main LibreSign)
target_include_directories(TtfSubsetTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(TtfSubsetTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(TtfSubsetTests)

add_executable(PdfFontTests pdf_font_test.cpp)
target_link_libraries(PdfFontTests PRIVATE GTest::gtest_main LibreSign)
target_include_directories(PdfFontTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(PdfFontTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(PdfFontTests)

# Public visual-signature auto-fit layout API (rc2). Pure tests
# over the LibreSCRS::Signing interface — no internals, no
# libresign:: include path; LibreSCRS_Signing transitively pulls
# the LibreSign archive at link time so the symbols resolve.
add_executable(VisualSignatureLayoutTests visual_signature_layout_test.cpp)
target_link_libraries(VisualSignatureLayoutTests
    PRIVATE GTest::gtest_main LibreSCRS_Signing)
gtest_discover_tests(VisualSignatureLayoutTests)

# Integration: the public SigningRequest reason and location wired
# through the libresign bridge into the PDF /Reason and /Location
# signature-dictionary entries. Links LibreSCRS_Signing for the
# public builder and LibreSign for the internal PAdES module.
add_executable(SignatureDictionaryIntegrationTests signature_dictionary_integration_test.cpp)
target_link_libraries(SignatureDictionaryIntegrationTests
    PRIVATE GTest::gtest_main LibreSCRS_Signing LibreSign OpenSSL_Crypto SigningTestSupport)
target_include_directories(SignatureDictionaryIntegrationTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(SignatureDictionaryIntegrationTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(SignatureDictionaryIntegrationTests)

add_executable(JAdESModuleTests jades_module_test.cpp)
target_link_libraries(JAdESModuleTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
target_include_directories(JAdESModuleTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann)
gtest_discover_tests(JAdESModuleTests)

# JCS (RFC 8785) canonical JSON serializer — internal LibreSign TU,
# reached via LIBRESCRS_INTERNAL_BUILD plus the libresign src tree.
add_executable(JcsTests jcs_test.cpp)
target_link_libraries(JcsTests PRIVATE GTest::gtest_main LibreSign)
target_include_directories(JcsTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include
    ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann)
target_compile_definitions(JcsTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(JcsTests)

find_package(LibXml2 REQUIRED)
add_executable(XAdESModuleTests xades_module_test.cpp)
target_link_libraries(XAdESModuleTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto LibXml2::LibXml2 SigningTestSupport)
gtest_discover_tests(XAdESModuleTests)

add_executable(ASiCModuleTests asic_module_test.cpp)
target_link_libraries(ASiCModuleTests PRIVATE GTest::gtest_main LibreSign SigningTestSupport)
target_include_directories(ASiCModuleTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/thirdparty/miniz)
# The fuzz corpus holds the inputs the harness found; a unit test reads
# them from there rather than carrying a second copy that can drift.
target_compile_definitions(ASiCModuleTests PRIVATE
    LIBRESCRS_FUZZ_CORPUS_DIR="${LibreMiddleware_SOURCE_DIR}/fuzz/corpus")
gtest_discover_tests(ASiCModuleTests)

add_executable(TrustedListParserTests trusted_list_parser_test.cpp)
target_link_libraries(TrustedListParserTests PRIVATE GTest::gtest_main LibreSign LibXml2::LibXml2)
target_include_directories(TrustedListParserTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(TrustedListParserTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(TrustedListParserTests)

add_executable(TlSignatureVerifierTests tl_signature_verifier_test.cpp)
target_link_libraries(TlSignatureVerifierTests PRIVATE GTest::gtest_main LibreSign SigningTestSupport
    OpenSSL_Crypto LibXml2::LibXml2)
target_include_directories(TlSignatureVerifierTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src/native
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(TlSignatureVerifierTests PRIVATE LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_SOURCE_DIR="${LibreMiddleware_SOURCE_DIR}")
gtest_discover_tests(TlSignatureVerifierTests)

add_executable(TlCacheTests tl_cache_test.cpp)
target_link_libraries(TlCacheTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto)
target_include_directories(TlCacheTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src/native)
target_compile_definitions(TlCacheTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(TlCacheTests)

add_executable(CrossBackendTests cross_backend_test.cpp)
target_link_libraries(CrossBackendTests PRIVATE GTest::gtest_main LibreSign)
if(TARGET LibreSignDssOracle)
    target_link_libraries(CrossBackendTests PRIVATE LibreSignDssOracle)
endif()
target_include_directories(CrossBackendTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include)
target_compile_definitions(CrossBackendTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(CrossBackendTests)

add_executable(PdfParserTests pdf_parser_test.cpp)
target_link_libraries(PdfParserTests PRIVATE GTest::gtest_main LibreSign)
target_include_directories(PdfParserTests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../lib/libresign/src/native)
target_compile_definitions(PdfParserTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(PdfParserTests)

add_executable(ECSigningTests ec_signing_test.cpp)
target_link_libraries(ECSigningTests PRIVATE GTest::gtest_main LibreSign CardSigningKeySupport)
# Every case in this binary (ECSigningTest, ECMatrix/ECSigningMatrixTest)
# GTEST_SKIPs without a real card; the whole target is card-gated.
gtest_discover_tests(ECSigningTests DISCOVERY_TIMEOUT 30
    PROPERTIES LABELS "HARDWARE"
)

# A census of the PC/SC handles one document signature opens.
#
# The counting provider is compiled INTO this executable. ENABLE_EXPORTS is
# load-bearing, not tidiness -- it is what puts this executable's SCardConnect,
# dlopen and dlclose in its dynamic symbol table, where every library's
# references resolve to them. A linker --wrap cannot do this job: a call made
# inside libLibreSCRS_Signing is not redirected by --wrap, which only
# redirects references in the objects it links.
#
# SmartCard_Impl is deliberately NOT linked here: a second copy of the PC/SC
# wrapper in this executable would make it ambiguous whose calls were counted.
#
# The preemption is ELF's flat symbol lookup, and macOS reaches no card through
# PC/SC: the suite is built where it can count.
if(NOT APPLE)
    add_executable(pcsc_handle_census_test
        pcsc_handle_census_test.cpp
        ${PROJECT_SOURCE_DIR}/test/pcsc_counting_shim/counting_pcsc_shim.c)
    target_link_libraries(pcsc_handle_census_test PRIVATE
        LibreSCRS::Signing LibreSCRS::SmartCard
        # The stub plugins derive from CardPlugin, whose vtable is
        # libLibreSCRS_Plugin's.
        LibreSCRS::Plugin
        LibreSCRS_SmartCard_TestHelpers GTest::gtest_main ${CMAKE_DL_LIBS}
        # The soft-key plugin's in-memory key; no PC/SC.
        OpenSSL_Crypto)
    target_include_directories(pcsc_handle_census_test PRIVATE
        ${PROJECT_SOURCE_DIR}/test/include
        ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
        ${PROJECT_SOURCE_DIR}/test/pcsc_counting_shim
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/include
        ${PROJECT_SOURCE_DIR}/lib/SecureChannel/include)
    target_include_directories(pcsc_handle_census_test SYSTEM PRIVATE $<TARGET_PROPERTY:PCSC::PCSC,INTERFACE_INCLUDE_DIRECTORIES>)
    target_compile_definitions(pcsc_handle_census_test PRIVATE LIBRESCRS_INTERNAL_BUILD)
    set_target_properties(pcsc_handle_census_test PROPERTIES ENABLE_EXPORTS ON)
    gtest_discover_tests(pcsc_handle_census_test)
endif()

# RequestBridge.cpp is compiled in: the bridge's signature names the engine's
# internal request type, so the signing library does not export it.
add_executable(LibreSCRS_SigningTests LibreSCRS_Signing_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/Signing/detail/RequestBridge.cpp)
# StubPkiPlugin derives from CardPlugin; CardPlugin_Impl compiles the plugin
# layer into this executable. LibreSCRS_Signing brings libLibreSCRS_Plugin.so
# too, so the process holds two definitions of it. The linker exports the
# executable's, because the shared libraries reference them, and at load time
# those references bind to the executable's copy: the process runs one copy,
# the one built here.
target_link_libraries(LibreSCRS_SigningTests GTest::gtest_main LibreSCRS_Signing CardPlugin_Impl SmartCard_Impl LibreSign)
# buildTestPdf and the in-memory key the soft-key plugin signs with.
target_link_libraries(LibreSCRS_SigningTests SigningTestSupport OpenSSL_Crypto LibreSCRS_SmartCardTesting)
# Expose the internal Signing detail headers (lib/LibreSCRS/Signing/detail/*) so
# the classifier test can include ErrorClassifier.h without making it public API.
# Reach libresign's src/ for ErrorClassifier.h and <types.h>.
target_include_directories(LibreSCRS_SigningTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/Signing
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/libresign/src)
# The ErrorClassifier.h header (an internal implementation detail) is guarded by
# LIBRESCRS_INTERNAL_BUILD; this test unit is allowed to include it.
target_compile_definitions(LibreSCRS_SigningTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
# Mixed target: only the SigningServiceBridgeTest suite (3 cases, which need
# a PC/SC reader with a card) is card-gated; the other 15 suites in this
# binary are pure unit tests. `PROPERTIES LABELS` applies to the whole
# target, so it is not added here.
gtest_discover_tests(LibreSCRS_SigningTests)

# SignFailureKind cardinality + bridge-mapping lock test. Same include /
# definition pattern as LibreSCRS_SigningTests above — reaches into
# lib/LibreSCRS/Signing/detail/ErrorClassifier.h and lib/libresign/src/types.h.
add_executable(SigningFailureKindTests signing_failure_kind_test.cpp)
target_link_libraries(SigningFailureKindTests PRIVATE GTest::gtest_main LibreSCRS_Signing LibreSign)
target_include_directories(SigningFailureKindTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/Signing
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/libresign/src)
target_compile_definitions(SigningFailureKindTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(SigningFailureKindTests)

add_executable(LibreSCRS_SecureBufferTests
    LibreSCRS_SecureBufferTests.cpp
)
target_link_libraries(LibreSCRS_SecureBufferTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
gtest_discover_tests(LibreSCRS_SecureBufferTests)

add_executable(LibreSCRS_SecureStringTests
    LibreSCRS_SecureStringTests.cpp
)
target_link_libraries(LibreSCRS_SecureStringTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
gtest_discover_tests(LibreSCRS_SecureStringTests)

add_executable(LibreSCRS_SecureAllocatorTests
    LibreSCRS_SecureAllocatorTests.cpp
)
target_link_libraries(LibreSCRS_SecureAllocatorTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
gtest_discover_tests(LibreSCRS_SecureAllocatorTests)

add_executable(LibreSCRS_CardSessionTests
    LibreSCRS_CardSessionTests.cpp
)
target_link_libraries(LibreSCRS_CardSessionTests PRIVATE
    GTest::gtest_main
    LibreSCRS_SmartCard
    SmartCard_Impl
    LibreSCRS_SmartCard_TestHelpers
)
# The CardSessionPaceCapabilityHoist tests script a card via PCSCConnection::setTransmitFilter
# (the same detached-session seam the eMRTD plugin tests use); expose apdu.h /
# pcsc_connection.h from the low-level SmartCard_Impl source tree.
target_include_directories(LibreSCRS_CardSessionTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
# The internal apdu.h / pcsc_connection.h above (transmitInternal routing on
# detached sessions) are gated behind LIBRESCRS_INTERNAL_BUILD.
target_compile_definitions(LibreSCRS_CardSessionTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_CardSessionTests)

# SessionTransmitTest — drives the routing matrix of the SM-aware transmit
# funnel: live SM channel path, closed channel / no channel path,
# moved-from / detached session path, and the snapshot-keeps-channel-alive
# contract. Links against LibreSCRS_SmartCard_TestHelpers for the
# detail::ChannelInjector helper that swaps the active channel slot from
# outside the production translation unit.
add_executable(SessionTransmitTest SessionTransmitTest.cpp)
target_link_libraries(SessionTransmitTest PRIVATE
    GTest::gtest_main
    LibreSCRS_SmartCard
    LibreSCRS_SmartCard_TestHelpers
    SmartCard_Impl
)
target_include_directories(SessionTransmitTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
)
target_compile_definitions(SessionTransmitTest PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(SessionTransmitTest)

# CardSessionApiInvariantTest — load-bearing compile-time check that the
# public @ref CardSession surface never sprouts a connection() /
# pcscConnection() accessor that would re-expose the PC/SC transport.
# The static_assert at namespace scope is the actual test; the
# placeholder TEST() exists only so gtest_main has a TU body to link.
add_executable(CardSessionApiInvariantTest CardSessionApiInvariantTest.cpp)
target_link_libraries(CardSessionApiInvariantTest PRIVATE
    GTest::gtest_main
    LibreSCRS_SmartCard
)
gtest_discover_tests(CardSessionApiInvariantTest)

add_executable(LibreSCRS_MonitorTests
    LibreSCRS_MonitorTests.cpp
)
target_link_libraries(LibreSCRS_MonitorTests PRIVATE
    GTest::gtest_main
    LibreSCRS_SmartCard
    LibreSCRS_SmartCard_TestHelpers
    SmartCard_Impl
    Threads::Threads
)
# Grants access to detail/MonitorInjection.h (test-only mock injection) and
# to <ipcsc_scan_provider.h> used by the mock scan provider (relocated from
# include/smartcard/ to src/ in Chunk E).
target_compile_definitions(LibreSCRS_MonitorTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(LibreSCRS_MonitorTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
gtest_discover_tests(LibreSCRS_MonitorTests)

add_executable(SigningRequestTsaOverrideTest
    SigningRequestTsaOverrideTest.cpp
)
target_link_libraries(SigningRequestTsaOverrideTest PRIVATE
    GTest::gtest_main
    LibreSCRS_Signing
)
gtest_discover_tests(SigningRequestTsaOverrideTest)

add_executable(PluginAbiVersionTest
    PluginAbiVersionTest.cpp
)
target_link_libraries(PluginAbiVersionTest PRIVATE
    GTest::gtest_main
    LibreSCRS::Plugin
)
gtest_discover_tests(PluginAbiVersionTest)

# M3: narrowed BAC-fallback policy — shouldTryFallback fires ONLY on the
# structural PaceUnsupported verdict (no downgrade on any other non-stop
# error). Reaches the internal shouldTryFallback predicate the same way
# lib/plugin/test/ActivationProfileTests.cpp does (CardPlugin_Impl object
# archive + LIBRESCRS_INTERNAL_BUILD), but registers under the top-level
# test/ tree so it runs in the CI-literal `ctest --test-dir build/test` gate.
add_executable(ActivationFallbackPolicyTests
    plugin/activation_profile_test.cpp
)
target_link_libraries(ActivationFallbackPolicyTests PRIVATE
    GTest::gtest_main
    LibreSCRS::Plugin
    CardPlugin_Impl
    LibreSCRS::SmartCard
    LibreSCRS::Secure
)
target_include_directories(ActivationFallbackPolicyTests PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(ActivationFallbackPolicyTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(ActivationFallbackPolicyTests)

# A1 (4.0 hardening): Atr::matches semantics — exact + masked match cases.
add_executable(AtrMatchingTests
    plugin/atr_matching_test.cpp
)
target_link_libraries(AtrMatchingTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Plugin
    CardPlugin_Impl
)
gtest_discover_tests(AtrMatchingTests)

# NVI readCard wrapper observes a LibreSCRS::CancelToken and short-circuits
# before dispatching to doReadCard when isCancelled() returns true.
add_executable(CancellationNviTests
    plugin/cancellation_test.cpp
)
target_link_libraries(CancellationNviTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Plugin
    LibreSCRS_Auth
    LibreSCRS_SmartCard
    CardPlugin_Impl
    SmartCard_Impl
)
# A detached session (no PC/SC I/O) for the stub plugin comes from the declared
# test archive, exactly as another project's tests get one: public headers
# only, no LIBRESCRS_INTERNAL_BUILD.
target_link_libraries(CancellationNviTests PRIVATE LibreSCRS_SmartCardTesting)
gtest_discover_tests(CancellationNviTests)

# A3 (4.0 hardening): mandatory LocalizedText userMessage on ReadResult,
# SigningResult, and OpenError; ErrorKeys generic-builder set.
add_executable(LocalizedTextFactoriesTests
    plugin/localized_text_factories_test.cpp
)
target_link_libraries(LocalizedTextFactoriesTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
    LibreSCRS_Plugin
    LibreSCRS_SmartCard
    LibreSCRS_Signing
)
gtest_discover_tests(LocalizedTextFactoriesTests)

# A4 (4.0 hardening): compile-time SecretParameter concept enforcing
# Secure::String const& on credential-bearing parameters. Most of the work
# happens at compile time (static_asserts in the test source); the binary
# exists so GTest discovery picks it up.
add_executable(SecretParameterConceptTests
    plugin/secret_parameter_concept_test.cpp
)
target_link_libraries(SecretParameterConceptTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
    LibreSCRS_Secure
)
gtest_discover_tests(SecretParameterConceptTests)

# 4.0 hardening: codegen golden-output test for manifest2header.py.
# The test invokes the Python tool against a fixture manifest at runtime
# and diffs the output against expected_manifest.h, then re-invokes with
# an invalid fixture and confirms the schema gate rejects it.
add_executable(ManifestCodegenTests
    build_system/manifest_codegen_test.cpp
)
target_link_libraries(ManifestCodegenTests PRIVATE GTest::gtest_main)
target_compile_definitions(ManifestCodegenTests PRIVATE
    LIBRESCRS_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/build_system/fixtures"
    LIBRESCRS_MANIFEST2HEADER_PATH="${PROJECT_SOURCE_DIR}/tools/manifest2header/manifest2header.py"
    LIBRESCRS_MANIFEST_SCHEMA_PATH="${PROJECT_SOURCE_DIR}/cmake/schemas/plugin-manifest.schema.json"
    LIBRESCRS_PYTHON_EXECUTABLE="${Python3_EXECUTABLE}"
)
gtest_discover_tests(ManifestCodegenTests)

add_subdirectory(smartcard)
add_subdirectory(pkcs15-plugin)
add_subdirectory(Trust)

# Opensc-plugin PIN lifecycle classification tests (no hardware).
# Compiles the plugin translation unit directly (OpenScBridgeTests
# precedent) so the internal evidence-building seam can be driven with
# synthetic sc_pkcs15 objects — pure struct input, no card I/O,
# preserving the getPINList non-consumption invariant. Link list mirrors
# OpenSCFallbackIntegrationTest; the generated manifest.h include dir and
# the opensc-plugin dependency come from the plugin target this TU
# normally builds into.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenscPinLifecycleTests
        OpenscPinLifecycleTests.cpp
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src/opensc_card_plugin.cpp
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src/opensc_reader_bridge.cpp
    )
    target_include_directories(OpenscPinLifecycleTests PRIVATE
        ${PROJECT_BINARY_DIR}/lib/opensc-plugin/generated
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        ${PROJECT_SOURCE_DIR}/lib/plugin/src
        ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
        ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
    )
    target_link_libraries(OpenscPinLifecycleTests PRIVATE
        GTest::gtest_main
        CardPlugin_Impl
        LibreSCRS_SmartCard
        SmartCard_Impl
        opensc_plugin_static_with_deps
        OpenSSL_Crypto
    )
    target_compile_definitions(OpenscPinLifecycleTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
    add_dependencies(OpenscPinLifecycleTests opensc-plugin)
    gtest_discover_tests(OpenscPinLifecycleTests)
endif()

# Opensc routing tests (no hardware): the REAL plugin registry probes a
# detached CardSession whose injected FakeChannel scripts the card, so the
# two-phase candidate lookup runs every shipped plugin's probe against the
# same scripted answers. Needs the registry (CardPlugin_Impl), the shipped
# plugin .so set, and the SmartCard test-helpers archive for the channel
# injection seams.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenscRoutingTests
        OpenscRoutingTests.cpp
    )
    target_include_directories(OpenscRoutingTests PRIVATE
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    )
    target_link_libraries(OpenscRoutingTests PRIVATE
        GTest::gtest_main
        CardPlugin_Impl
        LibreSCRS_SmartCard
        LibreSCRS_SmartCard_TestHelpers
        SmartCard_Impl
    )
    target_compile_definitions(OpenscRoutingTests PRIVATE
        PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
        LIBRESCRS_INTERNAL_BUILD
    )
    add_dependencies(OpenscRoutingTests opensc-plugin pkcs15-plugin)
    gtest_discover_tests(OpenscRoutingTests)
endif()

# Opensc-plugin channel lifecycle + probe-gate tests (no hardware).
# Same TU-compilation harness as OpenscPinLifecycleTests, plus the
# SmartCard test-helpers archive for the FakeChannel double and the
# detached-session / channel-injection seams that stand in for a live
# SM tunnel.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenscChannelLifecycleTests
        OpenscChannelLifecycleTests.cpp
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src/opensc_card_plugin.cpp
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src/opensc_reader_bridge.cpp
    )
    target_include_directories(OpenscChannelLifecycleTests PRIVATE
        ${PROJECT_BINARY_DIR}/lib/opensc-plugin/generated
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        ${PROJECT_SOURCE_DIR}/lib/plugin/src
        ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
        ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
    )
    target_link_libraries(OpenscChannelLifecycleTests PRIVATE
        GTest::gtest_main
        CardPlugin_Impl
        LibreSCRS_SmartCard
        LibreSCRS_SmartCard_TestHelpers
        SmartCard_Impl
        opensc_plugin_static_with_deps
        OpenSSL_Crypto
    )
    target_compile_definitions(OpenscChannelLifecycleTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
    add_dependencies(OpenscChannelLifecycleTests opensc-plugin)
    gtest_discover_tests(OpenscChannelLifecycleTests)
endif()

# pkcs15-plugin PIN lifecycle classification tests (no hardware).
# Drives the plugin .so through the registry (PKCS15PluginTests wiring)
# against a scripted PKCS#15 card: detached CardSession + injected
# PlainChannel (LibreSCRS_SmartCard_TestHelpers seams, the
# lib/pkcs15/test harness pattern) with a PCSCConnection transmit filter
# serving the hardware-scanned AppletSuiteGen1 EF.AODF fixture.
add_executable(Pkcs15PinLifecycleTests Pkcs15PinLifecycleTests.cpp)
target_link_libraries(Pkcs15PinLifecycleTests PRIVATE
    GTest::gtest_main
    CardPlugin_Impl
    PKCS15
    LibreSCRS_SmartCard
    LibreSCRS_SmartCard_TestHelpers
    SmartCard_Impl
)
target_include_directories(Pkcs15PinLifecycleTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/pkcs15/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(Pkcs15PinLifecycleTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
    LIBRESCRS_INTERNAL_BUILD
)
add_dependencies(Pkcs15PinLifecycleTests pkcs15-plugin)
gtest_discover_tests(Pkcs15PinLifecycleTests)

# Opensc-plugin changePIN selector-correctness tests (no hardware).
# Same TU-compilation harness as OpenscPinLifecycleTests: drives the
# plugin's change-dispatch seam with synthetic sc_pkcs15 auth objects and
# injected driver entry points, so the addressed-object contract (and the
# unknown-selector refusal) is asserted without any card I/O.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenscChangePinSelectorTests
        OpenscChangePinSelectorTests.cpp
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src/opensc_card_plugin.cpp
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src/opensc_reader_bridge.cpp
    )
    target_include_directories(OpenscChangePinSelectorTests PRIVATE
        ${PROJECT_BINARY_DIR}/lib/opensc-plugin/generated
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        ${PROJECT_SOURCE_DIR}/lib/plugin/src
        ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
        ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
    )
    target_link_libraries(OpenscChangePinSelectorTests PRIVATE
        GTest::gtest_main
        CardPlugin_Impl
        LibreSCRS_SmartCard
        SmartCard_Impl
        opensc_plugin_static_with_deps
        OpenSSL_Crypto
    )
    target_compile_definitions(OpenscChangePinSelectorTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
    add_dependencies(OpenscChangePinSelectorTests opensc-plugin)
    gtest_discover_tests(OpenscChangePinSelectorTests)
endif()

# Opensc-plugin user-PIN selection tests (no hardware). Same TU-compilation
# harness: drives the plugin's verify/counter seams with synthetic
# sc_pkcs15 objects and injected driver entry points, so the addressed-object
# contract is asserted without any card I/O.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenscUserPinSelectionTests
        OpenscUserPinSelectionTests.cpp
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src/opensc_card_plugin.cpp
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src/opensc_reader_bridge.cpp
    )
    target_include_directories(OpenscUserPinSelectionTests PRIVATE
        ${PROJECT_BINARY_DIR}/lib/opensc-plugin/generated
        ${PROJECT_SOURCE_DIR}/lib/opensc-plugin/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        ${PROJECT_SOURCE_DIR}/lib/plugin/src
        ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
        ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
    )
    target_link_libraries(OpenscUserPinSelectionTests PRIVATE
        GTest::gtest_main
        CardPlugin_Impl
        LibreSCRS_SmartCard
        SmartCard_Impl
        opensc_plugin_static_with_deps
        OpenSSL_Crypto
    )
    target_compile_definitions(OpenscUserPinSelectionTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
    add_dependencies(OpenscUserPinSelectionTests opensc-plugin)
    gtest_discover_tests(OpenscUserPinSelectionTests)
endif()

# pkcs15-plugin changePIN selector-correctness tests (no hardware).
# Same harness as Pkcs15PinLifecycleTests (plugin .so via the registry,
# detached CardSession + injected PlainChannel, scripted transmit
# filter); the scripted card additionally answers CHANGE REFERENCE DATA
# so the default-PIN regression guard can observe the mutation on the
# wire.
add_executable(Pkcs15ChangePinSelectorTests Pkcs15ChangePinSelectorTests.cpp)
target_link_libraries(Pkcs15ChangePinSelectorTests PRIVATE
    GTest::gtest_main
    CardPlugin_Impl
    LibreSCRS_SmartCard
    LibreSCRS_SmartCard_TestHelpers
    SmartCard_Impl
)
target_include_directories(Pkcs15ChangePinSelectorTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(Pkcs15ChangePinSelectorTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
    LIBRESCRS_INTERNAL_BUILD
)
add_dependencies(Pkcs15ChangePinSelectorTests pkcs15-plugin)
gtest_discover_tests(Pkcs15ChangePinSelectorTests)

# pkcs15-plugin EF.ODF re-read census (no hardware).
# Same harness as Pkcs15PinLifecycleTests (plugin .so via the registry,
# detached CardSession + injected PlainChannel, scripted transmit filter).
# Counts SELECT-by-FID of EF.ODF — emitted by PKCS15Card::readProfile and
# by nothing else — to measure profile reads per public entry point. The
# same scripted card, with its optional signing behaviour on, also drives
# the plugin's and PKCS15Card's signing paths.
add_executable(Pkcs15ProfileReadCensusTests
    Pkcs15ProfileReadCensusTests.cpp
)
target_link_libraries(Pkcs15ProfileReadCensusTests PRIVATE
    GTest::gtest_main
    CardPlugin_Impl
    PKCS15
    EMRTDCrypto
    LibreSCRS_SmartCard
    LibreSCRS_SmartCard_TestHelpers
    SmartCard_Impl
    LibreSCRS::Secure
    OpenSSL_Crypto
)
target_include_directories(Pkcs15ProfileReadCensusTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/pkcs15/src
    ${LibreMiddleware_SOURCE_DIR}/lib/SecureChannel/include
    ${LibreMiddleware_SOURCE_DIR}/lib/emrtd-crypto/src
    ${LibreMiddleware_SOURCE_DIR}/lib/LibreSCRS/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(Pkcs15ProfileReadCensusTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
    LIBRESCRS_INTERNAL_BUILD
)
add_dependencies(Pkcs15ProfileReadCensusTests pkcs15-plugin)
gtest_discover_tests(Pkcs15ProfileReadCensusTests)
