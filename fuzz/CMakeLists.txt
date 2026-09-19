# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# libFuzzer harnesses for LibreMiddleware public parsers.
#
# Gated behind LIBRESCRS_BUILD_FUZZ=ON. Requires Clang with libFuzzer
# (-fsanitize=fuzzer,address). GCC is not supported for these targets.
#
# Build:
#   cmake -B build-fuzz -S . -DLIBRESCRS_BUILD_FUZZ=ON \
#         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
#         -DCMAKE_BUILD_TYPE=RelWithDebInfo
#   cmake --build build-fuzz -j4
#
# Run (60s per harness, hermetic seed corpus):
#   ./build-fuzz/fuzz/fuzz_parsed_certificate \
#       -max_total_time=60 fuzz/corpus/parsed_certificate
#   ./build-fuzz/fuzz/fuzz_trusted_list_parser \
#       -max_total_time=60 fuzz/corpus/trusted_list_parser
#   ./build-fuzz/fuzz/fuzz_tl_signature_verifier \
#       -max_total_time=60 fuzz/corpus/tl_signature_verifier

if(NOT (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR
        CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang"))
    message(WARNING
        "LIBRESCRS_BUILD_FUZZ=ON requires Clang/libFuzzer; current compiler "
        "is ${CMAKE_CXX_COMPILER_ID}. Skipping fuzz target generation.")
    return()
endif()

# Common compile/link flags for every fuzz target.
set(LIBRESCRS_FUZZ_FLAGS
    -fsanitize=fuzzer,address,undefined
    -fno-omit-frame-pointer
    -g
)

# ---------------------------------------------------------------------------
# Which harness compiles the code it fuzzes: read from one file, here and in
# ci/scripts/check-fuzz-instrumentation.sh.
#
# The flags above are PRIVATE on each executable, so they reach that
# executable's own translation units and nothing else. A harness that only
# links the library it is meant to fuzz therefore fuzzes uninstrumented code.
# fuzz/instrumented-sources.txt says, per harness, which sources are compiled
# in and which harness deliberately has none; this block turns that into the
# LIBRESCRS_FUZZ_SRC_<harness> variables the targets below use, and the check
# reads the resulting objects back to prove the flags really arrived. Two
# hand-kept copies of one list is what cmake/EmrtdCryptoPrivateIncludes.cmake
# exists to prevent.
# ---------------------------------------------------------------------------
set(LIBRESCRS_FUZZ_SOURCE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/instrumented-sources.txt")
if(NOT EXISTS "${LIBRESCRS_FUZZ_SOURCE_LIST}")
    message(FATAL_ERROR "missing ${LIBRESCRS_FUZZ_SOURCE_LIST}")
endif()
file(STRINGS "${LIBRESCRS_FUZZ_SOURCE_LIST}" LIBRESCRS_FUZZ_ROWS REGEX "^[A-Za-z0-9_]+:")
set(LIBRESCRS_FUZZ_DECLARED "")
foreach(row IN LISTS LIBRESCRS_FUZZ_ROWS)
    if(NOT row MATCHES "^([A-Za-z0-9_]+):[ \t]*([^#]*)")
        continue()
    endif()
    set(harness "${CMAKE_MATCH_1}")
    set(value "${CMAKE_MATCH_2}")
    string(STRIP "${value}" value)
    list(APPEND LIBRESCRS_FUZZ_DECLARED "${harness}")
    if(value STREQUAL "LINK_ONLY" OR value STREQUAL "")
        continue()
    endif()
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/${value}")
        message(FATAL_ERROR
            "instrumented-sources.txt names ${value} for ${harness}, which does not exist")
    endif()
    list(APPEND LIBRESCRS_FUZZ_SRC_${harness} "${PROJECT_SOURCE_DIR}/${value}")
endforeach()
list(REMOVE_DUPLICATES LIBRESCRS_FUZZ_DECLARED)

# Reconfigure when the list changes, or the build would keep the shape the
# previous configure read out of it.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${LIBRESCRS_FUZZ_SOURCE_LIST}")

# Convert the test TL signing certificate from PEM to DER and embed it as a
# C array for the signature-verifier harness. We do this at configure time
# rather than depending on the CMake EmbedBinary helper because we want a
# stable symbol name (kTlFuzzSigningCertDer) plus a separate ...Len constant.
set(LIBRESCRS_FUZZ_TL_PEM
    "${PROJECT_SOURCE_DIR}/test/fixtures/trust/test-tl-signing-cert.pem")
set(LIBRESCRS_FUZZ_TL_DER
    "${CMAKE_CURRENT_BINARY_DIR}/test-tl-signing-cert.der")
set(LIBRESCRS_FUZZ_TL_EMBED
    "${CMAKE_CURRENT_BINARY_DIR}/embedded_tl_cert.cpp")

find_program(OPENSSL_BIN openssl REQUIRED)

add_custom_command(
    OUTPUT  "${LIBRESCRS_FUZZ_TL_DER}"
    COMMAND ${OPENSSL_BIN} x509
            -in "${LIBRESCRS_FUZZ_TL_PEM}"
            -outform DER
            -out "${LIBRESCRS_FUZZ_TL_DER}"
    DEPENDS "${LIBRESCRS_FUZZ_TL_PEM}"
    COMMENT "Converting test TL signing cert PEM -> DER for fuzz harness"
    VERBATIM)

add_custom_command(
    OUTPUT  "${LIBRESCRS_FUZZ_TL_EMBED}"
    COMMAND ${CMAKE_COMMAND}
            -DIN_FILE=${LIBRESCRS_FUZZ_TL_DER}
            -DOUT_FILE=${LIBRESCRS_FUZZ_TL_EMBED}
            -DSYMBOL=kTlFuzzSigningCertDer
            -P ${PROJECT_SOURCE_DIR}/fuzz/EmbedFuzzCert.cmake
    DEPENDS "${LIBRESCRS_FUZZ_TL_DER}"
            "${PROJECT_SOURCE_DIR}/fuzz/EmbedFuzzCert.cmake"
    COMMENT "Embedding TL signing cert as C array for fuzz harness"
    VERBATIM)

# ---------------------------------------------------------------------------
# Harness: ParsedCertificate::fromDer
# ---------------------------------------------------------------------------
add_executable(fuzz_parsed_certificate fuzz_parsed_certificate.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_parsed_certificate})
target_compile_options(fuzz_parsed_certificate PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_parsed_certificate PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_libraries(fuzz_parsed_certificate PRIVATE LibreSCRS_Certificate)

# ---------------------------------------------------------------------------
# Harness: TrustedListParser::parse
# ---------------------------------------------------------------------------
add_executable(fuzz_trusted_list_parser fuzz_trusted_list_parser.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_trusted_list_parser})
target_compile_options(fuzz_trusted_list_parser PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_trusted_list_parser PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_trusted_list_parser PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_trusted_list_parser PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/libresign/src
)
target_link_libraries(fuzz_trusted_list_parser PRIVATE LibreSign)

# ---------------------------------------------------------------------------
# Harness: pkcs15 parser (parseODF / parseTokenInfo / parseCDF / parsePrKDF /
# parseAODF). External-byte attack surface — a hostile PKCS#15 card can put
# any bytes in any directory file.
# ---------------------------------------------------------------------------
add_executable(fuzz_pkcs15_parser fuzz_pkcs15_parser.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_pkcs15_parser})
target_compile_features(fuzz_pkcs15_parser PRIVATE cxx_std_23)
target_compile_options(fuzz_pkcs15_parser PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_pkcs15_parser PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_pkcs15_parser PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_pkcs15_parser PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include
)
target_link_libraries(fuzz_pkcs15_parser PRIVATE PKCS15)

# ---------------------------------------------------------------------------
# Harness: emrtd parseDataGroups + parseMRZ. External-byte attack surface —
# DG file contents are card-controlled bytes that dispatch into per-DG
# sub-parsers.
# ---------------------------------------------------------------------------
add_executable(fuzz_emrtd_dg_parser fuzz_emrtd_dg_parser.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_emrtd_dg_parser})
target_compile_features(fuzz_emrtd_dg_parser PRIVATE cxx_std_23)
target_compile_options(fuzz_emrtd_dg_parser PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_emrtd_dg_parser PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_emrtd_dg_parser PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_emrtd_dg_parser PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/emrtd/src
)
target_link_libraries(fuzz_emrtd_dg_parser PRIVATE EMRTD)

include(EmrtdCryptoPrivateIncludes)

# ---------------------------------------------------------------------------
# Harness: parseCscaMasterList. External-byte attack surface — a published CSCA
# master list is walked before anything has verified its signature, so every
# byte in it is whatever produced the file.
# ---------------------------------------------------------------------------
add_executable(fuzz_csca_master_list fuzz_csca_master_list.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_csca_master_list})
# Explicit, unlike the harnesses above: csca_master_list.h returns
# std::expected, so this target needs C++23 in its own right and does not get
# it from the library's directory-scope setting.
target_compile_features(fuzz_csca_master_list PRIVATE cxx_std_23)
target_compile_options(fuzz_csca_master_list PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_csca_master_list PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_csca_master_list PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_csca_master_list PRIVATE ${LIBRESCRS_EMRTD_CRYPTO_PRIVATE_INCLUDES})
target_link_libraries(fuzz_csca_master_list PRIVATE EMRTDCrypto SmartCard_Impl LibreSCRS_SecureChannel)

# ---------------------------------------------------------------------------
# Harnesses: the eMRTD walkers that run over unauthenticated card bytes.
#
# Unlike the harnesses above, these compile the source under test INTO the
# target. ${LIBRESCRS_FUZZ_FLAGS} is PRIVATE on an executable, so it reaches
# that executable's own sources and nothing else: the libraries are built
# without any sanitizer. A harness that only links them fuzzes uninstrumented
# code, and a scalar read past the end of a buffer -- which is what these
# walkers do on a hostile length -- is then not reported at all. The private
# include directories come from cmake/EmrtdCryptoPrivateIncludes.cmake, which
# lib/emrtd-crypto/CMakeLists.txt reads too, for the same reason: PRIVATE
# settings do not arrive over the link. That list used to be hand-copied here
# and drifted; the top-level CMakeLists.txt now fails the configure if it and
# EMRTDCrypto disagree. LIBRESCRS_INTERNAL_BUILD stays spelled out below: the
# internal headers #error on its absence, so a missing one fails loudly at
# compile time, which an include directory does not. SmartCard_Impl is named on
# the link line because EMRTDCrypto links it PRIVATE, so the smartcard public
# include root and the PC/SC interface it carries stop there, and apdu.h needs
# both.
# ---------------------------------------------------------------------------
include(EmrtdCryptoPrivateIncludes)

# Harness: parseSOD — EF.SOD, walked before its signature is checked.
add_executable(fuzz_emrtd_sod fuzz_emrtd_sod.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_emrtd_sod})
target_compile_features(fuzz_emrtd_sod PRIVATE cxx_std_23)
target_compile_options(fuzz_emrtd_sod PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_emrtd_sod PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_emrtd_sod PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_emrtd_sod PRIVATE ${LIBRESCRS_EMRTD_CRYPTO_PRIVATE_INCLUDES})
target_link_libraries(fuzz_emrtd_sod PRIVATE EMRTDCrypto SmartCard_Impl LibreSCRS_SecureChannel)

# Harness: parseCardAccess — EF.CardAccess, read over a plain channel.
add_executable(fuzz_emrtd_card_access fuzz_emrtd_card_access.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_emrtd_card_access})
target_compile_features(fuzz_emrtd_card_access PRIVATE cxx_std_23)
target_compile_options(fuzz_emrtd_card_access PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_emrtd_card_access PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_emrtd_card_access PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_emrtd_card_access PRIVATE ${LIBRESCRS_EMRTD_CRYPTO_PRIVATE_INCLUDES})
target_link_libraries(fuzz_emrtd_card_access PRIVATE EMRTDCrypto SmartCard_Impl LibreSCRS_SecureChannel)

# Harness: parseDG14 / parseDG15 — the security infos and the AA public key.
add_executable(fuzz_emrtd_security_info fuzz_emrtd_security_info.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_emrtd_security_info})
target_compile_features(fuzz_emrtd_security_info PRIVATE cxx_std_23)
target_compile_options(fuzz_emrtd_security_info PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_emrtd_security_info PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_emrtd_security_info PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_emrtd_security_info PRIVATE ${LIBRESCRS_EMRTD_CRYPTO_PRIVATE_INCLUDES})
target_link_libraries(fuzz_emrtd_security_info PRIVATE EMRTDCrypto SmartCard_Impl LibreSCRS_SecureChannel)

# ---------------------------------------------------------------------------
# Harness: readChunkedFile — the one file-read loop under every card reader.
#
# The length it allocates for comes out of the file header, so the chip picks
# the size of the buffer. chunked_read.cpp is compiled into the target for the
# same reason the eMRTD walkers above are: PRIVATE sanitizer flags do not
# arrive over the link, and a harness that only links the library fuzzes
# uninstrumented code. SmartCard_Impl is still on the link line for readBinary()
# and the PC/SC interface; it is a static archive, so pulling apdu.o out of it
# does not also pull the uninstrumented chunked_read.o.
# ---------------------------------------------------------------------------
add_executable(fuzz_chunked_read fuzz_chunked_read.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_chunked_read})
target_compile_features(fuzz_chunked_read PRIVATE cxx_std_23)
target_compile_options(fuzz_chunked_read PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_chunked_read PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_chunked_read PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_chunked_read PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include)
target_link_libraries(fuzz_chunked_read PRIVATE SmartCard_Impl)

# ---------------------------------------------------------------------------
# Harness: the PDF xref / trailer walker.
#
# The document arrives by mail or download and goes into the signing wizard, so
# every byte of it is the sender's choice. Three translation units are compiled
# in because the tokenizer and the value tree are separate from the walker and
# all three see the same bytes.
# ---------------------------------------------------------------------------
add_executable(fuzz_pdf_parser fuzz_pdf_parser.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_pdf_parser})
target_compile_features(fuzz_pdf_parser PRIVATE cxx_std_23)
target_compile_options(fuzz_pdf_parser PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_pdf_parser PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_pdf_parser PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_pdf_parser PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/libresign/src
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
)
target_link_libraries(fuzz_pdf_parser PRIVATE LibreSign)

# ---------------------------------------------------------------------------
# Harnesses: the Serbian card TLV reader, and the BER-TLV walker under it.
#
# Both Serbian families read their fields through one little-endian 16-bit TLV
# reader with a UTF-16 decode behind it, so one harness covers both. The BER
# walker is the canonical decoder the tree consolidated its length decodes
# onto and had no harness at all.
# ---------------------------------------------------------------------------
add_executable(fuzz_rs_tlv fuzz_rs_tlv.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_rs_tlv})
target_compile_features(fuzz_rs_tlv PRIVATE cxx_std_23)
target_compile_options(fuzz_rs_tlv PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_rs_tlv PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_rs_tlv PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_rs_tlv PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
)
target_link_libraries(fuzz_rs_tlv PRIVATE SmartCard_Impl)

add_executable(fuzz_ber fuzz_ber.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_ber})
target_compile_features(fuzz_ber PRIVATE cxx_std_23)
target_compile_options(fuzz_ber PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_ber PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_ber PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_ber PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
)
target_link_libraries(fuzz_ber PRIVATE SmartCard_Impl)

# ---------------------------------------------------------------------------
# Harness: the EU vehicle-registration path.
#
# The header derivation decides how many bytes to read from the card, and the
# field walk turns the result into what a user sees. The whole BER stack under
# both is compiled in.
# ---------------------------------------------------------------------------
add_executable(fuzz_eu_vrc fuzz_eu_vrc.cpp ${LIBRESCRS_FUZZ_SRC_fuzz_eu_vrc})
target_compile_features(fuzz_eu_vrc PRIVATE cxx_std_23)
target_compile_options(fuzz_eu_vrc PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_eu_vrc PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_eu_vrc PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_eu_vrc PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/eu-vrc/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
)
target_link_libraries(fuzz_eu_vrc PRIVATE EuVrc SmartCard_Impl)

# ---------------------------------------------------------------------------
# Harness: TlSignatureVerifier::verify (with constant signing cert)
# ---------------------------------------------------------------------------
add_executable(fuzz_tl_signature_verifier
    fuzz_tl_signature_verifier.cpp
    "${LIBRESCRS_FUZZ_TL_EMBED}"
    ${LIBRESCRS_FUZZ_SRC_fuzz_tl_signature_verifier}
)
target_compile_options(fuzz_tl_signature_verifier PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_tl_signature_verifier PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_tl_signature_verifier PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_tl_signature_verifier PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/libresign/src
)
target_link_libraries(fuzz_tl_signature_verifier PRIVATE LibreSign)

# A harness the list does not mention would be silently link-only, and a row
# naming a harness that does not exist would describe a build nobody has. The
# runtime check asserts the same two things against the objects; this one fails
# the configure, which is cheaper to read.
get_property(LIBRESCRS_FUZZ_TARGETS DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
foreach(t IN LISTS LIBRESCRS_FUZZ_TARGETS)
    if(t MATCHES "^fuzz_" AND NOT t IN_LIST LIBRESCRS_FUZZ_DECLARED)
        message(FATAL_ERROR "${t} is a fuzz target but instrumented-sources.txt does not mention it")
    endif()
endforeach()
foreach(h IN LISTS LIBRESCRS_FUZZ_DECLARED)
    if(NOT TARGET ${h})
        message(FATAL_ERROR "instrumented-sources.txt names ${h}, which is not a target here")
    endif()
endforeach()

# Stage corpora next to the binaries so users can `cd build && ./fuzz/...`
# without a long path argument.
file(COPY "${PROJECT_SOURCE_DIR}/fuzz/corpus" DESTINATION
    "${CMAKE_CURRENT_BINARY_DIR}/")
