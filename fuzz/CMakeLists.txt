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
add_executable(fuzz_parsed_certificate fuzz_parsed_certificate.cpp)
target_compile_options(fuzz_parsed_certificate PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_parsed_certificate PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_libraries(fuzz_parsed_certificate PRIVATE LibreSCRS_Certificate)

# ---------------------------------------------------------------------------
# Harness: TrustedListParser::parse
# ---------------------------------------------------------------------------
add_executable(fuzz_trusted_list_parser fuzz_trusted_list_parser.cpp)
target_compile_options(fuzz_trusted_list_parser PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_trusted_list_parser PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_trusted_list_parser PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_trusted_list_parser PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/libresign/src
)
target_link_libraries(fuzz_trusted_list_parser PRIVATE LibreSign)

# ---------------------------------------------------------------------------
# Harness: TlSignatureVerifier::verify (with constant signing cert)
# ---------------------------------------------------------------------------
add_executable(fuzz_tl_signature_verifier
    fuzz_tl_signature_verifier.cpp
    "${LIBRESCRS_FUZZ_TL_EMBED}"
)
target_compile_options(fuzz_tl_signature_verifier PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_link_options(fuzz_tl_signature_verifier PRIVATE ${LIBRESCRS_FUZZ_FLAGS})
target_compile_definitions(fuzz_tl_signature_verifier PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(fuzz_tl_signature_verifier PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/libresign/src
)
target_link_libraries(fuzz_tl_signature_verifier PRIVATE LibreSign)

# Stage corpora next to the binaries so users can `cd build && ./fuzz/...`
# without a long path argument.
file(COPY "${PROJECT_SOURCE_DIR}/fuzz/corpus" DESTINATION
    "${CMAKE_CURRENT_BINARY_DIR}/")
