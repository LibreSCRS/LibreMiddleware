// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for libresign::TlSignatureVerifier::verify.
// Uses a constant DER signing certificate (compiled into the binary at build
// time from test/fixtures/trust/test-tl-signing-cert.pem). The harness drives
// the libxml2 C14N + OpenSSL EVP path with arbitrary input bytes treated as
// the to-be-verified XML document.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON.
// Run:   ./fuzz_tl_signature_verifier -max_total_time=60 corpus/tl_signature_verifier

// LIBRESCRS_INTERNAL_BUILD is set via target_compile_definitions in CMake.
#include "native/tl_signature_verifier.h"

#include <cstddef>
#include <cstdint>
#include <span>

// Embedded DER signing certificate (generated at configure time).
extern const unsigned char kTlFuzzSigningCertDer[];
extern const unsigned int kTlFuzzSigningCertDerLen;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    libresign::TlSignatureVerifier verifier;
    (void)verifier.verify(std::span<const std::uint8_t>(data, size),
                          std::span<const std::uint8_t>(kTlFuzzSigningCertDer, kTlFuzzSigningCertDerLen));
    return 0;
}
