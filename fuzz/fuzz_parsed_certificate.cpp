// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for LibreSCRS::Certificate::ParsedCertificate::fromDer.
// Build: -DLIBRESCRS_BUILD_FUZZ=ON; binaries land in build/fuzz/.
// Run:   ./fuzz_parsed_certificate -max_total_time=60 corpus/parsed_certificate

#include <LibreSCRS/Certificate/ParsedCertificate.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    auto cert = LibreSCRS::Certificate::ParsedCertificate::fromDer(std::span<const std::uint8_t>(data, size));
    if (cert) {
        // Touch every typed accessor to maximize coverage of the parser body.
        // Each must tolerate being invoked on a successfully-parsed cert.
        (void)cert->subject();
        (void)cert->issuer();
        (void)cert->serialNumber();
        (void)cert->version();
        (void)cert->notBefore();
        (void)cert->notAfter();
        (void)cert->signatureAlgorithmOid();
        (void)cert->signatureAlgorithmDescription();
        (void)cert->signatureValue();
        (void)cert->publicKey();
        (void)cert->keyUsage();
        (void)cert->extendedKeyUsage();
        (void)cert->subjectAlternativeNames();
        (void)cert->issuerAlternativeNames();
        (void)cert->basicConstraints();
        (void)cert->authorityKeyIdentifier();
        (void)cert->subjectKeyIdentifier();
        (void)cert->crlDistributionPoints();
        (void)cert->ocspResponderUrls();
        (void)cert->caIssuersUrls();
        (void)cert->certificatePolicies();
        (void)cert->extensions();
        (void)cert->derBytes();
    }
    return 0;
}
