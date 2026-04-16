// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace libresign {

/// Verifies XML-DSig signatures on ETSI Trust List documents.
/// Uses libxml2 for C14N canonicalization and OpenSSL for signature verification.
class TlSignatureVerifier
{
public:
    /// Verify the XML-DSig signature in an ETSI Trust List XML document.
    /// @param xmlData The raw XML content of the Trust List.
    /// @param signingCertDer DER-encoded X.509 certificate of the expected signer.
    /// @return true if the signature is valid and was made by the given certificate.
    bool verify(std::span<const uint8_t> xmlData, std::span<const uint8_t> signingCertDer);

    /// Returns a human-readable description of the last error (empty on success).
    std::string lastError() const
    {
        return error;
    }

private:
    std::string error;
};

} // namespace libresign
