// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <utility>

// Forward-declare to avoid pulling <openssl/evp.h> into a public-ish header.
typedef struct evp_md_st EVP_MD;

namespace libresign {

/// Map an `xmldsig` `ds:DigestMethod/@Algorithm` URI to its EVP_MD.
/// Accepts only digest-method URIs (xmlenc#sha256, xmldsig-more#sha384,
/// xmlenc#sha512). Returns nullptr for SHA-1, for signature-method
/// URIs, and for any unknown URI — callers must treat nullptr as a
/// hard rejection.
const EVP_MD* digestFromDigestMethodUri(const std::string& uri);

/// Map an `xmldsig` `ds:SignatureMethod/@Algorithm` URI to its EVP_MD
/// **and** the expected OpenSSL public-key type NID (EVP_PKEY_RSA /
/// EVP_PKEY_EC). Callers MUST assert `EVP_PKEY_base_id(pkey) ==
/// expectedKeyTypeNid` before calling EVP_DigestVerify*, so a
/// signature-method URI cannot smuggle a different key-type contract
/// past the verifier (e.g. an RSA-SHA256 URI applied to an EC key).
/// Returns `{nullptr, 0}` for SHA-1 and unknown URIs.
std::pair<const EVP_MD*, int> digestFromSignatureMethodUri(const std::string& uri);

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
