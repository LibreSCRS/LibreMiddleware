// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "openssl_raii.h"

// Forward declarations for helper functions
typedef struct x509_st X509;

namespace libresign {
class Pkcs11Token;
struct TSAConfig;
struct RevocationData;
} // namespace libresign

// Error handling convention for native signing modules:
// - throw std::runtime_error: programming errors, corrupt data, broken invariants.
// - Return error struct (TSAResult, SigningResult with success=false): expected
//   operational failures — network timeouts, invalid input, card not present.
// - Top-level NativeSigningService::sign() catches all exceptions and wraps
//   in SigningResult{false, {}, errorMessage}.

namespace libresign::native_utils {

// Re-export from openssl_raii.h for existing callers
using libresign::X509Deleter;
using libresign::X509Ptr;

/// @brief Uppercase hex digit table — `data[i]` is the ASCII character for
///        the nibble value @p i (0..15). Used by every internal byte→hex
///        encoder (PAdES /Contents, XAdES percent-encoder, …) to avoid
///        re-defining the same 16-byte literal in multiple TUs.
inline constexpr std::string_view kHexChars = "0123456789ABCDEF";

// OpenSSL error string
std::string opensslError();

// SHA-256 hash
std::vector<uint8_t> sha256(const uint8_t* data, size_t len);
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
std::vector<uint8_t> sha256(const std::string& data);

// SHA-384 hash
std::vector<uint8_t> sha384(const uint8_t* data, size_t len);
std::vector<uint8_t> sha384(const std::string& data);

// SHA-512 hash
std::vector<uint8_t> sha512(const uint8_t* data, size_t len);
std::vector<uint8_t> sha512(const std::string& data);

// Parse DER-encoded X509 certificate
X509Ptr parseCert(const std::vector<uint8_t>& der);

// Ensure libxml2 is initialized (thread-safe, idempotent)
void ensureXmlInitialized();

// Base64 encoding (standard RFC 4648 section 4)
std::string base64Encode(const std::vector<uint8_t>& data);
std::string base64Encode(const uint8_t* data, size_t len);

// Base64 decoding (standard RFC 4648 section 4, whitespace-tolerant)
std::vector<uint8_t> base64Decode(const std::string& input);

// SHA-256 hash as base64-encoded string
std::string sha256Base64(const std::vector<uint8_t>& data);

// Decomposed UTC time parts (from system_clock::now())
struct UtcTimeParts
{
    int year;
    unsigned month, day;
    int hour, min, sec;
};
UtcTimeParts utcNow();

// ISO 8601 UTC timestamp
std::string iso8601Now();

// MIME type from file extension
std::string mimeTypeFromFileName(const std::string& fileName);

// Collect revocation data (CRLs + OCSP) for the token's certificate chain.
libresign::RevocationData collectRevocationData(libresign::Pkcs11Token& token, const libresign::TSAConfig& tsa);

// Return the DigestInfo prefix for the given digest name, or empty span if unknown.
// Accepts OpenSSL-style names: SHA256, SHA-256, SHA2-256, etc. (case-insensitive).
std::span<const uint8_t> digestInfoPrefixForAlgo(const std::string& mdName);

// Return the Pkcs11Token algorithm string for the given key type + digest.
// keyType is EVP_PKEY_RSA or EVP_PKEY_EC; mdName uses OpenSSL-style names.
std::string tokenAlgorithm(int keyType, const std::string& mdName);

// Sign a SHA-256 hash with a PKCS#11 token, prepending DigestInfo for RSA.
// Returns the raw signature bytes.
std::vector<uint8_t> signHashWithToken(libresign::Pkcs11Token& token, X509* cert, const std::vector<uint8_t>& hash,
                                       const std::string& hashAlgo = "SHA256");

// Decompress FlateDecode (zlib) data. Returns nullopt on error.
std::optional<std::vector<uint8_t>> flateDecode(std::span<const uint8_t> compressed, size_t sizeHint = 0);

/// Reverse PNG row filters (predictor 10-15). columns = bytes per row (excluding filter byte).
std::optional<std::vector<uint8_t>> reversePngPredictor(std::span<const uint8_t> data, int columns);

// DER-encode any OpenSSL object using its i2d function
template <typename T, typename Fn>
std::vector<uint8_t> derEncode(Fn i2dFn, const T* obj)
{
    unsigned char* der = nullptr;
    int len = i2dFn(obj, &der);
    if (len <= 0 || !der)
        return {};
    std::vector<uint8_t> result(der, der + len);
    OPENSSL_free(der);
    return result;
}

} // namespace libresign::native_utils

// Re-export DigestInfo prefixes into native_utils for existing callers.
#include "digest_info.h"
namespace libresign::native_utils {
using libresign::kDigestInfoSha1Prefix;
using libresign::kDigestInfoSha256Prefix;
using libresign::kDigestInfoSha384Prefix;
using libresign::kDigestInfoSha512Prefix;
} // namespace libresign::native_utils
