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
#include "types.h" // SigningResult / SignFailureKind for revocationFailClosed

// Forward declarations for helper functions
typedef struct x509_st X509;

// Forward declarations for libxml2 — kept at global scope to match
// libxml2's own typedef placement so callers that include libxml2
// headers see the same type identity.
struct _xmlNode;

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

/// @brief Returns the text content of @p node as a std::string,
///        rejecting embedded NUL bytes.
///
/// libxml2's xmlNodeGetContent returns a C-style (NUL-terminated)
/// xmlChar*, so any embedded NUL in the original XML CDATA / text
/// segment is silently truncated when wrapped into std::string via the
/// `const char*` constructor — and downstream digest / signature math
/// would then run over a payload different from what the verifier
/// thought it was checking. Use the explicit-length API instead and
/// throw `std::runtime_error` if an embedded NUL is detected.
///
/// @throws std::runtime_error if the content carries an embedded NUL.
std::string xmlContentToString(::_xmlNode* node);

/// @brief Returns the named attribute's value as a std::string, with
///        the same embedded-NUL rejection contract as
///        xmlContentToString.
///
/// @throws std::runtime_error if the attribute value carries an
///         embedded NUL.
std::string xmlAttrToString(::_xmlNode* node, const char* attrName);

/// @brief Uppercase hex digit table — `data[i]` is the ASCII character for
///        the nibble value @p i (0..15). Used by every internal byte→hex
///        encoder (PAdES /Contents, XAdES percent-encoder, …) to avoid
///        re-defining the same 16-byte literal in multiple TUs.
inline constexpr std::string_view kHexChars = "0123456789ABCDEF";

// OpenSSL error string
std::string opensslError();

// SHA-1 hash
std::vector<uint8_t> sha1(const uint8_t* data, size_t len);
std::vector<uint8_t> sha1(const std::vector<uint8_t>& data);
std::vector<uint8_t> sha1(const std::string& data);

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

// Base64url encoding (RFC 4648 §5): standard base64 alphabet with `+` → `-`
// and `/` → `_`, trailing `=` padding stripped. JWS / JAdES (RFC 7515) uses
// this form for the protected header, payload, and signature fields.
std::string base64urlEncode(const std::vector<uint8_t>& data);
std::string base64urlEncode(std::string_view str);

// Base64url decoding (RFC 4648 §5): inverse of base64urlEncode. Restores
// the standard base64 alphabet and re-pads to a 4-byte multiple before
// delegating to base64Decode.
std::vector<uint8_t> base64urlDecode(const std::string& input);

// Hex-encode a byte span as an ASCII string. With @p lowercase false
// (default) emits uppercase `[0-9A-F]+` — PAdES /Contents blobs and any
// callsite that needs the uppercase form. With @p lowercase true emits
// `[0-9a-f]+` — the ISO 32000-2 §12.8.4.3 DSS/VRI key (lowercase-hex
// SHA-1 of the signed /Contents), matching iText / eu.europa.ec.dss.
std::string hexEncode(std::span<const uint8_t> data, bool lowercase = false);

// Percent-encode a byte span per RFC 3986 §2.1. Bytes outside the
// unreserved set (`A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `~`) are emitted as
// `%HH` (uppercase). When @p preserveSlash is true, `/` is also emitted
// verbatim — required for URI paths where `/` is a path separator
// (ASiC `URI` attributes with embedded directories). When false, every
// byte outside the unreserved set is percent-encoded (XAdES URI filename
// references, single-segment URIs).
std::string percentEncode(std::string_view in, bool preserveSlash = false);

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

// Fail-closed gate for long-term (B-LT/B-LTA) signatures: returns a
// RevocationFetchFailed failure result when @p rev reports any non-root chain
// certificate without verified revocation evidence
// (RevocationData::certsWithoutRevocation non-empty); std::nullopt when every
// required certificate is covered and the caller may embed @p rev. Splitting
// the policy out of the format modules keeps it card-free and unit-tested.
std::optional<libresign::SigningResult> revocationFailClosed(const libresign::RevocationData& rev);

// Build an ordered, completed certificate chain (DER, leaf-first) for a
// long-term signature. Starting from the card's signer cert (@p tokenChain[0]),
// walk issuers found among the remaining token certs and the supplied
// @p candidateCas (sourced from the Trusted List), appending each cert that
// cryptographically signed the current one, and stop at the first issuer that
// is a supplied candidate (a TL trust anchor) or is self-signed. Returns the
// ordered chain on success; returns EMPTY when the leaf's issuer cannot be
// resolved — the caller fails closed for B-LT/B-LTA. A subject-DN match is NOT
// trusted unless the candidate's key actually verifies the issued certificate.
std::vector<std::vector<uint8_t>> buildOrderedChain(const std::vector<std::vector<uint8_t>>& tokenChain,
                                                    const std::vector<std::vector<uint8_t>>& candidateCas);

// Return the DigestInfo prefix for the given digest name, or empty span if unknown.
// Accepts OpenSSL-style names: SHA256, SHA-256, SHA2-256, etc. (case-insensitive).
std::span<const uint8_t> digestInfoPrefixForAlgo(const std::string& mdName);

// Return the Pkcs11Token algorithm string for the given key type + digest.
// keyType is EVP_PKEY_RSA or EVP_PKEY_EC; mdName uses OpenSSL-style names.
std::string tokenAlgorithm(int keyType, const std::string& mdName);

// Sign a hash with a PKCS#11 token, prepending DigestInfo for RSA.
// When @p rawData is non-empty, it is forwarded to Pkcs11Token::sign as
// the "original data" hint so certain IAS-ECC hash-on-card SSCDs
// (German nPA family) can use the combined CKM_SHA*_RSA_PKCS mechanism
// instead of the legacy pre-built DigestInfo path that those cards
// reject with SW 6A80 / wrong-data-format. Returns the raw signature
// bytes.
std::vector<uint8_t> signHashWithToken(libresign::Pkcs11Token& token, X509* cert, const std::vector<uint8_t>& hash,
                                       const std::string& hashAlgo = "SHA256", std::span<const uint8_t> rawData = {});

// Decompress FlateDecode (zlib) data. Returns nullopt on malformed input.
// Throws std::runtime_error if the inflated output would exceed
// @p maxOutputBytes — a streaming check that fail-fasts decompression
// bombs (small compressed payload, huge expansion) before the allocator
// is exhausted. The default 64 MiB cap matches the largest legitimate
// PDF object stream any sane consumer should ever encounter; callers
// embedded in narrower contexts should pass a tighter bound.
std::optional<std::vector<uint8_t>> flateDecode(std::span<const uint8_t> compressed, size_t sizeHint = 0,
                                                std::size_t maxOutputBytes = 64ULL * 1024 * 1024);

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
