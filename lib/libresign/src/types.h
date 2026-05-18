// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "credentials.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace libresign {

/// @brief Typed classification of why an internal sign call failed.
///
/// Each module-level return path sets this at the point where the failure
/// is known precisely (CMS_final returned 0, libxml2 reported parse fail,
/// TSA HTTP returned 5xx, etc.). The bridge in
/// LibreSCRS::Signing::SigningService::sign maps each kind to the public
/// SigningResult::Status enum via a closed switch under -Wswitch-enum so
/// adding a new kind triggers a compile error at the bridge.
///
/// Append-only across the 4.x cycle per API-POLICY §4 — new kinds land at
/// the tail; reordering or removal requires a major bump.
enum class SignFailureKind : std::uint8_t {
    TsaUnreachable,
    RevocationFetchFailed,
    CardError,
    PinFailed,
    UserCancelled,
    InvalidInput,
    PdfPreparationError,
    XmlSerializationError,
    JsonSerializationError,
    ZipBuildError,
    OpensslError,
    PolicyViolation,
    EngineError
};

/// @brief Signature format taxonomy.
///
/// PascalCase per API-POLICY §7. The internal and public (LibreSCRS::Signing
/// namespace) surfaces share the same names; the SCREAMING form
/// (PAdES, CAdES, ...) is retained only on the DSS wire protocol.
///
/// Append-only across the 4.x cycle per §4 plugin-ABI rules — new formats
/// land at the tail. The on-the-wire string form for the DSS bridge
/// (`dss_signing_service.cpp::formatToString`) retains the legacy
/// SCREAMING values for Java-side compatibility.
enum class SignatureFormat { Pades, Cades, Xades, Jades, AsicE };

enum class SignaturePackaging { Enveloped, Detached };

/// @brief Baseline level. B_* form preserved (ETSI-token exception per
/// API-POLICY §7) — underscores stand for the spec's hyphens.
enum class SignatureLevel { B_B, B_T, B_LT, B_LTA };

/// @brief Signing-engine TSA configuration.
///
/// Bundles the URL + network timeout with the credentials used for the
/// outbound HTTP request, plus the revocation-data toggles the LT/LTA
/// levels need to pass through to @ref RevocationClient.
///
/// @ref credentials is a @ref TransportCredentials — the single internal
/// carrier shared with @ref HttpClient / @ref TSAClient. The public
/// @c LibreSCRS::Signing::TsaCredentials is translated into it at the
/// API bridge (see @c LibreSCRS::Signing::SigningService::sign) so the
/// signing core never includes public headers.
struct TSAConfig
{
    std::string url;
    int timeoutSeconds = 10;
    /// @brief Credentials applied to requests against @ref url.
    TransportCredentials credentials;
    bool crlEnabled = true;  // passed to RevocationClient for B-LT/B-LTA
    bool ocspEnabled = true; // passed to RevocationClient for B-LT/B-LTA
};

struct VisualSignatureParams
{
    bool enabled = false;
    int page = -1; // -1 = last page
    float x = 0, y = 0, width = 200, height = 50;
    std::string text; // Pre-formatted signature text (GUI builds this)
    std::string reason;
    std::string location;
    // Signer contact info, written into the PDF signature dictionary as
    // /ContactInfo (ISO 32000-1:2008 §12.8.1, sibling of /Reason and
    // /Location). Populated from the public SigningRequest::contactInfo()
    // by the LibreSCRS::Signing bridge.
    std::string contactInfo;
};

struct SigningRequest
{
    std::vector<uint8_t> document;
    std::string fileName;
    SignatureFormat format = SignatureFormat::Pades;
    SignaturePackaging packaging = SignaturePackaging::Enveloped;
    SignatureLevel level = SignatureLevel::B_T;
    TSAConfig tsa;
    VisualSignatureParams visual;
    // Explicit user-consent gate for signing with an expired certificate.
    // Default false rejects expired signers (DSS- and native-backend
    // consistent); host GUI flips to true only after the user has
    // acknowledged the expiry warning on the signing page.
    bool allowExpiredCertificate = false;
};

struct SigningResult
{
    bool success = false;
    std::vector<uint8_t> signedDocument;
    /// @brief ASCII-for-logs diagnostic. Not user-facing — the user message
    /// is derived from @ref failureKind via the bridge's kindToUserMessage.
    /// Field ordering (success / signedDocument / errorMessage) is preserved
    /// so legacy `{false, {}, "..."}` initializers remain compilable while a
    /// module is converted to typed failures. When @ref failureKind is set,
    /// the bridge prefers it over substring matching on this string.
    std::string errorMessage;
    /// @brief Typed classification of failure. Set iff `!success`.
    /// Bridge maps this to public SigningResult::Status + LocalizedText.
    /// @since 4.2
    std::optional<SignFailureKind> failureKind;
};

/// @brief Factory for typed failure results. Replaces the legacy shape
/// `{false, {}, "..."}` at every return site. The diagnostic detail is
/// preserved verbatim from the call site (it goes to logs); the user
/// message is derived from @p kind via the bridge.
inline SigningResult makeFailure(SignFailureKind kind, std::string detail = {})
{
    return SigningResult{false, {}, std::move(detail), kind};
}

/// @brief Factory for success results. Symmetric with @ref makeFailure.
inline SigningResult makeSuccess(std::vector<uint8_t> bytes)
{
    return SigningResult{true, std::move(bytes), {}, std::nullopt};
}

struct TrustedListEntry
{
    std::string url;
    bool isLotl = false;         // TLSource vs LOTLSource
    bool eager = true;           // sync vs background loading
    std::string signingCertPath; // optional: override pinned cert (PEM or DER file)

    /// @brief Internal flag: when @c true, @ref url may use the @c file://
    ///        scheme and the engine will read @ref url directly from disk via
    ///        @c std::ifstream rather than going through @ref HttpClient.
    ///
    /// @details @ref TrustConfig::trustedListFile lets a
    /// caller hand the engine a pre-fetched TL XML on disk. The bridge in
    /// @c LibreSCRS::Signing::SigningService::sign synthesises a
    /// @ref TrustedListEntry whose @ref url is @c "file://" + path and sets
    /// this flag to opt into the disk-read path. @c HttpClient's
    /// @c CURLOPT_PROTOCOLS_STR="http,https" guard remains intact (defense in
    /// depth) — @c file:// never reaches HttpClient on the public path.
    /// Public @c TrustedListSource entries (URL-fetched) leave this flag at
    /// the default @c false and continue to flow through HTTP.
    bool localFileOnly = false;
};

struct TrustConfig
{
    std::vector<TrustedListEntry> trustedLists;
    std::string cacheDirectory;
    bool crlEnabled = true;
    bool ocspEnabled = true;
};

} // namespace libresign
