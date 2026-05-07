// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "credentials.h"

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

enum class SignatureFormat { PAdES, CAdES, XAdES, ASiC_E, JAdES };

enum class SignaturePackaging { ENVELOPED, DETACHED };

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
    SignatureFormat format = SignatureFormat::PAdES;
    SignaturePackaging packaging = SignaturePackaging::ENVELOPED;
    SignatureLevel level = SignatureLevel::B_T;
    TSAConfig tsa;
    VisualSignatureParams visual;
    bool allowExpiredCertificate = false; // for testing with expired certs
};

struct SigningResult
{
    bool success = false;
    std::vector<uint8_t> signedDocument;
    std::string errorMessage;
};

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
