// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
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
    EngineError,
    /// @brief The input (or prior/original) document is not a valid document of
    ///        the requested format — wrong magic, truncated, unparseable, or
    ///        empty. A client-input fault the user fixes by replacing the file;
    ///        distinct from @ref InvalidInput (reserved for request-parameter
    ///        problems such as a missing TSA URL). Append-only. @since 5.0
    InvalidDocument,
    /// @brief A long-term (B-LT/B-LTA) signature was requested but the
    ///        signer's certificate chain has no PROVEN terminal — no Trusted
    ///        List anchor completed it and the card-provided chain does not
    ///        end in a verified self-signed root — so revocation evidence for
    ///        the tail cannot be signature-verified at all. Distinct from
    ///        @ref RevocationFetchFailed (evidence endpoints failed for a
    ///        cert WITH a known issuer): the user-actionable fix is to
    ///        configure a Trusted List or use a card that provides its full
    ///        chain, not to retry the fetch. @since 5.0
    CertificateChainIncomplete,
    /// @brief The card refused the PIN and reports it blocked: no try is
    ///        left. Distinct from @ref PinFailed (a wrong PIN with tries left)
    ///        because the user cannot fix it by typing again. Append-only.
    ///        @since 5.0
    PinBlocked
};

/// @brief Provenance of a certificate chain handed to the revocation gate:
///        how (whether) its LAST element is proven to be the chain's trust
///        terminal. AnchorTerminated is asserted ONLY by the caller that
///        completed the chain against a Trusted List (the resolver's success
///        return appends the anchor by construction); everything else is
///        Unterminated and the gate proves (or fails) the tail itself.
enum class ChainTermination : std::uint8_t { Unterminated, AnchorTerminated };

/// @brief Signature format taxonomy.
///
/// PascalCase per API-POLICY §7. The internal and public (LibreSCRS::Signing
/// namespace) surfaces share the same names; the SCREAMING form
/// (PAdES, CAdES, ...) is retained only on the DSS wire protocol.
///
/// Append-only across the 4.x cycle per §4 plugin-ABI rules — new formats
/// land at the tail. The on-the-wire string form for the DSS test oracle
/// (`test/dss_oracle/dss_signing_service.cpp::formatToString`) retains the
/// legacy SCREAMING values for Java-side compatibility.
// MIRROR-OF: LibreMiddleware/include/LibreSCRS/Signing/Enums.h - the engine's
// own vocabulary, deliberately separate from the published one so that adding
// a format here is not an ABI event out there. RequestBridge translates.
enum class SignatureFormat { Pades, Cades, Xades, Jades, AsicE };

enum class SignaturePackaging { Enveloped, Detached };

/// @brief The PDF file-header magic.
inline constexpr std::string_view kPdfMagic = "%PDF-";

/// @brief Number of leading bytes scanned for @ref kPdfMagic when deciding
///        whether a byte buffer is a PDF.
///
/// Adobe Acrobat Implementation Notes §H.3: a PDF may carry up to 1024 bytes
/// of non-PDF prefix ahead of its header — multipart/form-data wrappers from
/// web-form uploads are the common real-world source. Acrobat, Foxit, qpdf and
/// pdfinfo all accept those files, and so does @c PAdESModule::sign, which
/// strips the prefix before parsing.
///
/// The whole 5-byte magic must fall inside the window, so the last accepted
/// header offset is `kPdfHeaderScanWindow - kPdfMagic.size()`.
///
/// Shared rather than duplicated so the cheap fail-fast gate in
/// @c LibreSCRS::Signing::detail::documentPrecheck applies exactly the
/// tolerance the engine applies: a narrower gate rejects documents the engine
/// would sign, and a wider one defeats the point of failing fast.
inline constexpr std::size_t kPdfHeaderScanWindow = 1024;

/// @brief Baseline level. B_* form preserved (ETSI-token exception per
/// API-POLICY §7) — underscores stand for the spec's hyphens.
enum class SignatureLevel { B_B, B_T, B_LT, B_LTA };

/// @brief Who may sign a time-stamp token: the anchors a token's signer must
///        chain to.
///
/// The nonce and the message imprint travel in the clear to an http:// TSA, so
/// anyone on the path can echo them into a token of their own; only a
/// signature that chains to one of these anchors says a trusted authority
/// issued it.
struct TimestampTrust
{
    /// @brief Certificates (DER) trusted as they are, root or not: the
    ///        qualified time-stamping services of the configured Trusted Lists.
    std::vector<std::vector<uint8_t>> anchors;
    /// @brief Also trust the certificate store of the operating system.
    bool includeSystemTrustStore = true;
    /// @brief Asked at most once, and only when a token verifies against
    ///        neither of the above: the anchors of the Trusted Lists whose fetch
    ///        was deferred until a signature needed them. May be empty.
    std::function<std::vector<std::vector<uint8_t>>()> deferredAnchors;
};

/// @brief Signing-engine TSA configuration.
///
/// The URL + network timeout of the outbound HTTP request, plus the
/// revocation-data toggles the LT/LTA levels need to pass through to
/// @ref RevocationClient.
struct TSAConfig
{
    std::string url;
    int timeoutSeconds = 10;
    bool crlEnabled = true;  // passed to RevocationClient for B-LT/B-LTA
    bool ocspEnabled = true; // passed to RevocationClient for B-LT/B-LTA
    /// @brief Anchors the token's signer must chain to.
    TimestampTrust trust;
};

struct VisualSignatureParams
{
    bool enabled = false;
    int page = -1; // -1 = last page
    float x = 0, y = 0, width = 200, height = 50;
    std::string text; // Pre-formatted signature text (GUI builds this)
    std::string reason;
    std::string location;
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
    std::string errorMessage;
    /// @brief Typed classification of failure. Set iff `!success`.
    /// Bridge maps this to public SigningResult::Status + LocalizedText.
    /// @since 4.2
    std::optional<SignFailureKind> failureKind;
};

/// @brief Factory for typed failure results, used at every return site. The
/// diagnostic detail is preserved verbatim from the call site (it goes to
/// logs); the user message is derived from @p kind via the bridge.
inline SigningResult makeFailure(SignFailureKind kind, std::string detail = {})
{
    return SigningResult{false, {}, std::move(detail), kind};
}

/// @brief Factory for success results. Symmetric with @ref makeFailure.
inline SigningResult makeSuccess(std::vector<uint8_t> bytes)
{
    return SigningResult{true, std::move(bytes), {}, std::nullopt};
}

/// @brief Carries a typed @ref SignFailureKind out of code that cannot return
///        a result (a signing key's verdict on the PIN, a TSA fault deep in a
///        format module) so the module or service try/catch can map it to a
///        precise @ref makeFailure instead of collapsing it into the generic
///        @ref SignFailureKind::EngineError bucket. The @ref what string
///        becomes the result's diagnostic detail.
/// @since 5.0
struct SignFailureException : std::runtime_error
{
    SignFailureKind kind;
    SignFailureException(SignFailureKind k, const std::string& detail) : std::runtime_error(detail), kind(k) {}
};

struct TrustedListEntry
{
    std::string url;
    bool isLotl = false;         // TLSource vs LOTLSource
    bool eager = true;           // sync vs background loading
    std::string signingCertPath; // optional: override pinned cert (PEM or DER file)
    /// @brief The signer certificates a List of Trusted Lists names for this
    ///        list (DER), tried in order when no override or pinned
    ///        certificate applies. Filled for the lists a LOTL points to.
    std::vector<std::vector<uint8_t>> signingCertsDer;

    /// @brief Internal flag: when @c true, @ref url may use the @c file://
    ///        scheme and the engine will read @ref url directly from disk via
    ///        @c std::ifstream rather than going through @ref HttpClient.
    ///
    /// @details The engine's own tests hand it a pre-fetched TL XML on disk
    /// this way. @c HttpClient's @c CURLOPT_PROTOCOLS_STR="http,https" guard
    /// remains intact (defense in depth) — @c file:// never reaches
    /// HttpClient. Entries built from the public @c TrustedListSource leave
    /// this flag at the default @c false and flow through HTTP.
    bool localFileOnly = false;
};

struct TrustConfig
{
    std::vector<TrustedListEntry> trustedLists;
    std::string cacheDirectory;
    bool crlEnabled = true;
    bool ocspEnabled = true;
    /// @brief Whether the operating system's certificate store vouches for a
    ///        time-stamping authority, beside the Trusted Lists.
    bool includeSystemTrustStore = true;
};

} // namespace libresign
