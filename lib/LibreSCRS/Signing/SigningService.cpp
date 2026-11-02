// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Signing/SigningService.h>
#include <LibreSCRS/Signing/VisualSignatureParams.h>

#include "detail/DocumentPrecheck.h"
#include "detail/ErrorClassifier.h"
#include "detail/RequestBridge.h"

// LM-internal Trust friend header used by the lazy-fetch-merge lambda
// bound into libresign's NativeSigningService::setAnchorEmitter (below).
// LibreSCRS_Signing already builds with LIBRESCRS_INTERNAL_BUILD, so this
// internal include is allowed.
#include "../Trust/internal/TrustStoreInternalAccess.h"
#include "native/native_signing_service.h"
#include "native/plugin_signing_key.h"

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <signing_service.h>
#include <types.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace LibreSCRS::Signing {

namespace {

// The signer the caller chose among the certificates it read from the card:
// the engine neither reads them again nor chooses again.
struct SignerChoice
{
    const LibreSCRS::Plugin::CertificateData& signer;
    std::span<const LibreSCRS::Plugin::CertificateData> cardCerts;
};

// The key the engine signs with: the plugin on the caller's session, for the
// signer @p choice names. No PKCS#11 module is loaded and no second
// connection to the card is opened.
std::expected<std::unique_ptr<libresign::PluginSigningKey>, SigningResult>
pluginSigningKey(const SigningRequest& request, const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
                 const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session,
                 const LibreSCRS::Secure::Buffer& pin, const SignerChoice& choice)
{
    // A key id no PKCS#15 card can carry names no key: the request is
    // malformed. The key re-checks it as its own invariant.
    if (request.keyId().size() > libresign::PluginSigningKey::kMaxKeyIdLength) {
        return std::unexpected(
            SigningResult::invalidRequest(LibreSCRS::Auth::ErrorKeys::invalidRequest(),
                                          std::string{"the key id is longer than a PKCS#15 identifier (255 bytes)"}));
    }
    if (!choice.signer.keyFID) {
        return std::unexpected(SigningResult::invalidRequest(LibreSCRS::Auth::ErrorKeys::invalidRequest(),
                                                             std::string{"the chosen signer carries no key handle"}));
    }
    std::vector<std::vector<std::uint8_t>> chain;
    for (const auto& cert : choice.cardCerts) {
        if (!cert.derBytes.empty())
            chain.push_back(cert.derBytes);
    }
    try {
        return std::make_unique<libresign::PluginSigningKey>(cardPlugin, session, choice.signer, pin, std::move(chain),
                                                             request.keyId(), CancelToken{});
    } catch (const std::invalid_argument& e) {
        return std::unexpected(SigningResult::invalidRequest(LibreSCRS::Auth::ErrorKeys::invalidRequest(), e.what()));
    }
}

// The caller's result for a failed engine call: the status the classifier
// names, built by its factory, with the user message of the failure's kind.
SigningResult engineFailure(const libresign::SigningResult& libResult)
{
    LocalizedText userMsg = libResult.failureKind.has_value() ? detail::kindToUserMessage(*libResult.failureKind)
                                                              : LibreSCRS::Auth::ErrorKeys::signingEngineError();
    switch (detail::classifyLibresignError(libResult)) {
    case SigningResult::Status::PinVerificationFailed:
        return SigningResult::pinVerificationFailed(std::move(userMsg), libResult.errorMessage);
    case SigningResult::Status::CardBlocked:
        return SigningResult::cardBlocked(std::move(userMsg), libResult.errorMessage);
    case SigningResult::Status::UserCancelled:
        return SigningResult::userCancelled();
    case SigningResult::Status::TsaUnreachable:
        return SigningResult::tsaUnreachable(std::move(userMsg), libResult.errorMessage);
    case SigningResult::Status::InvalidDocument:
        return SigningResult::invalidDocument(std::move(userMsg), libResult.errorMessage);
    case SigningResult::Status::SigningEngineError:
    default:
        return SigningResult::signingEngineError(std::move(userMsg), libResult.errorMessage);
    }
}

// Format / level / packaging translation helpers plus the full
// SigningRequest → libresign::SigningRequest bridge live in
// detail/RequestBridge.h so the unit test suite can exercise the exact
// production translation without standing up a PC/SC reader or PKCS#11
// token. See that header for the visibility rationale.

// Outcome of the signing pipeline (runSignPipeline). Exactly one of the two
// members is meaningful: when @ref failure is engaged the caller returns it
// verbatim; otherwise @ref signedDocument carries the finished artifact.
// SigningResult is factory-only (no default ctor), hence the std::optional
// wrapper.
struct SignPipelineOutcome
{
    std::optional<SigningResult> failure;
    std::vector<std::uint8_t> signedDocument;
};

} // namespace

// Pure DI: configuration is injected at construction and immutable afterwards.
// No process-wide singleton cache, no "was configured?" flag — the service
// object *is* the configured pipeline. LM's preferred ownership pattern is
// std::shared_ptr factory ownership held by the caller; SigningService
// closes out the last classical-singleton anti-pattern by handing ownership
// to callers directly. Hosts construct once per trust/TSA policy change and
// reuse across sign() calls.
struct LIBRESCRS_INTERNAL SigningService::Impl
{
    std::shared_ptr<Trust::TrustStoreService> trustService;
    TsaProvider tsa;

    // validateAndResolveTsa runs the document-independent preconditions
    // (credential provider, plugin/session, trust service) and resolves the
    // TSA URL into @p tsaUrl: the request's override when it names one,
    // else the service's (the level-required guard depends on it). Returns an
    // engaged result on early failure, else std::nullopt to proceed.
    [[nodiscard]] std::optional<SigningResult>
    validateAndResolveTsa(const SigningRequest& request, const Auth::CredentialProvider& credentialProvider,
                          const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
                          const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session, std::string& tsaUrl) const;

    // runSignPipeline collects the PIN, translates trust, builds the
    // libresign request from @p document (moved in) + the resolved
    // @p tsaUrl,
    // selects + configures the backend, drives the in-process sign, and
    // classifies any failure. Returns an engaged failure or the signed bytes.
    [[nodiscard]] SignPipelineOutcome
    runSignPipeline(const SigningRequest& request, const Auth::CredentialProvider& credentialProvider,
                    const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
                    const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session,
                    std::vector<std::uint8_t> document, std::string tsaUrl, const SignerChoice& choice) const;
};

SigningService::SigningService(std::shared_ptr<Trust::TrustStoreService> trustService, TsaProvider tsa)
    : d(std::make_unique<Impl>())
{
    d->trustService = std::move(trustService);
    d->tsa = std::move(tsa);
}

SigningService::~SigningService() = default;

SigningService::SigningService(SigningService&&) noexcept = default;
SigningService& SigningService::operator=(SigningService&&) noexcept = default;

SigningService::operator bool() const noexcept
{
    return d != nullptr;
}

std::optional<SigningResult> SigningService::Impl::validateAndResolveTsa(
    const SigningRequest& request, const Auth::CredentialProvider& credentialProvider,
    const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
    const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session, std::string& tsaUrl) const
{
    // Reject an empty std::function<> provider up front — calling it would throw
    // std::bad_function_call. A signing flow without a way to collect PIN/PUK from
    // the user is an InvalidRequest, not an engine error.
    if (!credentialProvider) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.noCredentialProvider", "No credential provider was supplied."});
    }
    if (!cardPlugin || !session) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is missing required fields."},
            std::string{"sign(): cardPlugin or session shared_ptr is null"});
    }

    // Trust + TSA are fixed at ctor time. A per-request TSA override naming
    // a URL (SigningRequest::Builder::tsaOverride) takes precedence over the
    // service-level authority supplied at construction.
    if (!trustService) {
        return SigningResult::trustStoreUnavailableDiagnosticOnly(
            std::string{"SigningService: TrustStoreService is null"});
    }
    tsaUrl = !request.tsaOverride().url.empty() ? request.tsaOverride().url : tsa.url;

    // B-T / B-LT / B-LTA require a TSA. Surface TsaUnreachable up front
    // rather than letting libresign emit a generic SigningEngineError.
    // Matches the contract documented on SigningService::SigningService
    // (an empty TsaProvider is acceptable at construction; sign() enforces
    // the level-specific need).
    if (request.level() != SignatureLevel::B_B && tsaUrl.empty()) {
        return SigningResult::tsaUnreachable(
            LocalizedText{"librescrs.signing.error.tsaUnreachable",
                          "Time-stamping authority not configured or unreachable."},
            std::string{"TsaProvider names no URL; B-T/B-LT/B-LTA requires a configured TSA"});
    }

    return std::nullopt;
}

SignPipelineOutcome
SigningService::Impl::runSignPipeline(const SigningRequest& request, const Auth::CredentialProvider& credentialProvider,
                                      const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
                                      const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session,
                                      std::vector<std::uint8_t> document, std::string tsaUrl,
                                      const SignerChoice& choice) const
{
    const Trust::TrustConfig& trustSnapshot = trustService->config();

    // Collect the PIN via the host-supplied CredentialProvider.
    auto authReq = Auth::AuthRequirement::forSigning();

    auto credResult = credentialProvider(authReq);
    if (credResult.status == Auth::CredentialResult::Status::UserCancelled) {
        return {SigningResult::userCancelled(), {}};
    }
    if (credResult.status != Auth::CredentialResult::Status::Ok) {
        // CredentialResult::userMessage is mandatory in 4.0 —
        // collapse it into diagnosticDetail by preferring the defaultText.
        // The structured LocalizedText is not passed through as the signing
        // result's userMessage here because a provider-side error surfaces as
        // SigningEngineError to the user anyway; the original message is
        // logged but not user-presented.
        const auto& lt = credResult.userMessage;
        std::string diag = !lt.defaultText.empty()
                               ? lt.defaultText
                               : (!lt.key.empty() ? lt.key : std::string{"CredentialProvider reported error"});
        return {SigningResult::signingEngineErrorDiagnosticOnly(std::move(diag)), {}};
    }
    const LibreSCRS::Secure::String* pinPtr = credResult.find("pin");
    if (pinPtr == nullptr || pinPtr->empty()) {
        return {SigningResult::invalidRequest(LocalizedText{"librescrs.signing.error.invalidRequest",
                                                            "Signing request is missing required fields."},
                                              std::string{"CredentialProvider returned Ok but no pin field"}),
                {}};
    }
    // Go directly from Secure::String::view() into Secure::Buffer — no
    // intermediate std::string to escape cleansing. Both the source
    // Secure::String (owned by credResult.values) and this Secure::Buffer
    // cleanse their storage on destruction; no manual OPENSSL_cleanse needed
    // here.
    LibreSCRS::Secure::Buffer pinBuffer(pinPtr->view());

    // Translate TrustConfig to libresign::TrustConfig.
    libresign::TrustConfig libTrust;
    for (const auto& src : trustSnapshot.trustedListSources) {
        libresign::TrustedListEntry entry;
        entry.url = src.url;
        entry.isLotl = src.lotl;
        entry.eager = src.eager;
        libTrust.trustedLists.push_back(std::move(entry));
    }
    if (trustSnapshot.cacheDirectory.has_value()) {
        libTrust.cacheDirectory = trustSnapshot.cacheDirectory->string();
    }

    libresign::SigningRequest libReq;
    // Translate all request-sourced fields (fileName, format, packaging,
    // level, signature-dictionary fields, the CKA_ID key discriminator, and
    // visual appearance when configured) via the extracted bridge helper.
    // Document bytes and TSA configuration are populated below because they
    // draw on state that lives outside the public SigningRequest (the loaded
    // input bytes and the resolved TSA URL).
    detail::translatePublicRequestToLibresign(request, libReq);
    libReq.document = std::move(document);
    // The TSA URL resolved up front (see the level-required guard in
    // validateAndResolveTsa); empty for a B-B signature without one.
    libReq.tsa.url = std::move(tsaUrl);

    auto service = std::make_unique<libresign::NativeSigningService>();
    // Bind the lazy-fetch anchor-merge callback into libresign's native
    // backend. libresign emits TL-extracted anchors via the AnchorEmitter
    // (see NativeSigningService::setAnchorEmitter); this lambda merges them
    // into the same TrustStore the eager-fetch worker
    // (Trust::TrustStoreService) populates. Inverted call direction —
    // libresign no longer reaches into Trust internals — keeps the
    // libresign target free of any link edge to LibreSCRS_Trust.
    {
        auto trustStore = std::const_pointer_cast<Trust::TrustStore>(trustService->trustStore());
        service->setAnchorEmitter([trustStore](std::vector<Trust::TrustAnchor> anchors) {
            if (!trustStore)
                return;
            Trust::detail::TrustStoreInternalAccess::mergeTrustedListAnchors(*trustStore, std::move(anchors));
        });
    }
    if (!service->configure(libTrust)) {
        return {SigningResult::trustStoreUnavailableDiagnosticOnly(std::string{"libresign rejected TrustConfig"}), {}};
    }

    // The engine signs through the caller's plugin on the caller's session
    // — the card the caller chose, over the channel it already holds. No
    // module is loaded and no second connection to the card is opened.
    auto key = pluginSigningKey(request, cardPlugin, session, pinBuffer, choice);
    if (!key)
        return {std::move(key.error()), {}};
    auto libResult = service->sign(libReq, **key);

    if (!libResult.success)
        return {engineFailure(libResult), {}};

    return {std::nullopt, std::move(libResult.signedDocument)};
}

SigningResult SigningService::sign(const SigningRequest& request, std::span<const std::uint8_t> input,
                                   Auth::CredentialProvider credentialProvider,
                                   const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
                                   const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session,
                                   const LibreSCRS::Plugin::CertificateData& signer,
                                   std::span<const LibreSCRS::Plugin::CertificateData> cardCerts) noexcept
try {
    std::string tsaUrl;
    if (auto early = d->validateAndResolveTsa(request, credentialProvider, cardPlugin, session, tsaUrl); early) {
        return std::move(*early);
    }

    // The document is already in memory; no file is named or read.
    constexpr std::uintmax_t maxBytes = 256ULL * 1024 * 1024;
    if (input.empty() || input.size() > maxBytes) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is missing required fields."},
            input.empty() ? std::string{"Input buffer is empty"} : std::string{"Input buffer exceeds 256 MiB cap"});
    }

    // Fail-fast document pre-check (#6): reject an obviously-wrong document
    // (e.g. a non-PDF for PAdES) before any card/PIN interaction. Sits after the
    // empty-buffer guard so a zero-byte input still surfaces as InvalidRequest.
    if (auto bad = detail::documentPrecheck(request.format(), input)) {
        return SigningResult::invalidDocument(Auth::ErrorKeys::invalidDocument(), std::move(*bad));
    }

    std::vector<std::uint8_t> document(input.begin(), input.end());

    const SignerChoice choice{signer, cardCerts};
    auto outcome = d->runSignPipeline(request, credentialProvider, cardPlugin, session, std::move(document),
                                      std::move(tsaUrl), choice);
    if (outcome.failure) {
        return std::move(*outcome.failure);
    }

    // The finished artifact goes back in memory — no file is written: the
    // caller owns the artifact's destination.
    return SigningResult::okWithBytes(std::move(outcome.signedDocument));
} catch (const std::bad_alloc&) {
    // API-POLICY §5.3 noexcept-alloc contract: a noexcept public entry
    // point that allocates internally MUST degrade to a non-Ok
    // SigningResult rather than `std::terminate` on bad_alloc.
    return SigningResult::signingEngineErrorDiagnosticOnly(
        std::string{"sign(): out of memory during signing pipeline"});
} catch (const std::exception& ex) {
    return SigningResult::signingEngineErrorDiagnosticOnly(std::string{"sign(): unexpected exception: "} + ex.what());
} catch (...) {
    return SigningResult::signingEngineErrorDiagnosticOnly(std::string{"sign(): unexpected non-std::exception"});
}

} // namespace LibreSCRS::Signing
