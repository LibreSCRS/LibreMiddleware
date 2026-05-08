// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Signing/SigningService.h>
#include <LibreSCRS/Signing/VisualSignatureParams.h>

#include "detail/ErrorClassifier.h"
#include "detail/RequestBridge.h"

// TrustStore construction now lives in
// Trust::TrustStoreService (passed in via DI). The bridge no longer
// needs the LM-internal friend header.
#include "native/native_signing_service.h"

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <signing_service.h>
#include <signing_service_factory.h>
#include <types.h>
#include <openssl/crypto.h>
#include <smartcard/secure_buffer.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>

namespace LibreSCRS::Signing {

namespace {

// Resolve the PKCS#11 module LibreMiddleware ships alongside the middleware.
// Mirror-search same candidate list LC uses (src/signing/pkcs11utils.cpp); the
// environment variable takes precedence so tests and packagers can override.
std::string resolvePkcs11Module()
{
#if defined(__APPLE__)
    const std::string moduleName = "librescrs-pkcs11.dylib";
#else
    const std::string moduleName = "librescrs-pkcs11.so";
#endif
    if (const char* env = std::getenv("LIBRESCRS_PKCS11_MODULE"); env && *env) {
        return std::string{env};
    }

    // LibreMiddleware is typically installed alongside the consumer binary;
    // the install-relative candidates match LC's pkcs11utils search order.
#if defined(__linux__)
    std::error_code ec;
    auto exePath = std::filesystem::canonical("/proc/self/exe", ec).parent_path();
    if (ec) {
        return moduleName;
    }
    // Keep this list ordered by "most specific to least specific":
    //   1-3: exe-relative flat + standard lib/Frameworks (deployed app bundles).
    //   4-5: LM in-tree test layouts — `build/test/LibreSCRSSigningTests`
    //        locates the module at `build/lib/pkcs11/librescrs-pkcs11.so`, and
    //        an installed prefix keeps plugins at `${prefix}/lib/pkcs11/`.
    //   6-7: LC FetchContent and LM-side-by-side layouts.
    const std::array<std::filesystem::path, 7> candidates{
        exePath / moduleName,
        exePath / ".." / "lib" / moduleName,
        exePath / ".." / "Frameworks" / moduleName,
        exePath / ".." / "lib" / "pkcs11" / moduleName,
        exePath / "lib" / "pkcs11" / moduleName,
        exePath / ".." / "_deps" / "libremiddleware-build" / "lib" / "pkcs11" / moduleName,
        exePath / ".." / ".." / "LibreMiddleware" / "build" / "lib" / "pkcs11" / moduleName,
    };
    for (const auto& p : candidates) {
        std::error_code cec;
        auto c = std::filesystem::canonical(p, cec);
        if (!cec && std::filesystem::exists(c)) {
            return c.string();
        }
    }
#endif
    return moduleName; // let the dynamic loader search path handle it
}

// NOTE: when LIBRESCRS_SIGNING_BACKEND=dss is set, the DSS backend silently
// drops TSA credentials and /ContactInfo. DSS is retained as a
// cross-verification oracle for tests; production paths must use Native.
libresign::Backend chooseBackend()
{
    if (const char* env = std::getenv("LIBRESCRS_SIGNING_BACKEND"); env && *env) {
        std::string v{env};
        std::transform(v.begin(), v.end(), v.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (v == "dss")
            return libresign::Backend::DSS;
    }
    return libresign::Backend::Native;
}

// Format / level / packaging translation helpers plus the full
// SigningRequest → libresign::SigningRequest bridge live in
// detail/RequestBridge.h so the unit test suite can exercise the exact
// production translation without standing up a PC/SC reader or PKCS#11
// token. See that header for the visibility rationale.

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

SigningResult SigningService::sign(const SigningRequest& request, Auth::CredentialProvider credentialProvider,
                                   std::shared_ptr<LibreSCRS::Plugin::CardPlugin> cardPlugin,
                                   std::shared_ptr<LibreSCRS::SmartCard::CardSession> session)
{
    // Reject an empty std::function<> provider up front — calling it would throw
    // std::bad_function_call. A signing flow without a way to collect PIN/PUK from
    // the user is an InvalidRequest, not an engine error.
    if (!credentialProvider) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.noCredentialProvider", "No credential provider was supplied.", {}});
    }
    if (!cardPlugin || !session) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is missing required fields.", {}},
            std::string{"sign(): cardPlugin or session shared_ptr is null"});
    }

    // Trust + TSA are fixed at ctor time; snapshot the TSA as a local by-value
    // copy because SigningRequest::tsaOverride() returns by value (independent-
    // lifetime contract, matching visualParams()). A per-request TSA override
    // (SigningRequest::Builder::tsaOverride) takes precedence over the service-
    // level provider supplied at construction.
    if (!d->trustService) {
        return SigningResult::trustStoreUnavailableDiagnosticOnly(
            std::string{"SigningService: TrustStoreService is null"});
    }
    const Trust::TrustConfig& trustSnapshot = d->trustService->config();
    TsaProvider tsaOverrideSnapshot = request.tsaOverride();
    const TsaProvider& tsaSnapshot = tsaOverrideSnapshot ? tsaOverrideSnapshot : d->tsa;

    // Resolve TSA once, up front. For B-T / B-LT / B-LTA the call is
    // mandatory; for B-B it's harmless (unused by libresign). Invoking the
    // provider here (rather than deeper in the bridge) centralises the
    // level-required guard below and avoids double-calling a user-supplied
    // std::function that may be nondeterministic.
    std::optional<TsaRequest> tsaOut;
    if (tsaSnapshot) {
        TsaContext tctx{request.format(), request.level(), {}};
        tsaOut = tsaSnapshot(tctx);
    }

    // B-T / B-LT / B-LTA require a TSA. Surface TsaUnreachable up front
    // rather than letting libresign emit a generic SigningEngineError.
    // Matches the contract documented on SigningService::SigningService
    // (empty TsaProvider is acceptable at construction; sign() enforces
    // the level-specific need).
    if (request.level() != SignatureLevel::B_B && (!tsaOut || tsaOut->url.empty())) {
        return SigningResult::tsaUnreachable(
            LocalizedText{
                "librescrs.signing.error.tsaUnreachable", "Time-stamping authority not configured or unreachable.", {}},
            !tsaOut ? std::string{"TsaProvider is empty; B-T/B-LT/B-LTA requires a configured TSA"}
                    : std::string{"TsaProvider returned empty URL; B-T/B-LT/B-LTA requires a reachable TSA"});
    }

    if (request.inputFile().empty() || request.outputFile().empty()) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is missing required fields.", {}});
    }

    // Read input (with 256 MiB cap, matching LC's pre-migration limit).
    constexpr std::uintmax_t maxBytes = 256ULL * 1024 * 1024;
    std::error_code fsErr;
    auto sz = std::filesystem::file_size(request.inputFile(), fsErr);
    if (fsErr || sz == 0 || sz > maxBytes) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is missing required fields.", {}},
            fsErr ? fsErr.message() : std::string{"Input file is empty or exceeds 256 MiB cap"});
    }
    std::vector<uint8_t> document(sz);
    std::ifstream in(request.inputFile(), std::ios::binary);
    if (!in.read(reinterpret_cast<char*>(document.data()), static_cast<std::streamsize>(sz))) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is missing required fields.", {}},
            std::string{"Failed to read input file"});
    }

    // Collect the PIN via the host-supplied CredentialProvider. Retry count comes
    // from the card when the plugin can determine it; nullopt means "unknown"
    // and AuthRequirement::forSigning converts to the host UI's "?" retries.
    // AuthRequirement::forSigning takes a negative sentinel to indicate
    // "unknown retry count"; collapse the plugin's optional back to -1 at this
    // single bridge point.
    const int retriesLeft = cardPlugin->getPINTriesLeft(*session).value_or(-1);
    // Use the LocalizedText overload so the host receives a translatable
    // i18n key alongside the English fallback. Previously the std::string
    // overload synthesised key="librescrs.auth.label.pin" from the
    // field id, which leaked the implementation-defined label-id mapping
    // through every signing prompt.
    auto authReq = Auth::AuthRequirement::forSigning(
        LocalizedText{.key = "librescrs.signing.label.pin", .defaultText = "Signing PIN", .placeholders = {}},
        retriesLeft);

    auto credResult = credentialProvider(authReq);
    if (credResult.status == Auth::CredentialResult::Status::UserCancelled) {
        return SigningResult::userCancelled();
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
        return SigningResult::signingEngineErrorDiagnosticOnly(std::move(diag));
    }
    const LibreSCRS::Secure::String* pinPtr = credResult.find("pin");
    if (pinPtr == nullptr || pinPtr->empty()) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is missing required fields.", {}},
            std::string{"CredentialProvider returned Ok but no pin field"});
    }
    // Go directly from Secure::String::view() into SecureBuffer — no
    // intermediate std::string to escape cleansing. The Secure::String owned
    // by credResult.values cleanses its storage when the CredentialResult
    // goes out of scope; no manual OPENSSL_cleanse needed here.
    smartcard::SecureBuffer pinBuffer(pinPtr->view());

    // Translate TrustConfig to libresign::TrustConfig.
    libresign::TrustConfig libTrust;
    for (const auto& src : trustSnapshot.trustedListSources) {
        libresign::TrustedListEntry entry;
        entry.url = src.url;
        entry.isLotl = src.lotl;
        entry.eager = src.eager;
        libTrust.trustedLists.push_back(std::move(entry));
    }
    if (trustSnapshot.trustedListFile.has_value()) {
        libresign::TrustedListEntry entry;
        entry.url = "file://" + trustSnapshot.trustedListFile->string();
        entry.isLotl = false;
        entry.eager = true;
        // The engine's HttpClient rejects file:// via CURLOPT_PROTOCOLS_STR
        // ("http,https"). Setting this internal flag routes the entry through
        // libresign's std::ifstream branch instead. Public TrustedListSource
        // entries (URL-fetched) never reach this path and leave the flag at
        // its default false.
        entry.localFileOnly = true;
        if (trustSnapshot.trustedListFileSigningCert.has_value())
            entry.signingCertPath = trustSnapshot.trustedListFileSigningCert->string();
        libTrust.trustedLists.push_back(std::move(entry));
    }
    if (trustSnapshot.cacheDirectory.has_value()) {
        libTrust.cacheDirectory = trustSnapshot.cacheDirectory->string();
    }

    // Resolve the PKCS#11 key alias from the request. LC populates this from the
    // user-selected certificate's label (CertificateData::label). When absent,
    // libresign's auto-select path picks the first signing-capable key on the
    // token — the common case for single-cert cards.
    const std::string& keyAlias = request.certificateLabel();

    libresign::SigningRequest libReq;
    // Translate all request-sourced fields (fileName, format, packaging,
    // level, signature-dictionary fields, and visual appearance when
    // configured) via the extracted bridge helper. Document bytes and TSA
    // configuration are populated below because they draw on state that
    // lives outside the public SigningRequest (the loaded input file and
    // the service-level TsaProvider snapshot).
    detail::translatePublicRequestToLibresign(request, libReq);
    libReq.document = std::move(document);
    // Use the TSA probe cached at the top of sign() (avoids double-calling
    // the TsaProvider std::function; see level-required guard above).
    if (tsaOut && !tsaOut->url.empty()) {
        libReq.tsa.url = tsaOut->url;
        // Basic-auth pair invariant is type-enforced via the BasicAuth
        // struct — no manual pair-validation needed. Translate the public
        // optional<BasicAuth> into the internal libresign optional<BasicAuth>
        // with a field-wise move.
        if (tsaOut->credentials.basicAuth.has_value()) {
            libresign::TransportCredentials::BasicAuth ba;
            ba.user = std::move(tsaOut->credentials.basicAuth->user);
            ba.password = std::move(tsaOut->credentials.basicAuth->password);
            libReq.tsa.credentials.basicAuth = std::move(ba);
        }

        // Mirror the public TsaCredentials into the internal
        // libresign::TransportCredentials held by libresign::TSAConfig.
        // Each sign-module narrows this to a TSARequest via toTsaRequest()
        // before handing it to TSAClient, which forwards the same
        // TransportCredentials straight into HttpClient — auth +
        // extraHeaders + extraSecretHeaders flow end-to-end to the
        // outbound HTTP call without any intermediate struct translation.
        libReq.tsa.credentials.bearerToken = std::move(tsaOut->credentials.bearerToken);
        // PemSource variant: the public alternative is
        // `variant<path, Secure::Buffer>`, the internal alternative is
        // `variant<path, shared_ptr<Secure::Buffer>>`. The internal shape
        // keeps TransportCredentials copyable (each sign-module's
        // toTsaRequest narrows TSAConfig to TSARequest by copy) while
        // preserving cleansing semantics on the in-memory alternative.
        auto translatePem =
            [](LibreSCRS::Signing::TsaCredentials::PemSource&& src) -> libresign::TransportCredentials::PemSource {
            return std::visit(
                [](auto&& alt) -> libresign::TransportCredentials::PemSource {
                    using Alt = std::decay_t<decltype(alt)>;
                    if constexpr (std::is_same_v<Alt, std::filesystem::path>) {
                        return libresign::TransportCredentials::PemSource{std::forward<decltype(alt)>(alt)};
                    } else {
                        return libresign::TransportCredentials::PemSource{
                            std::make_shared<LibreSCRS::Secure::Buffer>(std::forward<decltype(alt)>(alt))};
                    }
                },
                std::move(src));
        };
        if (tsaOut->credentials.clientCert.has_value()) {
            libReq.tsa.credentials.clientCert = translatePem(std::move(*tsaOut->credentials.clientCert));
        }
        if (tsaOut->credentials.clientCertKey.has_value()) {
            libReq.tsa.credentials.clientCertKey = translatePem(std::move(*tsaOut->credentials.clientCertKey));
        }
        libReq.tsa.credentials.extraHeaders = std::move(tsaOut->credentials.extraHeaders);
        libReq.tsa.credentials.extraSecretHeaders = std::move(tsaOut->credentials.extraSecretHeaders);
    }

    const auto backend = chooseBackend();
    // The DSS backend silently drops TSA credentials and the /ContactInfo
    // sig-dict entry (DSS is retained as a cross-verification oracle for
    // tests, not for production signing). Fail LOUD so a caller that set
    // those fields does not get a silent auth downgrade resulting in a
    // confusing "TSA timestamp failed" later.
    if (backend == libresign::Backend::DSS) {
        const bool hasCredentials =
            libReq.tsa.credentials.basicAuth.has_value() || libReq.tsa.credentials.bearerToken.has_value() ||
            libReq.tsa.credentials.clientCert.has_value() || libReq.tsa.credentials.clientCertKey.has_value() ||
            !libReq.tsa.credentials.extraSecretHeaders.empty() || !request.contactInfo().empty();
        if (hasCredentials) {
            return SigningResult::signingEngineErrorDiagnosticOnly(
                std::string{"DSS backend does not support TSA credentials or contactInfo — "
                            "use Native backend (unset LIBRESCRS_SIGNING_BACKEND or set =native). "
                            "See Path-A deprecation in 2026-04-22-pre-doc-design-decisions.md."});
        }
    }

    auto service = libresign::createSigningService(backend);
    if (!service) {
        return SigningResult::signingEngineErrorDiagnosticOnly(
            std::string{"Failed to construct libresign::SigningService"});
    }
    // hand the public TrustStore (owned by the
    // TrustStoreService passed at construction) to the native backend so
    // lazy TL fetches during configure() merge into the same store the
    // cert viewer / plugin registry are reading. The service itself drives
    // eager fetches; this path is for the lazy lookup path that runs only
    // when sign() needs an anchor not yet in the eager set.
    if (backend == libresign::Backend::Native) {
        if (auto* native = dynamic_cast<libresign::NativeSigningService*>(service.get())) {
            native->setPublicTrustStore(std::const_pointer_cast<Trust::TrustStore>(d->trustService->trustStore()));
        }
    }
    if (!service->configure(libTrust)) {
        return SigningResult::trustStoreUnavailableDiagnosticOnly(std::string{"libresign rejected TrustConfig"});
    }

    // Pass the caller-chosen reader name through to libresign so its
    // PKCS#11 slot lookup targets THIS card, not whichever card the
    // PCSC daemon enumerated first. Without this, multi-card setups
    // routed PIN to slots[0] and produced spurious "wrong PIN" errors.
    auto libResult = service->sign(libReq, resolvePkcs11Module(), pinBuffer, keyAlias, session->readerName());

    if (!libResult.success) {
        // The classifier returns one of the SigningResult::Status values; map
        // each to its corresponding named factory so we keep the "factory is
        // the only way to construct" invariant end-to-end.
        const auto classified = detail::classifyLibresignError(libResult);
        LocalizedText engineMsg{"librescrs.signing.error.engine", "Signing failed: see log for details.", {}};
        switch (classified) {
        case SigningResult::Status::PinVerificationFailed:
            return SigningResult::pinVerificationFailed(std::move(engineMsg), libResult.errorMessage);
        case SigningResult::Status::CardBlocked:
            return SigningResult::cardBlocked(std::move(engineMsg), libResult.errorMessage);
        case SigningResult::Status::TsaUnreachable:
            return SigningResult::tsaUnreachable(std::move(engineMsg), libResult.errorMessage);
        case SigningResult::Status::SigningEngineError:
        default:
            return SigningResult::signingEngineError(std::move(engineMsg), libResult.errorMessage);
        }
    }

    // Atomic write: stream the signed PDF into <output>.tmp, flush + close,
    // then rename(2) it into place. POSIX rename() and NTFS same-volume
    // MoveFileEx() are atomic, so observers never see a half-written file
    // even if the process is killed between write and rename. Without this,
    // a partial-write failure (full disk, ENOSPC mid-write, kill mid-stream)
    // leaves a truncated PDF at the user-visible output path — which a
    // downstream verifier cannot distinguish from a tampered document.
    auto outputPath = request.outputFile();
    auto tempPath = outputPath;
    tempPath += ".tmp";

    {
        std::ofstream out(tempPath, std::ios::binary);
        if (!out) {
            return SigningResult::signingEngineErrorDiagnosticOnly(std::string{"Failed to open output temp file: "} +
                                                                   tempPath.string());
        }
        out.write(reinterpret_cast<const char*>(libResult.signedDocument.data()),
                  static_cast<std::streamsize>(libResult.signedDocument.size()));
        out.close();
        if (!out) {
            std::error_code rmEc;
            std::filesystem::remove(tempPath, rmEc);
            return SigningResult::signingEngineErrorDiagnosticOnly(std::string{"Failed to write output temp file: "} +
                                                                   tempPath.string());
        }
    }

    std::error_code renameEc;
    std::filesystem::rename(tempPath, outputPath, renameEc);
    if (renameEc) {
        std::error_code rmEc;
        std::filesystem::remove(tempPath, rmEc); // best-effort cleanup
        return SigningResult::signingEngineErrorDiagnosticOnly(std::string{"Failed to rename output temp file: "} +
                                                               renameEc.message());
    }

    return SigningResult::ok(request.outputFile());
}

} // namespace LibreSCRS::Signing
