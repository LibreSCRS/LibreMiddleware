// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Signing/SigningService.h>
#include <LibreSCRS/Signing/VisualSignatureParams.h>

#include "detail/ErrorClassifier.h"
#include "detail/RequestBridge.h"

// LM-internal Trust friend header used by the lazy-fetch-merge lambda
// bound into libresign's NativeSigningService::setAnchorEmitter (below).
// LibreSCRS_Signing already builds with LIBRESCRS_INTERNAL_BUILD, so this
// internal include is allowed.
#include "../Trust/internal/TrustStoreInternalAccess.h"
#include "native/native_signing_service.h"

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <signing_service.h>
#include <signing_service_factory.h>
#include <types.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <openssl/crypto.h>

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
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

namespace LibreSCRS::Signing {

namespace {

// Resolve the PKCS#11 module LibreMiddleware ships alongside itself.
// Consumers (LibreCelik, LibreKDE, third-party tools) do not need to know
// where the module lives — LM owns its own resource discovery. The
// LIBRESCRS_PKCS11_MODULE environment variable is the override escape
// hatch for tests and packagers; otherwise the candidate list below covers
// every standard deploy layout LM ships into.
std::string resolvePkcs11Module()
{
    // PKCS#11 module filename uses each platform's native shared-library
    // suffix: `.so` on Linux, `.dylib` on macOS. Matches what third-party
    // PKCS#11 consumers (Firefox, Thunderbird, Adobe Acrobat, GnuPG,
    // p11-kit) expect to see when the user picks a module file from a GUI
    // dialog on the corresponding platform.
#if defined(__APPLE__)
    const std::string moduleName = "librescrs-pkcs11.dylib";
#else
    const std::string moduleName = "librescrs-pkcs11.so";
#endif
    if (const char* env = std::getenv("LIBRESCRS_PKCS11_MODULE"); env && *env) {
        return std::string{env};
    }

    std::error_code ec;
    std::filesystem::path exePath;
#if defined(__linux__)
    exePath = std::filesystem::canonical("/proc/self/exe", ec).parent_path();
    if (ec) {
        return moduleName;
    }
#elif defined(__APPLE__)
    {
        std::uint32_t bufSize = 0;
        _NSGetExecutablePath(nullptr, &bufSize);
        std::string buf(bufSize, '\0');
        if (_NSGetExecutablePath(buf.data(), &bufSize) != 0) {
            return moduleName;
        }
        // _NSGetExecutablePath may return a symlinked path; canonicalise it
        // so candidate-relative lookups land in the expected install layout.
        auto resolved = std::filesystem::canonical(buf.c_str(), ec);
        if (ec) {
            return moduleName;
        }
        exePath = resolved.parent_path();
    }
#else
    // Other platforms (Windows etc.) — defer to dyld search path.
    return moduleName;
#endif
    // Candidate layouts, ordered most-specific to least-specific:
    //   1-3: exe-relative flat + standard lib/Frameworks (deployed bundles).
    //   4-5: LM in-tree test layouts — `build/test/LibreSCRSSigningTests`
    //        locates the module at `build/lib/pkcs11/librescrs-pkcs11.so`, and
    //        an installed prefix keeps plugins at `${prefix}/lib/pkcs11/`.
    //   6-7: consumer FetchContent and side-by-side dev checkouts.
    //   8:   macOS dev .app bundle — binary at
    //        `build/src/Foo.app/Contents/MacOS/Foo`, module at
    //        `build/lib/pkcs11/librescrs-pkcs11.so` (4 parents up).
    const std::array<std::filesystem::path, 8> candidates{
        exePath / moduleName,
        exePath / ".." / "lib" / moduleName,
        exePath / ".." / "Frameworks" / moduleName,
        exePath / ".." / "lib" / "pkcs11" / moduleName,
        exePath / "lib" / "pkcs11" / moduleName,
        exePath / ".." / "_deps" / "libremiddleware-build" / "lib" / "pkcs11" / moduleName,
        exePath / ".." / ".." / "LibreMiddleware" / "build" / "lib" / "pkcs11" / moduleName,
        exePath / ".." / ".." / ".." / ".." / "lib" / "pkcs11" / moduleName,
    };
    for (const auto& p : candidates) {
        std::error_code cec;
        auto c = std::filesystem::canonical(p, cec);
        if (!cec && std::filesystem::exists(c)) {
            return c.string();
        }
    }
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
                                   const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
                                   const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session) noexcept
try {
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
    // from the card when the plugin can determine it; std::nullopt means
    // "unknown" and forwards unchanged to the host UI for a "?" rendering.
    const std::optional<int> retriesLeft = cardPlugin->getPINTriesLeft(*session);
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
                            "use Native backend (unset LIBRESCRS_SIGNING_BACKEND or set =native)."});
        }
    }

    auto service = libresign::createSigningService(backend);
    if (!service) {
        return SigningResult::signingEngineErrorDiagnosticOnly(
            std::string{"Failed to construct libresign::SigningService"});
    }
    // Bind the lazy-fetch anchor-merge callback into libresign's native
    // backend. libresign emits TL-extracted anchors via the AnchorEmitter
    // (see NativeSigningService::setAnchorEmitter); this lambda merges them
    // into the same TrustStore the eager-fetch worker
    // (Trust::TrustStoreService) populates. Inverted call direction —
    // libresign no longer reaches into Trust internals — keeps the
    // libresign target free of any link edge to LibreSCRS_Trust.
    if (backend == libresign::Backend::Native) {
        if (auto* native = dynamic_cast<libresign::NativeSigningService*>(service.get())) {
            auto trustStore = std::const_pointer_cast<Trust::TrustStore>(d->trustService->trustStore());
            native->setAnchorEmitter([trustStore](std::vector<Trust::TrustAnchor> anchors, std::string label) {
                if (!trustStore)
                    return;
                Trust::detail::TrustStoreInternalAccess::mergeTrustedListAnchors(*trustStore, std::move(anchors),
                                                                                 label);
            });
        }
    }
    if (!service->configure(libTrust)) {
        return SigningResult::trustStoreUnavailableDiagnosticOnly(std::string{"libresign rejected TrustConfig"});
    }

    // Pass the caller-chosen reader name through to libresign so its
    // PKCS#11 slot lookup targets THIS card, not whichever card the
    // PCSC daemon enumerated first. Without this, multi-card setups
    // routed PIN to slots[0] and produced spurious "wrong PIN" errors.
    // Forward the live display CardSession so libresign's PKCS#11
    // path can adopt it via SessionAttachment instead of opening a
    // second standalone session against the same reader (would tear
    // down PACE on the eMRTD/RS eID/EU VRC families). Legacy callers
    // that don't have a session in scope can pass nullptr — the
    // standalone bind path then runs unchanged.
    auto libResult = service->sign(libReq, resolvePkcs11Module(), pinBuffer, keyAlias, session->readerName(), session);

    if (!libResult.success) {
        // The classifier returns one of the SigningResult::Status values; map
        // each to its corresponding named factory so we keep the "factory is
        // the only way to construct" invariant end-to-end.
        const auto classified = detail::classifyLibresignError(libResult);
        // Derive the user-facing message from the typed failure kind when the
        // module set one; fall back to the generic engine-error key for the
        // legacy exception path (Pkcs11Token CKR throws that bypass the
        // module's typed return shape).
        LocalizedText userMsg = libResult.failureKind.has_value() ? detail::kindToUserMessage(*libResult.failureKind)
                                                                  : LibreSCRS::Auth::ErrorKeys::signingEngineError();
        switch (classified) {
        case SigningResult::Status::PinVerificationFailed:
            return SigningResult::pinVerificationFailed(std::move(userMsg), libResult.errorMessage);
        case SigningResult::Status::CardBlocked:
            return SigningResult::cardBlocked(std::move(userMsg), libResult.errorMessage);
        case SigningResult::Status::TsaUnreachable:
            return SigningResult::tsaUnreachable(std::move(userMsg), libResult.errorMessage);
        case SigningResult::Status::SigningEngineError:
        default:
            return SigningResult::signingEngineError(std::move(userMsg), libResult.errorMessage);
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
} catch (const std::bad_alloc&) {
    // API-POLICY §5.3 noexcept-alloc contract: a noexcept public entry
    // point that allocates internally MUST degrade to a non-Ok
    // SigningResult rather than `std::terminate` on bad_alloc. The
    // signing pipeline allocates in many places (libresign request
    // construction, file I/O buffers, std::string formatting); any
    // of them can surface bad_alloc on a memory-pressure machine.
    // Surface as signingEngineError so the host UI sees a normal
    // failure path rather than an opaque crash.
    return SigningResult::signingEngineErrorDiagnosticOnly(
        std::string{"sign(): out of memory during signing pipeline"});
} catch (const std::exception& ex) {
    // Defence in depth — any other std::exception derived class
    // escaping the inner machinery (libresign throws, ifstream
    // exceptions enabled by a future caller wrapper, etc.) must
    // also surface as a structured signingEngineError rather than
    // propagate through the noexcept contract.
    return SigningResult::signingEngineErrorDiagnosticOnly(std::string{"sign(): unexpected exception: "} + ex.what());
} catch (...) {
    return SigningResult::signingEngineErrorDiagnosticOnly(std::string{"sign(): unexpected non-std::exception"});
}

SigningResult SigningService::appendSigner(const SigningRequest& request, std::span<const std::uint8_t> priorSignature,
                                           std::span<const std::uint8_t> originalDocument,
                                           Auth::CredentialProvider credentialProvider,
                                           const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& cardPlugin,
                                           const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session) noexcept
try {
    // Same up-front guards as sign(): empty CredentialProvider, null
    // plugin/session, and null TrustStoreService are all InvalidRequest /
    // diagnostic-only failures rather than engine errors. Mirroring sign()
    // keeps callers' error-handling switches identical between the two
    // entry points.
    if (!credentialProvider) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.noCredentialProvider", "No credential provider was supplied.", {}});
    }
    if (!cardPlugin || !session) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is missing required fields.", {}},
            std::string{"appendSigner(): cardPlugin or session shared_ptr is null"});
    }
    if (!d->trustService) {
        return SigningResult::trustStoreUnavailableDiagnosticOnly(
            std::string{"SigningService: TrustStoreService is null"});
    }
    if (priorSignature.empty()) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is missing required fields.", {}},
            std::string{"appendSigner(): priorSignature span is empty"});
    }
    if (request.outputFile().empty()) {
        return SigningResult::invalidRequest(
            LocalizedText{"librescrs.signing.error.invalidRequest", "Signing request is missing required fields.", {}},
            std::string{"appendSigner(): outputFile is empty"});
    }

    const Trust::TrustConfig& trustSnapshot = d->trustService->config();
    TsaProvider tsaOverrideSnapshot = request.tsaOverride();
    const TsaProvider& tsaSnapshot = tsaOverrideSnapshot ? tsaOverrideSnapshot : d->tsa;

    // TSA probe + level-required guard — same contract as sign().
    std::optional<TsaRequest> tsaOut;
    if (tsaSnapshot) {
        TsaContext tctx{request.format(), request.level(), {}};
        tsaOut = tsaSnapshot(tctx);
    }
    if (request.level() != SignatureLevel::B_B && (!tsaOut || tsaOut->url.empty())) {
        return SigningResult::tsaUnreachable(
            LocalizedText{
                "librescrs.signing.error.tsaUnreachable", "Time-stamping authority not configured or unreachable.", {}},
            !tsaOut ? std::string{"TsaProvider is empty; B-T/B-LT/B-LTA requires a configured TSA"}
                    : std::string{"TsaProvider returned empty URL; B-T/B-LT/B-LTA requires a reachable TSA"});
    }

    // PIN collection — same path as sign(); centralised AuthRequirement
    // build so a retry-count change in sign() automatically applies here
    // too. PIN flows from Secure::String → Secure::Buffer with no
    // intermediate non-cleansing copy.
    const std::optional<int> retriesLeft = cardPlugin->getPINTriesLeft(*session);
    auto authReq = Auth::AuthRequirement::forSigning(
        LocalizedText{.key = "librescrs.signing.label.pin", .defaultText = "Signing PIN", .placeholders = {}},
        retriesLeft);
    auto credResult = credentialProvider(authReq);
    if (credResult.status == Auth::CredentialResult::Status::UserCancelled) {
        return SigningResult::userCancelled();
    }
    if (credResult.status != Auth::CredentialResult::Status::Ok) {
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
    LibreSCRS::Secure::Buffer pinBuffer(pinPtr->view());

    // Trust translation — identical structure to sign(). Refactoring this
    // into a helper is left for a follow-up; keeping the two flows visibly
    // symmetric here keeps future per-format dispatcher work a strict diff.
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
        entry.localFileOnly = true;
        if (trustSnapshot.trustedListFileSigningCert.has_value())
            entry.signingCertPath = trustSnapshot.trustedListFileSigningCert->string();
        libTrust.trustedLists.push_back(std::move(entry));
    }
    if (trustSnapshot.cacheDirectory.has_value()) {
        libTrust.cacheDirectory = trustSnapshot.cacheDirectory->string();
    }

    const std::string& keyAlias = request.certificateLabel();

    // For appendSigner the prior-signature bytes flow as a span; libReq.document
    // is left empty (the per-format dispatcher reads from the priorSignature
    // span instead). All other request-sourced fields (level, TSA, visual,
    // contactInfo, fileName) still apply to the NEW signer and translate the
    // same way they do for sign().
    libresign::SigningRequest libReq;
    detail::translatePublicRequestToLibresign(request, libReq);
    if (tsaOut && !tsaOut->url.empty()) {
        libReq.tsa.url = tsaOut->url;
        if (tsaOut->credentials.basicAuth.has_value()) {
            libresign::TransportCredentials::BasicAuth ba;
            ba.user = std::move(tsaOut->credentials.basicAuth->user);
            ba.password = std::move(tsaOut->credentials.basicAuth->password);
            libReq.tsa.credentials.basicAuth = std::move(ba);
        }
        libReq.tsa.credentials.bearerToken = std::move(tsaOut->credentials.bearerToken);
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
    if (backend == libresign::Backend::DSS) {
        const bool hasCredentials =
            libReq.tsa.credentials.basicAuth.has_value() || libReq.tsa.credentials.bearerToken.has_value() ||
            libReq.tsa.credentials.clientCert.has_value() || libReq.tsa.credentials.clientCertKey.has_value() ||
            !libReq.tsa.credentials.extraSecretHeaders.empty() || !request.contactInfo().empty();
        if (hasCredentials) {
            return SigningResult::signingEngineErrorDiagnosticOnly(
                std::string{"DSS backend does not support TSA credentials or contactInfo — "
                            "use Native backend (unset LIBRESCRS_SIGNING_BACKEND or set =native)."});
        }
    }

    auto service = libresign::createSigningService(backend);
    if (!service) {
        return SigningResult::signingEngineErrorDiagnosticOnly(
            std::string{"Failed to construct libresign::SigningService"});
    }
    if (backend == libresign::Backend::Native) {
        if (auto* native = dynamic_cast<libresign::NativeSigningService*>(service.get())) {
            auto trustStore = std::const_pointer_cast<Trust::TrustStore>(d->trustService->trustStore());
            native->setAnchorEmitter([trustStore](std::vector<Trust::TrustAnchor> anchors, std::string label) {
                if (!trustStore)
                    return;
                Trust::detail::TrustStoreInternalAccess::mergeTrustedListAnchors(*trustStore, std::move(anchors),
                                                                                 label);
            });
        }
    }
    if (!service->configure(libTrust)) {
        return SigningResult::trustStoreUnavailableDiagnosticOnly(std::string{"libresign rejected TrustConfig"});
    }

    // Forward the live display CardSession to the engine so the PKCS#11
    // path adopts it via SessionAttachment — mandatory for PACE-protected
    // re-signs where a standalone bind would tear down the host's SM
    // channel before C_Login.
    auto libResult = service->appendSigner(libReq, priorSignature, originalDocument, pinBuffer, resolvePkcs11Module(),
                                           keyAlias, session->readerName(), session);

    if (!libResult.success) {
        const auto classified = detail::classifyLibresignError(libResult);
        LocalizedText userMsg = libResult.failureKind.has_value() ? detail::kindToUserMessage(*libResult.failureKind)
                                                                  : LibreSCRS::Auth::ErrorKeys::signingEngineError();
        switch (classified) {
        case SigningResult::Status::PinVerificationFailed:
            return SigningResult::pinVerificationFailed(std::move(userMsg), libResult.errorMessage);
        case SigningResult::Status::CardBlocked:
            return SigningResult::cardBlocked(std::move(userMsg), libResult.errorMessage);
        case SigningResult::Status::TsaUnreachable:
            return SigningResult::tsaUnreachable(std::move(userMsg), libResult.errorMessage);
        case SigningResult::Status::SigningEngineError:
        default:
            return SigningResult::signingEngineError(std::move(userMsg), libResult.errorMessage);
        }
    }

    // Atomic write — same .tmp + rename(2) idiom as sign().
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
        std::filesystem::remove(tempPath, rmEc);
        return SigningResult::signingEngineErrorDiagnosticOnly(std::string{"Failed to rename output temp file: "} +
                                                               renameEc.message());
    }

    return SigningResult::ok(request.outputFile());
} catch (const std::bad_alloc&) {
    // API-POLICY §5.3 noexcept-alloc contract — same shape as sign().
    return SigningResult::signingEngineErrorDiagnosticOnly(
        std::string{"appendSigner(): out of memory during signing pipeline"});
} catch (const std::exception& ex) {
    return SigningResult::signingEngineErrorDiagnosticOnly(std::string{"appendSigner(): unexpected exception: "} +
                                                           ex.what());
} catch (...) {
    return SigningResult::signingEngineErrorDiagnosticOnly(
        std::string{"appendSigner(): unexpected non-std::exception"});
}

} // namespace LibreSCRS::Signing
