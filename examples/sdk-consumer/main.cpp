// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Minimal reference consumer. Exercises one call per public target to
// prove the LibreSCRS public API is self-contained — no private header
// leaks via any public include. Not intended to produce useful output.
//
// Migrated to the 4.0 surface:
//   * Trust now exposes its own top-level namespace (LibreSCRS::Trust);
//     SigningService takes a shared_ptr<TrustStoreService> via DI rather
//     than a plain TrustConfig
//   * TrustConfig moved from <LibreSCRS/Signing/TrustConfig.h> to
//     <LibreSCRS/Trust/TrustConfig.h>
//   * Direct use of TrustStore (validateChain) and ParsedCertificate
//     (fromDer) is exercised end-to-end so a future regression that
//     hides those types behind a non-public header fails the link

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Certificate/ParsedCertificate.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/SigningService.h>
#include <LibreSCRS/Signing/TsaProvider.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStore.h>
#include <LibreSCRS/Trust/TrustStoreService.h>

#include <filesystem>
#include <iostream>
#include <utility>

int main()
{
    // 1. Auth — request shape + i18n container.
    auto req = LibreSCRS::Auth::AuthRequirement::forSigning(LibreSCRS::LocalizedText{"", "PIN", {}}, 3);
    std::cout << "Auth: " << req.fields().size() << " field(s)\n";

    // 2. Secure::Buffer — secret material with cleanse-on-destruction.
    LibreSCRS::Secure::Buffer b(8, 0x42);
    std::cout << "Secure::Buffer: " << b.size() << " bytes\n";

    // 3. SmartCard::MonitorService — enumerate readers (may be empty on CI).
    //    listReaders() is noexcept in 4.0: optional<vector<string>>, with
    //    nullopt signalling an unavailable PC/SC subsystem.
    LibreSCRS::SmartCard::MonitorService mon;
    auto readersOpt = mon.listReaders();
    if (readersOpt.has_value()) {
        std::cout << "SmartCard::MonitorService: " << readersOpt->size() << " reader(s)\n";
    } else {
        std::cout << "SmartCard::MonitorService: PC/SC unavailable\n";
    }

    // 4. Plugin — construction is the only load point in 4.0; pass a
    //    nonexistent path to demonstrate that an empty registry is
    //    a valid, non-throwing state. isUsable() reports not-usable
    //    since no plugins loaded.
    LibreSCRS::Plugin::CardPluginService registry{std::filesystem::path{"/nonexistent/plugins"}};
    std::cout << "Plugin: ABI v" << LibreSCRS::Plugin::kCardPluginAbiVersion << ", loaded=" << registry.size()
              << ", isUsable=" << (registry.isUsable() ? "true" : "false") << "\n";

    // 5. Trust — TrustStoreService is the unified async trust surface in 4.0.
    //    Constructed via the noexcept factory create(TrustConfig) which
    //    returns std::expected<std::shared_ptr<TrustStoreService>, CreateError>
    //    (4.0 Idiom — see developer-guide/sdk-reference/expected-result-handling).
    LibreSCRS::Trust::TrustConfig trustConfig;
    trustConfig.includeSystemTrustStore = false;
    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(std::move(trustConfig));
    if (!trustResult) {
        std::cerr << "Trust::TrustStoreService::create failed: " << trustResult.error().userMessage.defaultText << "\n";
        return 1;
    }
    std::shared_ptr<LibreSCRS::Trust::TrustStoreService> trustService = *trustResult;
    std::cout << "Trust::TrustStoreService: status=" << static_cast<int>(trustService->status()) << "\n";

    // 6. Direct use of TrustStore::validateChain — proves the public type is
    //    reachable for downstream consumers without going through SigningService.
    //    validateChain takes std::span<const CertificateView> (where
    //    CertificateView = std::span<const uint8_t>); empty chain is a
    //    valid degenerate case used here just to exercise the API.
    auto store = trustService->trustStore();
    std::vector<LibreSCRS::Trust::CertificateView> emptyChain;
    auto chainStatus =
        store ? store->validateChain(emptyChain) : LibreSCRS::Trust::TrustStore::ChainStatus::BrokenChain;
    std::cout << "TrustStore::validateChain(empty)=" << static_cast<int>(chainStatus) << "\n";

    // 7. Direct use of ParsedCertificate::fromDer — proves the public type is
    //    reachable. Returns std::expected<ParsedCertificate, ParseError>;
    //    invalid DER (here: an empty span) yields a structured ParseError
    //    with kind=Invalid and a translator-friendly userMessage.
    auto parsed = LibreSCRS::Certificate::ParsedCertificate::fromDer({});
    if (!parsed) {
        std::cout << "ParsedCertificate::fromDer(empty)=ParseError{kind=" << static_cast<int>(parsed.error().kind)
                  << ", key=\"" << parsed.error().userMessage.key << "\"}\n";
    } else {
        std::cout << "ParsedCertificate::fromDer(empty)=ok (unexpected!)\n";
    }

    // 8. Signing — SigningService takes shared_ptr<TrustStoreService> via DI.
    auto tsa = LibreSCRS::Signing::staticTsa("https://timestamp.example.com");
    auto svc = std::make_shared<LibreSCRS::Signing::SigningService>(trustService, tsa);
    std::cout << "Signing: service constructed at " << svc.get() << ", tsa provider valid: " << static_cast<bool>(tsa)
              << "\n";

    // 9. SigningRequest — repo-idiomatic Builder (build() && is rvalue-qualified,
    //    so chain-build does NOT compile; use lvalue setters then std::move).
    LibreSCRS::Signing::SigningRequest::Builder sb;
    sb.inputFile("/tmp/in.pdf");
    sb.outputFile("/tmp/out.pdf");
    sb.format(LibreSCRS::Signing::SignatureFormat::Pades);
    sb.level(LibreSCRS::Signing::SignatureLevel::B_T);
    sb.contactInfo("sdk-consumer@example.com");
    LibreSCRS::Signing::TsaProvider authedTsa =
        [](const LibreSCRS::Signing::TsaContext&) -> LibreSCRS::Signing::TsaRequest {
        LibreSCRS::Signing::TsaCredentials creds;
        creds.basicAuth =
            LibreSCRS::Signing::TsaCredentials::BasicAuth{"demo-user", LibreSCRS::Secure::String{"demo-pass"}};
        return LibreSCRS::Signing::TsaRequest{"https://tsa.example.com", std::move(creds)};
    };
    sb.tsaOverride(std::move(authedTsa));
    auto sreq = std::move(sb).build();
    std::cout << "SigningRequest: built (tsaOverride " << (static_cast<bool>(sreq.tsaOverride()) ? "set" : "unset")
              << ", contactInfo=\"" << sreq.contactInfo() << "\")\n";

    // 10. Exercise TsaProvider by actually invoking it — proves TsaContext /
    //     TsaRequest / TsaCredentials (with Secure::String password) all compile
    //     and round-trip through the public surface.
    LibreSCRS::Signing::TsaContext tctx;
    tctx.format = LibreSCRS::Signing::SignatureFormat::Pades;
    tctx.level = LibreSCRS::Signing::SignatureLevel::B_T;
    auto tsaOut = sreq.tsaOverride()(tctx);
    std::cout << "TsaProvider: url=" << tsaOut.url << ", basicAuth "
              << (tsaOut.credentials.basicAuth.has_value() ? "set" : "unset") << "\n";

    return 0;
}
