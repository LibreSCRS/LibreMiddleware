// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Signing/Enums.h>
#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/VisualSignatureParams.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using namespace LibreSCRS::Signing;

TEST(SigningEnumsTest, SignatureFormatAllCasesCovered)
{
    // This switch must cover every SignatureFormat value. If a new value is
    // added to the enum and the switch is not updated, -Werror=switch in the
    // build will surface it. Each case intentionally falls through to a single
    // assertion to keep the body minimal.
    auto nameFor = [](SignatureFormat f) -> const char* {
        switch (f) {
        case SignatureFormat::Pades:
            return "Pades";
        case SignatureFormat::Cades:
            return "Cades";
        case SignatureFormat::Xades:
            return "Xades";
        case SignatureFormat::Jades:
            return "Jades";
        case SignatureFormat::AsicE:
            return "AsicE";
        }
        return nullptr;
    };
    EXPECT_STREQ(nameFor(SignatureFormat::Pades), "Pades");
    EXPECT_STREQ(nameFor(SignatureFormat::Cades), "Cades");
    EXPECT_STREQ(nameFor(SignatureFormat::Xades), "Xades");
    EXPECT_STREQ(nameFor(SignatureFormat::Jades), "Jades");
    EXPECT_STREQ(nameFor(SignatureFormat::AsicE), "AsicE");
}

TEST(SigningEnumsTest, SignatureLevelAllCasesCovered)
{
    auto nameFor = [](SignatureLevel l) -> const char* {
        switch (l) {
        case SignatureLevel::B_B:
            return "B_B";
        case SignatureLevel::B_T:
            return "B_T";
        case SignatureLevel::B_LT:
            return "B_LT";
        case SignatureLevel::B_LTA:
            return "B_LTA";
        }
        return nullptr;
    };
    EXPECT_STREQ(nameFor(SignatureLevel::B_B), "B_B");
    EXPECT_STREQ(nameFor(SignatureLevel::B_T), "B_T");
    EXPECT_STREQ(nameFor(SignatureLevel::B_LT), "B_LT");
    EXPECT_STREQ(nameFor(SignatureLevel::B_LTA), "B_LTA");
}

TEST(SigningEnumsTest, PackagingModeAllCasesCovered)
{
    auto nameFor = [](PackagingMode p) -> const char* {
        switch (p) {
        case PackagingMode::Enveloped:
            return "Enveloped";
        case PackagingMode::Detached:
            return "Detached";
        }
        return nullptr;
    };
    EXPECT_STREQ(nameFor(PackagingMode::Enveloped), "Enveloped");
    EXPECT_STREQ(nameFor(PackagingMode::Detached), "Detached");
}

TEST(SigningRequestBuilderTest, BuildsMinimalValid)
{
    SigningRequest::Builder b;
    b.inputFile("/tmp/in.pdf").outputFile("/tmp/out.pdf").format(SignatureFormat::Pades).level(SignatureLevel::B_LT);
    auto req = std::move(b).build();
    EXPECT_EQ(req.inputFile(), std::filesystem::path("/tmp/in.pdf"));
    EXPECT_EQ(req.outputFile(), std::filesystem::path("/tmp/out.pdf"));
    EXPECT_EQ(req.format(), SignatureFormat::Pades);
    EXPECT_EQ(req.level(), SignatureLevel::B_LT);
}

TEST(SigningRequestBuilderTest, ThrowsOnMissingInputFile)
{
    SigningRequest::Builder b;
    b.outputFile("/tmp/out.pdf");
    EXPECT_THROW((void)std::move(b).build(), std::invalid_argument);
}

TEST(SigningRequestBuilderTest, ThrowsOnMissingOutputFile)
{
    SigningRequest::Builder b;
    b.inputFile("/tmp/in.pdf");
    EXPECT_THROW((void)std::move(b).build(), std::invalid_argument);
}

TEST(VisualSignatureParamsTest, BuilderProducesDefaults)
{
    VisualSignatureParams::Builder b;
    auto v = std::move(b).build();
    EXPECT_EQ(v.pageIndex(), 0);
    EXPECT_GT(v.width(), 0);
    EXPECT_GT(v.height(), 0);
}

TEST(VisualSignatureParamsTest, BuilderAcceptsRectAndTextTemplate)
{
    VisualSignatureParams::Builder b;
    b.pageIndex(2);
    b.rect(Rect{10, 20, 300, 80});
    b.textTemplate("Signed by {signerCN} on {date}");
    auto v = std::move(b).build();
    EXPECT_EQ(v.pageIndex(), 2);
    EXPECT_EQ(v.x(), 10);
    EXPECT_EQ(v.width(), 300);
    EXPECT_EQ(v.textTemplate(), "Signed by {signerCN} on {date}");
}

TEST(VisualSignatureParamsTest, ThrowsOnInvalidRect)
{
    VisualSignatureParams::Builder b;
    EXPECT_THROW(b.rect(Rect{0, 0, 0, 50}), std::invalid_argument);
}

TEST(VisualSignatureParamsTest, ThrowsOnNegativePageIndex)
{
    VisualSignatureParams::Builder b;
    EXPECT_THROW(b.pageIndex(-1), std::invalid_argument);
}

// §5.1 alignment: all invariants are enforced at setter-invocation time;
// defaults are independently valid, so build() && is assembly-only (noexcept).
TEST(VisualSignatureParamsTest, BuildIsNoexcept)
{
    static_assert(noexcept(std::declval<VisualSignatureParams::Builder>().build()),
                  "VisualSignatureParams::Builder::build() && must be noexcept — "
                  "all validation is done at the setter level (API-POLICY §5.1)");
}

// VisualSignatureParams must be value-semantic (copyable) so
// SigningRequest::visualParams() can return std::optional<VSP> by value
// without exposing caller-invalidation footguns. Verify that a copy is
// independent of the source — mutating/destroying the source must not
// invalidate the copy.
TEST(VisualSignatureParamsTest, CopyIsIndependent)
{
    VisualSignatureParams::Builder b;
    b.pageIndex(3);
    b.rect(Rect{11, 22, 333, 44});
    b.textTemplate("original");
    auto original = std::move(b).build();

    VisualSignatureParams copy = original; // copy-ctor
    // Destroy the source; the copy must remain fully valid.
    {
        auto moved = std::move(original);
        (void)moved;
    }
    EXPECT_EQ(copy.pageIndex(), 3);
    EXPECT_EQ(copy.x(), 11);
    EXPECT_EQ(copy.y(), 22);
    EXPECT_EQ(copy.width(), 333);
    EXPECT_EQ(copy.height(), 44);
    EXPECT_EQ(copy.textTemplate(), "original");
}

// Regression guard for the accessor footgun — callers that
// observed a prior visualParams() return value must not be invalidated by
// move-assigning the owning SigningRequest. The value-by-optional contract
// makes this trivially safe.
TEST(SigningRequestTest, VisualParamsSurvivesSourceMoveAssign)
{
    VisualSignatureParams::Builder vb;
    vb.pageIndex(1);
    vb.rect(Rect{5, 5, 200, 60});
    vb.textTemplate("v1");
    auto visual = std::move(vb).build();

    SigningRequest::Builder rb;
    rb.inputFile("/tmp/librescrs-req-move.pdf");
    rb.outputFile("/tmp/librescrs-req-move-out.pdf");
    rb.format(SignatureFormat::Pades);
    rb.level(SignatureLevel::B_B);
    rb.visualParams(std::move(visual));
    auto req = std::move(rb).build();

    // Observer pulls visualParams() — independently-owned optional copy.
    auto observed = req.visualParams();
    ASSERT_TRUE(observed.has_value());

    // Replace `req` wholesale via move-assign — would have invalidated a
    // raw `const VisualSignatureParams*` under the old API.
    SigningRequest::Builder rb2;
    rb2.inputFile("/tmp/librescrs-req-move-2.pdf");
    rb2.outputFile("/tmp/librescrs-req-move-out-2.pdf");
    rb2.format(SignatureFormat::Pades);
    rb2.level(SignatureLevel::B_B);
    // No visualParams on the replacement — exercises the hardest case.
    req = std::move(rb2).build();

    // `observed` is independent — still carries the original fields.
    EXPECT_EQ(observed->pageIndex(), 1);
    EXPECT_EQ(observed->x(), 5);
    EXPECT_EQ(observed->width(), 200);
    EXPECT_EQ(observed->textTemplate(), "v1");

    // And the replacement request correctly reports no visualParams.
    EXPECT_FALSE(req.visualParams().has_value());
}

TEST(SigningRequestBuilderTest, ThrowsOnVisualParamsWithNonPades)
{
    VisualSignatureParams::Builder vb;
    vb.rect(Rect{0, 0, 100, 50});
    auto visual = std::move(vb).build();

    SigningRequest::Builder rb;
    rb.inputFile("/tmp/in.xml");
    rb.outputFile("/tmp/out.xml");
    rb.format(SignatureFormat::Xades);
    rb.visualParams(std::move(visual));
    EXPECT_THROW((void)std::move(rb).build(), std::invalid_argument);
}

#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStoreService.h>
#include <LibreSCRS/Signing/TsaProvider.h>

TEST(TrustConfigTest, DefaultConstructs)
{
    LibreSCRS::Trust::TrustConfig cfg;
    EXPECT_FALSE(cfg.trustedListFile.has_value());
    EXPECT_TRUE(cfg.trustedListSources.empty());
    EXPECT_FALSE(cfg.cacheDirectory.has_value());
    EXPECT_TRUE(cfg.includeSystemTrustStore);
}

TEST(TsaProviderTest, StaticTsaReturnsConfiguredUrl)
{
    auto provider = staticTsa("http://timestamp.digicert.com");
    TsaContext ctx{SignatureFormat::Pades, SignatureLevel::B_T, {}};
    auto req = provider(ctx);
    EXPECT_EQ(req.url, "http://timestamp.digicert.com");
    EXPECT_FALSE(req.credentials.basicAuth.has_value());
    EXPECT_FALSE(req.credentials.bearerToken.has_value());
}

TEST(TsaProviderTest, CustomProviderCanReturnCredentials)
{
    TsaProvider provider = [](const TsaContext& ctx) {
        TsaRequest req;
        req.url = "https://tsa.enterprise.example/tsa";
        req.credentials.bearerToken =
            LibreSCRS::Secure::String("token-for-" + std::to_string(static_cast<int>(ctx.format)));
        return req;
    };
    TsaContext ctx{SignatureFormat::Pades, SignatureLevel::B_LT, {}};
    auto req = provider(ctx);
    EXPECT_EQ(req.url, "https://tsa.enterprise.example/tsa");
    ASSERT_TRUE(req.credentials.bearerToken.has_value());
    EXPECT_NE(req.credentials.bearerToken->view().find("token-for-"), std::string_view::npos);
}

#include <LibreSCRS/Signing/SigningResult.h>

// SigningResult is no longer default-constructible.
// The Uninitialized sentinel was removed — producers must choose an outcome
// at construction time via a named factory.
TEST(SigningResultTest, NotDefaultConstructible)
{
    static_assert(!std::is_default_constructible_v<LibreSCRS::Signing::SigningResult>,
                  "SigningResult must be constructed via a named factory (ok/invalidRequest/...)");
}

TEST(SigningResultTest, FactoriesSetStatus)
{
    using S = LibreSCRS::Signing::SigningResult::Status;
    auto genericLt = []() { return LibreSCRS::LocalizedText{"x", "x", {}}; };
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::ok("/tmp/out.pdf").status, S::Ok);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::userCancelled().status, S::UserCancelled);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::trustStoreUnavailableDiagnosticOnly(std::string{"x"}).status,
              S::TrustStoreUnavailable);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::signingEngineError(genericLt()).status, S::SigningEngineError);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::cardBlocked(genericLt()).status, S::CardBlocked);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::pinVerificationFailed(genericLt()).status, S::PinVerificationFailed);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::invalidRequestDiagnosticOnly(std::string{"bad"}).status,
              S::InvalidRequest);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::tsaUnreachable(genericLt()).status, S::TsaUnreachable);
}

#include <LibreSCRS/Signing/SigningService.h>
#include "detail/DocumentPrecheck.h"
#include "detail/ErrorClassifier.h"
#include "detail/RequestBridge.h"
#include <types.h>

TEST(DocumentPrecheck, RejectsNonPdfForPadesButNotOtherFormats)
{
    using LibreSCRS::Signing::SignatureFormat;
    namespace det = LibreSCRS::Signing::detail;
    const std::vector<std::uint8_t> notPdf{'h', 'e', 'l', 'l', 'o'};
    EXPECT_TRUE(det::documentPrecheck(SignatureFormat::Pades, notPdf).has_value()); // fast reject, no card

    const std::vector<std::uint8_t> pdfish{'%', 'P', 'D', 'F', '-', '1', '.', '7'};
    EXPECT_FALSE(det::documentPrecheck(SignatureFormat::Pades, pdfish).has_value());

    // Non-PAdES formats have NO magic gate — arbitrary bytes are a valid input
    // to enveloping/detached/container signing. Must NOT be rejected here.
    EXPECT_FALSE(det::documentPrecheck(SignatureFormat::AsicE, notPdf).has_value());
    EXPECT_FALSE(det::documentPrecheck(SignatureFormat::Cades, notPdf).has_value());
    EXPECT_FALSE(det::documentPrecheck(SignatureFormat::Xades, notPdf).has_value());
    EXPECT_FALSE(det::documentPrecheck(SignatureFormat::Jades, notPdf).has_value());
}

TEST(SigningServiceClassifierTest, MapsCKRHexCodesToPinErrors)
{
    using LibreSCRS::Signing::SigningResult;
    auto make = [](std::string msg) {
        libresign::SigningResult r;
        r.errorMessage = std::move(msg);
        return r;
    };

    // Native backend: "<op> failed: CKR 0x<UPPER-HEX>" (see pkcs11_token.cpp checkRv).
    EXPECT_EQ(SigningResult::Status::PinVerificationFailed,
              LibreSCRS::Signing::detail::classifyLibresignError(
                  make("Native signing error: C_Login failed: CKR 0x000000A0")));
    EXPECT_EQ(SigningResult::Status::PinVerificationFailed,
              LibreSCRS::Signing::detail::classifyLibresignError(make("CKR 0x000000A1 presented")));
    EXPECT_EQ(SigningResult::Status::PinVerificationFailed,
              LibreSCRS::Signing::detail::classifyLibresignError(make("C_Login failed: CKR 0x000000A2")));

    EXPECT_EQ(SigningResult::Status::CardBlocked, LibreSCRS::Signing::detail::classifyLibresignError(
                                                      make("Native signing error: C_Login failed: CKR 0x000000A4")));
    EXPECT_EQ(SigningResult::Status::CardBlocked,
              LibreSCRS::Signing::detail::classifyLibresignError(make("Token reports CKR 0x000000A3")));

    // DSS backend / symbolic names.
    EXPECT_EQ(SigningResult::Status::PinVerificationFailed,
              LibreSCRS::Signing::detail::classifyLibresignError(make("Wrong PIN entered")));
    EXPECT_EQ(SigningResult::Status::PinVerificationFailed,
              LibreSCRS::Signing::detail::classifyLibresignError(make("CKR_PIN_INCORRECT from token")));
    EXPECT_EQ(SigningResult::Status::CardBlocked,
              LibreSCRS::Signing::detail::classifyLibresignError(make("CKR_PIN_LOCKED")));
    EXPECT_EQ(SigningResult::Status::CardBlocked,
              LibreSCRS::Signing::detail::classifyLibresignError(make("CKR_PIN_EXPIRED")));

    // TSA bucket.
    EXPECT_EQ(SigningResult::Status::TsaUnreachable,
              LibreSCRS::Signing::detail::classifyLibresignError(make("timestamping service unreachable")));
    EXPECT_EQ(SigningResult::Status::TsaUnreachable,
              LibreSCRS::Signing::detail::classifyLibresignError(make("TSA returned HTTP 500")));

    // Fallback + defensive checks: unrelated strings must NOT match the old
    // lowercase "pin" trap (the reviewer's concrete false-positive concern).
    EXPECT_EQ(SigningResult::Status::SigningEngineError,
              LibreSCRS::Signing::detail::classifyLibresignError(make("random library error")));
    EXPECT_EQ(SigningResult::Status::SigningEngineError,
              LibreSCRS::Signing::detail::classifyLibresignError(make("pipeline stalled")));
    EXPECT_EQ(SigningResult::Status::SigningEngineError,
              LibreSCRS::Signing::detail::classifyLibresignError(make("/home/user/pinfile missing")));
}

// ---------------------------------------------------------------------------
// Bridge translation tests (LibreSCRS::Signing::detail::translatePublicRequestToLibresign)
//
// These cover the exact production mapping that SigningService::sign uses to
// hand a public SigningRequest to libresign — without needing a PC/SC reader
// or PKCS#11 token. The original contact-info end-to-end test re-implemented
// the bridge locally, so a regression in SigningService.cpp would not have
// been detected; this suite guards against that path drifting again.
// ---------------------------------------------------------------------------

TEST(SigningServiceBridgeTranslationTest, ForwardsContactInfoForInvisibleSignature)
{
    // Regression guard for the pre-fix behaviour where reason / location /
    // contactInfo were only forwarded inside `if (visualParams() != nullptr)`.
    // An invisible signature (no visualParams configured) would therefore have
    // silently dropped all three PDF signature-dictionary fields even though
    // ISO 32000-1:2008 §12.8.1 defines them as independent of visual
    // appearance. pades_module.cpp emits /Reason, /Location, /ContactInfo
    // unconditionally on visual.enabled, so the bridge must populate them the
    // same way.
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.inputFile("/tmp/librescrs-bridge-invisible.pdf");
    b.outputFile("/tmp/librescrs-bridge-invisible-out.pdf");
    b.format(LibreSCRS::Signing::SignatureFormat::Pades);
    b.level(LibreSCRS::Signing::SignatureLevel::B_B);
    b.reason("Approval");
    b.location("Belgrade");
    b.contactInfo("signer@example.com");
    // Deliberately NO visualParams(...) — this is the invisible-signature
    // path that exercised the I2 bug.
    auto request = std::move(b).build();
    ASSERT_FALSE(request.visualParams().has_value());

    libresign::SigningRequest out;
    LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);

    EXPECT_FALSE(out.visual.enabled) << "Invisible signature must not enable visual widget";
    EXPECT_EQ(out.visual.reason, "Approval");
    EXPECT_EQ(out.visual.location, "Belgrade");
    EXPECT_EQ(out.visual.contactInfo, "signer@example.com");
}

TEST(SigningServiceBridgeTranslationTest, ForwardsContactInfoForVisibleSignature)
{
    // Companion path: with visualParams configured, reason / location /
    // contactInfo still flow through AND the appearance rectangle is honoured.
    LibreSCRS::Signing::VisualSignatureParams::Builder vb;
    vb.pageIndex(2);
    vb.rect(Rect{10, 20, 300, 80});
    vb.textTemplate("Signed by {signerCN} on {date}");
    auto visual = std::move(vb).build();

    LibreSCRS::Signing::SigningRequest::Builder b;
    b.inputFile("/tmp/librescrs-bridge-visible.pdf");
    b.outputFile("/tmp/librescrs-bridge-visible-out.pdf");
    b.format(LibreSCRS::Signing::SignatureFormat::Pades);
    b.level(LibreSCRS::Signing::SignatureLevel::B_B);
    b.reason("Approval");
    b.location("Belgrade");
    b.contactInfo("signer@example.com");
    b.visualParams(std::move(visual));
    auto request = std::move(b).build();
    ASSERT_TRUE(request.visualParams().has_value());

    libresign::SigningRequest out;
    LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);

    EXPECT_TRUE(out.visual.enabled);
    // Public pageIndex is 0-based; libresign's visual.page is 1-based with
    // <= 0 meaning "last page" — RequestBridge converts via pageIndex + 1.
    EXPECT_EQ(out.visual.page, 3);
    EXPECT_FLOAT_EQ(out.visual.x, 10.0f);
    EXPECT_FLOAT_EQ(out.visual.y, 20.0f);
    EXPECT_FLOAT_EQ(out.visual.width, 300.0f);
    EXPECT_FLOAT_EQ(out.visual.height, 80.0f);
    EXPECT_EQ(out.visual.text, "Signed by {signerCN} on {date}");
    EXPECT_EQ(out.visual.reason, "Approval");
    EXPECT_EQ(out.visual.location, "Belgrade");
    EXPECT_EQ(out.visual.contactInfo, "signer@example.com");
}

TEST(SigningServiceBridgeTranslationTest, MapsFormatLevelPackagingCorrectly)
{
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.inputFile("/tmp/in.xml");
    b.outputFile("/tmp/out.xml");
    b.format(LibreSCRS::Signing::SignatureFormat::Xades);
    b.level(LibreSCRS::Signing::SignatureLevel::B_LTA);
    b.packaging(LibreSCRS::Signing::PackagingMode::Detached);
    auto request = std::move(b).build();

    libresign::SigningRequest out;
    LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);

    EXPECT_EQ(out.format, libresign::SignatureFormat::Xades);
    EXPECT_EQ(out.level, libresign::SignatureLevel::B_LTA);
    EXPECT_EQ(out.packaging, libresign::SignaturePackaging::Detached);
    EXPECT_EQ(out.fileName, "in.xml");
}

TEST(SigningServiceBridgeTranslationTest, LeavesDocumentAndTsaUntouched)
{
    // The helper must not touch document / tsa: the caller fills those from
    // state that lives outside the public SigningRequest. Callers rely on
    // this no-aliasing invariant when they std::move the loaded document into
    // out.document *after* the helper runs.
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.inputFile("/tmp/in.pdf");
    b.outputFile("/tmp/out.pdf");
    b.format(LibreSCRS::Signing::SignatureFormat::Pades);
    auto request = std::move(b).build();

    libresign::SigningRequest out;
    out.document = {0xDE, 0xAD, 0xBE, 0xEF};
    out.tsa.url = "https://preset.example/tsa";

    LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);

    ASSERT_EQ(out.document.size(), 4u);
    EXPECT_EQ(out.document[0], 0xDE);
    EXPECT_EQ(out.tsa.url, "https://preset.example/tsa");
}

TEST(SigningServiceTest, ConstructorAcceptsTrustAndTsa)
{
    // SigningService is now pure-DI (no instance() factory).
    // This test proves the constructor accepts a TrustConfig + nullable
    // TsaProvider and yields a usable shared_ptr. TrustConfig validity is
    // deferred to sign() per the no-throw ctor contract, so construction must
    // succeed even with a minimal TL source and an empty TsaProvider.
    LibreSCRS::Trust::TrustConfig trust;
    trust.trustedListSources.push_back({"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false, false});
    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(std::move(trust));
    ASSERT_TRUE(trustResult.has_value());
    auto svc = std::make_shared<LibreSCRS::Signing::SigningService>(*trustResult, LibreSCRS::Signing::TsaProvider{});
    ASSERT_NE(svc, nullptr);
}

TEST(TsaContextTest, SigningTimeDefaultIsNullopt)
{
    TsaContext ctx;
    EXPECT_FALSE(ctx.signingTime.has_value());
}

TEST(TrustConfigTest, AcceptsUrlSources)
{
    LibreSCRS::Trust::TrustConfig cfg;
    cfg.trustedListSources.push_back({"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false, true});
    cfg.trustedListSources.push_back({"https://ec.europa.eu/tools/lotl/eu-lotl.xml", true, false});
    cfg.cacheDirectory = std::filesystem::temp_directory_path() / "librescrs-tsl-test";

    ASSERT_EQ(cfg.trustedListSources.size(), 2u);
    EXPECT_EQ(cfg.trustedListSources[0].url, "https://www.mit.gov.rs/TrustedList/TSL-RS.xml");
    EXPECT_FALSE(cfg.trustedListSources[0].lotl);
    EXPECT_TRUE(cfg.trustedListSources[0].eager);
    EXPECT_TRUE(cfg.trustedListSources[1].lotl);
    EXPECT_FALSE(cfg.trustedListSources[1].eager);
    EXPECT_TRUE(cfg.cacheDirectory.has_value());
}

TEST(SigningRequestBuilderTest, CertificateLabelRoundTrips)
{
    SigningRequest::Builder b;
    b.inputFile("/tmp/in.pdf")
        .outputFile("/tmp/out.pdf")
        .format(SignatureFormat::Pades)
        .certificateLabel("My Signing Cert");
    auto req = std::move(b).build();
    EXPECT_EQ(req.certificateLabel(), "My Signing Cert");
}

TEST(SigningRequestBuilderTest, AllowExpiredCertDefaultsFalse)
{
    SigningRequest::Builder b;
    b.inputFile("/tmp/in.pdf").outputFile("/tmp/out.pdf").format(SignatureFormat::Pades);
    auto req = std::move(b).build();
    EXPECT_FALSE(req.allowExpiredCert());
}

TEST(SigningRequestBuilderTest, AllowExpiredCertRoundTrips)
{
    SigningRequest::Builder b;
    b.inputFile("/tmp/in.pdf").outputFile("/tmp/out.pdf").format(SignatureFormat::Pades).allowExpiredCert(true);
    auto req = std::move(b).build();
    EXPECT_TRUE(req.allowExpiredCert());
}

TEST(SigningServiceBridgeTranslationTest, ForwardsAllowExpiredCert)
{
    // Default request: bridge must produce allowExpiredCertificate=false.
    {
        LibreSCRS::Signing::SigningRequest::Builder b;
        b.inputFile("/tmp/in.pdf");
        b.outputFile("/tmp/out.pdf");
        b.format(LibreSCRS::Signing::SignatureFormat::Pades);
        auto request = std::move(b).build();

        libresign::SigningRequest out;
        LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);
        EXPECT_FALSE(out.allowExpiredCertificate);
    }
    // Opt-in: bridge must propagate the flag.
    {
        LibreSCRS::Signing::SigningRequest::Builder b;
        b.inputFile("/tmp/in.pdf");
        b.outputFile("/tmp/out.pdf");
        b.format(LibreSCRS::Signing::SignatureFormat::Pades);
        b.allowExpiredCert(true);
        auto request = std::move(b).build();

        libresign::SigningRequest out;
        LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);
        EXPECT_TRUE(out.allowExpiredCertificate);
    }
}

// A stub CardPlugin that advertises PKI but whose sign() is never reached —
// we use it to satisfy the SigningService::sign signature. The bridge must
// resolve the signing path through libresign, not by calling cardPlugin.sign().
// readCounters is overridden to return {} (nullopt retriesLeft) so the bridge
// never dereferences the connection reference for tests that exercise
// InvalidRequest / UserCancelled paths.
namespace {
class StubPkiPlugin : public LibreSCRS::Plugin::CardPlugin
{
public:
    StubPkiPlugin()
    {
        setIdentity("stub-pki", "Stub PKI", /*priority=*/1000);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::PKI | LibreSCRS::Plugin::CardCapabilities::PinManagement;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        // The stub matches every ATR via canHandleConnection — give an empty
        // ATR table here; the bridge tests below never exercise canHandle.
        static constexpr std::array<LibreSCRS::Plugin::Atr, 0> kAtrs{};
        return kAtrs;
    }
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::ok(LibreSCRS::Plugin::CardData{});
    }
    LibreSCRS::Plugin::CredentialCounters readCounters(LibreSCRS::SmartCard::CardSession&,
                                                       std::string_view) const override
    {
        // Return without touching the session — the bridge tests below pass a
        // live session (or skip when no reader is available), but we don't
        // want to generate APDU traffic.
        return {};
    }
};

// Try to open a live CardSession for tests that must pass a real session.
// Returns nullptr when no reader/card is present; callers must GTEST_SKIP in
// that case.
std::shared_ptr<LibreSCRS::SmartCard::CardSession> tryOpenSession()
{
    LibreSCRS::SmartCard::MonitorService mon;
    auto readersOpt = mon.listReaders();
    if (!readersOpt.has_value() || readersOpt->empty())
        return nullptr;
    auto opened = LibreSCRS::SmartCard::CardSession::open(readersOpt->front());
    if (!opened.has_value())
        return nullptr;
    return std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
}

LibreSCRS::Signing::SigningRequest makeBuiltRequest(const std::filesystem::path& in, const std::filesystem::path& out)
{
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.inputFile(in)
        .outputFile(out)
        .format(LibreSCRS::Signing::SignatureFormat::Pades)
        .level(LibreSCRS::Signing::SignatureLevel::B_B)
        .packaging(LibreSCRS::Signing::PackagingMode::Enveloped);
    return std::move(b).build();
}
} // namespace

TEST(SigningServiceBridgeTest, ReturnsInvalidRequestWhenInputMissing)
{
    auto session = tryOpenSession();
    if (!session) {
        GTEST_SKIP() << "No PC/SC reader available for opening a CardSession";
    }

    LibreSCRS::Trust::TrustConfig trust;
    // The InvalidRequest path short-circuits before libresign reads the trust
    // store, so a minimal TL source is sufficient to satisfy the
    // trust-availability precondition in sign().
    trust.trustedListSources.push_back({"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false, false});
    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(std::move(trust));
    ASSERT_TRUE(trustResult.has_value());
    auto svc = std::make_shared<LibreSCRS::Signing::SigningService>(*trustResult, LibreSCRS::Signing::TsaProvider{});

    auto request = makeBuiltRequest("/does/not/exist/input.pdf", "/tmp/out.pdf");

    auto provider = [](const LibreSCRS::Auth::AuthRequirement&) {
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{"0000"});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    };

    auto plugin = std::make_shared<StubPkiPlugin>();
    auto result = svc->sign(request, provider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::InvalidRequest);
    EXPECT_FALSE(result.userMessage.key.empty());
}

TEST(SigningServiceBridgeTest, ReturnsUserCancelledWhenProviderCancels)
{
    auto session = tryOpenSession();
    if (!session) {
        GTEST_SKIP() << "No PC/SC reader available for opening a CardSession";
    }

    LibreSCRS::Trust::TrustConfig trust;
    // The UserCancelled path short-circuits before libresign reads the trust
    // store, so a minimal TL source is sufficient to satisfy the
    // trust-availability precondition in sign().
    trust.trustedListSources.push_back({"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false, false});
    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(std::move(trust));
    ASSERT_TRUE(trustResult.has_value());
    auto svc = std::make_shared<LibreSCRS::Signing::SigningService>(*trustResult, LibreSCRS::Signing::TsaProvider{});

    // Create a real tiny input file so the input-file check passes. A %PDF-
    // header clears the fail-fast document pre-check (makeBuiltRequest signs as
    // PAdES) so this test still exercises the provider-cancel path rather than
    // the InvalidDocument reject path.
    auto tmpIn = std::filesystem::temp_directory_path() / "librescrs-bridge-input.pdf";
    {
        std::ofstream f(tmpIn);
        f << "%PDF-1.7\n";
    }
    auto request = makeBuiltRequest(tmpIn, tmpIn.parent_path() / "out.asice");

    auto cancellingProvider = [](const LibreSCRS::Auth::AuthRequirement&) {
        return LibreSCRS::Auth::CredentialResult::cancelled();
    };

    auto plugin = std::make_shared<StubPkiPlugin>();
    auto result = svc->sign(request, cancellingProvider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::UserCancelled);
}

// Scoped env-var helper: set on construction, restore on destruction.
// Keeps tests hermetic even if the suite runs under LIBRESCRS_SIGNING_BACKEND
// already set in the shell (which would otherwise silently change behavior).
namespace {
class ScopedEnvVar
{
public:
    ScopedEnvVar(const char* name, const char* value) : name_(name)
    {
        const char* old = std::getenv(name);
        if (old)
            previous_ = old;
        if (value)
            ::setenv(name, value, /*overwrite=*/1);
        else
            ::unsetenv(name);
    }
    ~ScopedEnvVar()
    {
        if (previous_)
            ::setenv(name_, previous_->c_str(), /*overwrite=*/1);
        else
            ::unsetenv(name_);
    }
    ScopedEnvVar(const ScopedEnvVar&) = delete;
    ScopedEnvVar& operator=(const ScopedEnvVar&) = delete;

private:
    const char* name_;
    std::optional<std::string> previous_;
};
} // namespace

// SigningService.h documents that B-T / B-LT / B-LTA
// signatures require a configured TSA. With pure-DI ctor + nullable
// TsaProvider, sign() must surface TsaUnreachable up front rather than letting
// libresign emit a generic SigningEngineError.
TEST(SigningServiceBridgeTest, TsaUnreachableWhenNonBBLevelAndEmptyTsa)
{
    auto session = tryOpenSession();
    if (!session) {
        GTEST_SKIP() << "No PC/SC reader available for opening a CardSession";
    }

    LibreSCRS::Trust::TrustConfig trust;
    trust.trustedListSources.push_back({"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false, false});
    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(std::move(trust));
    ASSERT_TRUE(trustResult.has_value());
    auto svc = std::make_shared<LibreSCRS::Signing::SigningService>(*trustResult, LibreSCRS::Signing::TsaProvider{});

    // Create a real tiny input file so the InvalidRequest input-file guard passes.
    auto tmpIn = std::filesystem::temp_directory_path() / "librescrs-tsa-unreachable-input.pdf";
    {
        std::ofstream f(tmpIn);
        f << "dummy";
    }
    LibreSCRS::Signing::SigningRequest::Builder rb;
    rb.inputFile(tmpIn);
    rb.outputFile(tmpIn.parent_path() / "out.pdf");
    rb.format(LibreSCRS::Signing::SignatureFormat::Pades);
    rb.level(LibreSCRS::Signing::SignatureLevel::B_T);
    auto request = std::move(rb).build();

    auto provider = [](const LibreSCRS::Auth::AuthRequirement&) {
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{"0000"});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    };

    auto plugin = std::make_shared<StubPkiPlugin>();
    auto result = svc->sign(request, provider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::TsaUnreachable);
    ASSERT_TRUE(result.diagnosticDetail.has_value());
    EXPECT_NE(result.diagnosticDetail->find("TsaProvider"), std::string::npos)
        << "Diagnostic should name TsaProvider; got: " << *result.diagnosticDetail;
}

// DSS-backend silent-drop guard: when LIBRESCRS_SIGNING_BACKEND=dss AND the
// caller set TSA credentials or contactInfo, SigningService::sign() must
// fail LOUD (not silently drop) with a SigningEngineError whose
// diagnosticDetail names the DSS backend.
TEST(SigningServiceBridgeTest, DssBackendFailsLoudWhenCredentialsSet)
{
    auto session = tryOpenSession();
    if (!session) {
        GTEST_SKIP() << "No PC/SC reader available for opening a CardSession";
    }

    ScopedEnvVar envGuard("LIBRESCRS_SIGNING_BACKEND", "dss");

    LibreSCRS::Trust::TrustConfig trust;
    trust.trustedListSources.push_back({"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false, false});

    // TsaProvider returns credentials — the silent-drop path we are guarding.
    LibreSCRS::Signing::TsaProvider tsaProvider = [](const LibreSCRS::Signing::TsaContext&) {
        LibreSCRS::Signing::TsaRequest req;
        req.url = "https://tsa.example.com/tsa";
        req.credentials.bearerToken = LibreSCRS::Secure::String("demo-bearer-token");
        return req;
    };

    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(std::move(trust));
    ASSERT_TRUE(trustResult.has_value());
    auto svc = std::make_shared<LibreSCRS::Signing::SigningService>(*trustResult, std::move(tsaProvider));

    // Create a real tiny input file so the input-file check passes and we
    // reach the backend-guard block inside sign(). A %PDF- header clears the
    // fail-fast document pre-check (makeBuiltRequest signs as PAdES) so this
    // test still reaches the DSS backend guard rather than the InvalidDocument
    // reject path.
    auto tmpIn = std::filesystem::temp_directory_path() / "librescrs-dss-guard-input.pdf";
    {
        std::ofstream f(tmpIn);
        f << "%PDF-1.7\n";
    }
    auto request = makeBuiltRequest(tmpIn, tmpIn.parent_path() / "out.asice");

    auto provider = [](const LibreSCRS::Auth::AuthRequirement&) {
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{"0000"});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    };

    auto plugin = std::make_shared<StubPkiPlugin>();
    auto result = svc->sign(request, provider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::SigningEngineError);
    // Diagnostic must name the DSS backend so a deployer flipping the env
    // var gets an actionable error rather than a silent auth downgrade.
    ASSERT_TRUE(result.diagnosticDetail.has_value());
    ASSERT_FALSE(result.diagnosticDetail->empty());
    EXPECT_NE(result.diagnosticDetail->find("DSS"), std::string::npos)
        << "Diagnostic should name DSS backend; got: " << *result.diagnosticDetail;
    EXPECT_NE(result.diagnosticDetail->find("credentials"), std::string::npos)
        << "Diagnostic should mention credentials; got: " << *result.diagnosticDetail;

    // No cleanup needed: svc is per-test (pure DI), goes out of scope here.
}

// ---------------------------------------------------------------------------
// Buffer-sign overload (4.3): span in -> SigningResult::signedDocumentBytes,
// no file touched. These two cases exercise the overload's input seam and the
// SHARED validate+pipeline core WITHOUT a PC/SC reader: a detached CardSession
// drives the path, and both assertions land on early returns that fire before
// any card I/O. The signed-bytes-equal-file-output round-trip and the CKA_ID
// key-selection matrix require a real token and are covered by the HW matrix.
// ---------------------------------------------------------------------------

namespace {
// Minimal trust service for the buffer-sign early-return tests. The
// InvalidRequest / UserCancelled paths short-circuit before libresign ever
// reads the trust store, so only a non-null service is required.
std::shared_ptr<LibreSCRS::Signing::SigningService> makeBufferSignService()
{
    LibreSCRS::Trust::TrustConfig trust;
    trust.trustedListSources.push_back({"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false, false});
    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(std::move(trust));
    if (!trustResult.has_value())
        return nullptr;
    return std::make_shared<LibreSCRS::Signing::SigningService>(*trustResult, LibreSCRS::Signing::TsaProvider{});
}

LibreSCRS::Signing::SigningRequest makeBufferSignRequest()
{
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.format(LibreSCRS::Signing::SignatureFormat::Pades)
        .level(LibreSCRS::Signing::SignatureLevel::B_B)
        .packaging(LibreSCRS::Signing::PackagingMode::Enveloped);
    // buildForBufferSign skips the inputFile/outputFile required-field checks.
    return std::move(b).buildForBufferSign();
}
} // namespace

TEST(SigningServiceBufferSignTest, ReturnsInvalidRequestWhenBufferEmpty)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    auto svc = makeBufferSignService();
    ASSERT_NE(svc, nullptr);
    auto request = makeBufferSignRequest();

    auto provider = [](const LibreSCRS::Auth::AuthRequirement&) {
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{"0000"});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    };
    auto plugin = std::make_shared<StubPkiPlugin>();

    const std::span<const std::uint8_t> emptyInput;
    auto result = svc->sign(request, emptyInput, provider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::InvalidRequest);
    // No artifact is produced on the error path.
    EXPECT_FALSE(result.signedDocumentBytes.has_value());
}

TEST(SigningServiceBufferSignTest, ReturnsUserCancelledWhenProviderCancels)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    auto svc = makeBufferSignService();
    ASSERT_NE(svc, nullptr);
    auto request = makeBufferSignRequest();

    // A non-empty buffer drives the shared pipeline up to PIN collection; the
    // cancelling provider returns before any card I/O — proving the buffer
    // overload reuses the same validate+pipeline core as the file path.
    auto cancellingProvider = [](const LibreSCRS::Auth::AuthRequirement&) {
        return LibreSCRS::Auth::CredentialResult::cancelled();
    };
    auto plugin = std::make_shared<StubPkiPlugin>();

    // A %PDF--prefixed buffer clears the fail-fast document pre-check so this
    // test still exercises the provider-cancel path (not the InvalidDocument
    // reject path). The bytes need not be a valid PDF — the provider cancels
    // before the deep parse ever runs.
    const std::vector<std::uint8_t> document{'%', 'P', 'D', 'F', '-', '1', '.', '7', '\n', '%', 0xE2, 0xE3};
    auto result = svc->sign(request, std::span<const std::uint8_t>{document}, cancellingProvider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::UserCancelled);
    EXPECT_FALSE(result.signedDocumentBytes.has_value());
}

TEST(SigningResultFactories, InvalidDocumentCarriesStatusAndKey)
{
    using LibreSCRS::Signing::SigningResult;
    auto r = SigningResult::invalidDocument(LibreSCRS::Auth::ErrorKeys::invalidDocument(), "broken pdf xref");
    EXPECT_EQ(r.status, SigningResult::Status::InvalidDocument);
    EXPECT_EQ(r.userMessage.key, "librescrs.error.sign.invalid_document");
    ASSERT_TRUE(r.diagnosticDetail.has_value());
    EXPECT_EQ(*r.diagnosticDetail, "broken pdf xref");

    auto d = SigningResult::invalidDocumentDiagnosticOnly("only-detail");
    EXPECT_EQ(d.status, SigningResult::Status::InvalidDocument);
    EXPECT_EQ(d.userMessage.key, "librescrs.error.sign.invalid_document");
}

// Document-content faults (bad/unparseable document bytes) route to the public
// InvalidDocument status, distinct from request-parameter faults (InvalidInput
// -> InvalidRequest) and genuine engine faults (EngineError -> SigningEngineError).
TEST(ErrorClassifier, DocumentContentKindsMapToInvalidDocument)
{
    using S = LibreSCRS::Signing::SigningResult::Status;
    using libresign::SignFailureKind;
    namespace det = LibreSCRS::Signing::detail;
    auto kind = [](SignFailureKind k) { return libresign::SigningResult{false, {}, "detail", k}; };
    EXPECT_EQ(S::InvalidDocument, det::classifyLibresignError(kind(SignFailureKind::InvalidDocument)));
    EXPECT_EQ(S::InvalidDocument, det::classifyLibresignError(kind(SignFailureKind::PdfPreparationError)));
    // Request-param problems (e.g. "TSA URL required") stay InvalidRequest.
    EXPECT_EQ(S::InvalidRequest, det::classifyLibresignError(kind(SignFailureKind::InvalidInput)));
    // Genuine engine faults stay SigningEngineError.
    EXPECT_EQ(S::SigningEngineError, det::classifyLibresignError(kind(SignFailureKind::EngineError)));
}
