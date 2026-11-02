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
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
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
    b.format(SignatureFormat::Pades).level(SignatureLevel::B_LT);
    auto req = std::move(b).buildForBufferSign();
    EXPECT_EQ(req.format(), SignatureFormat::Pades);
    EXPECT_EQ(req.level(), SignatureLevel::B_LT);
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
    rb.format(SignatureFormat::Pades);
    rb.level(SignatureLevel::B_B);
    rb.visualParams(std::move(visual));
    auto req = std::move(rb).buildForBufferSign();

    // Observer pulls visualParams() — independently-owned optional copy.
    auto observed = req.visualParams();
    ASSERT_TRUE(observed.has_value());

    // Replace `req` wholesale via move-assign — would have invalidated a
    // raw `const VisualSignatureParams*` under the old API.
    SigningRequest::Builder rb2;
    rb2.format(SignatureFormat::Pades);
    rb2.level(SignatureLevel::B_B);
    // No visualParams on the replacement — exercises the hardest case.
    req = std::move(rb2).buildForBufferSign();

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
    rb.format(SignatureFormat::Xades);
    rb.visualParams(std::move(visual));
    EXPECT_THROW((void)std::move(rb).buildForBufferSign(), std::invalid_argument);
}

#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStoreService.h>
#include <LibreSCRS/Signing/TsaProvider.h>

TEST(TrustConfigTest, DefaultConstructs)
{
    LibreSCRS::Trust::TrustConfig cfg;
    EXPECT_TRUE(cfg.trustedListSources.empty());
    EXPECT_FALSE(cfg.cacheDirectory.has_value());
}

TEST(TsaProviderTest, StaticTsaReturnsConfiguredUrl)
{
    auto provider = staticTsa("http://timestamp.digicert.com");
    EXPECT_EQ(provider.url, "http://timestamp.digicert.com");
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
    auto genericLt = []() { return LibreSCRS::LocalizedText{"x", "x"}; };
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::okWithBytes({0x25}).status, S::Ok);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::userCancelled().status, S::UserCancelled);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::trustStoreUnavailableDiagnosticOnly(std::string{"x"}).status,
              S::TrustStoreUnavailable);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::signingEngineError(genericLt()).status, S::SigningEngineError);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::cardBlocked(genericLt()).status, S::CardBlocked);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::pinVerificationFailed(genericLt()).status, S::PinVerificationFailed);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::invalidRequest(genericLt()).status, S::InvalidRequest);
    EXPECT_EQ(LibreSCRS::Signing::SigningResult::tsaUnreachable(genericLt()).status, S::TsaUnreachable);
}

#include <LibreSCRS/Signing/SigningService.h>
#include "detail/DocumentPrecheck.h"
#include "detail/ErrorClassifier.h"
#include "detail/RequestBridge.h"
#include <types.h>

#include "signing_stub_plugin.h"
#include "soft_key_plugin.h"
#include "signing_test_support/mock_tsa_server.h"
#include "signing_test_support/signing_test_support.h"

#include <openssl/bio.h>
#include <openssl/cms.h>

#include <cstdio>
#include <iterator>
#include <regex>

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

TEST(DocumentPrecheck, ToleratesTheSameLeadingPrefixAsThePadesEngine)
{
    // PAdESModule::sign tolerates up to libresign::kPdfHeaderScanWindow bytes
    // of non-PDF prefix before the "%PDF-" header (Adobe Acrobat Implementation
    // Notes §H.3 — multipart/form-data wrappers from web-form uploads are the
    // real-world source) and strips it before parsing. A precheck demanding the
    // header at byte 0 would fail-fast on documents the engine signs happily,
    // so the gate must scan the SAME window off the SAME constant.
    using LibreSCRS::Signing::SignatureFormat;
    namespace det = LibreSCRS::Signing::detail;

    auto docWithPrefix = [](std::size_t prefixLen) {
        std::vector<std::uint8_t> doc(prefixLen, static_cast<std::uint8_t>('X'));
        const std::string header = "%PDF-1.7\n%\xE2\xE3\n";
        doc.insert(doc.end(), header.begin(), header.end());
        return doc;
    };

    // Header at byte 0 — the classic case — stays accepted.
    EXPECT_FALSE(det::documentPrecheck(SignatureFormat::Pades, docWithPrefix(0)).has_value());
    // A small wrapper in front of the header must NOT be rejected.
    EXPECT_FALSE(det::documentPrecheck(SignatureFormat::Pades, docWithPrefix(100)).has_value());
    // Last offset at which the whole 5-byte magic still fits in the window.
    EXPECT_FALSE(
        det::documentPrecheck(SignatureFormat::Pades, docWithPrefix(libresign::kPdfHeaderScanWindow - 5)).has_value());
    // One byte further and the engine's own scan misses it too — reject, so the
    // caller gets the cheap InvalidDocument instead of a deep-parse failure.
    EXPECT_TRUE(
        det::documentPrecheck(SignatureFormat::Pades, docWithPrefix(libresign::kPdfHeaderScanWindow - 4)).has_value());
    EXPECT_TRUE(det::documentPrecheck(SignatureFormat::Pades, docWithPrefix(4096)).has_value());

    // No header anywhere: still rejected, however long the document is.
    const std::vector<std::uint8_t> headerless(2048, static_cast<std::uint8_t>('X'));
    EXPECT_TRUE(det::documentPrecheck(SignatureFormat::Pades, headerless).has_value());
}

// The status comes from the failure's kind and from nothing else: a message
// that merely reads like a PIN error is not one.
TEST(SigningServiceClassifierTest, MapsTheKeysVerdictToItsStatus)
{
    using S = LibreSCRS::Signing::SigningResult::Status;
    using libresign::SignFailureKind;
    namespace det = LibreSCRS::Signing::detail;
    auto kind = [](SignFailureKind k) { return libresign::SigningResult{false, {}, "detail", k}; };
    EXPECT_EQ(S::PinVerificationFailed, det::classifyLibresignError(kind(SignFailureKind::PinFailed)));
    EXPECT_EQ(S::CardBlocked, det::classifyLibresignError(kind(SignFailureKind::PinBlocked)));
    EXPECT_EQ(S::UserCancelled, det::classifyLibresignError(kind(SignFailureKind::UserCancelled)));
    EXPECT_EQ(S::TsaUnreachable, det::classifyLibresignError(kind(SignFailureKind::TsaUnreachable)));

    libresign::SigningResult untyped;
    untyped.errorMessage = "C_Login failed: CKR_PIN_INCORRECT (CKR 0x000000A0)";
    EXPECT_EQ(S::SigningEngineError, det::classifyLibresignError(untyped));
}

// ---------------------------------------------------------------------------
// Bridge translation tests (LibreSCRS::Signing::detail::translatePublicRequestToLibresign)
//
// These cover the exact production mapping that SigningService::sign uses to
// hand a public SigningRequest to libresign — without needing a PC/SC reader
// or a card. The original contact-info end-to-end test re-implemented
// the bridge locally, so a regression in SigningService.cpp would not have
// been detected; this suite guards against that path drifting again.
// ---------------------------------------------------------------------------

TEST(SigningServiceBridgeTranslationTest, ForwardsReasonAndLocationForInvisibleSignature)
{
    // Regression guard for the pre-fix behaviour where reason / location
    // were only forwarded inside `if (visualParams() != nullptr)`. An
    // invisible signature (no visualParams configured) would therefore have
    // silently dropped both PDF signature-dictionary fields even though
    // ISO 32000-1:2008 §12.8.1 defines them as independent of visual
    // appearance. pades_module.cpp emits /Reason and /Location
    // unconditionally on visual.enabled, so the bridge must populate them the
    // same way.
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.format(LibreSCRS::Signing::SignatureFormat::Pades);
    b.level(LibreSCRS::Signing::SignatureLevel::B_B);
    b.reason("Approval");
    b.location("Belgrade");
    // Deliberately NO visualParams(...) — this is the invisible-signature
    // path that exercised the I2 bug.
    auto request = std::move(b).buildForBufferSign();
    ASSERT_FALSE(request.visualParams().has_value());

    libresign::SigningRequest out;
    LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);

    EXPECT_FALSE(out.visual.enabled) << "Invisible signature must not enable visual widget";
    EXPECT_EQ(out.visual.reason, "Approval");
    EXPECT_EQ(out.visual.location, "Belgrade");
}

TEST(SigningServiceBridgeTranslationTest, ForwardsReasonAndLocationForVisibleSignature)
{
    // Companion path: with visualParams configured, reason / location still
    // flow through AND the appearance rectangle is honoured.
    LibreSCRS::Signing::VisualSignatureParams::Builder vb;
    vb.pageIndex(2);
    vb.rect(Rect{10, 20, 300, 80});
    vb.textTemplate("Signed by {signerCN} on {date}");
    auto visual = std::move(vb).build();

    LibreSCRS::Signing::SigningRequest::Builder b;
    b.format(LibreSCRS::Signing::SignatureFormat::Pades);
    b.level(LibreSCRS::Signing::SignatureLevel::B_B);
    b.reason("Approval");
    b.location("Belgrade");
    b.visualParams(std::move(visual));
    auto request = std::move(b).buildForBufferSign();
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
}

TEST(SigningServiceBridgeTranslationTest, MapsFormatLevelPackagingCorrectly)
{
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.documentName("in.xml");
    b.format(LibreSCRS::Signing::SignatureFormat::Xades);
    b.level(LibreSCRS::Signing::SignatureLevel::B_LTA);
    b.packaging(LibreSCRS::Signing::PackagingMode::Detached);
    auto request = std::move(b).buildForBufferSign();

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
    b.format(LibreSCRS::Signing::SignatureFormat::Pades);
    auto request = std::move(b).buildForBufferSign();

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

TEST(SigningRequestBuilderTest, AllowExpiredCertDefaultsFalse)
{
    SigningRequest::Builder b;
    b.format(SignatureFormat::Pades);
    auto req = std::move(b).buildForBufferSign();
    EXPECT_FALSE(req.allowExpiredCert());
}

TEST(SigningRequestBuilderTest, AllowExpiredCertRoundTrips)
{
    SigningRequest::Builder b;
    b.format(SignatureFormat::Pades).allowExpiredCert(true);
    auto req = std::move(b).buildForBufferSign();
    EXPECT_TRUE(req.allowExpiredCert());
}

TEST(SigningRequestBuilderTest, DocumentNameDefaultsEmpty)
{
    SigningRequest::Builder b;
    b.format(SignatureFormat::AsicE);
    auto req = std::move(b).buildForBufferSign();
    EXPECT_TRUE(req.documentName().empty());
}

TEST(SigningRequestBuilderTest, DocumentNameRoundTripsOnBufferSignPath)
{
    SigningRequest::Builder b;
    b.format(SignatureFormat::AsicE).documentName("report.docx");
    auto req = std::move(b).buildForBufferSign();
    EXPECT_EQ(req.documentName(), "report.docx");
}

TEST(SigningRequestBuilderTest, DocumentNameKeepsTheStringItWasGiven)
{
    // The accessor round-trips the raw string the caller supplied; the
    // path-component strip happens at translation time, not in the setter.
    SigningRequest::Builder b;
    b.format(SignatureFormat::Pades).documentName("a/b/override.pdf");
    auto req = std::move(b).buildForBufferSign();
    EXPECT_EQ(req.documentName(), "a/b/override.pdf");
}

TEST(SigningServiceBridgeTranslationTest, ForwardsAllowExpiredCert)
{
    // Default request: bridge must produce allowExpiredCertificate=false.
    {
        LibreSCRS::Signing::SigningRequest::Builder b;
        b.format(LibreSCRS::Signing::SignatureFormat::Pades);
        auto request = std::move(b).buildForBufferSign();

        libresign::SigningRequest out;
        LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);
        EXPECT_FALSE(out.allowExpiredCertificate);
    }
    // Opt-in: bridge must propagate the flag.
    {
        LibreSCRS::Signing::SigningRequest::Builder b;
        b.format(LibreSCRS::Signing::SignatureFormat::Pades);
        b.allowExpiredCert(true);
        auto request = std::move(b).buildForBufferSign();

        libresign::SigningRequest out;
        LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);
        EXPECT_TRUE(out.allowExpiredCertificate);
    }
}

TEST(SigningServiceBridgeTranslationTest, DocumentNameNamesTheInMemoryDocument)
{
    // documentName is the only name the engine gets for the in-memory
    // document: it names the ASiC-E container entry.
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.format(LibreSCRS::Signing::SignatureFormat::AsicE).documentName("report.docx");
    auto request = std::move(b).buildForBufferSign();

    libresign::SigningRequest out;
    LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);

    EXPECT_EQ(out.fileName, "report.docx");
}

TEST(SigningServiceBridgeTranslationTest, DocumentNameStripsPathComponents)
{
    // Only the final path component reaches the engine. A caller cannot inject
    // directory separators (or a "../" traversal) into an ASiC container entry
    // name or a XAdES/JAdES detached reference — the strip is what makes the
    // knob foolproof, and it happens in the bridge so every signature gets it
    // for free.
    auto engineFileNameFor = [](std::string name) {
        LibreSCRS::Signing::SigningRequest::Builder b;
        b.format(LibreSCRS::Signing::SignatureFormat::AsicE).documentName(std::move(name));
        auto request = std::move(b).buildForBufferSign();
        libresign::SigningRequest out;
        LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);
        return out.fileName;
    };

    EXPECT_EQ(engineFileNameFor("a/b/report.docx"), "report.docx");
    EXPECT_EQ(engineFileNameFor("../../etc/passwd"), "passwd");
    EXPECT_EQ(engineFileNameFor("/absolute/path/doc.pdf"), "doc.pdf");
}

TEST(SigningServiceBridgeTranslationTest, DegenerateDocumentNameIsTreatedAsUnset)
{
    // Post-strip degenerate finals are NOT usable entry names: "a/b/" strips to
    // nothing, while "." and ".." survive the strip verbatim — and a "." or
    // ".." ZIP entry name is exactly the class the strip exists to prevent. All
    // are treated as absent, which yields the honest nameless failure rather
    // than a poisoned container entry.
    auto engineFileNameFor = [](std::string name) {
        LibreSCRS::Signing::SigningRequest::Builder b;
        b.format(LibreSCRS::Signing::SignatureFormat::AsicE).documentName(std::move(name));
        auto request = std::move(b).buildForBufferSign();
        libresign::SigningRequest out;
        // Sentinel proves the bridge OVERWRITES fileName rather than leaving a
        // stale value behind.
        out.fileName = "sentinel";
        LibreSCRS::Signing::detail::translatePublicRequestToLibresign(request, out);
        return out.fileName;
    };

    EXPECT_EQ(engineFileNameFor("a/b/"), "");
    EXPECT_EQ(engineFileNameFor("."), "");
    EXPECT_EQ(engineFileNameFor(".."), "");
    EXPECT_EQ(engineFileNameFor("../.."), "");
    EXPECT_EQ(engineFileNameFor("a/b/."), "");
}

// A stub CardPlugin that advertises PKI but whose sign() is never reached —
// we use it to satisfy the SigningService::sign signature. The bridge must
// resolve the signing path through libresign, not by calling cardPlugin.sign().
namespace {
class StubPkiPlugin : public LibreSCRS::TestSupport::SigningStubPlugin
{
public:
    StubPkiPlugin()
        : SigningStubPlugin(LibreSCRS::Plugin::CardCapabilities::PKI |
                            LibreSCRS::Plugin::CardCapabilities::PinManagement)
    {}
};
} // namespace

// ---------------------------------------------------------------------------
// The in-memory sign: span in -> SigningResult::signedDocumentBytes, no file
// touched. The first cases exercise the input seam and the validate+pipeline
// core WITHOUT a PC/SC reader: a detached CardSession drives the path, and
// the assertions land on early returns that fire before any card I/O.
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
    return std::move(b).buildForBufferSign();
}

// The host's way into the service: it reads the card's certificates and signs
// with the first key among them (a plugin reporting none gives a signer with no
// key, which the cases that return before the key is needed never reach).
LibreSCRS::Signing::SigningResult hostSign(LibreSCRS::Signing::SigningService& svc,
                                           const LibreSCRS::Signing::SigningRequest& request,
                                           std::span<const std::uint8_t> input,
                                           LibreSCRS::Auth::CredentialProvider provider,
                                           const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>& plugin,
                                           const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session)
{
    const auto certs = plugin->readCertificates(*session);
    const LibreSCRS::Plugin::CertificateData signer =
        certs.empty() ? LibreSCRS::Plugin::CertificateData{} : certs.front();
    return svc.sign(request, input, std::move(provider), plugin, session, signer,
                    std::span<const LibreSCRS::Plugin::CertificateData>{certs});
}
} // namespace

TEST(SigningServiceBufferSignTest, ReturnsInvalidRequestWhenBufferEmpty)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("test-reader");
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
    auto result = hostSign(*svc, request, emptyInput, provider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::InvalidRequest);
    // No artifact is produced on the error path.
    EXPECT_FALSE(result.signedDocumentBytes.has_value());
}

TEST(SigningServiceBufferSignTest, ReturnsUserCancelledWhenProviderCancels)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("test-reader");
    auto svc = makeBufferSignService();
    ASSERT_NE(svc, nullptr);
    auto request = makeBufferSignRequest();

    // A non-empty buffer drives the pipeline up to PIN collection; the
    // cancelling provider returns before any card I/O.
    auto cancellingProvider = [](const LibreSCRS::Auth::AuthRequirement&) {
        return LibreSCRS::Auth::CredentialResult::cancelled();
    };
    auto plugin = std::make_shared<StubPkiPlugin>();

    // A %PDF--prefixed buffer clears the fail-fast document pre-check so this
    // test still exercises the provider-cancel path (not the InvalidDocument
    // reject path). The bytes need not be a valid PDF — the provider cancels
    // before the deep parse ever runs.
    const std::vector<std::uint8_t> document{'%', 'P', 'D', 'F', '-', '1', '.', '7', '\n', '%', 0xE2, 0xE3};
    auto result = hostSign(*svc, request, std::span<const std::uint8_t>{document}, cancellingProvider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::UserCancelled);
    EXPECT_FALSE(result.signedDocumentBytes.has_value());
}

// B-T / B-LT / B-LTA signatures require a configured TSA. With an empty
// TsaProvider, sign() must surface TsaUnreachable up front rather than letting
// libresign emit a generic SigningEngineError.
TEST(SigningServiceBufferSignTest, TsaUnreachableWhenNonBBLevelAndEmptyTsa)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("test-reader");
    auto svc = makeBufferSignService();
    ASSERT_NE(svc, nullptr);
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.format(LibreSCRS::Signing::SignatureFormat::Pades)
        .level(LibreSCRS::Signing::SignatureLevel::B_T)
        .packaging(LibreSCRS::Signing::PackagingMode::Enveloped);
    const auto request = std::move(b).buildForBufferSign();
    auto plugin = std::make_shared<LibreSCRS::TestSupport::SoftKeyPlugin>();
    const auto pdf = libresign::test::buildTestPdf();
    const std::vector<std::uint8_t> document(pdf.begin(), pdf.end());
    auto provider = [](const LibreSCRS::Auth::AuthRequirement&) {
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{"0000"});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    };

    auto result = hostSign(*svc, request, std::span<const std::uint8_t>{document}, provider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::TsaUnreachable);
    ASSERT_TRUE(result.diagnosticDetail.has_value());
    EXPECT_NE(result.diagnosticDetail->find("TsaProvider"), std::string::npos)
        << "Diagnostic should name TsaProvider; got: " << *result.diagnosticDetail;
    EXPECT_TRUE(plugin->signCalls.empty()) << "nothing is signed without the timestamp the level needs";
}

namespace {

LibreSCRS::Auth::CredentialResult pinProvider(const LibreSCRS::Auth::AuthRequirement&)
{
    std::vector<LibreSCRS::Auth::CredentialEntry> values;
    values.emplace_back("pin", LibreSCRS::Secure::String{"0000"});
    return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
}

// Whether @p pdf carries one PAdES signature, over its /ByteRange, made by the
// key whose certificate is @p signerDer.
bool padesSignatureVerifies(const std::vector<std::uint8_t>& pdf, const std::vector<std::uint8_t>& signerDer)
{
    const std::string text(pdf.begin(), pdf.end());
    const auto at = text.rfind("/ByteRange");
    if (at == std::string::npos)
        return false;
    long range[4] = {};
    if (std::sscanf(text.c_str() + at, "/ByteRange [%ld %ld %ld %ld]", &range[0], &range[1], &range[2], &range[3]) != 4)
        return false;
    std::vector<std::uint8_t> signedBytes(pdf.begin() + range[0], pdf.begin() + range[0] + range[1]);
    signedBytes.insert(signedBytes.end(), pdf.begin() + range[2], pdf.begin() + range[2] + range[3]);
    // The gap between the two ranges is "<hex>": the CMS, zero-padded.
    std::vector<std::uint8_t> cmsDer;
    for (long k = range[1] + 1; k + 1 < range[2] - 1; k += 2) {
        unsigned int byte = 0;
        if (std::sscanf(text.c_str() + k, "%2x", &byte) != 1)
            return false;
        cmsDer.push_back(static_cast<std::uint8_t>(byte));
    }
    const unsigned char* p = cmsDer.data();
    const std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms(
        d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(cmsDer.size())), &CMS_ContentInfo_free);
    const std::unique_ptr<BIO, decltype(&BIO_free)> content(
        BIO_new_mem_buf(signedBytes.data(), static_cast<int>(signedBytes.size())), &BIO_free);
    if (!cms || !content ||
        CMS_verify(cms.get(), nullptr, nullptr, content.get(), nullptr, CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY) != 1)
        return false;
    STACK_OF(X509)* signers = CMS_get0_signers(cms.get());
    if (signers == nullptr || sk_X509_num(signers) != 1)
        return false;
    unsigned char* der = nullptr;
    const int length = i2d_X509(sk_X509_value(signers, 0), &der);
    const bool same = length > 0 && std::vector<std::uint8_t>(der, der + length) == signerDer;
    OPENSSL_free(der);
    sk_X509_free(signers);
    return same;
}

} // namespace

// Document signing is made through the card plugin on the caller's session: the
// plugin's key, held in memory here, makes the document's one signature.
TEST(SigningServiceBufferSignTest, SignsWithoutAnyPkcs11Module)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("test-reader");
    auto svc = makeBufferSignService();
    ASSERT_NE(svc, nullptr);
    auto plugin = std::make_shared<LibreSCRS::TestSupport::SoftKeyPlugin>();
    const auto pdf = libresign::test::buildTestPdf();
    const std::vector<std::uint8_t> document(pdf.begin(), pdf.end());

    auto result =
        hostSign(*svc, makeBufferSignRequest(), std::span<const std::uint8_t>{document}, pinProvider, plugin, session);

    ASSERT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::Ok)
        << result.diagnosticDetail.value_or("no detail");
    ASSERT_TRUE(result.signedDocumentBytes.has_value());
    EXPECT_TRUE(padesSignatureVerifies(*result.signedDocumentBytes, plugin->certDer));
    EXPECT_EQ(plugin->count("pin:deposit"), 1);
    EXPECT_GE(plugin->signCalls.size(), 1U);
}

// A key id longer than a PKCS#15 identifier names no key on any card: the
// request is malformed, and it is refused as such before any PIN is deposited.
TEST(SigningServiceBufferSignTest, OverlongKeyIdIsRefusedBeforeTheCardIsRead)
{
    class CountingPlugin : public LibreSCRS::TestSupport::SoftKeyPlugin
    {
    public:
        std::vector<LibreSCRS::Plugin::CertificateData>
        doReadCertificates(LibreSCRS::SmartCard::CardSession& s) const override
        {
            ++reads;
            return SoftKeyPlugin::doReadCertificates(s);
        }
        mutable int reads = 0;
    };
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("test-reader");
    auto svc = makeBufferSignService();
    ASSERT_NE(svc, nullptr);
    auto plugin = std::make_shared<CountingPlugin>();
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.format(LibreSCRS::Signing::SignatureFormat::Pades)
        .level(LibreSCRS::Signing::SignatureLevel::B_B)
        .packaging(LibreSCRS::Signing::PackagingMode::Enveloped)
        .keyId(std::vector<std::uint8_t>(256, 0x45));
    const auto request = std::move(b).buildForBufferSign();
    const auto pdf = libresign::test::buildTestPdf();
    const std::vector<std::uint8_t> document(pdf.begin(), pdf.end());

    auto result = hostSign(*svc, request, std::span<const std::uint8_t>{document}, pinProvider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::InvalidRequest)
        << result.diagnosticDetail.value_or("no detail");
    EXPECT_EQ(plugin->reads, 1) << "only the host read the certificates";
    EXPECT_TRUE(plugin->events.empty()) << "no PIN is deposited";
    EXPECT_TRUE(plugin->signCalls.empty());
}

// Every format at B-B and B-T (against an in-process time-stamping authority),
// signed and, where the format holds the document it signs, given a second
// signer, through card plugins whose keys sign in memory: Ok in every cell,
// with each plugin's key having signed, is the proof that every format signs
// through the plugin it was handed.
TEST(SigningMatrix, EveryFormatAndLevelSignsAndCosignsWithoutAnyModule)
{
    using LibreSCRS::Signing::PackagingMode;
    using LibreSCRS::Signing::SignatureFormat;
    using LibreSCRS::Signing::SignatureLevel;
    using Status = LibreSCRS::Signing::SigningResult::Status;
    libresign::test::MockTsaServer tsa;
    // The certificate that issued the in-process authority's, as the system
    // store's CA bundle: without it no B-T token would be trusted. The engine's
    // own tests cover the same authority named by a Trusted List.
    struct RestoreCaFile
    {
        std::optional<std::string> saved;
        ~RestoreCaFile()
        {
            if (saved)
                ::setenv("SSL_CERT_FILE", saved->c_str(), 1);
            else
                ::unsetenv("SSL_CERT_FILE");
        }
    };
    const char* previousCaFile = std::getenv("SSL_CERT_FILE");
    const RestoreCaFile restoreCaFile{previousCaFile != nullptr ? std::optional<std::string>(previousCaFile)
                                                                : std::nullopt};
    const std::string caFile = std::string(CMAKE_SOURCE_DIR) + "/test/fixtures/trust/test-tl-signing-cert.pem";
    ::setenv("SSL_CERT_FILE", caFile.c_str(), 1);
    LibreSCRS::Trust::TrustConfig trust;
    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(std::move(trust));
    ASSERT_TRUE(trustResult.has_value());
    const auto svc =
        std::make_shared<LibreSCRS::Signing::SigningService>(*trustResult, LibreSCRS::Signing::staticTsa(tsa.url()));
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("matrix-reader");

    const auto pdf = libresign::test::buildTestPdf();
    const std::vector<std::uint8_t> pdfBytes(pdf.begin(), pdf.end());
    const auto xml = libresign::test::buildTestXml();
    const std::vector<std::uint8_t> xmlBytes(xml.begin(), xml.end());
    const std::vector<std::uint8_t> text{'t', 'h', 'e', ' ', 'c', 'o', 'n', 't', 'r', 'a', 'c', 't'};
    const struct
    {
        SignatureFormat format;
        PackagingMode packaging;
        const std::vector<std::uint8_t>* document;
        bool cosigns;
        const char* name;
    } formats[] = {
        {SignatureFormat::Pades, PackagingMode::Enveloped, &pdfBytes, true, "PAdES"},
        {SignatureFormat::Cades, PackagingMode::Detached, &text, false, "CAdES"},
        {SignatureFormat::Xades, PackagingMode::Detached, &text, false, "XAdES detached"},
        {SignatureFormat::Xades, PackagingMode::Enveloped, &xmlBytes, true, "XAdES enveloped"},
        {SignatureFormat::Jades, PackagingMode::Detached, &text, false, "JAdES detached"},
        {SignatureFormat::Jades, PackagingMode::Enveloped, &text, true, "JAdES enveloped"},
        {SignatureFormat::AsicE, PackagingMode::Enveloped, &text, true, "ASiC-E"},
    };

    for (const auto& f : formats) {
        for (const auto level : {SignatureLevel::B_B, SignatureLevel::B_T}) {
            SCOPED_TRACE(std::string{f.name} + (level == SignatureLevel::B_B ? " B-B" : " B-T"));
            LibreSCRS::Signing::SigningRequest::Builder b;
            b.format(f.format).level(level).packaging(f.packaging).documentName("contract.txt");
            const auto request = std::move(b).buildForBufferSign();

            auto first = std::make_shared<LibreSCRS::TestSupport::SoftKeyPlugin>();
            const auto signedOnce =
                hostSign(*svc, request, std::span<const std::uint8_t>{*f.document}, pinProvider, first, session);
            ASSERT_EQ(signedOnce.status, Status::Ok) << signedOnce.diagnosticDetail.value_or("no detail");
            ASSERT_TRUE(signedOnce.signedDocumentBytes.has_value());
            EXPECT_GE(first->signCalls.size(), 1U);
            if (!f.cosigns)
                continue;

            auto second = std::make_shared<LibreSCRS::TestSupport::SoftKeyPlugin>();
            const auto signedTwice =
                hostSign(*svc, request, *signedOnce.signedDocumentBytes, pinProvider, second, session);
            EXPECT_EQ(signedTwice.status, Status::Ok) << signedTwice.diagnosticDetail.value_or("no detail");
            EXPECT_GE(second->signCalls.size(), 1U);
        }
    }
}

// The card's verdict on the PIN reaches the caller as the status it names, in
// every format: a refused PIN, a blocked one and a cancel. CAdES, PAdES and
// ASiC-E sign through OpenSSL, which sees only that the key did not sign; the
// three statuses must not be lost on that way. The PIN is presented once and
// erased again.
TEST(SigningPinOutcomes, EveryFormatReportsTheCardsVerdict)
{
    using LibreSCRS::Plugin::SignResultOutcome;
    using LibreSCRS::Signing::PackagingMode;
    using LibreSCRS::Signing::SignatureFormat;
    using LibreSCRS::Signing::SignatureLevel;
    using Status = LibreSCRS::Signing::SigningResult::Status;

    auto svc = makeBufferSignService();
    ASSERT_NE(svc, nullptr);
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("pin-outcome-reader");
    const auto pdf = libresign::test::buildTestPdf();
    const std::vector<std::uint8_t> pdfBytes(pdf.begin(), pdf.end());
    const std::vector<std::uint8_t> text{'t', 'h', 'e', ' ', 'c', 'o', 'n', 't', 'r', 'a', 'c', 't'};
    const struct
    {
        SignatureFormat format;
        PackagingMode packaging;
        const std::vector<std::uint8_t>* document;
        const char* name;
    } formats[] = {
        {SignatureFormat::Pades, PackagingMode::Enveloped, &pdfBytes, "PAdES"},
        {SignatureFormat::Cades, PackagingMode::Detached, &text, "CAdES"},
        {SignatureFormat::AsicE, PackagingMode::Enveloped, &text, "ASiC-E"},
        {SignatureFormat::Xades, PackagingMode::Detached, &text, "XAdES"},
        {SignatureFormat::Jades, PackagingMode::Detached, &text, "JAdES"},
    };
    const struct
    {
        SignResultOutcome outcome;
        Status status;
        const char* name;
    } verdicts[] = {
        {SignResultOutcome::PinIncorrect, Status::PinVerificationFailed, "PIN refused"},
        {SignResultOutcome::PinBlocked, Status::CardBlocked, "PIN blocked"},
        {SignResultOutcome::Cancelled, Status::UserCancelled, "cancelled"},
    };

    for (const auto& f : formats) {
        for (const auto& v : verdicts) {
            SCOPED_TRACE(std::string{f.name} + ", " + v.name);
            LibreSCRS::Signing::SigningRequest::Builder b;
            b.format(f.format).level(SignatureLevel::B_B).packaging(f.packaging).documentName("contract.txt");
            const auto request = std::move(b).buildForBufferSign();
            auto plugin = std::make_shared<LibreSCRS::TestSupport::SoftKeyPlugin>();
            plugin->respond = [outcome = v.outcome](const LibreSCRS::TestSupport::SigningStubPlugin::SignCall&) {
                LibreSCRS::Plugin::SignResult r;
                r.outcome = outcome;
                return r;
            };

            const auto result =
                hostSign(*svc, request, std::span<const std::uint8_t>{*f.document}, pinProvider, plugin, session);

            EXPECT_EQ(result.status, v.status) << result.diagnosticDetail.value_or("no detail");
            EXPECT_FALSE(result.signedDocumentBytes.has_value());
            EXPECT_EQ(plugin->signCalls.size(), 1U) << "the PIN is presented once";
            EXPECT_TRUE(plugin->depositedPin.empty()) << "the PIN is erased after the card refused to sign";
        }
    }
}

TEST(SigningResultFactories, InvalidDocumentCarriesStatusAndKey)
{
    using LibreSCRS::Signing::SigningResult;
    auto r = SigningResult::invalidDocument(LibreSCRS::Auth::ErrorKeys::invalidDocument(), "broken pdf xref");
    EXPECT_EQ(r.status, SigningResult::Status::InvalidDocument);
    EXPECT_EQ(r.userMessage.key, "librescrs.error.sign.invalid_document");
    ASSERT_TRUE(r.diagnosticDetail.has_value());
    EXPECT_EQ(*r.diagnosticDetail, "broken pdf xref");
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

// A host that chose the key passes its choice: the service signs with it and
// does not read the card's certificates again, so one signature costs one
// read of them -- the host's.
TEST(SigningServiceBufferSignTest, ChosenSignerIsUsedWithoutReadingTheCardAgain)
{
    class CountingPlugin : public LibreSCRS::TestSupport::SoftKeyPlugin
    {
    public:
        std::vector<LibreSCRS::Plugin::CertificateData>
        doReadCertificates(LibreSCRS::SmartCard::CardSession& s) const override
        {
            ++reads;
            return SoftKeyPlugin::doReadCertificates(s);
        }
        mutable int reads = 0;
    };
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("test-reader");
    auto svc = makeBufferSignService();
    ASSERT_NE(svc, nullptr);
    auto plugin = std::make_shared<CountingPlugin>();
    const auto pdf = libresign::test::buildTestPdf();
    const std::vector<std::uint8_t> document(pdf.begin(), pdf.end());

    // The host's read, and its choice.
    const auto certs = plugin->readCertificates(*session);
    ASSERT_FALSE(certs.empty());
    const auto& signer = certs.front();

    auto result = svc->sign(makeBufferSignRequest(), std::span<const std::uint8_t>{document}, pinProvider, plugin,
                            session, signer, std::span<const LibreSCRS::Plugin::CertificateData>{certs});

    ASSERT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::Ok)
        << result.diagnosticDetail.value_or("no detail");
    ASSERT_TRUE(result.signedDocumentBytes.has_value());
    EXPECT_TRUE(padesSignatureVerifies(*result.signedDocumentBytes, signer.derBytes));
    EXPECT_EQ(plugin->reads, 1) << "only the host read the certificates";
}

namespace {

// How many signatures @p doc carries, read the way each format stores them.
std::size_t signatureCount(LibreSCRS::Signing::SignatureFormat format, const std::vector<std::uint8_t>& doc)
{
    using LibreSCRS::Signing::SignatureFormat;
    const std::string text(doc.begin(), doc.end());
    const auto occurrences = [&text](const std::regex& pattern) {
        return static_cast<std::size_t>(
            std::distance(std::sregex_iterator(text.begin(), text.end(), pattern), std::sregex_iterator()));
    };
    switch (format) {
    case SignatureFormat::Pades:
        return occurrences(std::regex{"/ByteRange"});
    case SignatureFormat::Xades:
        // Opening <ds:SignatureValue ...> tags only: the name also appears in
        // Id attributes and closing tags.
        return occurrences(std::regex{"<([A-Za-z0-9_]+:)?SignatureValue[ >]"});
    case SignatureFormat::Jades:
        return occurrences(std::regex{"\"protected\":"});
    case SignatureFormat::AsicE: {
        // Each entry name is in its local header and in the central directory.
        std::size_t n = 0;
        while (text.find("META-INF/signature00" + std::to_string(n + 1) + ".p7s") != std::string::npos)
            ++n;
        return n;
    }
    case SignatureFormat::Cades: {
        const unsigned char* p = doc.data();
        const std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms(
            d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(doc.size())), &CMS_ContentInfo_free);
        STACK_OF(CMS_SignerInfo)* signers = cms ? CMS_get0_SignerInfos(cms.get()) : nullptr;
        return signers != nullptr ? static_cast<std::size_t>(sk_CMS_SignerInfo_num(signers)) : 0;
    }
    }
    return 0;
}

} // namespace

// A document that already carries a signature is signed again through the
// entry a host uses -- the in-memory sign with the signer it chose -- and the
// result carries both signatures where the format can hold a second one over
// what the document alone gives back. A detached signature does not carry the
// document it signs, and a CMS signature is detached by construction: signing
// one of those again is refused, not answered with a signature over the
// signature's own bytes.
TEST(SigningOverASignature, EveryFormatThroughTheHostsEntry)
{
    using LibreSCRS::Signing::PackagingMode;
    using LibreSCRS::Signing::SignatureFormat;
    using LibreSCRS::Signing::SignatureLevel;
    using Status = LibreSCRS::Signing::SigningResult::Status;

    auto svc = makeBufferSignService();
    ASSERT_NE(svc, nullptr);
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("cosign-reader");
    const auto pdf = libresign::test::buildTestPdf();
    const std::vector<std::uint8_t> pdfBytes(pdf.begin(), pdf.end());
    const auto xml = libresign::test::buildTestXml();
    const std::vector<std::uint8_t> xmlBytes(xml.begin(), xml.end());
    const std::vector<std::uint8_t> text{'t', 'h', 'e', ' ', 'c', 'o', 'n', 't', 'r', 'a', 'c', 't'};
    const struct
    {
        SignatureFormat format;
        PackagingMode packaging;
        const std::vector<std::uint8_t>* document;
        Status second;
        const char* name;
    } cases[] = {
        {SignatureFormat::Pades, PackagingMode::Enveloped, &pdfBytes, Status::Ok, "PAdES"},
        {SignatureFormat::Xades, PackagingMode::Enveloped, &xmlBytes, Status::Ok, "XAdES enveloped"},
        {SignatureFormat::Jades, PackagingMode::Enveloped, &text, Status::Ok, "JAdES enveloped"},
        {SignatureFormat::AsicE, PackagingMode::Enveloped, &text, Status::Ok, "ASiC-E"},
        {SignatureFormat::Xades, PackagingMode::Detached, &text, Status::SigningEngineError, "XAdES detached"},
        {SignatureFormat::Jades, PackagingMode::Detached, &text, Status::SigningEngineError, "JAdES detached"},
        {SignatureFormat::Cades, PackagingMode::Detached, &text, Status::SigningEngineError, "CAdES"},
    };

    for (const auto& c : cases) {
        SCOPED_TRACE(c.name);
        LibreSCRS::Signing::SigningRequest::Builder b;
        b.format(c.format).level(SignatureLevel::B_B).packaging(c.packaging).documentName("contract.txt");
        const auto request = std::move(b).buildForBufferSign();

        auto first = std::make_shared<LibreSCRS::TestSupport::SoftKeyPlugin>();
        const auto firstCerts = first->readCertificates(*session);
        const auto signedOnce = svc->sign(request, std::span<const std::uint8_t>{*c.document}, pinProvider, first,
                                          session, firstCerts.front(), firstCerts);
        ASSERT_EQ(signedOnce.status, Status::Ok) << signedOnce.diagnosticDetail.value_or("no detail");
        ASSERT_TRUE(signedOnce.signedDocumentBytes.has_value());
        ASSERT_EQ(signatureCount(c.format, *signedOnce.signedDocumentBytes), 1U);

        auto second = std::make_shared<LibreSCRS::TestSupport::SoftKeyPlugin>();
        const auto secondCerts = second->readCertificates(*session);
        const auto signedTwice = svc->sign(request, *signedOnce.signedDocumentBytes, pinProvider, second, session,
                                           secondCerts.front(), secondCerts);
        EXPECT_EQ(signedTwice.status, c.second) << signedTwice.diagnosticDetail.value_or("no detail");
        if (c.second == Status::Ok) {
            EXPECT_TRUE(signedTwice.signedDocumentBytes.has_value());
            if (signedTwice.signedDocumentBytes.has_value()) {
                EXPECT_EQ(signatureCount(c.format, *signedTwice.signedDocumentBytes), 2U)
                    << "the first signer's signature and the second's";
            }
            EXPECT_GE(second->signCalls.size(), 1U);
        } else {
            EXPECT_FALSE(signedTwice.signedDocumentBytes.has_value());
            EXPECT_TRUE(second->signCalls.empty()) << "nothing is signed for a refused document";
        }
    }
}

// A request whose time-stamping override names no URL keeps the service's
// authority: an empty override is no override, so a B-T signature still gets
// its timestamp from the authority the service was built with.
TEST(SigningServiceBufferSignTest, OverrideNamingNoUrlKeepsTheServicesAuthority)
{
    libresign::test::MockTsaServer tsa;
    struct RestoreCaFile
    {
        std::optional<std::string> saved;
        ~RestoreCaFile()
        {
            if (saved)
                ::setenv("SSL_CERT_FILE", saved->c_str(), 1);
            else
                ::unsetenv("SSL_CERT_FILE");
        }
    };
    const char* previousCaFile = std::getenv("SSL_CERT_FILE");
    const RestoreCaFile restoreCaFile{previousCaFile != nullptr ? std::optional<std::string>(previousCaFile)
                                                                : std::nullopt};
    const std::string caFile = std::string(CMAKE_SOURCE_DIR) + "/test/fixtures/trust/test-tl-signing-cert.pem";
    ::setenv("SSL_CERT_FILE", caFile.c_str(), 1);
    LibreSCRS::Trust::TrustConfig trust;
    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(std::move(trust));
    ASSERT_TRUE(trustResult.has_value());
    const auto svc =
        std::make_shared<LibreSCRS::Signing::SigningService>(*trustResult, LibreSCRS::Signing::staticTsa(tsa.url()));
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("override-reader");
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.format(LibreSCRS::Signing::SignatureFormat::Pades)
        .level(LibreSCRS::Signing::SignatureLevel::B_T)
        .packaging(LibreSCRS::Signing::PackagingMode::Enveloped)
        .tsaOverride(LibreSCRS::Signing::staticTsa(""));
    const auto request = std::move(b).buildForBufferSign();
    auto plugin = std::make_shared<LibreSCRS::TestSupport::SoftKeyPlugin>();
    const auto pdf = libresign::test::buildTestPdf();
    const std::vector<std::uint8_t> document(pdf.begin(), pdf.end());

    const auto result = hostSign(*svc, request, std::span<const std::uint8_t>{document}, pinProvider, plugin, session);

    EXPECT_EQ(result.status, LibreSCRS::Signing::SigningResult::Status::Ok)
        << result.diagnosticDetail.value_or("no detail");
    EXPECT_TRUE(result.signedDocumentBytes.has_value());
}
