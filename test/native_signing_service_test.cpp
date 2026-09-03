// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/native_signing_service.h"
#include "native/pkcs11_module_manager.h"
#include "signing_test_support/mock_trusted_list_server.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"
#include "types.h"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

using namespace libresign;

// Service-level policy tests. The format modules have their own SoftHSM2
// fixtures, but those construct a Pkcs11Token directly and call the module,
// which skips everything NativeSigningService applies around the modules.
// This fixture drives the service entry points themselves via the SoftHSM2
// slot seam (setTestSlotId) so the shared policy is covered on BOTH of them.
class NativeSigningServiceSoftHSMTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
        Pkcs11ModuleManager probe;
        auto slot = libresign::test::findSoftHsmTestSlot(probe.acquire(softHsmPath));
        if (!slot)
            GTEST_SKIP() << "SoftHSM2 token '" << libresign::test::kSoftHsmTokenLabel << "' not initialised";
        service.setTestSlotId(*slot);
    }

    static SigningRequest pdfRequest(bool allowExpired)
    {
        SigningRequest req;
        auto pdf = libresign::test::buildTestPdf();
        req.document = std::vector<uint8_t>(pdf.begin(), pdf.end());
        req.fileName = "test.pdf";
        req.format = SignatureFormat::Pades;
        req.level = SignatureLevel::B_B;
        req.allowExpiredCertificate = allowExpired;
        return req;
    }

    /// Sign at B-B with the valid signer and return the signed PDF that the
    /// append cases start from.
    std::vector<uint8_t> priorSignature()
    {
        auto result = service.sign(pdfRequest(false), softHsmPath, libresign::as_pin("1234"), "test-key", "");
        EXPECT_TRUE(result.success) << result.errorMessage;
        return result.signedDocument;
    }

    /// Build a request around arbitrary bytes and an explicitly chosen format.
    /// The dispatcher cases below turn on exactly that pair.
    static SigningRequest bytesRequest(std::string_view payload, SignatureFormat format, const char* fileName)
    {
        SigningRequest req;
        req.document = std::vector<uint8_t>(payload.begin(), payload.end());
        req.fileName = fileName;
        req.format = format;
        req.packaging = SignaturePackaging::Detached;
        req.level = SignatureLevel::B_B;
        return req;
    }

    /// A CSV whose first byte is the ASCII digit zero — the same octet as the
    /// DER SEQUENCE tag a CMS starts with. Nothing else about it is a
    /// signature.
    static constexpr std::string_view kAsciiZeroCsv = "0,name,amount\n0,first,12\n1,second,34\n";

    const char* softHsmPath = nullptr;
    NativeSigningService service;
};

// Harness pin: the slot seam actually reaches the service entry point, so a
// failure in any test below is a policy result and not a fixture that never
// opened the token.
TEST_F(NativeSigningServiceSoftHSMTest, SignsAtBaselineWithValidSigner)
{
    auto result = service.sign(pdfRequest(false), softHsmPath, libresign::as_pin("1234"), "test-key", "");
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());
}

// Control for the append case below: expiry enforcement on the sign() entry
// point is the behaviour that already existed, and it must keep holding.
TEST_F(NativeSigningServiceSoftHSMTest, SignRejectsExpiredSignerByDefault)
{
    auto result = service.sign(pdfRequest(false), softHsmPath, libresign::as_pin("1234"),
                               libresign::test::kSoftHsmExpiredKeyLabel, "");
    EXPECT_FALSE(result.success);
    ASSERT_TRUE(result.failureKind.has_value()) << result.errorMessage;
    EXPECT_EQ(*result.failureKind, SignFailureKind::PolicyViolation) << result.errorMessage;
}

// Adding a signer to an already-signed document is signing. The default
// policy refuses an expired signer certificate, and the entry point the
// caller happens to use cannot decide whether that policy applies —
// sign() itself redirects an already-signed XAdES/JAdES/ASiC-E input here,
// so a policy that lived only in sign() would be silently dropped by the
// service's own dispatch.
TEST_F(NativeSigningServiceSoftHSMTest, AppendSignerRejectsExpiredSignerByDefault)
{
    auto prior = priorSignature();
    ASSERT_FALSE(prior.empty());

    auto result = service.appendSigner(pdfRequest(false), prior, {}, libresign::as_pin("1234"), softHsmPath,
                                       libresign::test::kSoftHsmExpiredKeyLabel, "");
    EXPECT_FALSE(result.success);
    ASSERT_TRUE(result.failureKind.has_value()) << result.errorMessage;
    EXPECT_EQ(*result.failureKind, SignFailureKind::PolicyViolation) << result.errorMessage;
}

// The opt-in is the user-consent gate, not a sign()-only escape hatch: with
// it set the append must go through, otherwise the fix above would have
// turned a fail-open into an unconditional refusal.
TEST_F(NativeSigningServiceSoftHSMTest, AppendSignerHonoursExpiredCertificateOptIn)
{
    auto prior = priorSignature();
    ASSERT_FALSE(prior.empty());

    auto result = service.appendSigner(pdfRequest(true), prior, {}, libresign::as_pin("1234"), softHsmPath,
                                       libresign::test::kSoftHsmExpiredKeyLabel, "");
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());
}

// A document is not a signature because of one byte. The leading octet of a
// DER SEQUENCE is 0x30, which is also the ASCII digit zero, so a CSV or a log
// that starts with it was being refused as an already-signed CMS — for every
// format the caller could ask for, including the two the guess did not name.
TEST_F(NativeSigningServiceSoftHSMTest, SignsDocumentWhoseFirstByteIsAsciiZero)
{
    for (auto format : {SignatureFormat::Cades, SignatureFormat::AsicE, SignatureFormat::Xades}) {
        auto result = service.sign(bytesRequest(kAsciiZeroCsv, format, "rows.csv"), softHsmPath,
                                   libresign::as_pin("1234"), "test-key", "");
        EXPECT_TRUE(result.success) << "format " << static_cast<int>(format) << ": " << result.errorMessage;
        EXPECT_FALSE(result.signedDocument.empty()) << "format " << static_cast<int>(format);
    }
}

// The same defect on the JSON arm: an ordinary payload carrying the word
// "signatures" reads as a JWS to the probe. The caller asked for ASiC-E, and
// the caller's answer is the one that counts.
TEST_F(NativeSigningServiceSoftHSMTest, SignsJsonContainingTheWordSignaturesAtAsicE)
{
    constexpr std::string_view json = R"({"kind":"report","signatures":["none collected yet"]})";
    auto result = service.sign(bytesRequest(json, SignatureFormat::AsicE, "report.json"), softHsmPath,
                               libresign::as_pin("1234"), "test-key", "");
    EXPECT_TRUE(result.success) << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());
}

// The guard on the other side. A genuine detached CMS sent as CAdES carries no
// payload to sign alongside, so it must still be refused with a pointer at the
// append API. If this ever turns green because nothing refuses any more, the
// dispatcher fix has gone too far.
TEST_F(NativeSigningServiceSoftHSMTest, RefusesRealDetachedCmsWhenCadesWasRequested)
{
    auto signed_ = service.sign(bytesRequest("payload for a detached CMS\n", SignatureFormat::Cades, "payload.txt"),
                                softHsmPath, libresign::as_pin("1234"), "test-key", "");
    ASSERT_TRUE(signed_.success) << signed_.errorMessage;
    ASSERT_FALSE(signed_.signedDocument.empty());

    SigningRequest req;
    req.document = signed_.signedDocument;
    req.fileName = "prior.p7s";
    req.format = SignatureFormat::Cades;
    req.packaging = SignaturePackaging::Detached;
    req.level = SignatureLevel::B_B;

    auto result = service.sign(req, softHsmPath, libresign::as_pin("1234"), "test-key", "");
    EXPECT_FALSE(result.success);
    ASSERT_TRUE(result.failureKind.has_value()) << result.errorMessage;
    EXPECT_EQ(*result.failureKind, SignFailureKind::InvalidInput) << result.errorMessage;
    EXPECT_NE(result.errorMessage.find("appendSigner"), std::string::npos) << result.errorMessage;
}

// ---------------------------------------------------------------------------
// Deferred Trusted List fetching.
//
// The public configuration says a non-eager list is fetched at sign time, only
// when a signature level actually requires the anchor. These two cases pin both
// halves of that sentence: one request when a long-term level needs anchors,
// none when a basic one does not. The second is as load-bearing as the first —
// without it, "fetch on every signature" passes.
// ---------------------------------------------------------------------------
class LazyTrustedListTest : public NativeSigningServiceSoftHSMTest
{
protected:
    void SetUp() override
    {
        NativeSigningServiceSoftHSMTest::SetUp();
        if (::testing::Test::IsSkipped())
            return;
        // A cache directory shared with another run would serve the list off
        // disk and drive the fetch count to zero for a reason that has nothing
        // to do with the code under test.
        cacheDir = std::filesystem::temp_directory_path() /
                   ("librescrs-lazy-tl-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
        std::filesystem::remove_all(cacheDir);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(cacheDir, ec);
    }

    /// Configure the service with exactly one LAZY trusted list served on
    /// loopback. Both non-default fields matter: `eager` defaults to true, and
    /// without `signingCertPath` the loopback URL resolves to no verification
    /// certificate at all, so the list is refused after the fetch and a
    /// fetch-count assertion would pass over a completely broken path.
    void configureWithLazyList(libresign::test::MockTrustedListServer& server)
    {
        TrustConfig cfg;
        TrustedListEntry entry;
        entry.url = server.url();
        entry.isLotl = false;
        entry.eager = false;
        entry.signingCertPath = std::string(CMAKE_SOURCE_DIR) + "/test/fixtures/trust/test-tl-signing-cert.pem";
        cfg.trustedLists.push_back(entry);
        cfg.cacheDirectory = cacheDir.string();

        service.setAnchorEmitter([this](std::vector<LibreSCRS::Trust::TrustAnchor> anchors, std::string) {
            anchorsEmitted += static_cast<int>(anchors.size());
        });
        service.configure(cfg);
    }

    std::filesystem::path cacheDir;
    int anchorsEmitted = 0;
    static inline int counter = 0;
};

TEST_F(LazyTrustedListTest, LazyTrustedListIsFetchedWhenALevelNeedsIt)
{
    libresign::test::MockTrustedListServer server(std::string(CMAKE_SOURCE_DIR) +
                                                  "/test/fixtures/trust/synthetic-tl.xml");
    configureWithLazyList(server);
    ASSERT_EQ(server.servedCount(), 0) << "configure() must leave a lazy source alone";

    auto req = pdfRequest(false);
    req.level = SignatureLevel::B_LT;
    auto result = service.sign(req, softHsmPath, libresign::as_pin("1234"), "test-key", "");

    EXPECT_EQ(server.servedCount(), 1) << "a long-term level must fetch the deferred list exactly once";
    // Not the same claim as the one above: a GET that arrives and is then
    // refused at verification leaves the anchor set empty and the count at one.
    EXPECT_GE(anchorsEmitted, 1) << "the list was fetched but never verified and parsed";

    // The provisioned signer is self-signed and this list does not name its
    // issuer, so the refusal is the chain gate working on anchors that really
    // were fetched — not the old walk-past over an empty set. Before this
    // change the same request died later, on an unrelated missing TSA.
    //
    // The message is the discriminating assertion, not the kind: this refusal
    // is reported as the generic EngineError even though
    // SignFailureKind::CertificateChainIncomplete exists and describes it. That
    // is pre-existing and is left alone here — remapping it is a wire-visible
    // change with four mirrors to move, and this change is about the fetch.
    EXPECT_FALSE(result.success);
    ASSERT_TRUE(result.failureKind.has_value()) << result.errorMessage;
    EXPECT_EQ(*result.failureKind, SignFailureKind::EngineError) << result.errorMessage;
    EXPECT_NE(result.errorMessage.find("issuing CA was not found"), std::string::npos) << result.errorMessage;
}

TEST_F(LazyTrustedListTest, LazyTrustedListIsNotFetchedForBasicLevel)
{
    libresign::test::MockTrustedListServer server(std::string(CMAKE_SOURCE_DIR) +
                                                  "/test/fixtures/trust/synthetic-tl.xml");
    configureWithLazyList(server);

    auto result = service.sign(pdfRequest(false), softHsmPath, libresign::as_pin("1234"), "test-key", "");
    EXPECT_TRUE(result.success) << result.errorMessage;
    EXPECT_EQ(server.servedCount(), 0) << "a basic signature needs no anchor and must make no request";
}

#endif
