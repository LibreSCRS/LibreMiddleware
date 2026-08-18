// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/native_signing_service.h"
#include "native/pkcs11_module_manager.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"
#include "types.h"

#include <string>
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

#else
TEST(NativeSigningService, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif
