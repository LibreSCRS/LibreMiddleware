// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "libresign/native/pades_module.h"
#include "libresign/native/pkcs11_token.h"
#include "signing_test_support/signing_test_support.h"
#include "libresign/signing_service.h"

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace libresign;

// ---- Helpers ----

static std::vector<uint8_t> testPdfBytes()
{
    auto s = libresign::test::buildTestPdf();
    return {s.begin(), s.end()};
}

// Check if a byte sequence contains a substring.
static bool containsString(const std::vector<uint8_t>& data, std::string_view needle)
{
    std::string_view sv(reinterpret_cast<const char*>(data.data()), data.size());
    return sv.find(needle) != std::string_view::npos;
}

// ---- Tests that don't require a PKCS#11 token ----

TEST(PAdESModule, MinimalPdfIsValid)
{
    auto pdf = testPdfBytes();
    ASSERT_GE(pdf.size(), 5u);
    std::string header(pdf.begin(), pdf.begin() + 5);
    ASSERT_EQ(header, "%PDF-");
    // Verify it has the required structural elements
    ASSERT_TRUE(containsString(pdf, "/Catalog"));
    ASSERT_TRUE(containsString(pdf, "/Pages"));
    ASSERT_TRUE(containsString(pdf, "startxref"));
    ASSERT_TRUE(containsString(pdf, "%%EOF"));
}

TEST(PAdESModule, RejectsEmptyInput)
{
    PAdESModule pades;
    std::vector<uint8_t> empty;
    // Token is never touched — sign() returns early on invalid PDF.
    // Use aligned storage to create a valid reference without constructing a real object.
    alignas(Pkcs11Token) char storage[sizeof(Pkcs11Token)]{};
    auto& dummyToken = *reinterpret_cast<Pkcs11Token*>(storage);
    auto result = pades.sign(empty, dummyToken, SignatureLevel::B_B, {}, {});
    ASSERT_FALSE(result.success);
    EXPECT_TRUE(result.errorMessage.find("too small") != std::string::npos);
}

TEST(PAdESModule, RejectsNonPdf)
{
    PAdESModule pades;
    std::vector<uint8_t> notPdf = {'N', 'O', 'T', 'P', 'D', 'F'};
    alignas(Pkcs11Token) char storage[sizeof(Pkcs11Token)]{};
    auto& dummyToken = *reinterpret_cast<Pkcs11Token*>(storage);
    auto result = pades.sign(notPdf, dummyToken, SignatureLevel::B_B, {}, {});
    ASSERT_FALSE(result.success);
    EXPECT_TRUE(result.errorMessage.find("not a valid PDF") != std::string::npos);
}

// ---- SoftHSM-based tests ----

class PAdESModuleSoftHSMTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
    }
    const char* softHsmPath = nullptr;
};

TEST_F(PAdESModuleSoftHSMTest, SignPdf_BB)
{
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", 0);
    auto pdf = testPdfBytes();
    PAdESModule pades;

    auto result = pades.sign(pdf, token, SignatureLevel::B_B, {}, {});
    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.signedDocument.empty());

    // Output should start with %PDF
    std::string hdr(result.signedDocument.begin(), result.signedDocument.begin() + 5);
    ASSERT_EQ(hdr, "%PDF-");

    // Should be larger than original (incremental update appended)
    ASSERT_GT(result.signedDocument.size(), pdf.size());

    // Should contain PAdES-specific markers
    ASSERT_TRUE(containsString(result.signedDocument, "/Type /Sig"));
    ASSERT_TRUE(containsString(result.signedDocument, "/SubFilter /ETSI.CAdES.detached"));
    ASSERT_TRUE(containsString(result.signedDocument, "/ByteRange"));
    ASSERT_TRUE(containsString(result.signedDocument, "/Contents <"));

    // Should end with %%EOF
    std::string_view tail(
        reinterpret_cast<const char*>(result.signedDocument.data() + result.signedDocument.size() - 6), 6);
    EXPECT_EQ(tail, "%%EOF\n");
}

TEST_F(PAdESModuleSoftHSMTest, SignPdf_BB_WithVisual)
{
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", 0);
    auto pdf = testPdfBytes();
    PAdESModule pades;

    VisualSignatureParams visual;
    visual.enabled = true;
    visual.page = 1;
    visual.x = 50;
    visual.y = 50;
    visual.width = 200;
    visual.height = 60;
    visual.signerName = "Test Signer";
    visual.reason = "Approval";
    visual.location = "Belgrade";

    auto result = pades.sign(pdf, token, SignatureLevel::B_B, {}, visual);
    ASSERT_TRUE(result.success) << result.errorMessage;

    // Should contain visual signature elements
    ASSERT_TRUE(containsString(result.signedDocument, "/Type /XObject"));
    ASSERT_TRUE(containsString(result.signedDocument, "/Subtype /Form"));
    ASSERT_TRUE(containsString(result.signedDocument, "/BaseFont /Helvetica"));
    ASSERT_TRUE(containsString(result.signedDocument, "Signed by: Test Signer"));
}

TEST_F(PAdESModuleSoftHSMTest, SignPdf_BB_InvisibleSignature)
{
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", 0);
    auto pdf = testPdfBytes();
    PAdESModule pades;

    VisualSignatureParams noVisual; // enabled = false by default

    auto result = pades.sign(pdf, token, SignatureLevel::B_B, {}, noVisual);
    ASSERT_TRUE(result.success) << result.errorMessage;

    // Should have invisible rect
    ASSERT_TRUE(containsString(result.signedDocument, "/Rect [0 0 0 0]"));
    // Should NOT contain appearance stream
    ASSERT_FALSE(containsString(result.signedDocument, "/Type /XObject"));
}

TEST_F(PAdESModuleSoftHSMTest, SignedPdfHasValidIncrementalUpdate)
{
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", 0);
    auto pdf = testPdfBytes();
    PAdESModule pades;

    auto result = pades.sign(pdf, token, SignatureLevel::B_B, {}, {});
    ASSERT_TRUE(result.success) << result.errorMessage;

    // The original PDF content should be preserved at the start
    ASSERT_GE(result.signedDocument.size(), pdf.size());
    EXPECT_TRUE(std::equal(pdf.begin(), pdf.end(), result.signedDocument.begin()));

    // Should have a second xref + trailer (incremental update)
    std::string_view sv(reinterpret_cast<const char*>(result.signedDocument.data()), result.signedDocument.size());
    // Count "xref" occurrences (should be at least 2)
    size_t xrefCount = 0;
    size_t pos = 0;
    while ((pos = sv.find("xref\n", pos)) != std::string_view::npos) {
        ++xrefCount;
        ++pos;
    }
    EXPECT_GE(xrefCount, 2u) << "Expected at least 2 xref tables (original + incremental)";

    // New trailer should have /Prev pointing to original xref
    ASSERT_TRUE(containsString(result.signedDocument, "/Prev"));
}

TEST_F(PAdESModuleSoftHSMTest, ContentsHexIsNonZero)
{
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", 0);
    auto pdf = testPdfBytes();
    PAdESModule pades;

    auto result = pades.sign(pdf, token, SignatureLevel::B_B, {}, {});
    ASSERT_TRUE(result.success) << result.errorMessage;

    // Find /Contents < and verify it has non-zero hex content
    std::string_view sv(reinterpret_cast<const char*>(result.signedDocument.data()), result.signedDocument.size());
    size_t contentsPos = sv.find("/Contents <");
    ASSERT_NE(contentsPos, std::string_view::npos);

    size_t hexStart = contentsPos + 11;
    // The CMS signature should produce non-zero hex at the beginning
    std::string_view hexView = sv.substr(hexStart, 16);
    EXPECT_NE(hexView, "0000000000000000") << "Contents hex appears to be all zeros (CMS not embedded)";
}

TEST_F(PAdESModuleSoftHSMTest, ByteRangeIsFilledIn)
{
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", 0);
    auto pdf = testPdfBytes();
    PAdESModule pades;

    auto result = pades.sign(pdf, token, SignatureLevel::B_B, {}, {});
    ASSERT_TRUE(result.success) << result.errorMessage;

    // Find /ByteRange and check it has real numbers, not all spaces
    std::string_view sv(reinterpret_cast<const char*>(result.signedDocument.data()), result.signedDocument.size());
    size_t brPos = sv.find("/ByteRange [0 ");
    ASSERT_NE(brPos, std::string_view::npos);

    // Extract the ByteRange value
    size_t brEnd = sv.find(']', brPos);
    ASSERT_NE(brEnd, std::string_view::npos);
    auto brValue = sv.substr(brPos + 12, brEnd - brPos - 12);

    // Should contain at least 3 non-zero numbers
    // Parse: [0 N1 N2 N3]
    EXPECT_TRUE(brValue.find_first_of("123456789") != std::string_view::npos)
        << "ByteRange appears to not have been filled in: " << brValue;
}

#else
TEST(PAdESModule, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif
