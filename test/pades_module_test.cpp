// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/pades_module.h"
#include "native/pkcs11_token.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"

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

// ---- Adobe §H.3 ingest tolerance (prefix/suffix strip, xref fallback) ----

TEST(PAdESModule, RejectsTrulyCorruptPdf)
{
    // 2 KB of deterministic non-PDF bytes with no "%PDF-" marker anywhere.
    // Must still be rejected at the header check with the same error message
    // as before — no false positives from the H.3 tolerance logic.
    std::vector<uint8_t> junk;
    for (int i = 0; i < 2048; ++i)
        junk.push_back(static_cast<uint8_t>((i * 37 + 11) & 0xFF));

    // Sanity: no %PDF- substring.
    std::string_view jv(reinterpret_cast<const char*>(junk.data()), junk.size());
    ASSERT_EQ(jv.find("%PDF-"), std::string_view::npos);

    PAdESModule pades;
    alignas(Pkcs11Token) char storage[sizeof(Pkcs11Token)]{};
    auto& dummyToken = *reinterpret_cast<Pkcs11Token*>(storage);
    auto result = pades.sign(junk, dummyToken, SignatureLevel::B_B, {}, {});
    ASSERT_FALSE(result.success);
    EXPECT_TRUE(result.errorMessage.find("missing %PDF- header") != std::string::npos) << result.errorMessage;
}

TEST(PAdESModule, AppearanceStreamIsUtf8DrivenFromVisualText)
{
    PAdESModule pades;
    VisualSignatureParams v;
    v.enabled = true;
    v.page = 1;
    v.width = 200;
    v.height = 50;
    v.text = "Potpisao: Hiršl\nDatum: 2026-04-24";

    auto appearance = pades.createAppearanceStream(v);
    std::string s(appearance.contentStream.begin(), appearance.contentStream.end());

    // Must reference the Type0 font /F1 with an auto-fit point size
    // (rc2: layoutVisualSignature picks the size; previously hardcoded
    // to 9pt). Match `/F1 <decimal> Tf` rather than a fixed integer.
    auto tfPos = s.find("/F1 ");
    ASSERT_NE(tfPos, std::string::npos);
    auto tfEnd = s.find(" Tf", tfPos);
    ASSERT_NE(tfEnd, std::string::npos);
    auto sizeStr = s.substr(tfPos + 4, tfEnd - (tfPos + 4));
    double parsedSize = std::stod(sizeStr);
    EXPECT_GE(parsedSize, 6.0);  // floor
    EXPECT_LE(parsedSize, 72.0); // ceiling

    // Text is emitted as hex-string Tj, not PDF literal strings (...) Tj.
    EXPECT_NE(s.find("<"), std::string::npos);
    EXPECT_NE(s.find("> Tj"), std::string::npos);
    // No more legacy "Signed by:" / "Reason:" / "Location:" hardcoded prefixes.
    EXPECT_EQ(s.find("Signed by:"), std::string::npos);
    EXPECT_EQ(s.find("Reason:"), std::string::npos);
    // Two input lines wrap to ≥ 2 Tj calls.
    size_t first = s.find("> Tj");
    ASSERT_NE(first, std::string::npos);
    size_t second = s.find("> Tj", first + 1);
    EXPECT_NE(second, std::string::npos);
}

// ---- Auto-fit emitter tests (rc2 visual-signature FILL_BOX) ----

#include <LibreSCRS/Signing/VisualSignatureLayout.h>

namespace {

// Count occurrences of @p needle in @p hay.
size_t countSubstr(std::string_view hay, std::string_view needle)
{
    size_t count = 0;
    for (size_t pos = 0;;) {
        pos = hay.find(needle, pos);
        if (pos == std::string_view::npos)
            break;
        ++count;
        pos += needle.size();
    }
    return count;
}

VisualSignatureParams makeVisualParams(std::string text)
{
    VisualSignatureParams v;
    v.enabled = true;
    v.page = 1;
    v.width = 200;
    v.height = 50;
    v.text = std::move(text);
    return v;
}

} // namespace

TEST(PAdESModule, AppearanceStreamMultilineTjMatchesLayoutLines)
{
    PAdESModule pades;
    auto v = makeVisualParams("Digitally signed by NEMANJA HIRŠL\nDate: 2026-05-08 14:23:45");
    auto appearance = pades.createAppearanceStream(v);
    std::string s(appearance.contentStream.begin(), appearance.contentStream.end());

    auto layout = LibreSCRS::Signing::layoutVisualSignature(
        v.text, LibreSCRS::Signing::Rect{0, 0, static_cast<int>(v.width), static_cast<int>(v.height)});
    EXPECT_EQ(countSubstr(s, "> Tj"), layout.lines.size());
}

TEST(PAdESModule, AppearanceStreamEmitsClipPathWhenClipped)
{
    PAdESModule pades;
    auto v = makeVisualParams(std::string(200, 'X'));
    auto appearance = pades.createAppearanceStream(v);
    std::string s(appearance.contentStream.begin(), appearance.contentStream.end());
    // Clipping path: "<x y w h> re W n" — assert "re W n" present.
    EXPECT_NE(s.find("re W n"), std::string::npos);
}

TEST(PAdESModule, AppearanceStreamOmitsClipPathWhenNotClipped)
{
    PAdESModule pades;
    auto v = makeVisualParams("Hi");
    auto appearance = pades.createAppearanceStream(v);
    std::string s(appearance.contentStream.begin(), appearance.contentStream.end());
    EXPECT_EQ(s.find("re W n"), std::string::npos);
}

TEST(PAdESModule, AppearanceStreamFontSizeMatchesLayout)
{
    PAdESModule pades;
    auto v = makeVisualParams("Sample text for layout");
    auto appearance = pades.createAppearanceStream(v);
    std::string s(appearance.contentStream.begin(), appearance.contentStream.end());

    auto layout = LibreSCRS::Signing::layoutVisualSignature(
        v.text, LibreSCRS::Signing::Rect{0, 0, static_cast<int>(v.width), static_cast<int>(v.height)});
    char buf[32];
    std::snprintf(buf, sizeof(buf), "/F1 %.2f Tf", static_cast<double>(layout.fontSize));
    EXPECT_NE(s.find(buf), std::string::npos) << "stream:\n" << s;
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
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
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
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
    auto pdf = testPdfBytes();
    PAdESModule pades;

    VisualSignatureParams visual;
    visual.enabled = true;
    visual.page = 1;
    visual.x = 50;
    visual.y = 50;
    visual.width = 200;
    visual.height = 60;
    visual.text = "Signed by: Test Signer\nApproval\nBelgrade";
    visual.reason = "Approval";
    visual.location = "Belgrade";

    auto result = pades.sign(pdf, token, SignatureLevel::B_B, {}, visual);
    ASSERT_TRUE(result.success) << result.errorMessage;

    // Should contain visual signature elements
    ASSERT_TRUE(containsString(result.signedDocument, "/Type /XObject"));
    ASSERT_TRUE(containsString(result.signedDocument, "/Subtype /Form"));
    // New Type0 font machinery replaces the old Helvetica Type1 font.
    ASSERT_TRUE(containsString(result.signedDocument, "/Subtype /Type0"));
    ASSERT_TRUE(containsString(result.signedDocument, "/Subtype /CIDFontType2"));
    ASSERT_TRUE(containsString(result.signedDocument, "/FontFile2"));
    ASSERT_FALSE(containsString(result.signedDocument, "/BaseFont /Helvetica"));
}

TEST_F(PAdESModuleSoftHSMTest, SignPdf_BB_WithUnicodeVisual)
{
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
    auto pdf = testPdfBytes();
    PAdESModule pades;

    VisualSignatureParams v;
    v.enabled = true;
    v.page = -1;
    v.x = 50;
    v.y = 50;
    v.width = 200;
    v.height = 50;
    v.text = "Potpisao: Hiršl Ćirković\nDatum: 2026-04-24";

    SigningRequest req;
    req.document = pdf;
    req.format = SignatureFormat::PAdES;
    req.level = SignatureLevel::B_B;
    req.visual = v;

    auto result = pades.sign(req.document, token, SignatureLevel::B_B, {}, req.visual);
    ASSERT_TRUE(result.success) << result.errorMessage;

    auto& out = result.signedDocument;
    // Output must contain the Type0 font machinery.
    ASSERT_TRUE(containsString(out, "/Subtype /Type0"));
    ASSERT_TRUE(containsString(out, "/Subtype /CIDFontType2"));
    ASSERT_TRUE(containsString(out, "/FontFile2"));
    ASSERT_TRUE(containsString(out, "/ToUnicode"));
    // Must NOT contain the old Type1 Helvetica font anymore.
    ASSERT_FALSE(containsString(out, "/BaseFont /Helvetica"));
}

TEST_F(PAdESModuleSoftHSMTest, SignPdf_BB_InvisibleSignature)
{
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
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
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
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
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
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
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
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

// ---- Adobe §H.3 ingest tolerance ----
//
// Helpers for the wrapped-PDF test cases below (see Acrobat Implementation
// Notes §H.3 and the mirrored documentation in developer-guide/
// signing-integration).

namespace {

static std::string kWebFormPrefix = "------WebKitFormBoundaryABCDEFGHIJKLMNOP\r\n"
                                    "Content-Disposition: form-data; name=\"file\"; filename=\"doc.pdf\"\r\n"
                                    "Content-Type: application/pdf\r\n\r\n";

static std::string kWebFormSuffix = "\r\n------WebKitFormBoundaryABCDEFGHIJKLMNOP--\r\n";

static std::vector<uint8_t> wrapPdfWithForm(const std::vector<uint8_t>& inner, size_t bumpStartxrefBy)
{
    std::vector<uint8_t> innerCopy = inner;
    if (bumpStartxrefBy != 0) {
        std::string s(innerCopy.begin(), innerCopy.end());
        size_t sx = s.rfind("startxref");
        if (sx != std::string::npos) {
            size_t numStart = sx + std::string("startxref").size();
            while (numStart < s.size() && (s[numStart] == '\n' || s[numStart] == '\r' || s[numStart] == ' '))
                ++numStart;
            size_t numEnd = numStart;
            while (numEnd < s.size() && s[numEnd] >= '0' && s[numEnd] <= '9')
                ++numEnd;
            int64_t original = std::stoll(std::string(s.begin() + numStart, s.begin() + numEnd));
            std::string replacement = std::to_string(original + static_cast<int64_t>(bumpStartxrefBy));
            s.replace(numStart, numEnd - numStart, replacement);
            innerCopy.assign(s.begin(), s.end());
        }
    }

    std::vector<uint8_t> out;
    out.reserve(kWebFormPrefix.size() + innerCopy.size() + kWebFormSuffix.size());
    out.insert(out.end(), kWebFormPrefix.begin(), kWebFormPrefix.end());
    out.insert(out.end(), innerCopy.begin(), innerCopy.end());
    out.insert(out.end(), kWebFormSuffix.begin(), kWebFormSuffix.end());
    return out;
}

} // namespace

TEST_F(PAdESModuleSoftHSMTest, SignsWrappedPdf_InnerRelativeStartxref)
{
    // Multipart/form-data wrapper around a clean PDF. startxref value inside
    // the inner PDF is unchanged — after prefix/suffix strip the offset is
    // already correct, no fallback scan needed.
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
    auto inner = testPdfBytes();
    auto wrapped = wrapPdfWithForm(inner, /*bumpStartxrefBy=*/0);

    // Sanity: %PDF- is not at byte 0 of the wrapped buffer.
    std::string_view wv(reinterpret_cast<const char*>(wrapped.data()), wrapped.size());
    ASSERT_NE(wv.find("%PDF-"), std::string_view::npos);
    ASSERT_GT(wv.find("%PDF-"), 0u);

    PAdESModule pades;
    auto result = pades.sign(wrapped, token, SignatureLevel::B_B, {}, {});
    ASSERT_TRUE(result.success) << result.errorMessage;

    // Signed output must begin with %PDF- (prefix was stripped before signing).
    ASSERT_GE(result.signedDocument.size(), 5u);
    EXPECT_EQ(std::string(result.signedDocument.begin(), result.signedDocument.begin() + 5), "%PDF-");
    EXPECT_TRUE(containsString(result.signedDocument, "/Type /Sig"));
}

TEST_F(PAdESModuleSoftHSMTest, SignsWrappedPdf_OuterRelativeStartxref)
{
    // Same wrapper, but the inner PDF's startxref value has been bumped by
    // the prefix length to simulate a generator that wrote outer-relative
    // offsets. After strip, the stored offset overruns; the fallback xref
    // keyword scan must recover.
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
    auto inner = testPdfBytes();
    auto wrapped = wrapPdfWithForm(inner, /*bumpStartxrefBy=*/kWebFormPrefix.size());

    PAdESModule pades;
    auto result = pades.sign(wrapped, token, SignatureLevel::B_B, {}, {});
    ASSERT_TRUE(result.success) << result.errorMessage;

    ASSERT_GE(result.signedDocument.size(), 5u);
    EXPECT_EQ(std::string(result.signedDocument.begin(), result.signedDocument.begin() + 5), "%PDF-");
    EXPECT_TRUE(containsString(result.signedDocument, "/Type /Sig"));
}

#else
TEST(PAdESModule, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif
