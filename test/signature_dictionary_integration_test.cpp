// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Integration test for the public SigningRequest reason and location being
// forwarded end-to-end into the PDF signature dictionary as /Reason and
// /Location: public SigningRequest builder → libresign internal
// VisualSignatureParams → PAdESModule → PDF dict.

#include <gtest/gtest.h>

#include <LibreSCRS/Signing/Enums.h>
#include <LibreSCRS/Signing/SigningRequest.h>

#include "native/pades_module.h"
#include "signing_keys.h"
#include "signing_service.h"
#include "signing_test_support/signing_test_support.h"

#include <string>
#include <string_view>
#include <vector>

using namespace LibreSCRS::Signing;

namespace {

std::vector<uint8_t> testPdfBytes()
{
    auto s = libresign::test::buildTestPdf();
    return {s.begin(), s.end()};
}

bool containsBytes(const std::vector<uint8_t>& haystack, std::string_view needle)
{
    std::string_view sv(reinterpret_cast<const char*>(haystack.data()), haystack.size());
    return sv.find(needle) != std::string_view::npos;
}

} // namespace

// The public SigningRequest::Builder stores reason() and location() and the
// request reads them back untouched; no signing key is needed.
TEST(SigningSignatureDictionary, PublicBuilderRoundtripsReasonAndLocation)
{
    SigningRequest::Builder b;
    b.format(SignatureFormat::Pades);
    b.reason("Approval");
    b.location("Belgrade");

    auto req = std::move(b).buildForBufferSign();
    EXPECT_EQ(req.reason(), "Approval");
    EXPECT_EQ(req.location(), "Belgrade");
}

// A signed PDF carries /Reason and /Location in the signature dictionary when
// the public SigningRequest carries them, for an invisible signature too.
//
// A real CMS signature, made with the in-memory test key, produces a complete
// PDF with a populated ByteRange.
TEST(SigningSignatureDictionaryInMemoryKeyTest, SignedPdfCarriesReasonAndLocationInSignatureDict)
{
    // 1. Build the public SigningRequest.
    SigningRequest::Builder builder;
    builder.format(SignatureFormat::Pades);
    builder.level(SignatureLevel::B_B);
    builder.reason("Approval");
    builder.location("Belgrade");

    auto request = std::move(builder).buildForBufferSign();

    // 2. Replicate the SigningService → libresign bridge translation for
    //    the fields that flow through VisualSignatureParams
    //    (lv.reason/.location = request.<field>()), keeping the test honest
    //    about the exact wire the production path uses.
    libresign::VisualSignatureParams lv;
    lv.enabled = false; // invisible sig: the dictionary fields are independent of appearance
    lv.reason = request.reason();
    lv.location = request.location();

    // 3. Sign via PAdESModule with the in-memory test key.
    libresign::test::SoftSigningKey token(libresign::test::validSignerKey());
    auto pdf = testPdfBytes();
    libresign::PAdESModule pades;

    auto result = pades.sign(pdf, token, libresign::SignatureLevel::B_B, {}, lv);
    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.signedDocument.empty());

    // 4. The PDF literal-string syntax wraps each value in parentheses
    //    (ISO 32000-1:2008 §7.3.4.2). The pairings are unique to this
    //    payload and cannot appear in the unsigned PDF content.
    EXPECT_TRUE(containsBytes(result.signedDocument, "/Reason (Approval)"));
    EXPECT_TRUE(containsBytes(result.signedDocument, "/Location (Belgrade)"));
    EXPECT_FALSE(containsBytes(result.signedDocument, "/ContactInfo"))
        << "no request field fills /ContactInfo, so the dictionary carries none";
}
