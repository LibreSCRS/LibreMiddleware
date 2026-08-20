// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "rs_container.h"
#include "rs_signed_object.h"
#include "synthetic_annex.h"

#include <algorithm>

using namespace LibreSCRS::RsEId::Core;
namespace Fx = LibreSCRS::RsEId::Core::TestData;

namespace {

BlockCandidates tlvOf(const std::vector<std::uint8_t>& file)
{
    const auto tlv = leadingTlv(file);
    EXPECT_TRUE(tlv.has_value());
    return BlockCandidates{std::vector<std::uint8_t>{tlv->begin(), tlv->end()}};
}

struct Covered
{
    std::vector<std::uint8_t> a = Fx::makeContainer(0x0F1B, {{1537, "05"}}, 150);
    std::vector<std::uint8_t> b = Fx::makeContainer(0x0F02, {{1548, "ID000000000"}}, 157);
    std::vector<std::uint8_t> c = Fx::makeContainer(0x0F03, {{1561, "PARENT"}}, 822);

    [[nodiscard]] std::vector<BlockCandidates> blocks() const
    {
        return {tlvOf(a), tlvOf(b), tlvOf(c)};
    }

    [[nodiscard]] std::vector<std::uint8_t> content() const
    {
        std::vector<std::uint8_t> out;
        for (const auto& blk : blocks()) {
            const auto d = sha256(blk.front());
            EXPECT_TRUE(d.has_value());
            out.insert(out.end(), d->begin(), d->end());
        }
        return out;
    }
};

} // namespace

// An unknown signer must not stop the binding question from being answered:
// the two axes are independent, and collapsing them loses that.
TEST(RsSignedObject, UntrustedSignerStillAnswersTheBindingQuestion)
{
    const Covered f;
    const auto fixture = Fx::makeSignedObject(f.content());
    ASSERT_FALSE(fixture.cms.empty());

    const TrustStore empty;
    const auto report = verifySignedObject(fixture.cms, f.blocks(), DigestBinding::Positional, empty);

    EXPECT_EQ(report.signer, VerificationResult::Invalid); // no anchor, so no chain
    EXPECT_TRUE(report.digestsBound);
}

// Chain builds but the signer is outside the document-signer domain: indeterminate,
// not tampered. Reporting Invalid here would accuse a merely unfamiliar issuer.
TEST(RsSignedObject, AnchoredButForeignSignerIsUnknownNotInvalid)
{
    const Covered f;
    const auto fixture = Fx::makeSignedObject(f.content());
    ASSERT_FALSE(fixture.signerCertDer.empty());

    TrustStore trust;
    trust.addCertificate(fixture.signerCertDer);
    EXPECT_EQ(trust.certificateCount(), 1);

    const auto report = verifySignedObject(fixture.cms, f.blocks(), DigestBinding::Positional, trust);

    EXPECT_EQ(report.signer, VerificationResult::Unknown);
    EXPECT_TRUE(report.digestsBound);
}

// Item 140 at the object level: the issuer emitted the digests out of order.
TEST(RsSignedObject, PositionalRejectsObjectWithReorderedDigests)
{
    const Covered f;
    auto content = f.content();
    std::swap_ranges(content.begin(), content.begin() + kDigestSize, content.begin() + kDigestSize);
    ASSERT_NE(content, f.content());

    const auto fixture = Fx::makeSignedObject(content);
    const TrustStore empty;

    EXPECT_FALSE(verifySignedObject(fixture.cms, f.blocks(), DigestBinding::Positional, empty).digestsBound);
    EXPECT_TRUE(verifySignedObject(fixture.cms, f.blocks(), DigestBinding::AnywhereLegacy, empty).digestsBound);
}

// The card emits BER indefinite-length; the parser must take it as it comes.
TEST(RsSignedObject, BerIndefiniteLengthIsAccepted)
{
    const Covered f;
    const auto fixture = Fx::makeSignedObject(f.content());
    ASSERT_GE(fixture.cms.size(), 2u);
    EXPECT_EQ(fixture.cms[0], 0x30);
    EXPECT_EQ(fixture.cms[1], 0x80);

    const TrustStore empty;
    EXPECT_TRUE(verifySignedObject(fixture.cms, f.blocks(), DigestBinding::Positional, empty).digestsBound);
}

TEST(RsSignedObject, GarbageIsInvalidAndBindsNothing)
{
    const Covered f;
    const std::vector<std::uint8_t> garbage(64, 0xAB);
    const TrustStore empty;

    const auto report = verifySignedObject(garbage, f.blocks(), DigestBinding::Positional, empty);
    EXPECT_EQ(report.signer, VerificationResult::Invalid);
    EXPECT_FALSE(report.digestsBound);
}

TEST(RsSignedObject, EmptyInputIsInvalid)
{
    const Covered f;
    const TrustStore empty;
    const auto report = verifySignedObject({}, f.blocks(), DigestBinding::Positional, empty);
    EXPECT_EQ(report.signer, VerificationResult::Invalid);
    EXPECT_FALSE(report.digestsBound);
}

// A covered file substituted after signing must break the binding while leaving
// the signature itself intact -- that is exactly the attack the binding stops.
TEST(RsSignedObject, SubstitutedCoveredFileBreaksBindingNotSignature)
{
    const Covered f;
    const auto fixture = Fx::makeSignedObject(f.content());

    TrustStore trust;
    trust.addCertificate(fixture.signerCertDer);

    auto blocks = f.blocks();
    blocks[1] = tlvOf(Fx::makeContainer(0x0F02, {{1548, "ID999999999"}}, 157));

    const auto report = verifySignedObject(fixture.cms, blocks, DigestBinding::Positional, trust);
    EXPECT_EQ(report.signer, VerificationResult::Unknown); // signature and chain unaffected
    EXPECT_FALSE(report.digestsBound);
}
