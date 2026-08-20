// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "rs_container.h"
#include "rs_digest_binding.h"
#include "synthetic_annex.h"

#include <algorithm>
#include <string>

using namespace LibreSCRS::RsEId::Core;
namespace Fx = LibreSCRS::RsEId::Core::TestData;

namespace {

BlockCandidates tlvOf(const std::vector<std::uint8_t>& file)
{
    const auto tlv = leadingTlv(file);
    EXPECT_TRUE(tlv.has_value());
    return BlockCandidates{std::vector<std::uint8_t>{tlv->begin(), tlv->end()}};
}

// Three covered files, so "take the first" and "take the last" cannot both pass
// by accident; the substitution test aims at the MIDDLE one.
struct Fixture
{
    std::vector<std::uint8_t> a = Fx::makeContainer(0x0F1B, {{1537, "05"}}, 150);
    std::vector<std::uint8_t> b = Fx::makeContainer(0x0F02, {{1548, "ID000000000"}}, 157);
    std::vector<std::uint8_t> c = Fx::makeContainer(0x0F03, {{1561, "PARENT"}}, 822);
    std::vector<std::uint8_t> outsider = Fx::makeContainer(0x0F04, {{1568, "STATE"}}, 886);

    [[nodiscard]] std::vector<BlockCandidates> blocks() const
    {
        return {tlvOf(a), tlvOf(b), tlvOf(c)};
    }

    /// Signed content in coverage order -- what a correct issuer emits.
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

// Anchor the digest to a published vector, so the tests below cannot pass by
// comparing one wrong implementation against itself.
TEST(RsDigestBinding, Sha256MatchesKnownAnswer)
{
    const std::string abc = "abc";
    const std::span<const std::uint8_t> in{reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size()};
    const auto got = sha256(in);
    ASSERT_TRUE(got.has_value());

    const std::array<std::uint8_t, 32> want{0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40,
                                            0xDE, 0x5D, 0xAE, 0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17,
                                            0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD};
    EXPECT_EQ(*got, want);
}

TEST(RsDigestBinding, PositionalAcceptsCorrectOrder)
{
    const Fixture f;
    EXPECT_TRUE(matchDigests(f.content(), f.blocks(), DigestBinding::Positional));
}

// Item 140. Two covered files swap places. "Search anywhere" still passes --
// that is precisely the weakness -- while positional binding must reject.
TEST(RsDigestBinding, PositionalRejectsSwappedBlocks)
{
    const Fixture f;
    auto blocks = f.blocks();
    std::swap(blocks[1], blocks[2]);
    ASSERT_NE(blocks[1], f.blocks()[1]); // the perturbation really changed something

    EXPECT_FALSE(matchDigests(f.content(), blocks, DigestBinding::Positional));
    EXPECT_TRUE(matchDigests(f.content(), blocks, DigestBinding::AnywhereLegacy));
}

TEST(RsDigestBinding, PositionalRejectsMiddleBlockSubstitution)
{
    const Fixture f;
    auto blocks = f.blocks();
    blocks[1] = tlvOf(f.outsider);
    ASSERT_NE(blocks[1], f.blocks()[1]);

    EXPECT_FALSE(matchDigests(f.content(), blocks, DigestBinding::Positional));
    EXPECT_FALSE(matchDigests(f.content(), blocks, DigestBinding::AnywhereLegacy));
}

// The block-count rule belongs to Positional alone. A repeated block is found by
// the legacy search, so this pins the rule down instead of merely observing that
// both bindings reject an unrelated file.
TEST(RsDigestBinding, BlockCountAboveSlotCountRejectedOnlyByPositional)
{
    const Fixture f;
    auto blocks = f.blocks();
    blocks.push_back(tlvOf(f.a)); // duplicate of block 0: legacy finds it in slot 0

    EXPECT_FALSE(matchDigests(f.content(), blocks, DigestBinding::Positional));
    EXPECT_TRUE(matchDigests(f.content(), blocks, DigestBinding::AnywhereLegacy));
}

// Legacy truncates a ragged tail exactly as the shipped CardEdge code does.
TEST(RsDigestBinding, RaggedContentRejectedOnlyByPositional)
{
    const Fixture f;
    auto content = f.content();
    content.push_back(0x00); // three whole slots plus a stray byte

    EXPECT_FALSE(matchDigests(content, f.blocks(), DigestBinding::Positional));
    EXPECT_TRUE(matchDigests(content, f.blocks(), DigestBinding::AnywhereLegacy));
}

// A generation unsure which encoding the issuer hashed may offer several; any
// one of them satisfies the slot.
TEST(RsDigestBinding, AnyCandidateEncodingSatisfiesItsSlot)
{
    const Fixture f;
    auto blocks = f.blocks();
    blocks[1].insert(blocks[1].begin(), f.b); // whole padded file first, TLV second

    EXPECT_TRUE(matchDigests(f.content(), blocks, DigestBinding::Positional));
}

TEST(RsDigestBinding, EmptyInputsAreRejectedByBothBindings)
{
    const Fixture f;
    EXPECT_FALSE(matchDigests({}, f.blocks(), DigestBinding::Positional));
    EXPECT_FALSE(matchDigests({}, f.blocks(), DigestBinding::AnywhereLegacy));
    EXPECT_FALSE(matchDigests(f.content(), {}, DigestBinding::Positional));
    EXPECT_FALSE(matchDigests(f.content(), {}, DigestBinding::AnywhereLegacy));
}

// An empty candidate list carries nothing to match, so it must not silently pass.
TEST(RsDigestBinding, BlockWithNoCandidatesIsRejected)
{
    const Fixture f;
    auto blocks = f.blocks();
    blocks[1] = BlockCandidates{};

    EXPECT_FALSE(matchDigests(f.content(), blocks, DigestBinding::Positional));
    EXPECT_FALSE(matchDigests(f.content(), blocks, DigestBinding::AnywhereLegacy));
}
