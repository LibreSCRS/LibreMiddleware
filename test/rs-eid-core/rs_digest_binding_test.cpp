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

    [[nodiscard]] static std::vector<SlotInput> asSlots(const std::vector<BlockCandidates>& blocks)
    {
        return {blocks.begin(), blocks.end()};
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
    EXPECT_TRUE(matchDigests(f.content(), Fixture::asSlots(f.blocks())));
}

// Two covered files swap places: every digest is in the object, yet
// neither file is where the issuer put it, and positional binding must reject.
TEST(RsDigestBinding, PositionalRejectsSwappedBlocks)
{
    const Fixture f;
    auto blocks = f.blocks();
    std::swap(blocks[1], blocks[2]);
    ASSERT_NE(blocks[1], f.blocks()[1]); // the perturbation really changed something

    EXPECT_FALSE(matchDigests(f.content(), Fixture::asSlots(blocks)));
}

TEST(RsDigestBinding, PositionalRejectsMiddleBlockSubstitution)
{
    const Fixture f;
    auto blocks = f.blocks();
    blocks[1] = tlvOf(f.outsider);
    ASSERT_NE(blocks[1], f.blocks()[1]);

    EXPECT_FALSE(matchDigests(f.content(), Fixture::asSlots(blocks)));
}

// A repeated block would find its digest in slot 0, so this pins the block-count
// rule down instead of merely observing that an unrelated file is rejected.
TEST(RsDigestBinding, BlockCountAboveSlotCountIsRejected)
{
    const Fixture f;
    auto blocks = f.blocks();
    blocks.push_back(tlvOf(f.a)); // duplicate of block 0

    EXPECT_FALSE(matchDigests(f.content(), Fixture::asSlots(blocks)));
}

TEST(RsDigestBinding, RaggedContentIsRejected)
{
    const Fixture f;
    auto content = f.content();
    content.push_back(0x00); // three whole slots plus a stray byte

    EXPECT_FALSE(matchDigests(content, Fixture::asSlots(f.blocks())));
}

// A generation unsure which encoding the issuer hashed may offer several; any
// one of them satisfies the slot.
TEST(RsDigestBinding, AnyCandidateEncodingSatisfiesItsSlot)
{
    const Fixture f;
    auto blocks = f.blocks();
    blocks[1].insert(blocks[1].begin(), f.b); // whole padded file first, TLV second

    EXPECT_TRUE(matchDigests(f.content(), Fixture::asSlots(blocks)));
}

TEST(RsDigestBinding, EmptyInputsAreRejected)
{
    const Fixture f;
    EXPECT_FALSE(matchDigests({}, Fixture::asSlots(f.blocks())));
    EXPECT_FALSE(matchDigests(f.content(), std::vector<SlotInput>{}));
}

// An empty candidate list carries nothing to match, so it must not silently pass.
TEST(RsDigestBinding, BlockWithNoCandidatesIsRejected)
{
    const Fixture f;
    auto blocks = f.blocks();
    blocks[1] = BlockCandidates{};

    EXPECT_FALSE(matchDigests(f.content(), Fixture::asSlots(blocks)));
}

// --- Slot inputs: the positional form with an explicit "skip this slot" ---

namespace {

std::vector<std::uint8_t> digestOf(const std::vector<std::uint8_t>& block)
{
    const auto d = sha256(block);
    EXPECT_TRUE(d.has_value());
    return {d->begin(), d->end()};
}

std::vector<std::uint8_t> concat(std::initializer_list<std::vector<std::uint8_t>> parts)
{
    std::vector<std::uint8_t> out;
    for (const auto& p : parts) {
        out.insert(out.end(), p.begin(), p.end());
    }
    return out;
}

} // namespace

TEST(RsDigestBinding, SkippedSlotStillCounts)
{
    const Fixture f;
    const std::vector<std::uint8_t> protectedDigest(kDigestSize, 0x77);
    const auto content = concat({digestOf(tlvOf(f.a).front()), protectedDigest, digestOf(tlvOf(f.c).front())});

    const std::vector<SlotInput> slots{tlvOf(f.a), SkipSlot{}, tlvOf(f.c)};
    EXPECT_TRUE(matchDigests(content, slots));

    // The skipped position is counted: dropping it shifts every later slot.
    const std::vector<SlotInput> shifted{tlvOf(f.a), tlvOf(f.c)};
    EXPECT_FALSE(matchDigests(content, shifted));

    // A skip does not excuse a neighbour.
    const std::vector<SlotInput> wrong{tlvOf(f.a), SkipSlot{}, tlvOf(f.b)};
    EXPECT_FALSE(matchDigests(content, wrong));
}

TEST(RsDigestBinding, SlotCountMustEqualProfile)
{
    std::vector<std::uint8_t> content;
    std::vector<SlotInput> nine;
    for (int i = 0; i < 9; ++i) {
        const auto block = Fx::makeContainer(0x0F02, {{1548, "ID" + std::to_string(i)}}, 40);
        const BlockCandidates one = tlvOf(block);
        const auto d = digestOf(one.front());
        content.insert(content.end(), d.begin(), d.end());
        nine.emplace_back(one);
    }
    EXPECT_TRUE(matchDigests(content, nine));

    const std::vector<SlotInput> eight(nine.begin(), nine.end() - 1);
    EXPECT_FALSE(matchDigests(content, eight));

    auto ten = nine;
    ten.emplace_back(nine.back());
    EXPECT_FALSE(matchDigests(content, ten));
}

TEST(RsDigestBinding, EmptyCandidatesNeverMatch)
{
    const Fixture f;
    const auto content = concat({digestOf(tlvOf(f.a).front()), digestOf(tlvOf(f.b).front())});

    EXPECT_FALSE(matchDigests(content, std::vector<SlotInput>{tlvOf(f.a), BlockCandidates{}}));
    EXPECT_FALSE(
        matchDigests(content, std::vector<SlotInput>{tlvOf(f.a), BlockCandidates{std::vector<std::uint8_t>{}}}));
}

TEST(RsDigestBinding, EmptyContentOrOnlySkipsIsFalse)
{
    const Fixture f;
    EXPECT_FALSE(matchDigests({}, std::vector<SlotInput>{tlvOf(f.a)}));
    EXPECT_FALSE(matchDigests(std::vector<std::uint8_t>(kDigestSize - 1, 0), std::vector<SlotInput>{tlvOf(f.a)}));
    EXPECT_FALSE(matchDigests(std::vector<std::uint8_t>(kDigestSize, 0), std::vector<SlotInput>{}));
    // Nothing was checked, so nothing may read as bound.
    EXPECT_FALSE(
        matchDigests(std::vector<std::uint8_t>(2 * kDigestSize, 0), std::vector<SlotInput>{SkipSlot{}, SkipSlot{}}));
}
