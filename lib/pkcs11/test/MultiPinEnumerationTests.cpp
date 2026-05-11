// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Integration tests for multi-slot enumeration via
///        @ref LibreSCRS::Pkcs11::Internal::Test::MockPKCS11CardProvider.
///        A card with N PINs surfaces N slots, each with a distinct,
///        deterministic stable ID, and each slot's tokenInfo carries
///        the matching PIN label.

#include "MockPKCS11CardProvider.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal::Test {
namespace {

class MultiPinEnumeration : public ::testing::Test
{
protected:
    static MockCardSpec twoSlotGEOSpec()
    {
        MockCardSpec spec;
        spec.needsPace = false;
        spec.slots.push_back(MockSlotSpec{
            .pinId = std::vector<std::uint8_t>{0x01},
            .pinLabel = "Auth",
            .correctPin = "1234",
            .kind = SlotKind::Auth,
        });
        spec.slots.push_back(MockSlotSpec{
            .pinId = std::vector<std::uint8_t>{0x02},
            .pinLabel = "Sign (QSCD)",
            .correctPin = "5678",
            .kind = SlotKind::Sign,
        });
        return spec;
    }
};

TEST_F(MultiPinEnumeration, TwoSlotGEOEmits2SlotIds)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotGEOSpec());

    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);

    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);
    EXPECT_NE(slots[0], nullptr);
    EXPECT_NE(slots[1], nullptr);
}

TEST_F(MultiPinEnumeration, EachSlotsTokenInfoReportsCorrectPinLabel)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotGEOSpec());

    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    EXPECT_EQ(slots[0]->tokenInfo().pinLabel, "Auth");
    EXPECT_EQ(slots[1]->tokenInfo().pinLabel, "Sign (QSCD)");
}

TEST_F(MultiPinEnumeration, SlotStableIdsDistinctAndDeterministic)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotGEOSpec());

    auto card1 = provider->probe("Mock Reader 0");
    ASSERT_NE(card1, nullptr);
    auto slots1 = card1->enumerateSlots();
    ASSERT_EQ(slots1.size(), 2u);

    const unsigned long slot0Id1 = slots1[0]->stableId();
    const unsigned long slot1Id1 = slots1[1]->stableId();

    EXPECT_NE(slot0Id1, 0u);
    EXPECT_NE(slot1Id1, 0u);
    EXPECT_NE(slot0Id1, slot1Id1);

    // Second probe must yield identical slot IDs (determinism).
    auto card2 = provider->probe("Mock Reader 0");
    ASSERT_NE(card2, nullptr);
    auto slots2 = card2->enumerateSlots();
    ASSERT_EQ(slots2.size(), 2u);

    EXPECT_EQ(slots2[0]->stableId(), slot0Id1);
    EXPECT_EQ(slots2[1]->stableId(), slot1Id1);
}

TEST_F(MultiPinEnumeration, MixedSinglePlusMultiPinFlatList)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();

    // Reader 0: single-slot generic card.
    MockCardSpec singleSpec;
    singleSpec.needsPace = false;
    singleSpec.slots.push_back(MockSlotSpec{
        .pinId = std::vector<std::uint8_t>{0xAA},
        .pinLabel = "User PIN",
        .correctPin = "0000",
        .kind = SlotKind::Generic,
    });
    provider->registerCard("Mock Reader 0", std::move(singleSpec));

    // Reader 1: two-slot GEO-style card.
    provider->registerCard("Mock Reader 1", twoSlotGEOSpec());

    auto card0 = provider->probe("Mock Reader 0");
    auto card1 = provider->probe("Mock Reader 1");
    ASSERT_NE(card0, nullptr);
    ASSERT_NE(card1, nullptr);

    auto slots0 = card0->enumerateSlots();
    auto slots1 = card1->enumerateSlots();
    ASSERT_EQ(slots0.size(), 1u);
    ASSERT_EQ(slots1.size(), 2u);

    std::set<unsigned long> seenIds;
    seenIds.insert(slots0[0]->stableId());
    seenIds.insert(slots1[0]->stableId());
    seenIds.insert(slots1[1]->stableId());

    // 3 logical slots, all stableIds distinct.
    EXPECT_EQ(seenIds.size(), 3u);
    EXPECT_EQ(seenIds.count(0u), 0u);
}

} // namespace
} // namespace LibreSCRS::Pkcs11::Internal::Test
