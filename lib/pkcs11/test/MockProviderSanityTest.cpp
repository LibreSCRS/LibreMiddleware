// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Smoke test for @ref LibreSCRS::Pkcs11::Internal::Test::MockPKCS11CardProvider.
///        Ensures probe() returns a bound card with the expected slot
///        count and that each slot's stable ID is non-zero and distinct.

#include "MockPKCS11CardProvider.h"

#include <gtest/gtest.h>

#include <memory>

namespace LibreSCRS::Pkcs11::Internal::Test {
namespace {

class MockProviderSanity : public ::testing::Test
{};

TEST_F(MockProviderSanity, ProbeReturnsCardWithTwoDistinctSlots)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();

    MockCardSpec spec;
    spec.needsPace = false;
    spec.slots.push_back(MockSlotSpec{
        .pinId = std::vector<std::uint8_t>{0x01},
        .pinLabel = "Auth PIN",
        .correctPin = "1234",
        .kind = SlotKind::Auth,
    });
    spec.slots.push_back(MockSlotSpec{
        .pinId = std::vector<std::uint8_t>{0x02},
        .pinLabel = "Sign PIN",
        .correctPin = "5678",
        .kind = SlotKind::Sign,
    });
    provider->registerCard("Mock Reader 0", std::move(spec));

    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);

    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    ASSERT_NE(slots[0], nullptr);
    ASSERT_NE(slots[1], nullptr);

    EXPECT_NE(slots[0]->stableId(), 0u);
    EXPECT_NE(slots[1]->stableId(), 0u);
    EXPECT_NE(slots[0]->stableId(), slots[1]->stableId());

    EXPECT_EQ(provider->probeCallCount("Mock Reader 0"), 1);
}

TEST_F(MockProviderSanity, UnknownReaderReturnsNullptr)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    EXPECT_EQ(provider->probe("Nonexistent Reader"), nullptr);
}

} // namespace
} // namespace LibreSCRS::Pkcs11::Internal::Test
