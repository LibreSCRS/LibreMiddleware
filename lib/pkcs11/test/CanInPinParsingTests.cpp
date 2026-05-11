// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Phase B.7.3 integration tests for CAN-in-PIN parsing and PACE
///        deferral (spec §5.3.4). Verifies that:
///         - "CAN:PIN" splits correctly on PACE-needed cards;
///         - PACE runs exactly once for the first sibling, sibling slot
///           logins reuse the cached CAN (no second PACE);
///         - wrong CAN short-circuits before the PIN portion;
///         - non-PACE cards never invoke PACE;
///         - empty CAN ":PIN" form is rejected.

#include "MockPKCS11CardProvider.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal::Test {
namespace {

constexpr unsigned long CkuUser = 1UL;

[[nodiscard]] std::vector<std::uint8_t> pinBytes(std::string_view s)
{
    return std::vector<std::uint8_t>{s.begin(), s.end()};
}

class CanInPinParsing : public ::testing::Test
{
protected:
    static MockCardSpec twoSlotPaceSpec()
    {
        MockCardSpec spec;
        spec.needsPace = true;
        spec.correctCan = "123456";
        spec.slots.push_back(MockSlotSpec{
            .pinId = std::vector<std::uint8_t>{0x01},
            .pinLabel = "Auth",
            .correctPin = "1234",
            .kind = SlotKind::Auth,
        });
        spec.slots.push_back(MockSlotSpec{
            .pinId = std::vector<std::uint8_t>{0x02},
            .pinLabel = "Sign",
            .correctPin = "5678",
            .kind = SlotKind::Sign,
        });
        return spec;
    }

    [[nodiscard]] static int paceCount(const std::shared_ptr<PKCS11Card>& card)
    {
        return static_cast<MockConfigurableCard*>(card.get())->paceCount();
    }
};

TEST_F(CanInPinParsing, CanInPinSplit)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotPaceSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("123456:1234")), Crv::Ok);
    EXPECT_TRUE(slots[0]->isLoggedIn());
    EXPECT_EQ(paceCount(card), 1);
}

TEST_F(CanInPinParsing, CanCachedAcrossSiblingSlotLogins)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotPaceSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    // First sibling: CAN-in-PIN form runs PACE once.
    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("123456:1234")), Crv::Ok);
    EXPECT_EQ(paceCount(card), 1);

    // Second sibling: PIN-only form must not retrigger PACE because the
    // CAN is already cached on the parent card.
    EXPECT_EQ(slots[1]->login(CkuUser, pinBytes("5678")), Crv::Ok);
    EXPECT_EQ(paceCount(card), 1);
}

TEST_F(CanInPinParsing, CanRejectedIfWrong)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotPaceSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    // Wrong CAN, but PIN portion would otherwise be correct: PACE failure
    // must short-circuit before the PIN gate is consulted.
    const auto rv = slots[0]->login(CkuUser, pinBytes("999999:1234"));
    EXPECT_NE(rv, Crv::Ok);
    EXPECT_FALSE(slots[0]->isLoggedIn());
    // PACE was attempted exactly once (and failed); PIN gate untouched.
    EXPECT_EQ(paceCount(card), 1);
}

TEST_F(CanInPinParsing, PinOnlyOnNonPaceCard)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();

    MockCardSpec spec;
    spec.needsPace = false;
    spec.slots.push_back(MockSlotSpec{
        .pinId = std::vector<std::uint8_t>{0x01},
        .pinLabel = "User",
        .correctPin = "1234",
        .kind = SlotKind::Generic,
    });
    provider->registerCard("Mock Reader 0", std::move(spec));

    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 1u);

    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("1234")), Crv::Ok);
    EXPECT_TRUE(slots[0]->isLoggedIn());
    EXPECT_EQ(paceCount(card), 0);
}

TEST_F(CanInPinParsing, EmptyCanThenPinOnlyFails)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotPaceSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    // ":1234" — empty CAN portion. The mock parses this as "extracted
    // CAN of length 0, with PIN portion 1234"; PACE establishment must
    // fail because correctCan is non-empty, and the slot must not be
    // authenticated.
    const auto rv = slots[0]->login(CkuUser, pinBytes(":1234"));
    EXPECT_NE(rv, Crv::Ok);
    EXPECT_FALSE(slots[0]->isLoggedIn());
}

} // namespace
} // namespace LibreSCRS::Pkcs11::Internal::Test
