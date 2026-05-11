// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Phase B.7.2 integration tests for per-slot login isolation
///        (spec §5.3.3). A successful login on one slot must not
///        authenticate sibling slots; logout is similarly per-slot;
///        failed-login retry counters and PIN-lock behaviour are
///        per-slot.

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

class LoginIsolation : public ::testing::Test
{
protected:
    static MockCardSpec twoSlotSpec()
    {
        MockCardSpec spec;
        spec.needsPace = false;
        spec.slots.push_back(MockSlotSpec{
            .pinId = std::vector<std::uint8_t>{0x01},
            .pinLabel = "Auth",
            .correctPin = "1111",
            .kind = SlotKind::Auth,
        });
        spec.slots.push_back(MockSlotSpec{
            .pinId = std::vector<std::uint8_t>{0x02},
            .pinLabel = "Sign",
            .correctPin = "2222",
            .kind = SlotKind::Sign,
        });
        return spec;
    }
};

TEST_F(LoginIsolation, LoginOnSlotADoesNotAffectSlotB)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("1111")), Crv::Ok);
    EXPECT_TRUE(slots[0]->isLoggedIn());
    EXPECT_FALSE(slots[1]->isLoggedIn());
}

TEST_F(LoginIsolation, SignSlotBBeforeLoginReturnsEmpty)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    // Login slot A. Sibling slot B must remain unauthenticated.
    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("1111")), Crv::Ok);

    const std::vector<std::uint8_t> data(32, 0xAB);
    const std::vector<std::uint8_t> keyId{0x02};
    auto sig = slots[1]->signData(data, /*mechanism=*/0x01UL, keyId);
    EXPECT_TRUE(sig.empty());
}

TEST_F(LoginIsolation, SignSlotASucceedsAfterLogin)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    ASSERT_EQ(slots[0]->login(CkuUser, pinBytes("1111")), Crv::Ok);

    const std::vector<std::uint8_t> data(32, 0xAB);
    const std::vector<std::uint8_t> keyId{0x01};
    auto sig = slots[0]->signData(data, /*mechanism=*/0x01UL, keyId);
    EXPECT_FALSE(sig.empty());
}

TEST_F(LoginIsolation, LogoutSlotADoesNotAffectSlotB)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    ASSERT_EQ(slots[0]->login(CkuUser, pinBytes("1111")), Crv::Ok);
    ASSERT_EQ(slots[1]->login(CkuUser, pinBytes("2222")), Crv::Ok);
    EXPECT_TRUE(slots[0]->isLoggedIn());
    EXPECT_TRUE(slots[1]->isLoggedIn());

    EXPECT_EQ(slots[0]->logout(), Crv::Ok);
    EXPECT_FALSE(slots[0]->isLoggedIn());
    EXPECT_TRUE(slots[1]->isLoggedIn());
}

TEST_F(LoginIsolation, FailedLoginDecrementsRetry)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    // First wrong attempt: must report PinIncorrect (not PinLocked yet),
    // and a subsequent correct PIN must still succeed (slot is not
    // permanently locked after a single failure).
    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("9999")), Crv::PinIncorrect);
    EXPECT_FALSE(slots[0]->isLoggedIn());

    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("1111")), Crv::Ok);
    EXPECT_TRUE(slots[0]->isLoggedIn());

    // Sibling slot's retry counter is independent — never bumped.
    EXPECT_FALSE(slots[1]->isLoggedIn());
}

TEST_F(LoginIsolation, ThreeFailedLoginsLockSlot)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", twoSlotSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 2u);

    // 1st + 2nd wrong: PinIncorrect; 3rd wrong locks.
    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("9999")), Crv::PinIncorrect);
    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("9999")), Crv::PinIncorrect);
    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("9999")), Crv::PinLocked);
    EXPECT_FALSE(slots[0]->isLoggedIn());

    // 4th attempt with correct PIN must still report locked.
    EXPECT_EQ(slots[0]->login(CkuUser, pinBytes("1111")), Crv::PinLocked);
    EXPECT_FALSE(slots[0]->isLoggedIn());

    // Sibling slot remains usable — lock is per-slot, not per-card.
    EXPECT_EQ(slots[1]->login(CkuUser, pinBytes("2222")), Crv::Ok);
    EXPECT_TRUE(slots[1]->isLoggedIn());
}

} // namespace
} // namespace LibreSCRS::Pkcs11::Internal::Test
