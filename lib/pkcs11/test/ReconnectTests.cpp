// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Phase B.7.4 integration tests for the reconnect / RESET path
///        on @ref LibreSCRS::Pkcs11::Internal::PKCS11Card (spec §5.3.5).
///
/// The mock provides a one-shot sign-fault injection (@c armSignFaultOnce)
/// and a PACE-replaying @c reconnectInline override; together they let
/// tests stage transport-level resets at the Card level without real
/// PCSC. Tests cover:
///  - non-PACE reset replays sign;
///  - PACE reset reuses the cached CAN (paceCallCount bumps);
///  - reset on one card's reader does not affect a sibling card on a
///    different reader;
///  - concurrent handleReset() calls serialise via cardMutex with no
///    deadlock and no lost increment.

#include "MockPKCS11CardProvider.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal::Test {
namespace {

constexpr unsigned long CkuUser = 1UL;

[[nodiscard]] std::vector<std::uint8_t> pinBytes(std::string_view s)
{
    return std::vector<std::uint8_t>{s.begin(), s.end()};
}

class Reconnect : public ::testing::Test
{
protected:
    static MockCardSpec singleSlotNonPace()
    {
        MockCardSpec spec;
        spec.needsPace = false;
        spec.slots.push_back(MockSlotSpec{
            .pinId = std::vector<std::uint8_t>{0x01},
            .pinLabel = "User",
            .correctPin = "1234",
            .kind = SlotKind::Generic,
        });
        return spec;
    }

    static MockCardSpec singleSlotPace()
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
        return spec;
    }

    [[nodiscard]] static int paceCount(const std::shared_ptr<PKCS11Card>& card)
    {
        return static_cast<MockConfigurableCard*>(card.get())->paceCount();
    }

    [[nodiscard]] static MockConfigurableCard& asConfigurable(const std::shared_ptr<PKCS11Card>& card)
    {
        return *static_cast<MockConfigurableCard*>(card.get());
    }
};

TEST_F(Reconnect, NoPaceResetReplaysSign)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", singleSlotNonPace());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 1u);

    ASSERT_EQ(slots[0]->login(CkuUser, pinBytes("1234")), Crv::Ok);

    const std::vector<std::uint8_t> data(32, 0xAB);
    const std::vector<std::uint8_t> keyId{0x01};

    // Initial sign succeeds.
    EXPECT_FALSE(slots[0]->signData(data, /*mechanism=*/0x01UL, keyId).empty());

    // Inject a one-shot sign fault — the next sign returns empty.
    asConfigurable(card).armSignFaultOnce();
    EXPECT_TRUE(slots[0]->signData(data, /*mechanism=*/0x01UL, keyId).empty());

    // Recovery: handleReset() under cardMutex, then re-sign succeeds.
    EXPECT_EQ(card->handleReset(), Crv::Ok);
    EXPECT_FALSE(slots[0]->signData(data, /*mechanism=*/0x01UL, keyId).empty());

    // Non-PACE card: PACE counter stays at zero across the full cycle.
    EXPECT_EQ(paceCount(card), 0);
}

TEST_F(Reconnect, PaceResetWithCachedCan)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", singleSlotPace());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 1u);

    // Login with CAN-in-PIN populates the cached CAN and bumps PACE to 1.
    ASSERT_EQ(slots[0]->login(CkuUser, pinBytes("123456:1234")), Crv::Ok);
    EXPECT_EQ(paceCount(card), 1);

    // Inject sign fault, observe failure, then drive reconnect.
    asConfigurable(card).armSignFaultOnce();
    const std::vector<std::uint8_t> data(32, 0xAB);
    const std::vector<std::uint8_t> keyId{0x01};
    EXPECT_TRUE(slots[0]->signData(data, /*mechanism=*/0x01UL, keyId).empty());

    EXPECT_EQ(card->handleReset(), Crv::Ok);
    // Cached CAN was reused → PACE call count bumps from 1 to 2.
    EXPECT_EQ(paceCount(card), 2);
    // Subsequent sign succeeds.
    EXPECT_FALSE(slots[0]->signData(data, /*mechanism=*/0x01UL, keyId).empty());
}

TEST_F(Reconnect, HotSwapAcrossDifferentReader)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", singleSlotPace());
    provider->registerCard("Mock Reader 1", singleSlotPace());

    auto cardA = provider->probe("Mock Reader 0");
    auto cardB = provider->probe("Mock Reader 1");
    ASSERT_NE(cardA, nullptr);
    ASSERT_NE(cardB, nullptr);
    auto slotsA = cardA->enumerateSlots();
    auto slotsB = cardB->enumerateSlots();
    ASSERT_EQ(slotsA.size(), 1u);
    ASSERT_EQ(slotsB.size(), 1u);

    // Login both cards (each gets paceCount == 1 independently).
    ASSERT_EQ(slotsA[0]->login(CkuUser, pinBytes("123456:1234")), Crv::Ok);
    ASSERT_EQ(slotsB[0]->login(CkuUser, pinBytes("123456:1234")), Crv::Ok);
    EXPECT_EQ(paceCount(cardA), 1);
    EXPECT_EQ(paceCount(cardB), 1);

    // Reset card A — must NOT bump card B's pace counter.
    EXPECT_EQ(cardA->handleReset(), Crv::Ok);
    EXPECT_EQ(paceCount(cardA), 2);
    EXPECT_EQ(paceCount(cardB), 1);

    // Card B remains usable and its sign is unaffected.
    const std::vector<std::uint8_t> data(32, 0xAB);
    const std::vector<std::uint8_t> keyId{0x01};
    EXPECT_FALSE(slotsB[0]->signData(data, /*mechanism=*/0x01UL, keyId).empty());
}

TEST_F(Reconnect, ConcurrentResetSerializesViaCardMutex)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", singleSlotPace());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 1u);

    // Prime cached CAN so reconnect bumps the pace counter.
    ASSERT_EQ(slots[0]->login(CkuUser, pinBytes("123456:1234")), Crv::Ok);
    EXPECT_EQ(paceCount(card), 1);

    // Two threads, each calling handleReset() once.
    auto fA = std::async(std::launch::async, [&card]() { return card->handleReset(); });
    auto fB = std::async(std::launch::async, [&card]() { return card->handleReset(); });

    // 10s deadline keeps a hung-deadlock from blocking the test runner.
    using namespace std::chrono_literals;
    ASSERT_EQ(fA.wait_for(10s), std::future_status::ready) << "handleReset (A) deadlocked";
    ASSERT_EQ(fB.wait_for(10s), std::future_status::ready) << "handleReset (B) deadlocked";
    EXPECT_EQ(fA.get(), Crv::Ok);
    EXPECT_EQ(fB.get(), Crv::Ok);

    // Both increments observed; cardMutex serialised the two reconnects
    // so no increment was lost.
    EXPECT_EQ(paceCount(card), 3);
}

} // namespace
} // namespace LibreSCRS::Pkcs11::Internal::Test
