// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Phase B.7.5 integration tests for concurrency-safety of the
///        @ref LibreSCRS::Pkcs11::Internal::PKCS11Card +
///        @ref LibreSCRS::Pkcs11::Internal::PKCS11Slot architecture
///        (spec §5.3.6).
///
/// These tests probe the lock-order invariant (slotMutex → cardMutex)
/// and the per-slot serialisation contract. They are designed to be
/// TSan-clean when compiled with @c -fsanitize=thread; TSan execution
/// happens in a separate build dir during Phase B.8 wall-clock
/// validation.

#include "MockPKCS11CardProvider.h"

#include <gtest/gtest.h>

#include <atomic>
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

class Concurrency : public ::testing::Test
{
protected:
    static MockCardSpec singleSlotGenericSpec(std::string_view pinValue = "1234")
    {
        MockCardSpec spec;
        spec.needsPace = false;
        spec.slots.push_back(MockSlotSpec{
            .pinId = std::vector<std::uint8_t>{0x01},
            .pinLabel = "User",
            .correctPin = std::string{pinValue},
            .kind = SlotKind::Generic,
        });
        return spec;
    }

    static MockCardSpec fourSlotSpec()
    {
        MockCardSpec spec;
        spec.needsPace = false;
        for (std::uint8_t i = 0; i < 4; ++i) {
            spec.slots.push_back(MockSlotSpec{
                .pinId = std::vector<std::uint8_t>{static_cast<std::uint8_t>(0x10 + i)},
                .pinLabel = "Slot " + std::to_string(int{i}),
                .correctPin = "1234",
                .kind = SlotKind::Generic,
            });
        }
        return spec;
    }
};

// 1) Four threads, one per separate card on its own reader. No shared
//    slot or card. Acts as the cleanest TSan signal: independent paths
//    must not race through the provider/registry plumbing.
TEST_F(Concurrency, FourThreadsSignDifferentCards)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    constexpr int kReaders = 4;
    constexpr int kIterations = 100;

    std::vector<std::shared_ptr<PKCS11Card>> cards;
    cards.reserve(kReaders);
    for (int i = 0; i < kReaders; ++i) {
        const std::string reader = "Mock Reader " + std::to_string(i);
        provider->registerCard(reader, singleSlotGenericSpec());
        auto card = provider->probe(reader);
        ASSERT_NE(card, nullptr);
        auto slots = card->enumerateSlots();
        ASSERT_EQ(slots.size(), 1u);
        ASSERT_EQ(slots[0]->login(CkuUser, pinBytes("1234")), Crv::Ok);
        cards.push_back(std::move(card));
    }

    std::vector<std::future<int>> futures;
    futures.reserve(kReaders);
    for (int i = 0; i < kReaders; ++i) {
        futures.push_back(std::async(std::launch::async, [card = cards[i]]() {
            int success = 0;
            auto slots = card->enumerateSlots();
            const std::vector<std::uint8_t> data(32, 0xAB);
            const std::vector<std::uint8_t> keyId{0x01};
            for (int j = 0; j < kIterations; ++j) {
                auto sig = slots[0]->signData(data, /*mechanism=*/0x01UL, keyId);
                if (!sig.empty()) {
                    ++success;
                }
            }
            return success;
        }));
    }

    using namespace std::chrono_literals;
    for (auto& f : futures) {
        ASSERT_EQ(f.wait_for(30s), std::future_status::ready) << "FourThreadsSignDifferentCards deadlocked";
        EXPECT_EQ(f.get(), kIterations);
    }
}

// 2) Four threads on the SAME single slot. slotMutex serialises sign;
//    no deadlock and every call eventually returns.
TEST_F(Concurrency, FourThreadsSameSlotSerialized)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", singleSlotGenericSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 1u);
    ASSERT_EQ(slots[0]->login(CkuUser, pinBytes("1234")), Crv::Ok);

    constexpr int kThreads = 4;
    constexpr int kIterations = 50;
    std::atomic<int> totalSuccess{0};

    std::vector<std::future<void>> futures;
    futures.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        futures.push_back(std::async(std::launch::async, [&]() {
            auto slotsLocal = card->enumerateSlots();
            const std::vector<std::uint8_t> data(32, 0xAB);
            const std::vector<std::uint8_t> keyId{0x01};
            for (int j = 0; j < kIterations; ++j) {
                auto sig = slotsLocal[0]->signData(data, /*mechanism=*/0x01UL, keyId);
                if (!sig.empty()) {
                    totalSuccess.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }));
    }

    using namespace std::chrono_literals;
    for (auto& f : futures) {
        ASSERT_EQ(f.wait_for(30s), std::future_status::ready) << "FourThreadsSameSlotSerialized deadlocked";
        f.get();
    }
    EXPECT_EQ(totalSuccess.load(), kThreads * kIterations);
}

// 3) One card with four slots; one thread per slot. Each thread signs
//    on its own slot. Card-level transport mutex serialises across
//    sibling slots; no deadlock.
TEST_F(Concurrency, FourThreadsDifferentSlotsSameCard)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", fourSlotSpec());
    auto card = provider->probe("Mock Reader 0");
    ASSERT_NE(card, nullptr);
    auto slots = card->enumerateSlots();
    ASSERT_EQ(slots.size(), 4u);
    for (auto& s : slots) {
        ASSERT_EQ(s->login(CkuUser, pinBytes("1234")), Crv::Ok);
    }

    constexpr int kIterations = 50;
    std::atomic<int> totalSuccess{0};

    std::vector<std::future<void>> futures;
    futures.reserve(4);
    for (int i = 0; i < 4; ++i) {
        futures.push_back(std::async(std::launch::async, [&, i]() {
            // Re-snapshot the slots span; PKCS11Card::enumerateSlots() is
            // documented as lock-free post-bind, which is part of the
            // contract under test.
            auto localSlots = card->enumerateSlots();
            const std::vector<std::uint8_t> data(32, 0xAB);
            const std::vector<std::uint8_t> keyId{0x01};
            for (int j = 0; j < kIterations; ++j) {
                auto sig = localSlots[i]->signData(data, /*mechanism=*/0x01UL, keyId);
                if (!sig.empty()) {
                    totalSuccess.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }));
    }

    using namespace std::chrono_literals;
    for (auto& f : futures) {
        ASSERT_EQ(f.wait_for(30s), std::future_status::ready) << "FourThreadsDifferentSlotsSameCard deadlocked";
        f.get();
    }
    EXPECT_EQ(totalSuccess.load(), 4 * kIterations);
}

// 4) Probe → login → sign → logout cycle, 100 iterations, single thread.
//    Asserts probe-call counter increments once per iteration AND no
//    cards leak (each iteration's card must be observably destroyed
//    before the next probe — verified via expired weak_ptr to the
//    previous iteration's card).
TEST_F(Concurrency, ProbeLoginSignLogoutCycle)
{
    auto provider = std::make_shared<MockPKCS11CardProvider>();
    provider->registerCard("Mock Reader 0", singleSlotGenericSpec());

    constexpr int kIterations = 100;
    std::weak_ptr<PKCS11Card> previousCard;

    for (int i = 0; i < kIterations; ++i) {
        // Previous iteration's card must have been destroyed by the time
        // we enter the next iteration (no leak / no rogue retained ref).
        if (i > 0) {
            EXPECT_TRUE(previousCard.expired()) << "card from iteration " << (i - 1) << " was not released";
        }

        auto card = provider->probe("Mock Reader 0");
        ASSERT_NE(card, nullptr);
        previousCard = card;

        auto slots = card->enumerateSlots();
        ASSERT_EQ(slots.size(), 1u);

        ASSERT_EQ(slots[0]->login(CkuUser, pinBytes("1234")), Crv::Ok);

        const std::vector<std::uint8_t> data(32, 0xAB);
        const std::vector<std::uint8_t> keyId{0x01};
        EXPECT_FALSE(slots[0]->signData(data, /*mechanism=*/0x01UL, keyId).empty());

        EXPECT_EQ(slots[0]->logout(), Crv::Ok);
    }

    // Probe counter must have advanced exactly once per iteration.
    EXPECT_EQ(provider->probeCallCount("Mock Reader 0"), kIterations);
    // Final iteration's card released after the loop body's scope ended.
    EXPECT_TRUE(previousCard.expired());
}

} // namespace
} // namespace LibreSCRS::Pkcs11::Internal::Test
