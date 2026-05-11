// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Phase A type-contract tests for the multi-PIN PKCS#11 base
///        classes. These tests exercise only the lifecycle / shape of
///        @ref LibreSCRS::Pkcs11::Internal::PKCS11Card and
///        @ref LibreSCRS::Pkcs11::Internal::PKCS11Slot — no real card I/O.

#include "MockPKCS11CardSlot.h"

#include <gtest/gtest.h>

#include <memory>

namespace LibreSCRS::Pkcs11::Internal::Test {
namespace {

class PKCS11CardContract : public ::testing::Test
{
protected:
    void SetUp() override
    {
        slotDtorCount.store(0, std::memory_order_relaxed);
        cardDtorCount.store(0, std::memory_order_relaxed);
    }
};

class PKCS11SlotContract : public PKCS11CardContract
{};

class PKCS11LifecycleContract : public PKCS11CardContract
{};

TEST_F(PKCS11CardContract, EmptyBeforeBind)
{
    auto card = std::make_shared<MockCard>();
    EXPECT_TRUE(card->reader().empty());
    EXPECT_EQ(card->enumerateSlots().size(), 0u);
}

TEST_F(PKCS11CardContract, BindPopulatesOneSlot)
{
    auto card = std::make_shared<MockCard>();
    EXPECT_EQ(card->bind("Mock Reader 0"), Crv::Ok);
    EXPECT_EQ(card->reader(), "Mock Reader 0");
    auto enumeratedSlots = card->enumerateSlots();
    ASSERT_EQ(enumeratedSlots.size(), 1u);
    EXPECT_NE(enumeratedSlots[0], nullptr);
}

TEST_F(PKCS11SlotContract, TokenInfoSnapshotEmpty)
{
    auto card = std::make_shared<MockCard>();
    ASSERT_EQ(card->bind("Mock Reader 0"), Crv::Ok);
    auto enumeratedSlots = card->enumerateSlots();
    ASSERT_EQ(enumeratedSlots.size(), 1u);
    PKCS11TokenInfo info = enumeratedSlots[0]->tokenInfo();
    EXPECT_TRUE(info.label.empty());
    EXPECT_TRUE(info.serialNumber.empty());
    EXPECT_EQ(info.minPinLen, 4u);
    EXPECT_EQ(info.maxPinLen, 16u);
}

TEST_F(PKCS11LifecycleContract, SlotsDestroyedBeforeCard)
{
    {
        auto card = std::make_shared<MockCard>();
        ASSERT_EQ(card->bind("Mock Reader 0"), Crv::Ok);
        EXPECT_EQ(slotDtorCount.load(), 0);
        EXPECT_EQ(cardDtorCount.load(), 0);
    }
    // Destruction order: ~PKCS11Card runs ~slots (vector dtor) BEFORE the
    // base-class subobject's other members are destroyed. Both counters
    // therefore reach their final value within the inner scope's exit.
    EXPECT_EQ(slotDtorCount.load(), 1);
    EXPECT_EQ(cardDtorCount.load(), 1);
}

TEST_F(PKCS11LifecycleContract, MultipleSlotsAllDestroyed)
{
    {
        auto card = std::make_shared<MockCard>();
        card->setExtraSlotCountBeforeBind(3);
        ASSERT_EQ(card->bind("Mock Reader 0"), Crv::Ok);
        ASSERT_EQ(card->enumerateSlots().size(), 4u);
    }
    EXPECT_EQ(slotDtorCount.load(), 4);
    EXPECT_EQ(cardDtorCount.load(), 1);
}

// -- Phase B.6b extension surface ----------------------------------
// signWithDigestInfo / signatureSize / isLoggedIn are added to the
// Slot contract before the legacy library swap (B.6c). The mock
// returns deterministic values; the assertions below pin the surface
// so subclasses cannot quietly drop overrides.

TEST_F(PKCS11SlotContract, IsLoggedInDefaultsFalse)
{
    auto card = std::make_shared<MockCard>();
    ASSERT_EQ(card->bind("Mock Reader 0"), Crv::Ok);
    auto enumeratedSlots = card->enumerateSlots();
    ASSERT_EQ(enumeratedSlots.size(), 1u);
    EXPECT_FALSE(enumeratedSlots[0]->isLoggedIn());
}

TEST_F(PKCS11SlotContract, SignatureSizeMockReturnsConstant)
{
    auto card = std::make_shared<MockCard>();
    ASSERT_EQ(card->bind("Mock Reader 0"), Crv::Ok);
    auto enumeratedSlots = card->enumerateSlots();
    ASSERT_EQ(enumeratedSlots.size(), 1u);
    const std::vector<std::uint8_t> stubKeyId{0x01, 0x02};
    EXPECT_EQ(enumeratedSlots[0]->signatureSize(stubKeyId), 256u);
}

TEST_F(PKCS11SlotContract, SignWithDigestInfoMockReturnsEmpty)
{
    auto card = std::make_shared<MockCard>();
    ASSERT_EQ(card->bind("Mock Reader 0"), Crv::Ok);
    auto enumeratedSlots = card->enumerateSlots();
    ASSERT_EQ(enumeratedSlots.size(), 1u);
    const std::vector<std::uint8_t> digestInfo(32, 0x00);
    const std::vector<std::uint8_t> rawData(64, 0x00);
    const std::vector<std::uint8_t> keyId{0x01};
    auto sig = enumeratedSlots[0]->signWithDigestInfo(digestInfo, rawData, /*mechanism=*/0x00000040UL, keyId);
    EXPECT_TRUE(sig.empty());
}

} // namespace
} // namespace LibreSCRS::Pkcs11::Internal::Test
