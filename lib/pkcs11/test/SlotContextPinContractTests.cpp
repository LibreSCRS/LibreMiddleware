// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief The slot-side contract of CKA_ALWAYS_AUTHENTICATE: which PIN a slot
///        may present for a key, and the fail-closed base of the per-operation
///        path for a slot family that never publishes such a key.

#include "MockPKCS11CardSlot.h"

#include "internal/Crv.h"
#include "internal/PKCS11Slot.h"

#include <LibreSCRS/Secure/String.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal::Test {
namespace {

const Secure::String& cachedPin()
{
    static const Secure::String pin{std::string_view{"1111"}};
    return pin;
}

TEST(SelectPresentedPin, PerOperationKeyPresentsOnlyTheContextPin)
{
    const Secure::String context{std::string_view{"2222"}};
    EXPECT_EQ(selectPresentedPin(true, true, cachedPin(), &context), &context);
}

TEST(SelectPresentedPin, PerOperationKeyWithoutAContextPinPresentsNothing)
{
    const Secure::String empty;
    EXPECT_EQ(selectPresentedPin(true, true, cachedPin(), nullptr), nullptr)
        << "the session login's PIN is never this operation's PIN";
    EXPECT_EQ(selectPresentedPin(true, true, cachedPin(), &empty), nullptr);
}

// The library's retry after a card reset presents the same one-shot PIN to a
// slot the reset has logged out; the PIN itself is the authorisation.
TEST(SelectPresentedPin, PerOperationKeyDoesNotNeedTheSessionLogin)
{
    const Secure::String context{std::string_view{"2222"}};
    EXPECT_EQ(selectPresentedPin(true, false, Secure::String{}, &context), &context);
}

TEST(SelectPresentedPin, OrdinaryKeyPresentsTheCachedPinWhileLoggedIn)
{
    const Secure::String context{std::string_view{"2222"}};
    EXPECT_EQ(selectPresentedPin(false, true, cachedPin(), nullptr), &cachedPin());
    EXPECT_EQ(selectPresentedPin(false, true, cachedPin(), &context), &cachedPin())
        << "an ordinary key keeps signing on the session login";
}

TEST(SelectPresentedPin, OrdinaryKeyPresentsNothingWhenLoggedOut)
{
    EXPECT_EQ(selectPresentedPin(false, false, cachedPin(), nullptr), nullptr);
    EXPECT_EQ(selectPresentedPin(false, true, Secure::String{}, nullptr), nullptr);
}

TEST(SlotContextPinContract, BaseClassPerOperationPathFailsClosed)
{
    MockSlot slot{std::weak_ptr<PKCS11Card>{}, std::vector<std::uint8_t>{0x01}, "PIN"};
    const std::vector<std::uint8_t> keyId{0x01};
    const std::vector<std::uint8_t> data(20, 0x42);
    const std::vector<std::uint8_t> pin{'1', '1', '1', '1'};
    const Secure::String context{std::string_view{"1111"}};

    EXPECT_EQ(slot.verifyContextPin(keyId, pin), Crv::FunctionFailed);
    const auto plain = slot.signDataWithContextPin(data, 0x0001UL, keyId, context);
    ASSERT_FALSE(plain.has_value());
    EXPECT_EQ(plain.error(), Crv::DeviceError) << "no PIN was refused: the base never reached a card";
    const auto withDigestInfo = slot.signWithDigestInfoAndContextPin(data, data, 0x0040UL, keyId, context);
    ASSERT_FALSE(withDigestInfo.has_value());
    EXPECT_EQ(withDigestInfo.error(), Crv::DeviceError);
}

} // namespace
} // namespace LibreSCRS::Pkcs11::Internal::Test
