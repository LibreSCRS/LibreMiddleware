// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <smartcard/secure_wipe.h>

#include <array>
#include <cstdint>

TEST(SecureWipeTest, ZeroesTheBuffer)
{
    std::array<std::uint8_t, 8> buf{1, 2, 3, 4, 5, 6, 7, 8};
    LibreSCRS::SmartCard::Internal::secureWipe(buf.data(), buf.size());
    for (auto b : buf)
        EXPECT_EQ(b, 0u);
}

TEST(SecureWipeTest, NullAndZeroAreNoops)
{
    LibreSCRS::SmartCard::Internal::secureWipe(nullptr, 0);
    std::array<std::uint8_t, 2> buf{9, 9};
    LibreSCRS::SmartCard::Internal::secureWipe(buf.data(), 0);
    EXPECT_EQ(buf[0], 9u); // n==0 wipes nothing
}
