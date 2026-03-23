// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <smartcard/apdu.h>

TEST(SelectByFileId, DefaultP2Is0x00)
{
    auto cmd = smartcard::selectByFileId(0x50, 0x15);
    EXPECT_EQ(cmd.p2, 0x00);
    EXPECT_TRUE(cmd.hasLe);
}

TEST(SelectByFileId, ExplicitP2_0x0C)
{
    auto cmd = smartcard::selectByFileId(0x50, 0x15, 0x0C);
    EXPECT_EQ(cmd.p2, 0x0C);
    EXPECT_FALSE(cmd.hasLe);
}
