// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Plugin/PluginTypes.h>
#include <gtest/gtest.h>

TEST(PluginAbiVersion, IsSix)
{
    EXPECT_EQ(LibreSCRS::Plugin::kCardPluginAbiVersion, 6u);
}
