// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include <rs_document_profile.h>

TEST(EidProtocolAids, ProfileAidsAre11BytesWithTheSerPrefix)
{
    const auto profiles = LibreSCRS::RsEId::Core::documentProfiles();
    ASSERT_EQ(profiles.size(), 4u);
    for (const auto& p : profiles) {
        ASSERT_EQ(p.aid.size(), 11u) << p.code;
        // F3 81 00 00 02, then ASCII "SER" and the two-letter application name.
        EXPECT_EQ(p.aid[0], 0xF3) << p.code;
        EXPECT_EQ(p.aid[5], 'S') << p.code;
        EXPECT_EQ(p.aid[6], 'E') << p.code;
        EXPECT_EQ(p.aid[7], 'R') << p.code;
    }
}
