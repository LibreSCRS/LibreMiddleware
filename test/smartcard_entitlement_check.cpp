// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Every executable of the macOS build is signed with the smart-card
// entitlement as it is linked. Without it the slot manager is unavailable and
// the card tests would skip or fail for a reason that has nothing to do with
// the code; this case, in the hardware binary, never skips and says so.

#include <gtest/gtest.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

TEST(SmartcardEntitlement, BinaryCarriesTheSmartcardEntitlement)
{
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    ASSERT_NE(task, nullptr);
    CFTypeRef value = SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.security.smartcard"), nullptr);
    const bool granted = value != nullptr && CFEqual(value, kCFBooleanTrue);
    if (value != nullptr)
        CFRelease(value);
    CFRelease(task);
    EXPECT_TRUE(granted) << "the link did not sign this binary with test/smartcard-entitlement.plist";
}
