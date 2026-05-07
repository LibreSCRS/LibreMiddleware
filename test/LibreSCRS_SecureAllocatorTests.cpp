// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#define LIBRESCRS_INTERNAL_BUILD
#include "../lib/LibreSCRS/Secure/secure_allocator.h"

#include <gtest/gtest.h>

#include <vector>

using LibreSCRS::Secure::detail::secure_allocator;

TEST(SecureAllocator, AllocatorAlwaysEqual)
{
    secure_allocator<int> a;
    secure_allocator<int> b;
    EXPECT_TRUE(a == b);

    secure_allocator<char> c;
    // Cross-type equality uses the heterogeneous operator== overload.
    EXPECT_TRUE(a == c);
}

TEST(SecureAllocator, ConstructFromOtherTemplateInstantiation)
{
    // Verifies the converting ctor used during rebind by node-based
    // containers. vector<T, secure_allocator<T>> doesn't trigger rebind,
    // but list/map will.
    secure_allocator<int> a;
    secure_allocator<char> b(a); // converting ctor
    (void)b;
    SUCCEED();
}

TEST(SecureAllocator, VectorRoundTrip)
{
    // Smoke-test that std::vector instantiates correctly with the allocator.
    std::vector<std::uint8_t, secure_allocator<std::uint8_t>> v;
    v.assign(100, 0xAB);
    EXPECT_EQ(v.size(), 100u);
    EXPECT_EQ(v[0], 0xAB);
    v.clear();
    v.shrink_to_fit(); // triggers deallocate → cleanse path
    EXPECT_TRUE(v.empty());
}
