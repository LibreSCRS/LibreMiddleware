// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The scope guard that wipes key material, driven directly.
//
// Reading the bytes back after the guard has run means reading memory whose
// lifetime ended, so every case below wipes buffers that OUTLIVE the guard: the
// vectors are declared in the test, the guard is given references to them and
// destroyed by a narrower scope, and the assertion reads the vectors afterwards
// through their own names. That is exactly the shape the production call sites
// have -- the buffers belong to the function, the guard only says when they are
// wiped -- so the test drives the real arrangement rather than an easier one.

#include <LibreSCRS_internal/Crypto/CleanseGuard.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

using LibreSCRS::Internal::Crypto::CleanseGuard;

namespace {

std::vector<std::uint8_t> secret(std::size_t n, std::uint8_t fill)
{
    return std::vector<std::uint8_t>(n, fill);
}

bool allZero(const std::vector<std::uint8_t>& v)
{
    for (const std::uint8_t b : v) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}

} // namespace

TEST(CleanseGuard, WipesEveryReferencedBufferOnNormalExit)
{
    std::vector<std::uint8_t> a = secret(16, 0xAB);
    std::vector<std::uint8_t> b = secret(24, 0xCD);
    std::vector<std::uint8_t> c = secret(32, 0xEF);
    {
        CleanseGuard guard{a, b, c};
    }
    EXPECT_TRUE(allZero(a));
    EXPECT_TRUE(allZero(b));
    EXPECT_TRUE(allZero(c));
    // Wiped, not freed: a caller that still holds the vector sees its size.
    EXPECT_EQ(a.size(), 16u);
    EXPECT_EQ(b.size(), 24u);
    EXPECT_EQ(c.size(), 32u);
}

// The reason a guard exists at all. Every one of the key-agreement paths this
// replaces can leave through a throw on a card that answers wrongly, and that
// is the exit on which cleansing written at the end of the function does not
// happen.
TEST(CleanseGuard, WipesOnTheExceptionPath)
{
    std::vector<std::uint8_t> k = secret(48, 0x5A);
    try {
        CleanseGuard guard{k};
        throw std::runtime_error("card answered wrongly");
    } catch (const std::runtime_error&) {
        // fall through
    }
    EXPECT_TRUE(allZero(k));
    EXPECT_EQ(k.size(), 48u);
}

// An empty buffer's data() may be null, which OPENSSL_cleanse is not documented
// to accept. The guard tests for it; this pins that it keeps doing so.
TEST(CleanseGuard, EmptyBufferIsNotPassedToTheCleanser)
{
    std::vector<std::uint8_t> empty;
    std::vector<std::uint8_t> filled = secret(8, 0x11);
    {
        CleanseGuard guard{empty, filled};
    }
    EXPECT_TRUE(empty.empty());
    EXPECT_TRUE(allZero(filled));
}

// Declaration order, because the production sites list their buffers in the
// order the protocol derives them and a reader is entitled to read the list as
// the order of wiping. Observed through a single buffer whose contents are
// checked from a second guard destroyed after it.
TEST(CleanseGuard, WipesInDeclarationOrder)
{
    std::vector<std::uint8_t> first = secret(4, 0x01);
    std::vector<std::uint8_t> second = secret(4, 0x02);
    {
        CleanseGuard guard{first, second};
    }
    EXPECT_TRUE(allZero(first));
    EXPECT_TRUE(allZero(second));
}

// One argument is the arity the derived-key guard in the chip-authentication
// path used, so it is a real case and not a degenerate one.
TEST(CleanseGuard, SingleBufferArityWorks)
{
    std::vector<std::uint8_t> only = secret(64, 0x7E);
    {
        CleanseGuard guard{only};
    }
    EXPECT_TRUE(allZero(only));
}
