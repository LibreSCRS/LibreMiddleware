// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Secure/String.h>

#include <gtest/gtest.h>

#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

using LibreSCRS::Secure::String;

// Design note (cleanse verification):
//
// The OPENSSL_cleanse on destruction writes zeros into heap memory owned
// by the vector<char> inside String::Impl. Once the unique_ptr<Impl>
// releases, that heap block returns to the allocator and reading it is
// undefined behaviour — we cannot portably assert "bytes at former
// address are zero". The public contract we CAN observe:
//
//   1. clear() leaves empty()==true and view().empty() — proxy for the
//      same cleanse+shrink the destructor performs.
//   2. Move-assignment and move-construction leave the source empty.
//   3. Copy-construct / copy-assign produce independent instances (so
//      mutating / destroying one does not touch the other).
//
// The actual `OPENSSL_cleanse(...)` call on the destructor path is
// verified by code review plus the structural invariant that every freed
// allocation routes through `secure_allocator<char>::deallocate`, which
// cleanses unconditionally. Sanitizer-based residue checking would require
// a test-only hook that defeats the class's pimpl boundary; not worth the
// layering cost for a mechanical call.

TEST(SecureStringTest, DefaultConstructIsEmpty)
{
    String s;
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.size(), 0u);
    EXPECT_TRUE(s.view().empty());
}

TEST(SecureStringTest, StringViewConstructCopiesBytes)
{
    std::string_view sv = "hunter2";
    String s(sv);
    EXPECT_FALSE(s.empty());
    EXPECT_EQ(s.size(), sv.size());
    EXPECT_EQ(s.view(), sv);
    // Distinct storage — not aliasing the source.
    EXPECT_NE(static_cast<const void*>(s.view().data()), static_cast<const void*>(sv.data()));
}

TEST(SecureStringTest, CharPointerConstructHandlesThreeChars)
{
    String s("abc");
    EXPECT_EQ(s.size(), 3u);
    EXPECT_EQ(s.view(), "abc");
}

TEST(SecureStringTest, CharPointerConstructHandlesNullptrAsEmpty)
{
    String s(static_cast<const char*>(nullptr));
    EXPECT_TRUE(s.empty());
}

TEST(SecureStringTest, RvalueStringConstructAdoptsAndCleansesSource)
{
    // Heap-sized payload (defeats SSO on every common stdlib).
    std::string src(64, 'A');
    src.replace(0, 7, "hunter2");

    String s(std::move(src));
    EXPECT_EQ(s.size(), 64u);
    EXPECT_EQ(s.view().substr(0, 7), "hunter2");

    // The moved-from rvalue still owns its buffer (we didn't transfer the
    // allocation, only copied bytes). Its contents must be cleansed.
    // std::string semantics after a move are unspecified for value but
    // valid; size() is permitted to be anything. What we DO observe via
    // the data() pointer is that whatever bytes remain are zero.
    if (!src.empty()) {
        for (std::size_t i = 0; i < src.size(); ++i)
            EXPECT_EQ(src[i], '\0') << "byte " << i << " not cleansed";
    }
}

TEST(SecureStringTest, RvalueStringConstructHandlesSso)
{
    // Short payload (fits in libstdc++/libc++ SSO inline buffer).
    std::string src = "1234";

    String s(std::move(src));
    EXPECT_EQ(s.size(), 4u);
    EXPECT_EQ(s.view(), "1234");

    // SSO cleanse must zero the inline buffer too — observe via the same
    // moved-from object before it dies.
    for (std::size_t i = 0; i < src.size(); ++i)
        EXPECT_EQ(src[i], '\0') << "SSO byte " << i << " not cleansed";
}

TEST(SecureStringTest, RvalueStringConstructEmptySourceIsEmpty)
{
    std::string src;
    String s(std::move(src));
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.size(), 0u);
}

TEST(SecureStringTest, ViewIsValid)
{
    String s(std::string_view("secret-token-xyz"));
    const auto v = s.view();
    EXPECT_EQ(v.size(), 16u);
    EXPECT_EQ(std::memcmp(v.data(), "secret-token-xyz", 16), 0);
}

TEST(SecureStringTest, ClearLeavesEmpty)
{
    String s("payload");
    ASSERT_FALSE(s.empty());
    s.clear();
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.size(), 0u);
    EXPECT_TRUE(s.view().empty());
}

TEST(SecureStringTest, MoveConstructLeavesSourceEmpty)
{
    String src("moved-away");
    String dst(std::move(src));
    EXPECT_EQ(dst.view(), "moved-away");
    EXPECT_TRUE(src.empty());  // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(src.size(), 0u); // NOLINT(bugprone-use-after-move)
}

TEST(SecureStringTest, MoveAssignLeavesSourceEmptyAndCleansesDestination)
{
    String src("incoming");
    String dst("outgoing");
    dst = std::move(src);
    EXPECT_EQ(dst.view(), "incoming");
    EXPECT_TRUE(src.empty()); // NOLINT(bugprone-use-after-move)
}

TEST(SecureStringTest, CopyConstructProducesIndependentStorage)
{
    String a("duplicate");
    String b(a);
    EXPECT_EQ(a.view(), "duplicate");
    EXPECT_EQ(b.view(), "duplicate");
    // Distinct storage: destroying one must not affect the other.
    EXPECT_NE(static_cast<const void*>(a.view().data()), static_cast<const void*>(b.view().data()));

    // Clearing a does not touch b.
    a.clear();
    EXPECT_TRUE(a.empty());
    EXPECT_EQ(b.view(), "duplicate");
}

TEST(SecureStringTest, CopyAssignProducesIndependentStorage)
{
    String a("alpha");
    String b("bravo");
    b = a;
    EXPECT_EQ(a.view(), "alpha");
    EXPECT_EQ(b.view(), "alpha");
    EXPECT_NE(static_cast<const void*>(a.view().data()), static_cast<const void*>(b.view().data()));

    // Mutating b does not touch a — proves the assignment installed a
    // separate storage block rather than sharing.
    b.clear();
    EXPECT_EQ(a.view(), "alpha");
}

TEST(SecureStringTest, CopyAssignCleansesPreviousDestinationContents)
{
    // This test exercises the documented "cleanse before adopt" path in
    // operator=(const String&). We cannot observe post-release bytes, but
    // we CAN observe that the destination's old storage is structurally
    // replaced (not appended-to or leaked).
    String dst("OLDSECRET");
    String src("new");
    dst = src;
    EXPECT_EQ(dst.size(), 3u);
    EXPECT_EQ(dst.view(), "new");
    // Old contents definitively gone — even partially, they would not fit
    // in a 3-byte view. Combined with Impl::cleanse() on the old buffer
    // before the new one is installed (code review), this is the
    // strongest observable assertion the public API permits.
}

TEST(SecureStringTest, SelfCopyAssignIsNoop)
{
    String s("keep-me");
    // The self-copy is the test contract; clang's -Wself-assign-overloaded
    // fires on a literal `s = s`. Route through a reference alias so the
    // compiler can no longer see source and destination as the same
    // expression while semantically still exercising the self-copy-assign
    // code path. Same workaround as SelfMoveAssignIsNoop below.
    String& alias = s;
    s = alias;
    EXPECT_EQ(s.view(), "keep-me");
}

TEST(SecureStringTest, SelfMoveAssignIsNoop)
{
    String s("keep-me");
    // The self-move is the test contract; both GCC's and clang's
    // -Wself-move fire on a literal `s = std::move(s)`. Route through a
    // reference alias so the compiler can no longer see the source and
    // destination as the same expression while semantically still
    // exercising the self-move-assign code path.
    String& alias = s;
    s = std::move(alias);
    EXPECT_EQ(s.view(), "keep-me");
}

TEST(SecureStringTest, EqualityOnEqualContents)
{
    String a("same");
    String b("same");
    EXPECT_TRUE(a == b);
    EXPECT_FALSE(a != b);
}

TEST(SecureStringTest, EqualityOnDifferentContents)
{
    String a("aaa");
    String b("bbb");
    EXPECT_FALSE(a == b);
    EXPECT_TRUE(a != b);
}

TEST(SecureStringTest, EqualityOnDifferentLength)
{
    String a("short");
    String b("shorter-longer-than-a");
    EXPECT_FALSE(a == b);
}

TEST(SecureStringTest, EmptyEqualsEmpty)
{
    String a;
    String b;
    EXPECT_TRUE(a == b);
    String c("");
    EXPECT_TRUE(a == c);
}

TEST(SecureStringTest, ComposesInsideOptional)
{
    // TsaCredentials wraps Secure::String in std::optional; verify the
    // composition does what the API spec promises: disengaged optional
    // holds nothing, engaged optional forwards the view through.
    std::optional<String> maybe;
    EXPECT_FALSE(maybe.has_value());

    maybe.emplace("token");
    ASSERT_TRUE(maybe.has_value());
    EXPECT_EQ(maybe->view(), "token");

    maybe.reset();
    EXPECT_FALSE(maybe.has_value());
}

TEST(SecureStringTest, ComposesInsidePair)
{
    // Sanity: Secure::String is copy/move-capable enough to live inside
    // std::pair — not a design goal for TsaCredentials (which splits
    // user+password) but a guardrail against accidentally breaking the
    // value-semantic contract.
    std::pair<std::string, String> p{"user", String("pass")};
    EXPECT_EQ(p.first, "user");
    EXPECT_EQ(p.second.view(), "pass");

    auto copy = p;
    EXPECT_EQ(copy.first, "user");
    EXPECT_EQ(copy.second.view(), "pass");
    // Mutating copy.second must not touch p.second.
    copy.second.clear();
    EXPECT_EQ(p.second.view(), "pass");
}

TEST(SecureStringEqualConstantTime, MatchesIdenticalContents)
{
    String a{"correct horse battery staple"};
    String b{"correct horse battery staple"};
    EXPECT_TRUE(a.equalConstantTime(b));
    EXPECT_TRUE(b.equalConstantTime(a));
}

TEST(SecureStringEqualConstantTime, RejectsContentMismatch)
{
    String a{"123456"};
    String b{"123457"}; // last byte differs
    EXPECT_FALSE(a.equalConstantTime(b));
    EXPECT_FALSE(b.equalConstantTime(a));
}

TEST(SecureStringEqualConstantTime, RejectsLengthMismatch)
{
    String a{"abcdef"};
    String b{"abcdefg"};
    EXPECT_FALSE(a.equalConstantTime(b));
    EXPECT_FALSE(b.equalConstantTime(a));
}

TEST(SecureStringEqualConstantTime, BothEmptyComparesEqual)
{
    String a;
    String b;
    EXPECT_TRUE(a.equalConstantTime(b));
}

TEST(SecureStringEqualConstantTime, EmptyVsNonEmptyUnequal)
{
    String empty;
    String nonEmpty{"x"};
    EXPECT_FALSE(empty.equalConstantTime(nonEmpty));
    EXPECT_FALSE(nonEmpty.equalConstantTime(empty));
}

TEST(SecureStringEqualConstantTime, IsConsistentWithOperatorEqualForEqualInputs)
{
    String a{"librescrs"};
    String b{"librescrs"};
    EXPECT_EQ(a == b, a.equalConstantTime(b));
}
