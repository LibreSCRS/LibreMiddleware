// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <cstddef>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

using namespace LibreSCRS::Auth;
// LocalizedText moved to top-level LibreSCRS namespace in 4.0.
using LibreSCRS::LocalizedText;

TEST(LocalizedTextTest, DefaultConstructs)
{
    LocalizedText text;
    EXPECT_TRUE(text.key.empty());
    EXPECT_TRUE(text.defaultText.empty());
}

TEST(LocalizedTextTest, EqualityWorks)
{
    LocalizedText a{"key.a", "Fallback A"};
    LocalizedText b{"key.a", "Fallback A"};
    LocalizedText c{"key.b", "Fallback A"};
    LocalizedText d{"key.a", "Fallback D"};
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
    EXPECT_NE(a, d);
}

TEST(AuthRequirementTest, ForSigningSingleField)
{
    auto r = AuthRequirement::forSigning();
    EXPECT_EQ(r.purpose(), Purpose::Signing);
    ASSERT_EQ(r.fields().size(), 1u);
    EXPECT_EQ(r.fields()[0].minLength, std::optional<std::size_t>{4});
    EXPECT_EQ(r.fields()[0].maxLength, std::optional<std::size_t>{12});
}

// Invariant enforcement via private members. External
// code cannot construct a populated AuthRequirement — only the factories
// can.
TEST(AuthRequirementTest, DataMembersAreNotPublic)
{
    // Aggregate-init would compile if the data members were public.
    // This static_assert ensures direct brace-init is rejected.
    static_assert(!std::is_aggregate_v<AuthRequirement>,
                  "AuthRequirement must not be an aggregate — factories are the only producer");
}

// CredentialResult is no longer default-
// constructible. A buggy provider that forgets to choose an outcome
// must fail at compile time.
TEST(CredentialResultTest, NotDefaultConstructible)
{
    static_assert(!std::is_default_constructible_v<LibreSCRS::Auth::CredentialResult>,
                  "CredentialResult must be constructed via a named factory (ok/cancelled/error)");
}

TEST(CredentialResultTest, FactoriesSetStatus)
{
    auto okR = LibreSCRS::Auth::CredentialResult::ok({});
    EXPECT_EQ(okR.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    auto cancelledR = LibreSCRS::Auth::CredentialResult::cancelled();
    EXPECT_EQ(cancelledR.status, LibreSCRS::Auth::CredentialResult::Status::UserCancelled);
    auto errorR = LibreSCRS::Auth::CredentialResult::error(LibreSCRS::Auth::ErrorKeys::genericComm());
    EXPECT_EQ(errorR.status, LibreSCRS::Auth::CredentialResult::Status::Error);
    EXPECT_FALSE(errorR.userMessage.key.empty());
}

TEST(CredentialProviderTest, LambdaIsAssignable)
{
    // Compile-time: CredentialProvider must accept a lambda matching the
    // function signature. A static_assert here catches regressions in the
    // typedef shape at build time.
    static_assert(std::is_assignable_v<CredentialProvider&, CredentialResult (*)(const AuthRequirement&)>,
                  "CredentialProvider must be assignable from a matching function pointer");
}

TEST(CredentialProviderTest, LambdaReturnsSetValues)
{
    CredentialProvider p = [](const AuthRequirement&) {
        std::vector<CredentialEntry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{"1234"});
        return CredentialResult::ok(std::move(values));
    };
    auto result = p(AuthRequirement::forSigning());
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    const auto* pin = result.find("pin");
    ASSERT_NE(pin, nullptr);
    EXPECT_EQ(pin->view(), "1234");
}
