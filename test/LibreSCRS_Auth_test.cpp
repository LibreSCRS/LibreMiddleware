// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/FieldDescriptor.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
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
    EXPECT_TRUE(text.placeholders.empty());
}

TEST(LocalizedTextTest, EqualityWorks)
{
    LocalizedText a{"key.a", "Fallback A", {{"name", "Ivan"}}};
    LocalizedText b{"key.a", "Fallback A", {{"name", "Ivan"}}};
    LocalizedText c{"key.b", "Fallback A", {{"name", "Ivan"}}};
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(FieldDescriptorTest, NumericPinDefaults)
{
    FieldDescriptor f{
        .id = "currentPin",
        .type = CredentialFieldType::NumericPin,
        .secret = true,
        .minLength = std::size_t{4},
        .maxLength = std::size_t{8},
        .label =
            LocalizedText{.key = "librescrs.auth.label.currentPin", .defaultText = "Current PIN", .placeholders = {}},
        .helpText = std::nullopt,
        .equalToFieldId = std::nullopt,
    };
    EXPECT_EQ(f.id, "currentPin");
    EXPECT_TRUE(f.secret);
    ASSERT_TRUE(f.minLength.has_value());
    EXPECT_EQ(*f.minLength, 4u);
    ASSERT_TRUE(f.maxLength.has_value());
    EXPECT_EQ(*f.maxLength, 8u);
    EXPECT_FALSE(f.equalToFieldId.has_value());
}

TEST(FieldDescriptorTest, EqualToFieldIdBinds)
{
    FieldDescriptor f;
    f.id = "confirmPin";
    f.equalToFieldId = "newPin";
    EXPECT_TRUE(f.equalToFieldId.has_value());
    EXPECT_EQ(*f.equalToFieldId, "newPin");
}

TEST(AuthRequirementTest, ForPreReadPaceCanHasOneCanField)
{
    auto r = AuthRequirement::forPreRead(PreReadAuthMethod::PaceCan);
    EXPECT_EQ(r.purpose(), Purpose::PreRead);
    ASSERT_EQ(r.fields().size(), 1u);
    EXPECT_EQ(r.fields()[0].id, "can");
    EXPECT_EQ(r.fields()[0].type, CredentialFieldType::NumericCan);
    EXPECT_FALSE(r.fields()[0].secret);
}

TEST(AuthRequirementTest, ForPreReadBacMrzHasOneMrzField)
{
    auto r = AuthRequirement::forPreRead(PreReadAuthMethod::BacMrz);
    ASSERT_EQ(r.fields().size(), 1u);
    EXPECT_EQ(r.fields()[0].type, CredentialFieldType::Mrz);
}

TEST(AuthRequirementTest, ForPreReadNoneIsEmpty)
{
    auto r = AuthRequirement::forPreRead(PreReadAuthMethod::None);
    EXPECT_TRUE(r.fields().empty());
}

TEST(AuthRequirementTest, ForSigningSingleField)
{
    auto r = AuthRequirement::forSigning(LocalizedText{"", "UserPIN", {}}, 3);
    EXPECT_EQ(r.purpose(), Purpose::Signing);
    ASSERT_EQ(r.fields().size(), 1u);
    EXPECT_EQ(r.fields()[0].id, "pin");
    ASSERT_TRUE(r.retriesLeft().has_value());
    EXPECT_EQ(*r.retriesLeft(), 3);
}

TEST(AuthRequirementTest, ForChangePinThreeFieldsConfirmBound)
{
    auto r = AuthRequirement::forChangePin(LocalizedText{"", "UserPIN", {}}, 3);
    EXPECT_EQ(r.purpose(), Purpose::ChangePin);
    ASSERT_EQ(r.fields().size(), 3u);
    EXPECT_EQ(r.fields()[0].id, "currentPin");
    EXPECT_EQ(r.fields()[1].id, "newPin");
    EXPECT_EQ(r.fields()[2].id, "confirmPin");
    ASSERT_TRUE(r.fields()[2].equalToFieldId.has_value());
    EXPECT_EQ(*r.fields()[2].equalToFieldId, "newPin");
}

TEST(AuthRequirementTest, ForUnblockPinThreeFieldsFirstIsPuk)
{
    auto r = AuthRequirement::forUnblockPin(LocalizedText{"", "UserPIN", {}});
    EXPECT_EQ(r.purpose(), Purpose::UnblockPin);
    ASSERT_EQ(r.fields().size(), 3u);
    EXPECT_EQ(r.fields()[0].id, "puk");
    EXPECT_EQ(r.fields()[0].type, CredentialFieldType::AlphaNumericPuk);
    EXPECT_EQ(r.fields()[1].id, "newPin");
    EXPECT_EQ(r.fields()[2].id, "confirmPin");
    ASSERT_TRUE(r.fields()[2].equalToFieldId.has_value());
    EXPECT_EQ(*r.fields()[2].equalToFieldId, "newPin");
}

TEST(AuthRequirementTest, ForChangePinLocalizedTextOverload)
{
    LocalizedText label;
    label.key = "auth.pin.label";
    label.defaultText = "Auth PIN";
    auto r = AuthRequirement::forChangePin(label, 3);
    EXPECT_EQ(r.purpose(), Purpose::ChangePin);
    ASSERT_EQ(r.fields().size(), 3u);
    // All three fields share the same LocalizedText label (per design
    // note in header — role distinguished via field id).
    EXPECT_EQ(r.fields()[0].id, "currentPin");
    EXPECT_EQ(r.fields()[0].label.key, "auth.pin.label");
    EXPECT_EQ(r.fields()[0].label.defaultText, "Auth PIN");
    EXPECT_EQ(r.fields()[1].id, "newPin");
    EXPECT_EQ(r.fields()[1].label.key, "auth.pin.label");
    EXPECT_EQ(r.fields()[2].id, "confirmPin");
    ASSERT_TRUE(r.retriesLeft().has_value());
    EXPECT_EQ(*r.retriesLeft(), 3);
}

TEST(AuthRequirementTest, ForChangePinLocalizedTextEmptyThrows)
{
    LocalizedText empty;
    EXPECT_THROW((void)AuthRequirement::forChangePin(empty, 3), std::invalid_argument);
}

TEST(AuthRequirementTest, ForChangePinLocalizedTextI18nKeyOnly)
{
    LocalizedText label;
    label.key = "auth.pin.label"; // defaultText intentionally empty
    auto r = AuthRequirement::forChangePin(label, -1);
    ASSERT_EQ(r.fields().size(), 3u);
    EXPECT_EQ(r.fields()[0].label.key, "auth.pin.label");
    EXPECT_FALSE(r.retriesLeft().has_value());
}

TEST(AuthRequirementTest, ForUnblockPinLocalizedTextOverload)
{
    LocalizedText label;
    label.key = "auth.pin.label";
    label.defaultText = "Auth PIN";
    auto r = AuthRequirement::forUnblockPin(label);
    EXPECT_EQ(r.purpose(), Purpose::UnblockPin);
    ASSERT_EQ(r.fields().size(), 3u);
    EXPECT_EQ(r.fields()[0].id, "puk"); // first field is PUK
    EXPECT_EQ(r.fields()[1].id, "newPin");
    EXPECT_EQ(r.fields()[1].label.key, "auth.pin.label");
    EXPECT_EQ(r.fields()[2].id, "confirmPin");
    EXPECT_FALSE(r.retriesLeft().has_value());
}

TEST(AuthRequirementTest, ForUnblockPinLocalizedTextEmptyThrows)
{
    LocalizedText empty;
    EXPECT_THROW((void)AuthRequirement::forUnblockPin(empty), std::invalid_argument);
}

TEST(AuthRequirementTest, ForUnblockPinLocalizedTextEnglishFallbackOnly)
{
    LocalizedText label;
    label.defaultText = "Auth PIN"; // key intentionally empty
    auto r = AuthRequirement::forUnblockPin(label);
    ASSERT_EQ(r.fields().size(), 3u);
    EXPECT_EQ(r.fields()[1].label.defaultText, "Auth PIN");
}

// Invariant enforcement via private members. External
// code cannot construct a populated AuthRequirement — only the factories
// can, so the documented invariants (unique field ids, valid
// equalToFieldId back-references) are structurally protected.
TEST(AuthRequirementTest, DataMembersAreNotPublic)
{
    // Aggregate-init would compile if `fields` / `retriesLeft` were public.
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
        std::vector<CredentialResult::Entry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{"1234"});
        return CredentialResult::ok(std::move(values));
    };
    auto result = p(AuthRequirement::forSigning(LocalizedText{"", "UserPIN", {}}, 3));
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    const auto* pin = result.find("pin");
    ASSERT_NE(pin, nullptr);
    EXPECT_EQ(pin->view(), "1234");
}

// ABI v6 retired the CredentialProvider-based CardPlugin::changePIN overload
// (and its LibreSCRS::Plugin::detail::runChangePinAdapter helper) in favour
// of a direct (oldPin, newPin) Secure::String signature. The previous
// ChangePINAdapter*Test cases lived here — they've been removed along with
// the adapter. Host applications that still want provider-driven UX call
// AuthRequirement::forChangePin + CredentialProvider themselves and feed
// the resulting Secure::Strings into CardPlugin::changePIN directly.

TEST(AuthRequirementTest, ForChangePinWithUnknownRetriesLeavesNullopt)
{
    auto r = LibreSCRS::Auth::AuthRequirement::forChangePin(LocalizedText{"", "UserPIN", {}}, -1);
    EXPECT_FALSE(r.retriesLeft().has_value());
}

TEST(AuthRequirementTest, ForSigningWithUnknownRetriesLeavesNullopt)
{
    auto r = LibreSCRS::Auth::AuthRequirement::forSigning(LocalizedText{"", "UserPIN", {}}, -1);
    EXPECT_FALSE(r.retriesLeft().has_value());
}

// §5.1 alignment: factories that validate caller-supplied inputs throw
// std::invalid_argument with a message identifying the bad field.

TEST(AuthRequirementTest, ForSigningThrowsOnEmptyLabel)
{
    EXPECT_THROW((void)LibreSCRS::Auth::AuthRequirement::forSigning(LocalizedText{}, 3), std::invalid_argument);
}

TEST(AuthRequirementTest, ForChangePinThrowsOnEmptyLabel)
{
    EXPECT_THROW((void)LibreSCRS::Auth::AuthRequirement::forChangePin(LocalizedText{}, 3), std::invalid_argument);
}

TEST(AuthRequirementTest, ForUnblockPinThrowsOnEmptyLabel)
{
    EXPECT_THROW((void)LibreSCRS::Auth::AuthRequirement::forUnblockPin(LocalizedText{}), std::invalid_argument);
}

// Pass-5 P4: LocalizedText overload preserves the i18n key end-to-end so
// hosts can translate the PIN label without the std::string overload's
// implicit "synthesise key from field id" leak.
TEST(AuthRequirementTest, ForSigningLocalizedTextPreservesI18nKey)
{
    LibreSCRS::LocalizedText label{
        .key = "librescrs.signing.label.pin", .defaultText = "Signing PIN", .placeholders = {}};
    auto r = LibreSCRS::Auth::AuthRequirement::forSigning(label, 2);
    ASSERT_EQ(r.fields().size(), 1u);
    EXPECT_EQ(r.fields()[0].id, "pin");
    EXPECT_EQ(r.fields()[0].label.key, "librescrs.signing.label.pin");
    EXPECT_EQ(r.fields()[0].label.defaultText, "Signing PIN");
    ASSERT_TRUE(r.retriesLeft().has_value());
    EXPECT_EQ(*r.retriesLeft(), 2);
}

TEST(AuthRequirementTest, ForSigningLocalizedTextThrowsWhenBothPartsEmpty)
{
    LibreSCRS::LocalizedText empty{};
    EXPECT_THROW((void)LibreSCRS::Auth::AuthRequirement::forSigning(empty, 0), std::invalid_argument);
}

TEST(AuthRequirementTest, ForSigningLocalizedTextAcceptsKeyOnlyOrFallbackOnly)
{
    LibreSCRS::LocalizedText keyOnly{.key = "k", .defaultText = "", .placeholders = {}};
    LibreSCRS::LocalizedText fallbackOnly{.key = "", .defaultText = "f", .placeholders = {}};
    EXPECT_NO_THROW((void)LibreSCRS::Auth::AuthRequirement::forSigning(keyOnly, -1));
    EXPECT_NO_THROW((void)LibreSCRS::Auth::AuthRequirement::forSigning(fallbackOnly, -1));
}

TEST(AuthRequirementTest, ForPreReadIsNoexcept)
{
    static_assert(noexcept(LibreSCRS::Auth::AuthRequirement::forPreRead(LibreSCRS::Auth::PreReadAuthMethod::None)),
                  "forPreRead must be noexcept — closed enum, no validation");
    // Sanity: exercise all three enum values at runtime.
    auto none = LibreSCRS::Auth::AuthRequirement::forPreRead(LibreSCRS::Auth::PreReadAuthMethod::None);
    auto bac = LibreSCRS::Auth::AuthRequirement::forPreRead(LibreSCRS::Auth::PreReadAuthMethod::BacMrz);
    auto pace = LibreSCRS::Auth::AuthRequirement::forPreRead(LibreSCRS::Auth::PreReadAuthMethod::PaceCan);
    EXPECT_TRUE(none.fields().empty());
    EXPECT_EQ(bac.fields().size(), 1u);
    EXPECT_EQ(pace.fields().size(), 1u);
}
