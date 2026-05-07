// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Secure/String.h>
#include <algorithm>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using namespace LibreSCRS::Auth;

TEST(CredentialProviderIntegrationTest, ProviderSeesExpectedFieldsForChangePin)
{
    std::vector<std::string> seenFieldIds;
    CredentialProvider provider = [&seenFieldIds](const AuthRequirement& req) {
        for (const auto& f : req.fields()) {
            seenFieldIds.push_back(f.id);
        }
        std::vector<CredentialResult::Entry> values;
        for (const auto& f : req.fields()) {
            values.emplace_back(f.id, LibreSCRS::Secure::String{"test"});
        }
        return CredentialResult::ok(std::move(values));
    };

    auto req = AuthRequirement::forChangePin("UserPIN", 3);
    auto result = provider(req);

    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    ASSERT_EQ(seenFieldIds.size(), 3u);
    EXPECT_EQ(seenFieldIds[0], "currentPin");
    EXPECT_EQ(seenFieldIds[1], "newPin");
    EXPECT_EQ(seenFieldIds[2], "confirmPin");
}

TEST(CredentialProviderIntegrationTest, ProviderHonorsEqualToFieldIdContract)
{
    auto req = AuthRequirement::forUnblockPin("UserPIN");
    auto fields = req.fields();
    auto confirmField =
        std::find_if(fields.begin(), fields.end(), [](const FieldDescriptor& f) { return f.id == "confirmPin"; });
    ASSERT_NE(confirmField, fields.end());
    ASSERT_TRUE(confirmField->equalToFieldId.has_value());
    EXPECT_EQ(*confirmField->equalToFieldId, "newPin");
}

TEST(CredentialProviderIntegrationTest, PreReadNoneProducesEmptyFields)
{
    CredentialProvider provider = [](const AuthRequirement& req) {
        if (req.fields().empty()) {
            return CredentialResult::ok({});
        }
        return CredentialResult::error(LibreSCRS::Auth::ErrorKeys::genericComm());
    };

    auto req = AuthRequirement::forPreRead(PreReadAuthMethod::None);
    EXPECT_TRUE(req.fields().empty());
    auto result = provider(req);
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
}

TEST(CredentialProviderIntegrationTest, EmptyValuesWithOkStatusIsLegal)
{
    CredentialProvider provider = [](const AuthRequirement&) {
        // values intentionally empty
        return CredentialResult::ok({});
    };
    auto req = AuthRequirement::forChangePin("UserPIN", 3);
    auto result = provider(req);
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    EXPECT_TRUE(result.values.empty());
    EXPECT_EQ(result.find("currentPin"), nullptr);
    // Consumer semantics: middleware treats missing field ids as MissingFields
    // at the adapter layer (see ChangePINAdapterTest.MissingFieldsProducesStructuredOutcome).
}

TEST(CredentialProviderIntegrationTest, ExtraKeysAreIgnored)
{
    CredentialProvider provider = [](const AuthRequirement&) {
        std::vector<CredentialResult::Entry> values;
        values.emplace_back("currentPin", LibreSCRS::Secure::String{"1234"});
        values.emplace_back("newPin", LibreSCRS::Secure::String{"5678"});
        values.emplace_back("confirmPin", LibreSCRS::Secure::String{"5678"});
        values.emplace_back("unexpectedExtra", LibreSCRS::Secure::String{"garbage"});
        return CredentialResult::ok(std::move(values));
    };
    auto req = AuthRequirement::forChangePin("UserPIN", 3);
    auto result = provider(req);
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    // Consumer contract: extra keys beyond fields[] are silently ignored.
    EXPECT_NE(result.find("unexpectedExtra"), nullptr);
}

TEST(CredentialProviderIntegrationTest, EmptyStringValueIsStoredAsIs)
{
    CredentialProvider provider = [](const AuthRequirement&) {
        std::vector<CredentialResult::Entry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{""});
        return CredentialResult::ok(std::move(values));
    };
    auto req = AuthRequirement::forSigning("UserPIN", 3);
    auto result = provider(req);
    const auto* pin = result.find("pin");
    ASSERT_NE(pin, nullptr);
    EXPECT_TRUE(pin->empty());
    EXPECT_EQ(pin->view(), "");
    // Contract: empty string is a distinct, legal value; middleware validates
    // length constraints (FieldDescriptor::minLength) before accepting.
}

TEST(CredentialProviderIntegrationTest, ErrorStatusCarriesMandatoryMessage)
{
    // 4.0: CredentialResult::error mandates a LocalizedText.
    // 3.x took std::optional<LocalizedText> with default std::nullopt;
    // this test asserts the new contract — every provider-error result
    // has a non-empty user-renderable message.
    CredentialProvider provider = [](const AuthRequirement&) {
        return CredentialResult::error(LibreSCRS::Auth::ErrorKeys::genericComm());
    };
    auto req = AuthRequirement::forSigning("UserPIN", 3);
    auto result = provider(req);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_FALSE(result.userMessage.key.empty());
}

// CredentialResult is no longer default-
// constructible. A buggy provider that forgets to choose an outcome
// fails at compile time rather than returning silently uninitialised
// status to a signing pipeline.
TEST(CredentialProviderIntegrationTest, ResultIsNotDefaultConstructible)
{
    static_assert(!std::is_default_constructible_v<CredentialResult>,
                  "CredentialResult must be constructed via a named factory (ok/cancelled/error)");
}

// CredentialResult::values is now a vector<pair> + find() helper.
TEST(CredentialProviderIntegrationTest, FindHelperReturnsPointerOrNull)
{
    std::vector<CredentialResult::Entry> values;
    values.emplace_back("pin", LibreSCRS::Secure::String{"9876"});
    auto result = CredentialResult::ok(std::move(values));
    const auto* found = result.find("pin");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->view(), "9876");
    EXPECT_EQ(result.find("missing"), nullptr);
}

TEST(CredentialProviderIntegrationTest, InsertionOrderIsPreserved)
{
    std::vector<CredentialResult::Entry> values;
    values.emplace_back("b", LibreSCRS::Secure::String{"1"});
    values.emplace_back("a", LibreSCRS::Secure::String{"2"});
    values.emplace_back("c", LibreSCRS::Secure::String{"3"});
    auto result = CredentialResult::ok(std::move(values));
    ASSERT_EQ(result.values.size(), 3u);
    EXPECT_EQ(result.values[0].first, "b");
    EXPECT_EQ(result.values[1].first, "a");
    EXPECT_EQ(result.values[2].first, "c");
}
