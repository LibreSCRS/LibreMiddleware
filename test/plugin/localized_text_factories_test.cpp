// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief 4.0 mandatory @ref LibreSCRS::LocalizedText userMessage on
///        @ref LibreSCRS::Plugin::ReadResult,
///        @ref LibreSCRS::Signing::SigningResult, and
///        @ref LibreSCRS::SmartCard::OpenError. The factories require a
///        message; callers without a card-specific text pass one of the
///        @ref LibreSCRS::Auth::ErrorKeys generic builders.

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardData.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/Signing/SigningResult.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <utility>
#include <variant>

using namespace LibreSCRS;

// ----------------------------------------------------------------------------
// ReadResult — every factory mandates a LocalizedText; success carries the
// generic @ref Auth::ErrorKeys::readOk text.

TEST(ReadResultFactories, OkOutcomeCarriesNonEmptyMessage)
{
    Plugin::CardData data;
    auto r = Plugin::ReadResult::ok(std::move(data));
    EXPECT_EQ(r.status, Plugin::ReadResult::Status::Ok);
    EXPECT_FALSE(r.userMessage.key.empty());
    EXPECT_EQ(r.userMessage.key, "librescrs.read.ok");
}

TEST(ReadResultFactories, CommunicationErrorCarriesGenericKey)
{
    auto r =
        Plugin::ReadResult::communicationError(Auth::ErrorKeys::genericComm(), std::string{"reader returned 6300"});
    EXPECT_EQ(r.status, Plugin::ReadResult::Status::CommunicationError);
    EXPECT_EQ(r.userMessage.key, "librescrs.error.communication.generic");
    ASSERT_TRUE(r.diagnosticDetail.has_value());
    EXPECT_EQ(*r.diagnosticDetail, "reader returned 6300");
}

TEST(ReadResultFactories, UnsupportedCardCarriesGenericMessage)
{
    auto r = Plugin::ReadResult::unsupportedCard(Auth::ErrorKeys::unsupportedCard());
    EXPECT_EQ(r.status, Plugin::ReadResult::Status::UnsupportedCard);
    EXPECT_EQ(r.userMessage.key, "librescrs.error.unsupported.generic");
}

TEST(ReadResultFactories, AuthenticationFailedCarriesGenericMessage)
{
    auto r = Plugin::ReadResult::authenticationFailed(Auth::ErrorKeys::authFailed());
    EXPECT_EQ(r.status, Plugin::ReadResult::Status::AuthenticationFailed);
    EXPECT_EQ(r.userMessage.key, "librescrs.error.auth.generic");
}

TEST(ReadResultFactories, CancelledCarriesCancelledKey)
{
    auto r = Plugin::ReadResult::cancelled();
    EXPECT_EQ(r.status, Plugin::ReadResult::Status::Cancelled);
    EXPECT_EQ(r.userMessage.key, "librescrs.error.cancelled");
    EXPECT_FALSE(r.data.has_value());
    EXPECT_FALSE(r.diagnosticDetail.has_value());
}

// ----------------------------------------------------------------------------
// SigningResult — every factory mandates a LocalizedText; specific factories
// (userCancelled, trustStoreUnavailable) substitute appropriate generic keys.

TEST(SigningResultFactories, OkCarriesGenericSignOkMessage)
{
    auto r = Signing::SigningResult::okWithBytes({0x25, 0x50});
    EXPECT_EQ(r.status, Signing::SigningResult::Status::Ok);
    EXPECT_EQ(r.userMessage.key, "librescrs.sign.ok");
}

TEST(SigningResultFactories, InvalidRequestCarriesProvidedMessage)
{
    auto r = Signing::SigningResult::invalidRequest(
        LocalizedText{"signing.invalid.output_missing", "The output path is missing."});
    EXPECT_EQ(r.status, Signing::SigningResult::Status::InvalidRequest);
    EXPECT_EQ(r.userMessage.key, "signing.invalid.output_missing");
    EXPECT_EQ(r.userMessage.defaultText, "The output path is missing.");
}

TEST(SigningResultFactories, UserCancelledCarriesUserCancelledKey)
{
    auto r = Signing::SigningResult::userCancelled();
    EXPECT_EQ(r.status, Signing::SigningResult::Status::UserCancelled);
    EXPECT_EQ(r.userMessage.key, "librescrs.error.user.cancelled");
}

TEST(SigningResultFactories, TrustStoreUnavailableDiagnosticOnlyCarriesGenericKey)
{
    auto r = Signing::SigningResult::trustStoreUnavailableDiagnosticOnly(std::string{"TL unreachable"});
    EXPECT_EQ(r.status, Signing::SigningResult::Status::TrustStoreUnavailable);
    EXPECT_EQ(r.userMessage.key, "librescrs.error.sign.trustStore");
    ASSERT_TRUE(r.diagnosticDetail.has_value());
}

TEST(SigningResultFactories, SigningEngineErrorDiagnosticOnlySubstitutesGenericMessage)
{
    auto r = Signing::SigningResult::signingEngineErrorDiagnosticOnly(std::string{"libresign internal failure"});
    EXPECT_EQ(r.status, Signing::SigningResult::Status::SigningEngineError);
    EXPECT_EQ(r.userMessage.key, "librescrs.error.sign.engine");
    ASSERT_TRUE(r.diagnosticDetail.has_value());
}

// ----------------------------------------------------------------------------
// OpenError — userMessage is no longer optional; producers populate it.

TEST(OpenErrorShape, UserMessageIsAlwaysPopulated)
{
    SmartCard::OpenError e{SmartCard::OpenError::Kind::ReaderUnavailable, Auth::ErrorKeys::readerUnavailable(),
                           std::nullopt};
    EXPECT_EQ(e.userMessage.key, "librescrs.error.reader.unavailable");
}

TEST(OpenErrorShape, NoCardPresentBuildsAppropriateKey)
{
    SmartCard::OpenError e{SmartCard::OpenError::Kind::NoCardPresent, Auth::ErrorKeys::noCardPresent(), std::nullopt};
    EXPECT_EQ(e.userMessage.key, "librescrs.error.reader.nocard");
}

// ----------------------------------------------------------------------------
// ErrorKeys builders — sanity-check the generic-key set.

TEST(ErrorKeysBuilders, AllBuildersReturnNonEmptyKeyAndFallback)
{
    const LocalizedText all[] = {
        Auth::ErrorKeys::genericComm(),
        Auth::ErrorKeys::unsupportedCard(),
        Auth::ErrorKeys::authFailed(),
        Auth::ErrorKeys::cancelled(),
        Auth::ErrorKeys::readerUnavailable(),
        Auth::ErrorKeys::noCardPresent(),
        Auth::ErrorKeys::readOk(),
        Auth::ErrorKeys::signOk(),
        Auth::ErrorKeys::signingEngineError(),
        Auth::ErrorKeys::trustStoreUnavailable(),
        Auth::ErrorKeys::userCancelled(),
    };
    for (const auto& lt : all) {
        EXPECT_FALSE(lt.key.empty()) << "empty key on builder";
        EXPECT_FALSE(lt.defaultText.empty()) << "empty defaultText on builder";
    }
}

// ----------------------------------------------------------------------------
// SignResultOutcome::Cancelled — 4.0 introduces this distinct outcome.

TEST(SignResultOutcomeShape, CancelledIsNotOk)
{
    // 4.0 hardening: use the named factory rather than mutating
    // outcome by hand — the factory is the only way callers should construct
    // the cancelled-shape SignResult.
    Plugin::SignResult r = Plugin::SignResult::cancelled();
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.outcome, Plugin::SignResultOutcome::Cancelled);
    EXPECT_NE(r.outcome, Plugin::SignResultOutcome::NotImplemented);
    EXPECT_NE(r.outcome, Plugin::SignResultOutcome::Ok);
    EXPECT_TRUE(r.signature.empty());
}
