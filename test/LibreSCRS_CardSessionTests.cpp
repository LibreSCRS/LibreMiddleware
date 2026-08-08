// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <gtest/gtest.h>

#include <utility>

using LibreSCRS::SmartCard::CardSession;

TEST(CardSessionTest, OpenReturnsErrorOnBadReader)
{
    // 4.0: noexcept factory replaces the throwing constructor. A bad reader
    // name yields a populated @ref OpenError rather than an exception.
    // std::expected<CardSession, OpenError> — has_value() / error() per C++23.
    auto result = CardSession::open("No Such Reader 9999");
    ASSERT_FALSE(result.has_value());
    const auto& err = result.error();
    EXPECT_TRUE(err.diagnosticDetail.has_value());
    EXPECT_FALSE(err.userMessage.key.empty()); // 4.0: userMessage mandatory
}

TEST(CardSessionTest, DefaultMoveSemantics)
{
    // CardSession is move-only; assert via type traits
    static_assert(!std::is_copy_constructible_v<CardSession>);
    static_assert(!std::is_copy_assignable_v<CardSession>);
    static_assert(std::is_move_constructible_v<CardSession>);
    static_assert(std::is_move_assignable_v<CardSession>);
    SUCCEED();
}

// A moved-from CardSession holds no Impl and must not be used.
// This aligns with sibling pimpl-backed classes (SigningService,
// SigningRequest). Verify the move-destination retains full state; the
// moved-from source is out-of-contract for any accessor (UB) and not tested.

TEST(CardSessionMove, MoveDestinationPreservesReaderName)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    CardSession moved{std::move(*src)};
    EXPECT_EQ(moved.readerName(), "TestReader");
    EXPECT_TRUE(moved.isConnected());
}

// -- 4.1 cross-plugin secure-channel coordination surface --------------------

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>

TEST(CardSession_4_1_API, MarkDeadIsObservable)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    EXPECT_FALSE(src->isDead());
    src->markDead();
    EXPECT_TRUE(src->isDead());
}

TEST(CardSession_4_1_API, ActivateChannelForOnDeadSessionReturnsCardRemoved)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    src->markDead();
    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    auto result = src->activateChannelFor(std::move(aid), LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::CardRemoved);
}

TEST(CardSession_4_1_API, ActivateChannelWithSmCacheMissNoProviderIsCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SmartCard::SmProtocolRequest req =
        LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can};

    auto result = src->activateChannelWithSm(std::move(aid), req, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired);
}

TEST(CardSession_4_1_API, ClearCachedPaceCredentialsRestoresCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    src->setPaceSecret(LibreSCRS::Auth::PaceSecretKind::Can, LibreSCRS::Secure::String{"123456"});
    src->clearCachedPaceCredentials();

    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SmartCard::SmProtocolRequest req =
        LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can};

    auto result = src->activateChannelWithSm(std::move(aid), req, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired);
}

TEST(CardSession_4_1_API, BacRequestCacheMissNoProviderIsCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SmartCard::SmProtocolRequest req = LibreSCRS::SmartCard::BacRequest{};
    auto result = src->activateChannelWithSm(std::move(aid), req, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired);
}

TEST(CardSession_4_1_API, SetBacInputThenClearReturnsCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    LibreSCRS::SecureChannel::BacInput input;
    input.documentNumber = LibreSCRS::Secure::String{"L898902C3"};
    input.dateOfBirth = LibreSCRS::Secure::String{"740812"};
    input.dateOfExpiry = LibreSCRS::Secure::String{"120415"};
    src->setBacInput(std::move(input));

    // No reader I/O happens against a detached session; clearing forces the
    // BAC branch back to CredentialsRequired through the pre-flight short
    // circuit, proving setBacInput populates a distinct slot from
    // setPaceSecret.
    src->clearCachedPaceCredentials();
    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SmartCard::SmProtocolRequest req = LibreSCRS::SmartCard::BacRequest{};
    auto result = src->activateChannelWithSm(std::move(aid), req, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired);
}

TEST(CardSession_4_1_API, ActiveChannelHolderIsMoveOnly)
{
    using LibreSCRS::SmartCard::ActiveChannelHolder;
    static_assert(!std::is_copy_constructible_v<ActiveChannelHolder>);
    static_assert(!std::is_copy_assignable_v<ActiveChannelHolder>);
    static_assert(std::is_move_constructible_v<ActiveChannelHolder>);
    static_assert(std::is_move_assignable_v<ActiveChannelHolder>);
    SUCCEED();
}

// -- Hoist the PACE EF.CardAccess read ahead of credential resolution --------
//
// A structurally PACE-less document must surface PaceUnsupported BEFORE the
// credential provider is ever invoked — no prompt is burned on a card that
// cannot do PACE. The BAC branch performs no pre-auth read (its check is the
// post-establish SM re-read), so a BAC activation still prompts once.

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>

#include "apdu.h"
#include <pcsc_connection.h>

#include <optional>
#include <string>
#include <vector>

namespace {

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

// Minimal card filter: SELECT by AID succeeds; the MF-scoped EF.CardAccess
// probe (SELECT 3F00 -> SELECT 011C) reports EF.CardAccess definitively absent
// (clean 6A82) so the PACE branch resolves to PaceUnsupported.
APDUResponse pacelessCardFilter(const APDUCommand& cmd)
{
    if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
        return APDUResponse{{}, 0x90, 0x00}; // SELECT by AID
    if (cmd.ins == 0xA4 && cmd.p1 == 0x00) { // MF-scoped SELECT by FID
        if (cmd.data.size() == 2 && cmd.data[0] == 0x3F && cmd.data[1] == 0x00)
            return APDUResponse{{}, 0x90, 0x00}; // MF
        return APDUResponse{{}, 0x6A, 0x82};     // EF.CardAccess (011C): definitive absence
    }
    return APDUResponse{{}, 0x6D, 0x00};
}

// BAC handshake filter that drives a wrong-secret rejection: SELECT by AID
// succeeds, GET CHALLENGE returns eight bytes, and MUTUAL AUTHENTICATE answers
// 6300 so performBAC yields no session keys -> PaceWrongSecret -> the loop
// evicts the BAC input and re-prompts. No card-side crypto is needed on this
// failure path.
APDUResponse bacWrongSecretFilter(const APDUCommand& cmd)
{
    if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
        return APDUResponse{{}, 0x90, 0x00}; // SELECT by AID
    if (cmd.ins == 0x84)
        return APDUResponse{std::vector<std::uint8_t>(8, 0x00), 0x90, 0x00}; // GET CHALLENGE (RND.ICC)
    if (cmd.ins == 0x82)
        return APDUResponse{{}, 0x63, 0x00}; // MUTUAL AUTHENTICATE fails
    return APDUResponse{{}, 0x6D, 0x00};
}

// SELECT by AID succeeds; the MF-scoped EF.CardAccess probe soft-fails (6982)
// so the hoisted PACE-capability read is Unknown (NOT a definitive absence) and
// the PACE branch reaches the credential prompt rather than short-circuiting to
// PaceUnsupported before the provider is ever consulted.
APDUResponse softFailProbeFilter(const APDUCommand& cmd)
{
    if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
        return APDUResponse{{}, 0x90, 0x00};
    if (cmd.ins == 0xA4 && cmd.p1 == 0x00)
        return APDUResponse{{}, 0x69, 0x82}; // MF selection chain soft-fails -> Unknown
    return APDUResponse{{}, 0x6D, 0x00};
}

} // namespace

TEST(CardSessionPaceCapabilityHoist, PaceUnsupportedSurfacesBeforeAnyCredentialPrompt)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    LibreSCRS::SmartCard::detail::unwrap(*session).setTransmitFilter(pacelessCardFilter);

    int providerInvocations = 0;
    session->setCredentialProvider([&providerInvocations](const LibreSCRS::Auth::AuthRequirement&) {
        ++providerInvocations;
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.push_back({"can", LibreSCRS::Secure::String{"123456"}});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    });

    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    auto result = session->activateChannelWithSm(
        std::move(aid), LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can},
        LibreSCRS::CancelToken{});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::PaceUnsupported);
    EXPECT_EQ(providerInvocations, 0)
        << "the hoisted EF.CardAccess read must fail before any credential prompt on a PACE-less document";
}

TEST(CardSessionPaceCapabilityHoist, BacBranchStillPromptsBeforeEstablish)
{
    // The hoisted read is PACE-branch-only. A BacRequest against the same
    // PACE-less filter still prompts exactly once — proving the `if (!isBac)`
    // gate did not short-circuit the BAC leg.
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    LibreSCRS::SmartCard::detail::unwrap(*session).setTransmitFilter(pacelessCardFilter);

    int providerInvocations = 0;
    session->setCredentialProvider([&providerInvocations](const LibreSCRS::Auth::AuthRequirement&) {
        ++providerInvocations;
        return LibreSCRS::Auth::CredentialResult::cancelled();
    });

    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    auto result =
        session->activateChannelWithSm(std::move(aid), LibreSCRS::SmartCard::BacRequest{}, LibreSCRS::CancelToken{});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::UserCancelled);
    EXPECT_EQ(providerInvocations, 1) << "BAC performs no pre-auth EF.CardAccess read and must still prompt once";
}

// -- Rejected-retry reason on re-prompts after a wrong secret -----------------
//
// After a wrong secret is rejected inside a single activation, the re-prompt
// carries a rejected-retry reason (preReadAuthFailed) so the agent can tell a
// rejection retry apart from a legitimate same-kind re-invocation. The first
// prompt, and any prompt on a fresh activation, carries the empty reason. The
// card-reported retry counter stays nullopt on every prompt (PACE/BAC cards
// surface no counter).

namespace {

// Per-invocation snapshot of what the provider was told.
struct PromptRecord
{
    bool hasReason = false;
    std::string reasonKey;
    bool hasRetries = false;
};

} // namespace

TEST(CardSessionRejectedRetryReason, RetryPromptAfterWrongBacSecretCarriesRejectedReason)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    LibreSCRS::SmartCard::detail::unwrap(*session).setTransmitFilter(bacWrongSecretFilter);

    std::vector<PromptRecord> prompts;
    session->setCredentialProvider([&prompts](const LibreSCRS::Auth::AuthRequirement& req) {
        PromptRecord rec;
        rec.hasReason = req.message().has_value();
        if (req.message().has_value())
            rec.reasonKey = req.message()->key;
        rec.hasRetries = req.retriesLeft().has_value();
        prompts.push_back(std::move(rec));

        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.push_back({"documentNumber", LibreSCRS::Secure::String{"L898902C3"}});
        values.push_back({"dateOfBirth", LibreSCRS::Secure::String{"740812"}});
        values.push_back({"dateOfExpiry", LibreSCRS::Secure::String{"120415"}});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    });

    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    auto result =
        session->activateChannelWithSm(std::move(aid), LibreSCRS::SmartCard::BacRequest{}, LibreSCRS::CancelToken{});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::PaceWrongSecret);

    ASSERT_GE(prompts.size(), 2u) << "the wrong secret must be rejected and re-prompted at least once";
    EXPECT_FALSE(prompts[0].hasReason) << "the first prompt of an activation carries no rejected-retry reason";
    EXPECT_FALSE(prompts[0].hasRetries) << "retriesLeft stays nullopt (M5 dropped)";
    ASSERT_TRUE(prompts[1].hasReason) << "the re-prompt after a wrong secret must carry a rejected-retry reason";
    EXPECT_EQ(prompts[1].reasonKey, LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key);
    EXPECT_FALSE(prompts[1].hasRetries) << "retriesLeft stays nullopt on the re-prompt too (M5 dropped)";
}

TEST(CardSessionRejectedRetryReason, FirstPromptCarriesNoRejectedReason)
{
    // BAC branch: a single fresh prompt carries the empty reason.
    {
        auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
        ASSERT_NE(session, nullptr);
        LibreSCRS::SmartCard::detail::unwrap(*session).setTransmitFilter(pacelessCardFilter);

        std::optional<PromptRecord> first;
        session->setCredentialProvider([&first](const LibreSCRS::Auth::AuthRequirement& req) {
            if (!first.has_value()) {
                PromptRecord rec;
                rec.hasReason = req.message().has_value();
                if (req.message().has_value())
                    rec.reasonKey = req.message()->key;
                rec.hasRetries = req.retriesLeft().has_value();
                first = std::move(rec);
            }
            return LibreSCRS::Auth::CredentialResult::cancelled();
        });

        LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
        auto result = session->activateChannelWithSm(std::move(aid), LibreSCRS::SmartCard::BacRequest{},
                                                     LibreSCRS::CancelToken{});
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::UserCancelled);
        ASSERT_TRUE(first.has_value());
        EXPECT_FALSE(first->hasReason) << "BAC first prompt must carry the empty reason";
        EXPECT_FALSE(first->hasRetries);
    }

    // PACE branch: an Unknown capability read keeps the walk on PACE so the
    // provider is prompted; the first prompt still carries the empty reason.
    {
        auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Contactless Reader");
        ASSERT_NE(session, nullptr);
        LibreSCRS::SmartCard::detail::unwrap(*session).setTransmitFilter(softFailProbeFilter);

        std::optional<PromptRecord> first;
        session->setCredentialProvider([&first](const LibreSCRS::Auth::AuthRequirement& req) {
            if (!first.has_value()) {
                PromptRecord rec;
                rec.hasReason = req.message().has_value();
                if (req.message().has_value())
                    rec.reasonKey = req.message()->key;
                rec.hasRetries = req.retriesLeft().has_value();
                first = std::move(rec);
            }
            return LibreSCRS::Auth::CredentialResult::cancelled();
        });

        LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
        auto result = session->activateChannelWithSm(
            std::move(aid), LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can},
            LibreSCRS::CancelToken{});
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::UserCancelled);
        ASSERT_TRUE(first.has_value());
        EXPECT_FALSE(first->hasReason) << "PACE first prompt must carry the empty reason";
        EXPECT_FALSE(first->hasRetries);
    }
}
