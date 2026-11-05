// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>

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
    auto src = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("TestReader");
    CardSession moved{std::move(*src)};
    EXPECT_EQ(moved.readerName(), "TestReader");
}

// -- 4.1 cross-plugin secure-channel coordination surface --------------------

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>

TEST(CardSession_4_1_API, ActivateChannelWithSmCacheMissNoProviderIsCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("TestReader");
    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SmartCard::SmProtocolRequest req =
        LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can};

    auto result = src->activateChannelWithSm(std::move(aid), req, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired);
}

TEST(CardSession_4_1_API, ClearCachedPaceCredentialsRestoresCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("TestReader");
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
    auto src = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("TestReader");
    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SmartCard::SmProtocolRequest req = LibreSCRS::SmartCard::BacRequest{};
    auto result = src->activateChannelWithSm(std::move(aid), req, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired);
}

TEST(CardSession_4_1_API, SetBacInputThenClearReturnsCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("TestReader");
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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
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

// EF.CardAccess naming two PACE OIDs (ECDH-GM-AES-CBC-CMAC-128 and -256,
// standardized parameters 13).
const std::vector<std::uint8_t> kTwoPaceOids = {
    0x31, 0x28,                                                                         // SET
    0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02, // OID
    0x02, 0x01, 0x02, 0x02, 0x01, 0x0D,                                                 // version, paramId
    0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04, // OID
    0x02, 0x01, 0x02, 0x02, 0x01, 0x0D};

} // namespace

// PACE with a PIN or PUK spends one of its tries on every attempt the card
// checks. A wrong PIN is tried with the first supported OID only, not once
// per OID the card lists.
TEST(CardSessionPacePin, WrongPinIsTriedOnOneOidOnly)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted PACE PIN Reader");
    int mseCount = 0;
    int mseAtSecondPrompt = -1;
    std::uint16_t selected = 0;
    LibreSCRS::SmartCard::detail::unwrap(*session).setTransmitFilter([&](const APDUCommand& cmd) {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return APDUResponse{{}, 0x90, 0x00};
        if (cmd.ins == 0xA4 && cmd.p1 == 0x00 && cmd.data.size() == 2) {
            selected = static_cast<std::uint16_t>((cmd.data[0] << 8) | cmd.data[1]);
            return APDUResponse{{}, 0x90, 0x00};
        }
        if (cmd.ins == 0xB0 && selected == 0x011C) {
            const std::size_t offset = (static_cast<std::size_t>(cmd.p1 & 0x7F) << 8) | cmd.p2;
            if (offset >= kTwoPaceOids.size())
                return APDUResponse{{}, 0x6B, 0x00};
            return APDUResponse{
                {kTwoPaceOids.begin() + static_cast<std::ptrdiff_t>(offset), kTwoPaceOids.end()}, 0x90, 0x00};
        }
        if (cmd.ins == 0x22) { // MSE:SET AT -- one per PACE attempt
            ++mseCount;
            return APDUResponse{{}, 0x90, 0x00};
        }
        if (cmd.ins == 0x86) // GENERAL AUTHENTICATE: the card refuses
            return APDUResponse{{}, 0x63, 0xC2};
        return APDUResponse{{}, 0x6D, 0x00};
    });

    int providerInvocations = 0;
    session->setCredentialProvider([&](const LibreSCRS::Auth::AuthRequirement&) {
        if (++providerInvocations > 1) {
            mseAtSecondPrompt = mseCount;
            return LibreSCRS::Auth::CredentialResult::cancelled();
        }
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.push_back({"pin", LibreSCRS::Secure::String{"123456"}});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    });

    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    (void)session->activateChannelWithSm(std::move(aid),
                                         LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Pin},
                                         LibreSCRS::CancelToken{});

    ASSERT_GE(providerInvocations, 2) << "the wrong PIN is followed by a new prompt";
    EXPECT_EQ(mseAtSecondPrompt, 1) << "one PACE attempt per PIN entered, not one per OID";
}

namespace {

// A card listing kTwoPaceOids. MSE:Set AT is answered by @p mseSw for each
// attempt in turn (the last entry repeats); every General Authenticate is
// refused with 63C2. @p mseOids records the OID each MSE:Set AT carried.
struct TwoOidPaceCard
{
    std::vector<std::uint16_t> mseSw;
    std::vector<std::vector<std::uint8_t>> mseOids;
    int mseAtSecondPrompt = -1;
    std::uint16_t selected = 0;

    APDUResponse operator()(const APDUCommand& cmd)
    {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return APDUResponse{{}, 0x90, 0x00};
        if (cmd.ins == 0xA4 && cmd.p1 == 0x00 && cmd.data.size() == 2) {
            selected = static_cast<std::uint16_t>((cmd.data[0] << 8) | cmd.data[1]);
            return APDUResponse{{}, 0x90, 0x00};
        }
        if (cmd.ins == 0xB0 && selected == 0x011C) {
            const std::size_t offset = (static_cast<std::size_t>(cmd.p1 & 0x7F) << 8) | cmd.p2;
            if (offset >= kTwoPaceOids.size())
                return APDUResponse{{}, 0x6B, 0x00};
            return APDUResponse{
                {kTwoPaceOids.begin() + static_cast<std::ptrdiff_t>(offset), kTwoPaceOids.end()}, 0x90, 0x00};
        }
        if (cmd.ins == 0x22) { // MSE:SET AT -- 80 <len> <oid> ...
            const auto n = std::min<std::size_t>(mseOids.size(), mseSw.size() - 1);
            mseOids.emplace_back(cmd.data.begin() + 2, cmd.data.begin() + 2 + cmd.data[1]);
            return APDUResponse{
                {}, static_cast<std::uint8_t>(mseSw[n] >> 8), static_cast<std::uint8_t>(mseSw[n] & 0xFF)};
        }
        if (cmd.ins == 0x86) // GENERAL AUTHENTICATE: the card refuses
            return APDUResponse{{}, 0x63, 0xC2};
        return APDUResponse{{}, 0x6D, 0x00};
    }
};

// Activates PACE with @p kind against @p card, answering the first prompt with
// a value and cancelling the second (recording how many MSE:Set AT the first
// value cost).
std::expected<LibreSCRS::SmartCard::ActiveChannelHolder, LibreSCRS::SecureChannel::ChannelActivationError>
activateOnce(const std::shared_ptr<CardSession>& session, TwoOidPaceCard& card, LibreSCRS::Auth::PaceSecretKind kind,
             const char* id, int& prompts)
{
    LibreSCRS::SmartCard::detail::unwrap(*session).setTransmitFilter(
        [&card](const APDUCommand& cmd) { return card(cmd); });
    session->setCredentialProvider([&card, &prompts, id](const LibreSCRS::Auth::AuthRequirement&) {
        if (++prompts > 1) {
            card.mseAtSecondPrompt = static_cast<int>(card.mseOids.size());
            return LibreSCRS::Auth::CredentialResult::cancelled();
        }
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.push_back({id, LibreSCRS::Secure::String{"123456"}});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    });
    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    return session->activateChannelWithSm(std::move(aid), LibreSCRS::SmartCard::PaceRequest{kind},
                                          LibreSCRS::CancelToken{});
}

const std::vector<std::uint8_t> kFirstOid = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02};
const std::vector<std::uint8_t> kSecondOid = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04};

} // namespace

// The card refusing MSE:Set AT for an OID says it does not support it; no
// try was spent, so the PIN goes to the next OID the card lists -- and only
// there.
TEST(CardSessionPaceOid, AnOidTheCardRefusesHandsThePinToTheNextOne)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted PACE OID Reader");
    TwoOidPaceCard card;
    card.mseSw = {0x6A80, 0x9000};
    int prompts = 0;
    (void)activateOnce(session, card, LibreSCRS::Auth::PaceSecretKind::Pin, "pin", prompts);

    ASSERT_GE(prompts, 2) << "the refused PIN is followed by a new prompt";
    EXPECT_EQ(card.mseAtSecondPrompt, 2) << "the refused OID, then the next one -- once";
    ASSERT_GE(card.mseOids.size(), 2u);
    EXPECT_EQ(card.mseOids[0], kFirstOid);
    EXPECT_EQ(card.mseOids[1], kSecondOid);
}

// Once the card has taken an OID, a refused General Authenticate ends the
// walk for a CAN as for a PIN: the next OID would put the same value to the
// card again.
TEST(CardSessionPaceOid, AWrongCanIsTriedWithOneOidOnly)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted PACE CAN Reader");
    TwoOidPaceCard card;
    card.mseSw = {0x9000};
    int prompts = 0;
    (void)activateOnce(session, card, LibreSCRS::Auth::PaceSecretKind::Can, "can", prompts);

    ASSERT_GE(prompts, 2) << "the wrong CAN is followed by a new prompt";
    EXPECT_EQ(card.mseAtSecondPrompt, 1) << "one PACE attempt per CAN entered, not one per OID";
}

// A card that lists OIDs and refuses every one of them is a protocol failure,
// not a PACE-less document (which would invite the BAC fallback), and not a
// wrong CAN to prompt for again.
TEST(CardSessionPaceOid, ACardRefusingEveryOidItListsIsAProtocolFailure)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted PACE refusing Reader");
    TwoOidPaceCard card;
    card.mseSw = {0x6A80};
    int prompts = 0;
    auto result = activateOnce(session, card, LibreSCRS::Auth::PaceSecretKind::Can, "can", prompts);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LibreSCRS::SecureChannel::ChannelActivationError::PaceProtocolFailure);
    EXPECT_EQ(prompts, 1);
    EXPECT_EQ(card.mseOids.size(), 2u);
}

TEST(CardSessionPaceCapabilityHoist, PaceUnsupportedSurfacesBeforeAnyCredentialPrompt)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted Contactless Reader");
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
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted Contactless Reader");
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
};

} // namespace

TEST(CardSessionRejectedRetryReason, RetryPromptAfterWrongBacSecretCarriesRejectedReason)
{
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted Contactless Reader");
    ASSERT_NE(session, nullptr);
    LibreSCRS::SmartCard::detail::unwrap(*session).setTransmitFilter(bacWrongSecretFilter);

    std::vector<PromptRecord> prompts;
    session->setCredentialProvider([&prompts](const LibreSCRS::Auth::AuthRequirement& req) {
        PromptRecord rec;
        rec.hasReason = req.message().has_value();
        if (req.message().has_value())
            rec.reasonKey = req.message()->key;
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
    ASSERT_TRUE(prompts[1].hasReason) << "the re-prompt after a wrong secret must carry a rejected-retry reason";
    EXPECT_EQ(prompts[1].reasonKey, LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key);
}

TEST(CardSessionRejectedRetryReason, FirstPromptCarriesNoRejectedReason)
{
    // BAC branch: a single fresh prompt carries the empty reason.
    {
        auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted Contactless Reader");
        ASSERT_NE(session, nullptr);
        LibreSCRS::SmartCard::detail::unwrap(*session).setTransmitFilter(pacelessCardFilter);

        std::optional<PromptRecord> first;
        session->setCredentialProvider([&first](const LibreSCRS::Auth::AuthRequirement& req) {
            if (!first.has_value()) {
                PromptRecord rec;
                rec.hasReason = req.message().has_value();
                if (req.message().has_value())
                    rec.reasonKey = req.message()->key;
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
    }

    // PACE branch: an Unknown capability read keeps the walk on PACE so the
    // provider is prompted; the first prompt still carries the empty reason.
    {
        auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted Contactless Reader");
        ASSERT_NE(session, nullptr);
        LibreSCRS::SmartCard::detail::unwrap(*session).setTransmitFilter(softFailProbeFilter);

        std::optional<PromptRecord> first;
        session->setCredentialProvider([&first](const LibreSCRS::Auth::AuthRequirement& req) {
            if (!first.has_value()) {
                PromptRecord rec;
                rec.hasReason = req.message().has_value();
                if (req.message().has_value())
                    rec.reasonKey = req.message()->key;
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
    }
}
