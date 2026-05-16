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
    EXPECT_EQ(result.error(),
              LibreSCRS::SecureChannel::ChannelActivationError::CardRemoved);
}

TEST(CardSession_4_1_API, ActivateChannelWithSmCacheMissNoProviderIsCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SmartCard::SmProtocolRequest req =
        LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can};

    auto result = src->activateChannelWithSm(std::move(aid), req, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(),
              LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired);
}

TEST(CardSession_4_1_API, ClearCachedPaceCredentialsRestoresCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    src->setPaceSecret(LibreSCRS::Auth::PaceSecretKind::Can,
                       LibreSCRS::Secure::String{"123456"});
    src->clearCachedPaceCredentials();

    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SmartCard::SmProtocolRequest req =
        LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can};

    auto result = src->activateChannelWithSm(std::move(aid), req, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(),
              LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired);
}

TEST(CardSession_4_1_API, BacRequestCacheMissNoProviderIsCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    LibreSCRS::SmartCard::AppletAid aid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SmartCard::SmProtocolRequest req = LibreSCRS::SmartCard::BacRequest{};
    auto result = src->activateChannelWithSm(std::move(aid), req, LibreSCRS::CancelToken{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(),
              LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired);
}

TEST(CardSession_4_1_API, SetBacInputThenClearReturnsCredentialsRequired)
{
    auto src = LibreSCRS::SmartCard::detail::makeDetachedCardSession("TestReader");
    LibreSCRS::SecureChannel::BacInput input;
    input.documentNumber = "L898902C3";
    input.dateOfBirth = "740812";
    input.dateOfExpiry = "120415";
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
    EXPECT_EQ(result.error(),
              LibreSCRS::SecureChannel::ChannelActivationError::CredentialsRequired);
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
