// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Regression tests for the CardSession re-entrancy guard.
///
/// @ref LibreSCRS::SmartCard::ActiveChannelHolder holds the session's
/// non-recursive @c sessionMutex for its lifetime; every CardSession entry
/// point re-locks it. A consumer calling a session method on the thread that
/// holds the holder therefore self-deadlocks. The guard tracks the owning
/// thread in @c Impl::activeChannelOwner: the holder-producing factories
/// (@c activateChannelWithSm / @c activateChannelFor) return
/// @ref LibreSCRS::SecureChannel::ChannelActivationError::ReentrantAccess
/// instead of blocking when the calling thread already owns the channel.
///
/// To obtain a genuine holder without a live reader, the tests drive the
/// real @ref CardSession::activateChannelFor fast path on a detached
/// session: a @ref LibreSCRS::SecureChannel::PlainChannel bound to the
/// target applet is installed via the channel-injection seam, so the
/// fast-path branch returns a holder built by the production
/// @c makeActiveChannelHolder factory — exercising the real owner set
/// (factory) and clear (holder release) paths. The detached connection's
/// @c CardTransaction is a no-op, so the transaction setup succeeds.
///
/// A watchdog thread aborts the suite if a test body fails to complete
/// within a deadline, so a regression that re-introduces the deadlock fails
/// loudly instead of hanging the suite.

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>
#include <session_access.h>

#include "fake_channel.h"

#include <pcsc_connection.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <thread>
#include <utility>
#include <variant>

namespace {

using LibreSCRS::SecureChannel::ChannelActivationError;
using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::PlainChannel;
using LibreSCRS::SecureChannel::TestSupport::FakeChannel;
using LibreSCRS::SmartCard::ActiveChannelHolder;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::PaceRequest;
using LibreSCRS::SmartCard::SmProtocolRequest;
using LibreSCRS::SmartCard::detail::ChannelInjector;
using LibreSCRS::SmartCard::Testing::makeDetachedCardSession;

constexpr const char* kReader = "Phantom Reader 0";

AppletAid makeAid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
}

SmProtocolRequest paceReq()
{
    return PaceRequest{};
}

// Install an SM-carrying fake channel (carriesSm=true) in @p state and stamp
// @p recordedProtocol as the session's activatedProtocol under the same lock,
// mirroring the activation paths. Returns a borrowed pointer for inspection;
// the session retains ownership.
FakeChannel* installSmFake(CardSession& session, ChannelState state, std::optional<SmProtocolRequest> recordedProtocol)
{
    auto channel = std::make_unique<FakeChannel>(makeAid(), state, /*carriesSm=*/true);
    auto* ptr = channel.get();
    ChannelInjector::installForTesting(session, std::move(channel), std::move(recordedProtocol));
    return ptr;
}

// Acquire a genuine ActiveChannelHolder over the Open SM fake installed with
// @p protocol recorded, via the activateChannelWithSm same-applet fast path: no
// wire traffic, and the production makeActiveChannelHolder factory takes the
// session lock and marks this thread as the owner. That is the holder-owner
// condition under which the public, mutex-locking CardSession::activatedProtocol
// aborts (debug) or self-deadlocks (release).
ActiveChannelHolder acquireSmHolder(CardSession& session, const SmProtocolRequest& protocol)
{
    auto result = session.activateChannelWithSm(makeAid(), protocol, LibreSCRS::CancelToken{});
    EXPECT_TRUE(result.has_value());
    return std::move(result).value();
}

// Acquire a genuine ActiveChannelHolder on a detached session via the real
// activateChannelFor fast path. Installs a PlainChannel bound to makeAid()
// (Open) so the fast-path dynamic_cast<PlainChannel*> succeeds and the
// production makeActiveChannelHolder factory runs — setting the owner.
ActiveChannelHolder acquireHolder(CardSession& session)
{
    auto plain = std::make_unique<PlainChannel>(LibreSCRS::SmartCard::Internal::connectionOf(session), makeAid());
    ChannelInjector::installForTesting(session, std::move(plain));
    auto result = session.activateChannelFor(makeAid(), LibreSCRS::CancelToken{});
    EXPECT_TRUE(result.has_value());
    return std::move(result).value();
}

// RAII watchdog: aborts the process if the test body does not signal
// completion within the deadline. Protects the suite against a regression
// that re-introduces the same-thread deadlock (the guarded calls would
// otherwise hang forever on the non-recursive sessionMutex).
class Watchdog
{
public:
    explicit Watchdog(std::chrono::milliseconds deadline) : deadline(deadline)
    {
        thread = std::thread([this] {
            const auto start = std::chrono::steady_clock::now();
            while (!done.load(std::memory_order_acquire)) {
                if (std::chrono::steady_clock::now() - start > this->deadline) {
                    std::fputs("CardSession re-entrancy test watchdog tripped — likely a "
                               "re-introduced self-deadlock. Aborting.\n",
                               stderr);
                    std::abort();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }
        });
    }

    ~Watchdog()
    {
        done.store(true, std::memory_order_release);
        if (thread.joinable()) {
            thread.join();
        }
    }

    Watchdog(const Watchdog&) = delete;
    Watchdog& operator=(const Watchdog&) = delete;

private:
    std::chrono::milliseconds deadline;
    std::atomic<bool> done{false};
    std::thread thread;
};

} // namespace

// ---------------------------------------------------------------------------
// The clean-error path: while a holder is held on this thread, the two
// holder-producing factories refuse with ReentrantAccess instead of
// self-deadlocking. After release the owner clears and a fresh activation no
// longer refuses for that reason.
// ---------------------------------------------------------------------------

TEST(CardSessionReentrancy, ActivateWhileHoldingHolderReturnsReentrantAccess)
{
    Watchdog watchdog(std::chrono::seconds(5));

    auto session = makeDetachedCardSession(kReader);

    {
        ActiveChannelHolder holder = acquireHolder(*session);
        ASSERT_TRUE(holder.isActive());

        // Same thread, holder alive: both factories must refuse cleanly.
        auto sm = session->activateChannelWithSm(makeAid(), paceReq(), LibreSCRS::CancelToken{});
        ASSERT_FALSE(sm.has_value());
        EXPECT_EQ(sm.error(), ChannelActivationError::ReentrantAccess);

        auto plain = session->activateChannelFor(makeAid(), LibreSCRS::CancelToken{});
        ASSERT_FALSE(plain.has_value());
        EXPECT_EQ(plain.error(), ChannelActivationError::ReentrantAccess);
    } // holder destructs here — owner cleared

    // Owner cleared: a fresh activation no longer refuses with ReentrantAccess.
    auto after = session->activateChannelFor(makeAid(), LibreSCRS::CancelToken{});
    EXPECT_TRUE(after.has_value());
}

// ---------------------------------------------------------------------------
// Move-transfer correctness: moving a holder transfers the owner-clear
// obligation. The moved-from holder's destruction must NOT clear the owner;
// only the final owning instance does.
// ---------------------------------------------------------------------------

TEST(CardSessionReentrancy, MovedHolderKeepsOwnerUntilFinalDestruction)
{
    Watchdog watchdog(std::chrono::seconds(5));

    auto session = makeDetachedCardSession(kReader);

    {
        ActiveChannelHolder h1 = acquireHolder(*session);
        ASSERT_TRUE(h1.isActive());

        ActiveChannelHolder h2 = std::move(h1);
        // h1 is moved-from (d == nullptr); h2 owns the lock + the owner state.

        // While h2 is alive, re-entry is still refused — the move preserved
        // the owner.
        auto sm = session->activateChannelWithSm(makeAid(), paceReq(), LibreSCRS::CancelToken{});
        ASSERT_FALSE(sm.has_value());
        EXPECT_EQ(sm.error(), ChannelActivationError::ReentrantAccess);
    } // h2 destructs here (and the moved-from h1) — owner cleared exactly once

    auto after = session->activateChannelFor(makeAid(), LibreSCRS::CancelToken{});
    EXPECT_TRUE(after.has_value());
}

// ---------------------------------------------------------------------------
// Debug-assert coverage (option 3): a void/value-returning locking method
// triggers the debug assert when re-entered while holding a holder. Gated on
// !NDEBUG since assert() compiles out in release builds.
// ---------------------------------------------------------------------------

#ifndef NDEBUG
TEST(CardSessionReentrancyDeathTest, VoidMethodWhileHoldingHolderAsserts)
{
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    auto session = makeDetachedCardSession(kReader);
    ActiveChannelHolder holder = acquireHolder(*session);
    ASSERT_TRUE(holder.isActive());

    // The channel queries read without the lock on the holder's thread; a
    // mutating call still refuses to re-enter.
    EXPECT_DEATH({ session->clearActiveChannel(); }, "ActiveChannelHolder");
}
#endif

// ---------------------------------------------------------------------------
// Owner-tolerant accessor: CardSession::activatedProtocol must be callable
// from the thread that owns the session's ActiveChannelHolder — the position a
// plugin's doReadCard runs from, while the base readCard wrapper still holds
// the holder. On that thread it reads the recorded protocol without taking the
// non-recursive sessionMutex (which the holder already holds); a locking read
// would abort (debug) or self-deadlock (release) there.
//
// Coverage:
//   1. Holder-owner thread + live Open SM channel with a recorded PACE-CAN
//      protocol → returns that protocol (the call the eMRTD plugin makes from
//      its read).
//   2. A genuinely held production holder (real sessionMutex locked + owner
//      set) → the accessor returns without hanging; the Watchdog tears the
//      suite down loudly if a regression re-introduces a locking accessor.
//   3. The held SM channel turning Closed / Failed → nullopt (gated on a live
//      Open SM channel exactly like the public accessor).
// ---------------------------------------------------------------------------

TEST(ActivatedProtocolOwnerTolerant, ReturnsRecordedProtocolOnOwnerThread)
{
    Watchdog watchdog(std::chrono::seconds(5));

    const SmProtocolRequest recorded = PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can};
    auto session = makeDetachedCardSession(kReader);
    installSmFake(*session, ChannelState::Open, recorded);

    // This thread holds the holder: callerOwnsActiveChannel() is now true, so
    // the public CardSession::activatedProtocol() would abort/deadlock.
    ActiveChannelHolder holder = acquireSmHolder(*session, recorded);
    ASSERT_TRUE(holder.isActive());

    auto proto = session->activatedProtocol();
    ASSERT_TRUE(proto.has_value());
    EXPECT_EQ(*proto, recorded);
    ASSERT_TRUE(std::holds_alternative<PaceRequest>(*proto));
    EXPECT_EQ(std::get<PaceRequest>(*proto).secretKind, LibreSCRS::Auth::PaceSecretKind::Can);
}

TEST(ActivatedProtocolOwnerTolerant, NoHangWhileGenuineHolderHeld)
{
    Watchdog watchdog(std::chrono::seconds(5));

    auto session = makeDetachedCardSession(kReader);
    ActiveChannelHolder holder = acquireHolder(*session);
    ASSERT_TRUE(holder.isActive());

    // Real holder: the sessionMutex is genuinely locked and the owner is set.
    // The plain channel installed by acquireHolder carries no SM, so the result
    // is nullopt — but the load-bearing assertion is that the call RETURNS
    // (a locking accessor would deadlock on the held non-recursive mutex; the
    // Watchdog aborts the suite if it does).
    EXPECT_FALSE(session->activatedProtocol().has_value());
}

TEST(ActivatedProtocolOwnerTolerant, NulloptOnNonLiveChannelUnderHolder)
{
    Watchdog watchdog(std::chrono::seconds(5));

    const SmProtocolRequest recorded = PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can};

    for (const ChannelState dead : {ChannelState::Closed, ChannelState::Failed}) {
        SCOPED_TRACE(dead == ChannelState::Closed ? "held SM channel Closed → nullopt"
                                                  : "held SM channel Failed → nullopt");
        auto session = makeDetachedCardSession(kReader);
        FakeChannel* fake = installSmFake(*session, ChannelState::Open, recorded);
        ActiveChannelHolder holder = acquireSmHolder(*session, recorded);
        ASSERT_TRUE(holder.isActive());
        // Live while the holder was acquired: the accessor reports it.
        ASSERT_TRUE(session->activatedProtocol().has_value());
        // The channel dies under the holder, the recorded protocol stays.
        fake->setState(dead);
        EXPECT_FALSE(session->activatedProtocol().has_value());
    }
}
