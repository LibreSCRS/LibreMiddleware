// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS_internal/SmartCard/CardSessionImpl.h>
#include "open_error.h"

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS_internal/SecureChannel/BacChannel.h>
#include <LibreSCRS_internal/SecureChannel/ChipAuthChannel.h>
#include <LibreSCRS_internal/SecureChannel/PaceChannel.h>
#include <LibreSCRS_internal/SecureChannel/PaceParams.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>

#include <LibreSCRS_internal/SecureChannel/detail/ChannelStateMutator.h>

#include <LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h>
#include <LibreSCRS_internal/SmartCard/CardAccessReader.h>
#include <LibreSCRS_internal/SmartCard/ActivationError.h>
#include <LibreSCRS_internal/SmartCard/ChannelDispatch.h>
#include <LibreSCRS_internal/SmartCard/PaceDowngradeVerdict.h>

#include "apdu.h"
#include "chip_auth.h"
#include <pcsc_classify.h>
#include <pcsc_connection.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace LibreSCRS::SmartCard {

// @ref CardSession::Impl is defined in
// `lib/SmartCard/include/LibreSCRS_internal/SmartCard/CardSessionImpl.h`
// so the production translation unit and the test-helper translation unit
// (built as a separate archive, @ref LibreSCRS_SmartCardTesting) share
// the same layout. Production builds of @c libLibreSCRS_SmartCard never
// carry the test-only @ref detail::ChannelInjector::installForTesting or
// @ref Testing::makeDetachedCardSession symbols in their dynamic export set.

// A session over a detached connection: no handle, no card. Built here, in the
// library, so the test support that hands such sessions out never names the
// connection's class, whose typeinfo the library keeps hidden.
CardSession::CardSession() : d(std::make_unique<Impl>())
{
    d->ownedConn = std::make_unique<LibreSCRS::SmartCard::Internal::PCSCConnection>(
        LibreSCRS::SmartCard::Internal::PCSCConnection::DetachedTag{}, std::string{});
}

// Private constructor -- used by @ref open only. It names the reader and holds
// no connection yet: open() takes the connection and the ATR, and reports a
// failure as the OpenError it is.
CardSession::CardSession(std::string readerName) : d(std::make_unique<Impl>())
{
    d->readerName = std::move(readerName);
}

namespace {

// Runs @p fn ordered against the other threads that use the session. The
// thread that holds the session's ActiveChannelHolder already holds the
// non-recursive session mutex for the holder's lifetime, and it is the only
// thread that can change the session state meanwhile, so it reads without
// locking; any other thread takes the mutex. The state is named by deduction
// because CardSession::Impl is private to the class.
template <typename State, typename Fn>
auto withSessionState(State& state, Fn&& fn) -> decltype(fn())
{
    if (state.callerOwnsActiveChannel()) {
        return fn();
    }
    std::lock_guard lock(state.sessionMutex);
    return fn();
}

// A SELECT that takes the card out of the application @p recorded (ISO/IEC
// 7816-4): by DF name of another application, of the parent DF, of the master
// file, or by a path from the master file. Selecting an EF, a child DF or a
// path from the current DF stays inside the application. A failed SELECT
// leaves the current DF as it was, so naming the recorded application keeps
// the record either way -- PKCS#15 selects its own application in every
// operation, and forgetting would cost a SELECT at each activation. Reader
// pseudo-APDUs (CLA FF) and proprietary classes are not ISO selections.
[[nodiscard]] bool selectsAwayFromApplication(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd,
                                              const AppletAid& recorded) noexcept
{
    if (cmd.ins != 0xA4 || (cmd.cla & 0x80) != 0) {
        return false;
    }
    switch (cmd.p1) {
    case 0x04: {
        // Only the first or only occurrence names one application; last,
        // next and previous move to another.
        const auto name = recorded.bytes();
        const bool sameApplication =
            (cmd.p2 & 0x03) == 0 && !name.empty() && std::ranges::equal(std::span<const std::uint8_t>(cmd.data), name);
        return !sameApplication;
    }
    case 0x03:
    case 0x08:
        return true;
    case 0x00:
        return cmd.data.empty() || (cmd.data.size() == 2 && cmd.data[0] == 0x3F && cmd.data[1] == 0x00);
    default:
        return false;
    }
}

// The same judgement on raw bytes, which may use either length form. A SELECT
// whose data field cannot be located is counted as leaving.
[[nodiscard]] bool rawSelectsAwayFromApplication(std::span<const std::uint8_t> apdu, const AppletAid& recorded)
{
    if (apdu.size() < 4 || apdu[1] != 0xA4 || (apdu[0] & 0x80) != 0) {
        return false;
    }
    const auto cmd = LibreSCRS::SmartCard::Internal::decodeCommand(apdu);
    return !cmd || selectsAwayFromApplication(*cmd, recorded);
}

// The application the installed channel records; empty without one.
template <typename State>
[[nodiscard]] const AppletAid& recordedApplet(const State& state) noexcept
{
    static const AppletAid none;
    return state.activeChannel ? state.activeChannel->currentApplet() : none;
}

// The installed channel stops recording its application, so the next
// activation selects one again. A tunnel that cannot switch applications may
// only ever select the one it was established for, so the session keeps that
// one for it. Throws only on allocation, before anything has changed.
template <typename State>
void forgetChannelApplet(State& state)
{
    auto& channel = state.activeChannel;
    if (!channel || channel->currentApplet().empty()) {
        return;
    }
    LibreSCRS::SmartCard::AppletAid bound;
    if (channel->carriesSm() && !channel->supportsCrossAppletReuse()) {
        bound = channel->currentApplet();
    }
    LibreSCRS::SecureChannel::detail::ChannelStateMutator::setCurrentApplet(*channel, {});
    state.forgottenTunnelApplet = std::move(bound);
}

// An installed secure-messaging channel that is open: the state in which a
// plain command would end the card's secure-messaging session.
[[nodiscard]] bool liveSecureChannel(const LibreSCRS::SecureChannel::ISecureChannel* channel) noexcept
{
    return channel != nullptr && channel->state() == LibreSCRS::SecureChannel::ChannelState::Open &&
           channel->carriesSm();
}

// A secure-messaging channel that is no longer open (it failed on a bad MAC
// or a 6987/6988 answer, or was closed) and that no operation runs over --
// the calling thread does not hold the session's ActiveChannelHolder, and the
// lock it took keeps every other thread out -- is dead: the card has ended,
// or will end on the next answer, the secure-messaging session it belonged
// to. Only an explicit discardFailedChannel() or the activation of another
// channel drops it; until then every command is refused. True when it
// dropped one.
template <typename State>
bool dropDeadSecureChannel(State& state) noexcept
{
    if (state.callerOwnsActiveChannel() || !state.activeChannel || !state.activeChannel->carriesSm() ||
        state.activeChannel->state() == LibreSCRS::SecureChannel::ChannelState::Open) {
        return false;
    }
    try {
        state.activeChannel->close();
    } catch (...) {
        // the channel goes regardless
    }
    state.replaceActiveChannel();
    return true;
}

// The answer as one byte string, data then SW1 SW2. The response data can be
// a decrypted record, so the copy it is taken from is wiped.
[[nodiscard]] std::vector<std::uint8_t> toAnswer(LibreSCRS::SmartCard::Internal::APDUResponse response)
{
    std::vector<std::uint8_t> answer;
    answer.reserve(response.data.size() + 2);
    answer.insert(answer.end(), response.data.begin(), response.data.end());
    answer.push_back(response.sw1);
    answer.push_back(response.sw2);
    if (!response.data.empty()) {
        LibreSCRS::SmartCard::Internal::secureWipe(response.data.data(), response.data.size());
    }
    return answer;
}

[[nodiscard]] std::expected<std::vector<std::uint8_t>, LibreSCRS::SmartCard::TransportError>
toAnswerOrError(std::expected<LibreSCRS::SmartCard::Internal::APDUResponse, LibreSCRS::SmartCard::TransportError> r)
{
    if (!r) {
        return std::unexpected(std::move(r.error()));
    }
    return toAnswer(std::move(*r));
}

} // namespace

std::expected<CardSession, OpenError> CardSession::open(std::string readerName) noexcept
{
    // 4.0 hardening: OpenError() is deleted; construction goes
    // through the field-wise ctor so userMessage cannot be silently empty.
    // The shared failure message (Internal::kOpenFailedMsg) is a load-time constant
    // so this noexcept body performs no throwing static initialisation.
    // std::expected<CardSession, OpenError> implicitly converts from a
    // CardSession rvalue (success) and from std::unexpected<OpenError>
    // (failure). No in-place tag dispatch is needed in the C++23 form.
    try {
        CardSession session{std::move(readerName)};
        // CardSession is the sole sanctioned opener of a connection (open() is
        // a member, a friend of the connection class).
        auto conn = LibreSCRS::SmartCard::Internal::PCSCConnection::open(session.d->readerName);
        if (!conn) {
            return std::unexpected{LibreSCRS::SmartCard::Internal::toOpenError(conn.error())};
        }
        session.d->ownedConn = std::move(*conn);
        auto atr = session.d->ownedConn->getATR();
        if (!atr) {
            return std::unexpected{LibreSCRS::SmartCard::Internal::toOpenError(atr.error())};
        }
        session.d->atr = std::move(*atr);
        return session;
    } catch (const std::exception& e) {
        return std::unexpected{OpenError{OpenError::Kind::ReaderUnavailable,
                                         LibreSCRS::SmartCard::Internal::kOpenFailedMsg, std::string{e.what()}}};
    } catch (...) {
        return std::unexpected{OpenError{OpenError::Kind::ReaderUnavailable,
                                         LibreSCRS::SmartCard::Internal::kOpenFailedMsg,
                                         std::string{"unknown non-std exception during CardSession open"}}};
    }
}

CardSession::~CardSession() = default;

CardSession::CardSession(CardSession&&) noexcept = default;
CardSession& CardSession::operator=(CardSession&&) noexcept = default;

// @ref detail::ChannelInjector::installForTesting and
// @ref Testing::makeDetachedCardSession are defined in
// `lib/LibreSCRS/SmartCard/testing/`, compiled into the static test archive
// @ref LibreSCRS_SmartCardTesting only.

// Accessors unconditionally dereference `d`. Calling any of these on a
// moved-from session is undefined behaviour (see header); this matches the
// invariant of sibling pimpl-backed classes (SigningService, SigningRequest).
const std::string& CardSession::readerName() const noexcept
{
    return d->readerName;
}
const std::vector<std::uint8_t>& CardSession::atr() const noexcept
{
    return d->atr;
}

bool CardSession::hasLiveSecureChannel() const noexcept
{
    // Cross-provider coordination predicate, ordered against activation paths
    // on other threads. On lock failure (allocator pressure inside std::mutex)
    // the noexcept contract is honoured by returning false — a coordination
    // consumer that gets a conservative "no live SM" answer will at worst skip
    // a defer it could have honoured.
    try {
        return withSessionState(*d, [this] { return liveSecureChannel(d->activeChannel.get()); });
    } catch (...) {
        return false;
    }
}

std::optional<SmProtocolRequest> CardSession::activatedProtocol() const noexcept
{
    // Reports the SM protocol that established the currently-live channel
    // (after any BAC fallback), ordered against activation / teardown paths on
    // other threads. On lock failure (allocator pressure inside std::mutex) the
    // noexcept contract is honoured by returning nullopt — the conservative
    // "no protocol" answer.
    try {
        return withSessionState(*d, [this]() -> std::optional<SmProtocolRequest> {
            // Self-consistent with hasLiveSecureChannel(): an installed SM
            // channel can transition to ChannelState::Failed on its own during
            // a transmit (card-side 6987/6988 / MAC-unwrap failure) with no
            // teardown call, leaving d->activeChannel set and
            // d->activatedProtocol recorded. Gate on the same live-Open-SM
            // predicate so the recorded protocol is never reported for a
            // non-live channel.
            if (liveSecureChannel(d->activeChannel.get())) {
                return d->activatedProtocol;
            }
            return std::nullopt;
        });
    } catch (...) {
        return std::nullopt;
    }
}

bool CardSession::hasCredentialProvider() const noexcept
{
    // Reports whether a credential provider has been installed via
    // setCredentialProvider. Locks the session mutex so the read is ordered
    // against setCredentialProvider on other threads. On lock failure
    // (allocator pressure inside std::mutex) the noexcept contract is honoured
    // by returning false — the conservative "no provider" answer.
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    try {
        std::lock_guard lock(d->sessionMutex);
        return static_cast<bool>(d->credentialProvider);
    } catch (...) {
        return false;
    }
}

// ----------------------------------------------------------------------------
// Cross-plugin secure-channel coordination.
//
// activateChannelWithSm wraps the entire activation sequence (PACE handshake,
// or BAC plain SELECT + handshake, plus the post-handshake wrapped SELECT to
// the target applet) in a single PC/SC transaction held via CardTransaction.
// This blocks cross-process callers from interleaving plain APDUs that would
// silently destroy the card-side SM tunnel mid-flight.
//
// The state machine has three cases. Case 1 — same applet, channel still
// live — is the no-op fast path. Case 2 — applet switch on a live PACE
// channel — uses wrapped SELECT (PACE SM is session-scoped at the card OS
// layer, so applet switches do NOT require a fresh handshake). Case 3
// falls back to a full handshake when no usable channel exists. The retry loop evicts the credentials-cache slot on a
// wrong-secret outcome and re-prompts via the credential provider before
// falling back; on terminal errors the transaction RAII unwinds and no
// channel is installed.
// ----------------------------------------------------------------------------

namespace {

LibreSCRS::SmartCard::Internal::APDUCommand buildSelectAppletCommand(const AppletAid& aid)
{
    return LibreSCRS::SmartCard::Internal::selectByAID(aid.asVector(), 0x0C);
}

constexpr int kSmActivationMaxAttempts = 3;

// Why a SELECT sent during activation did not succeed, or nothing when it
// did. A card that refuses it, or a channel that cannot carry it (closed,
// failed, MAC refused), is a failed SELECT; the rest is the reader's.
[[nodiscard]] std::optional<LibreSCRS::SecureChannel::ChannelActivationError> selectFailure(
    const std::expected<LibreSCRS::SmartCard::Internal::APDUResponse, LibreSCRS::SmartCard::TransportError>& answer)
{
    if (!answer) {
        return LibreSCRS::SmartCard::Internal::activationErrorFor(
            answer.error(), LibreSCRS::SmartCard::Internal::ActivationStep::SelectApplet);
    }
    if (!answer->isSuccess()) {
        return LibreSCRS::SecureChannel::ChannelActivationError::SelectAppletFailed;
    }
    return std::nullopt;
}

// The MF-scoped EF.CardAccess reader (SELECT 3F00 -> SELECT 011C -> READ
// BINARY) now lives in the shared internal header
// <LibreSCRS_internal/SmartCard/CardAccessReader.h> so the PACE path here,
// the eMRTD plugin's pre-auth capability probe, and the plugin host leg all
// read the SAME file the SAME way. The PACE branch below consumes
// @ref Internal::readCardAccessDetailed directly — the outcome detail (not
// just the bytes) feeds the pre-prompt definitive-absence check.

} // namespace

void CardSession::setCredentialProvider(LibreSCRS::Auth::CredentialProvider provider) noexcept
{
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    try {
        std::lock_guard lock(d->sessionMutex);
        d->credentialProvider = std::move(provider);
    } catch (...) {
        // noexcept contract: degraded no-op on lock or allocation failure.
        // The previously installed provider (if any) remains active; the
        // next channel-activation pass falls through to it.
    }
}

void CardSession::setPaceSecret(LibreSCRS::Auth::PaceSecretKind kind, LibreSCRS::Secure::String value) noexcept
{
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    try {
        std::lock_guard lock(d->sessionMutex);
        d->paceCredentialsCache[static_cast<std::size_t>(kind)] = std::move(value);
    } catch (...) {
        // noexcept contract: degraded no-op on lock or allocation failure.
        // The cache slot retains its previous content; the next activation
        // pass falls through to the credential provider.
    }
}

void CardSession::setBacInput(LibreSCRS::SecureChannel::BacInput input) noexcept
{
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    try {
        std::lock_guard lock(d->sessionMutex);
        d->bacInput = std::move(input);
    } catch (...) {
        // noexcept contract: degraded no-op on lock or allocation failure.
    }
}

void CardSession::clearCachedPaceCredentials() noexcept
{
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    try {
        std::lock_guard lock(d->sessionMutex);
        for (auto& slot : d->paceCredentialsCache) {
            slot = LibreSCRS::Secure::String{};
        }
        d->bacInput.reset();
    } catch (...) {
        // noexcept contract: degraded no-op on lock failure. The cache
        // body is an in-place zeroise that does not itself allocate;
        // only mutex acquisition can throw.
    }
}

void CardSession::clearActiveChannel() noexcept
{
    // Take the session mutex so the teardown is ordered against any in-
    // flight activateChannel*() / transmit on another thread. close() drives the channel to ChannelState::Closed
    // and zeroises the SM key material via SecureMessaging's dtor before
    // the unique_ptr release runs the virtual destructor.
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    try {
        std::lock_guard lock(d->sessionMutex);
        if (d->activeChannel) {
            d->activeChannel->close();
        }
        // The recorded protocol goes with the channel, so the accessor does
        // not report a stale SM family for a torn-down channel.
        d->replaceActiveChannel();
    } catch (...) {
        // noexcept contract: swallow any exception from close()/reset().
        // The worst case is a leaked channel which is preferable to
        // std::terminate.
    }
}

std::expected<std::vector<std::uint8_t>, TransportError> CardSession::transmit(std::span<const std::uint8_t> apdu,
                                                                               LibreSCRS::CancelToken token)
{
    auto cmd = LibreSCRS::SmartCard::Internal::parseCommand(apdu);
    if (!cmd) {
        return std::unexpected(
            TransportError{TransportError::Kind::InvalidCommand, "not a command APDU in the accepted encoding"});
    }
    // Nothing is sent after the token fired, so nothing below is noted either.
    if (token.isCancellable() && token.isCancelled()) {
        return std::unexpected(
            TransportError{TransportError::Kind::Cancelled, "cancelled before the command was sent"});
    }
    // The thread that holds the holder is the only one that can change the
    // session meanwhile: it reads and sends without the lock (the holder
    // holds it). Any other thread decides and sends under the lock, so no
    // secure-messaging handshake started on another thread can come between
    // the choice of the path and the command on the wire.
    //
    // A SELECT that leaves the channel's application is noted before it is
    // sent: whatever the card answers, the record no longer holds.
    if (d->callerOwnsActiveChannel()) {
        if (selectsAwayFromApplication(*cmd, recordedApplet(*d))) {
            forgetChannelApplet(*d);
        }
        return toAnswerOrError(LibreSCRS::SmartCard::Internal::dispatchCommand(d->activeChannel.get(), *d->ownedConn,
                                                                               *cmd, std::move(token)));
    }
    // A secure-messaging channel that is no longer open refuses the command
    // here as on the holder's thread: it is never dropped implicitly, so a
    // command the caller meant to be protected never goes plain.
    std::lock_guard lock(d->sessionMutex);
    if (selectsAwayFromApplication(*cmd, recordedApplet(*d))) {
        forgetChannelApplet(*d);
    }
    return toAnswerOrError(
        LibreSCRS::SmartCard::Internal::dispatchCommand(d->activeChannel.get(), *d->ownedConn, *cmd, std::move(token)));
}

std::expected<std::vector<std::uint8_t>, TransportError> CardSession::transmitRaw(std::span<const std::uint8_t> apdu)
{
    // The thread that holds the holder runs an operation over the installed
    // channel: under a secure-messaging channel, open or not, the raw bytes
    // would bypass it, so they are refused. That thread is the only one that
    // can change the session meanwhile, so it reads and sends without the lock.
    if (d->callerOwnsActiveChannel()) {
        if (auto refused = LibreSCRS::SmartCard::Internal::refuseRawUnder(d->activeChannel.get())) {
            return std::unexpected(std::move(*refused));
        }
        if (rawSelectsAwayFromApplication(apdu, recordedApplet(*d))) {
            forgetChannelApplet(*d);
        }
        return toAnswerOrError(d->ownedConn->transmitRaw(apdu));
    }
    // Any other thread: the decision and the exchange happen under the lock,
    // so no secure-messaging handshake on another thread can start between
    // them. The rule is the holder's: any secure-messaging channel, open or
    // not, refuses the bytes -- a live one because a plain command would end
    // the card's secure-messaging session, a dead one because the caller may
    // have meant them to be protected (only discardFailedChannel() or an
    // activation drops it).
    std::lock_guard lock(d->sessionMutex);
    if (auto refused = LibreSCRS::SmartCard::Internal::refuseRawUnder(d->activeChannel.get())) {
        return std::unexpected(std::move(*refused));
    }
    if (rawSelectsAwayFromApplication(apdu, recordedApplet(*d))) {
        forgetChannelApplet(*d);
    }
    return toAnswerOrError(d->ownedConn->transmitRaw(apdu));
}

bool CardSession::discardFailedChannel() noexcept
{
    // On the holder's thread the operation running over the channel keeps
    // it: its commands are refused, never sent plain.
    if (d->callerOwnsActiveChannel()) {
        return false;
    }
    try {
        std::lock_guard lock(d->sessionMutex);
        return dropDeadSecureChannel(*d);
    } catch (...) {
        return false; // noexcept: a failure to lock leaves the channel as it is
    }
}

std::uint64_t CardSession::generation() const noexcept
{
    return d->generation;
}

std::expected<void, TransportError> CardSession::reconnect()
{
    return d->ownedConn->reconnect();
}

std::expected<void, TransportError> CardSession::beginTransaction()
{
    return d->ownedConn->beginTransaction();
}

void CardSession::endTransaction() noexcept
{
    d->ownedConn->endTransaction();
}

bool CardSession::isTransactionHeld() const noexcept
{
    return d->ownedConn->isTransactionHeld();
}

std::optional<LibreSCRS::SecureChannel::ChannelState> CardSession::channelState() const noexcept
{
    try {
        return withSessionState(*d, [this]() -> std::optional<LibreSCRS::SecureChannel::ChannelState> {
            if (!d->activeChannel) {
                return std::nullopt;
            }
            return d->activeChannel->state();
        });
    } catch (...) {
        return std::nullopt;
    }
}

bool CardSession::carriesSecureMessaging() const noexcept
{
    try {
        return withSessionState(*d, [this] { return d->activeChannel && d->activeChannel->carriesSm(); });
    } catch (...) {
        return false;
    }
}

void CardSession::forgetCurrentApplet() noexcept
{
    try {
        withSessionState(*d, [this] { forgetChannelApplet(*d); });
    } catch (...) {
        // noexcept contract: on lock or allocation failure the channel keeps
        // its applet.
    }
}

std::expected<ActiveChannelHolder, LibreSCRS::SecureChannel::ChannelActivationError>
CardSession::activateChannelFor(AppletAid aid, LibreSCRS::CancelToken token)
{
    using LibreSCRS::SecureChannel::ChannelActivationError;
    using LibreSCRS::SecureChannel::ChannelState;
    using LibreSCRS::SecureChannel::PlainChannel;

    if (token.isCancellable() && token.isCancelled()) {
        return std::unexpected{ChannelActivationError::Cancelled};
    }
    // Re-entrancy guard: a caller already holding this session's
    // ActiveChannelHolder on this thread would self-deadlock on the
    // non-recursive sessionMutex below. Refuse cleanly instead of hanging.
    if (d->callerOwnsActiveChannel()) {
        return std::unexpected{ChannelActivationError::ReentrantAccess};
    }

    std::unique_lock lock(d->sessionMutex);

    // Symmetric SM-tunnel guard, hoisted ahead of the transaction setup: a
    // plain activation must not tear down a live SM channel mid-flight —
    // issuing the plain SELECT below would desynchronise the card-side
    // send-sequence counter and corrupt the tunnel. A NON-reusable SM channel
    // (BAC — single-applet card matrix) is refused here, cheaply, before the
    // transaction. A REUSABLE SM channel (PACE / Chip Authentication —
    // session-scoped SM, BSI TR-03110 §3) instead rides a wrapped SELECT
    // through the live tunnel below, so a plain-profile plugin (PKCS#15 sign
    // on the same card) can switch applets without a rePACE and without ever
    // emitting a bare SELECT over the live SM context. Closed and Failed
    // channels are dropped below, before the plain SELECT.
    if (d->activeChannel && d->activeChannel->state() == ChannelState::Open && d->activeChannel->carriesSm() &&
        !d->activeChannel->supportsCrossAppletReuse()) {
        return std::unexpected{ChannelActivationError::Internal};
    }

    auto began = LibreSCRS::SmartCard::Internal::CardTransaction::begin(*d->ownedConn);
    if (!began) {
        return std::unexpected{ChannelActivationError::ReaderError};
    }
    auto tx = std::make_unique<LibreSCRS::SmartCard::Internal::CardTransaction>(std::move(*began));

    // Reusable live SM tunnel: route the target applet through it with a
    // wrapped SELECT (mirrors activateChannelWithSm Case 2). The SM context is
    // session-scoped, so the switch does not re-handshake and the recorded
    // protocol is left untouched. A failed wrapped SELECT (e.g. 6A82 for an
    // applet absent on this card) surfaces SelectAppletFailed WITHOUT tearing
    // the tunnel down — it is a legitimate answer, not a channel fault.
    if (d->activeChannel && d->activeChannel->state() == ChannelState::Open && d->activeChannel->carriesSm() &&
        d->activeChannel->supportsCrossAppletReuse()) {
        if (const auto failure = selectFailure(d->activeChannel->transmit(buildSelectAppletCommand(aid), token))) {
            return std::unexpected{*failure};
        }
        LibreSCRS::SecureChannel::detail::ChannelStateMutator::setCurrentApplet(*d->activeChannel, aid);
        return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
    }

    // Fast path: already on the right applet under a plain channel. Use the
    // carriesSm() predicate (as every other branch does) rather than an RTTI
    // type-probe — the real condition is "no SM context", not "the concrete
    // PlainChannel type".
    if (d->activeChannel && d->activeChannel->currentApplet() == aid &&
        d->activeChannel->state() == ChannelState::Open && !d->activeChannel->carriesSm()) {
        // Plain channel carries no SM context — the accessor must report no
        // active SM protocol regardless of any prior SM channel's record.
        d->activatedProtocol.reset();
        return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
    }

    // Whatever channel is installed now goes: an open secure-messaging one
    // never reaches this point (refused above, or carried the SELECT), so it
    // is a plain channel bound to another applet, or a secure-messaging one
    // that failed or was closed. Dropped BEFORE the plain SELECT -- a dead
    // secure-messaging channel left installed would answer ChannelUnusable and
    // lock every plain plugin out of the session.
    if (d->activeChannel) {
        d->activeChannel->close();
    }
    d->replaceActiveChannel();

    if (const auto failure = selectFailure(LibreSCRS::SmartCard::Internal::dispatchCommand(
            nullptr, *d->ownedConn, buildSelectAppletCommand(aid), token))) {
        return std::unexpected{*failure};
    }

    // A plain channel carries no SM context, so no protocol is recorded.
    d->replaceActiveChannel(std::make_unique<PlainChannel>(*d->ownedConn, aid));
    return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
}

std::expected<ActiveChannelHolder, LibreSCRS::SecureChannel::ChannelActivationError>
CardSession::activateChannelWithSm(AppletAid aid, SmProtocolRequest protocol, LibreSCRS::CancelToken token)
{
    using LibreSCRS::SecureChannel::BacChannel;
    using LibreSCRS::SecureChannel::ChannelActivationError;
    using LibreSCRS::SecureChannel::ChannelState;
    using LibreSCRS::SecureChannel::PaceChannel;

    if (token.isCancellable() && token.isCancelled()) {
        return std::unexpected{ChannelActivationError::Cancelled};
    }
    // Re-entrancy guard: a caller already holding this session's
    // ActiveChannelHolder on this thread would self-deadlock on the
    // non-recursive sessionMutex below. Refuse cleanly instead of hanging.
    if (d->callerOwnsActiveChannel()) {
        return std::unexpected{ChannelActivationError::ReentrantAccess};
    }

    // PACE consults the variant's secretKind against the PACE credentials
    // cache. BAC consults a structurally distinct cache slot (BacInput tuple)
    // because the three MRZ-Z components are a tuple, not a single shared
    // secret; the kind value below is unused on the BAC branch.
    LibreSCRS::Auth::PaceSecretKind kind = LibreSCRS::Auth::PaceSecretKind::Mrz;
    const bool isBac = std::holds_alternative<BacRequest>(protocol);
    if (auto* paceReq = std::get_if<PaceRequest>(&protocol)) {
        kind = paceReq->secretKind;
    }

    std::unique_lock lock(d->sessionMutex);

    // A live channel serves the request when it carries SM and was activated
    // for the same protocol family. Judged from the protocol the session
    // recorded when it installed the channel, not from the channel's dynamic
    // type: a type probe needs each channel class's typeinfo to be one object
    // in every image that creates a channel, which only exporting the classes
    // provides, and libc++ compares typeinfo by address.
    auto channelMatchesProtocol = [&](const LibreSCRS::SecureChannel::ISecureChannel& ch) noexcept {
        return ch.carriesSm() && d->activatedProtocol.has_value() && d->activatedProtocol->index() == protocol.index();
    };

    // ChipAuthRequest is reuse-only: the CA handshake needs a freshly read
    // DG14 and so is driven from inside the eMRTD read, never established from
    // scratch by the session. Honour it ONLY when a matching live channel is
    // already installed (Case 1 same-applet fast path, or Case 2 wrapped
    // SELECT below); otherwise refuse HERE, before the credential pre-flight —
    // a stale cached MRZ would otherwise satisfy the pre-flight and drop the
    // request into the PACE establish loop, prompting for a secret the caller
    // never wanted.
    if (std::holds_alternative<ChipAuthRequest>(protocol)) {
        if (!(d->activeChannel && d->activeChannel->state() == ChannelState::Open &&
              channelMatchesProtocol(*d->activeChannel))) {
            return std::unexpected{ChannelActivationError::Internal};
        }
    }

    // Hoisted Case 3 refusal: an Open SM channel that does NOT match the
    // requested protocol family cannot be reused (same-protocol Cases 1/2
    // would have fired) and cannot be torn down — issuing the fresh PACE
    // or BAC handshake would corrupt the live tunnel. Engaging a PC/SC
    // transaction only to refuse is wasteful, so the check runs ahead of
    // the transaction setup. The remaining Case 3 teardown logic (closing
    // a non-Open channel or a plain channel) still runs below.
    if (d->activeChannel && d->activeChannel->state() == ChannelState::Open && d->activeChannel->carriesSm() &&
        !channelMatchesProtocol(*d->activeChannel)) {
        return std::unexpected{ChannelActivationError::Internal};
    }

    // Cheap pre-flight: if no credentials are cached, no provider exists,
    // AND no live SM channel could serve a fast / wrapped-SELECT path, the
    // retry loop has no work to do. Short-circuiting here avoids burning a
    // PC/SC transaction and matches the contract surfaced by detached
    // sessions used by API-shape unit tests.
    const bool cacheHit =
        isBac ? d->bacInput.has_value() : !d->paceCredentialsCache[static_cast<std::size_t>(kind)].empty();
    const bool hasUsableChannel = d->activeChannel && d->activeChannel->state() == ChannelState::Open &&
                                  channelMatchesProtocol(*d->activeChannel);
    if (!cacheHit && !d->credentialProvider && !hasUsableChannel) {
        return std::unexpected{ChannelActivationError::CredentialsRequired};
    }

    auto began = LibreSCRS::SmartCard::Internal::CardTransaction::begin(*d->ownedConn);
    if (!began) {
        return std::unexpected{ChannelActivationError::ReaderError};
    }
    auto tx = std::make_unique<LibreSCRS::SmartCard::Internal::CardTransaction>(std::move(*began));

    // Case 1: live channel of correct protocol, already on the target applet
    //         — fast path; reuse without touching the wire.
    if (d->activeChannel && d->activeChannel->currentApplet() == aid &&
        d->activeChannel->state() == ChannelState::Open && channelMatchesProtocol(*d->activeChannel)) {
        // Reused channel: re-record the protocol so a fast-path return still
        // reports the SM family that owns the live tunnel.
        d->activatedProtocol = protocol;
        return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
    }

    // Case 1b: live channel of correct protocol that cannot switch applets,
    //          whose applet a caller selected away from (forgetCurrentApplet,
    //          or a SELECT sent through transmit). Only the applet it was
    //          established for is selected again, through the tunnel; any
    //          other still reaches the Case 3 refusal.
    if (d->activeChannel && d->activeChannel->state() == ChannelState::Open &&
        channelMatchesProtocol(*d->activeChannel) && !d->activeChannel->supportsCrossAppletReuse() &&
        d->activeChannel->currentApplet().empty() && !aid.empty() && aid == d->forgottenTunnelApplet) {
        if (const auto failure = selectFailure(d->activeChannel->transmit(buildSelectAppletCommand(aid), token))) {
            return std::unexpected{*failure};
        }
        LibreSCRS::SecureChannel::detail::ChannelStateMutator::setCurrentApplet(*d->activeChannel, aid);
        d->forgottenTunnelApplet = AppletAid{};
        d->activatedProtocol = protocol;
        return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
    }

    // Case 2: live SM channel of correct protocol whose SM context survives
    //         a wrapped applet switch — wrapped SELECT through the existing
    //         SM tunnel. The applet selector inside a wrapped SELECT routes
    //         within the SM tunnel and does not terminate it (PACE: BSI
    //         TR-03110 §3 — session-scoped).
    //
    //         Channels whose @c supportsCrossAppletReuse returns @c false
    //         (e.g. BAC — single-applet card matrix) fall through to
    //         Case 3 and a fresh handshake.
    if (d->activeChannel && d->activeChannel->state() == ChannelState::Open &&
        channelMatchesProtocol(*d->activeChannel) && d->activeChannel->supportsCrossAppletReuse()) {
        if (const auto failure = selectFailure(d->activeChannel->transmit(buildSelectAppletCommand(aid), token))) {
            return std::unexpected{*failure};
        }
        LibreSCRS::SecureChannel::detail::ChannelStateMutator::setCurrentApplet(*d->activeChannel, aid);
        // Cross-applet wrapped-SELECT reuse keeps the same SM tunnel; re-record
        // the protocol so the accessor stays consistent across applet switches.
        d->activatedProtocol = protocol;
        return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
    }

    // Case 3: no usable channel of the right protocol — full rebuild. An
    //         Open SM channel is sacred: Cases 1 and 2 cover every supported
    //         live-SM scenario (same-protocol reuse and cross-applet wrapped
    //         SELECT), so reaching here with an Open SM-carrying channel is
    //         a precondition violation — surface it as Internal rather than
    //         corrupt the tunnel by emitting plain handshake APDUs.
    //         A plain channel carries no SM context, so it falls through to
    //         the teardown path; Closed and Failed channels are safe to drop
    //         and the existing reset path handles them.
    if (d->activeChannel) {
        if (d->activeChannel->state() == ChannelState::Open && d->activeChannel->carriesSm()) {
            return std::unexpected{ChannelActivationError::Internal};
        }
        d->activeChannel->close();
        // Channel torn down ahead of the fresh-handshake retry loop, with its
        // recorded protocol. A success below records one again; a failure
        // leaves the accessor reporting nullopt for the channelless session.
        d->replaceActiveChannel();
    }

    // Hoist the PACE EF.CardAccess capability read OUT of the retry loop and
    // ABOVE credential resolution. PACE binds SM at MF for the whole session, so
    // the advertised OID set is loop-invariant; d->activeChannel is null here
    // (any prior channel was torn down above), so the read is plain. BAC skips
    // this entirely: its downgrade check is the post-establish SM re-read.
    //
    // The security payoff: when the read DEFINITIVELY confirms the document is
    // PACE-less — a clean 6A82 at MF, a 6283 "file deactivated" answer on the
    // EF selection (the chip's own declaration that PACE parameters are
    // unobtainable; no READ is attempted), OR a complete well-formed
    // EF.CardAccess advertising no PACE OID (as judged by
    // cardAccessAdvertisesPaceOrIsMalformed, which counts a malformed inner
    // structure as PACE) — PaceUnsupported surfaces BEFORE the
    // credential provider is ever invoked, so no CAN/MRZ prompt is burned on a
    // card that cannot do PACE, on every host. An UNKNOWN read (unreadable / malformed / truncated / a PACE
    // OID with no usable parameterId) is NOT definitive: it falls through to the
    // fail-closed-to-PACE-CAN path, which prompts and only then surfaces
    // PaceUnsupported once the empty OID set is reached below — byte-identical
    // to the pre-hoist mapping. An Unknown verdict must keep the provider-driven
    // PACE attempt.
    std::vector<LibreSCRS::SecureChannel::PaceSecurityInfo> paceInfos;
    if (!isBac) {
        bool definitivelyNoPace = false;
        try {
            const auto read =
                LibreSCRS::SmartCard::Internal::readCardAccessDetailed(d->activeChannel.get(), *d->ownedConn, token);
            // A reader that failed says nothing about the document: do not
            // fall through to a CAN prompt on an empty OID set.
            if (read.transportError) {
                return std::unexpected{LibreSCRS::SmartCard::Internal::activationErrorFor(
                    *read.transportError, LibreSCRS::SmartCard::Internal::ActivationStep::Other)};
            }
            paceInfos = LibreSCRS::SecureChannel::parsePaceOidsFromCardAccess(read.data);
            definitivelyNoPace =
                read.efDefinitivelyAbsent || (read.readSucceeded && !read.data.empty() && read.data[0] == 0x31 &&
                                              Internal::cardAccessOuterLengthContained(read.data) &&
                                              !Internal::cardAccessAdvertisesPaceOrIsMalformed(read.data));
        } catch (const std::exception&) {
            return std::unexpected{ChannelActivationError::PaceProtocolFailure};
        }
        if (definitivelyNoPace) {
            return std::unexpected{ChannelActivationError::PaceUnsupported};
        }
    }

    int retriesLeft = kSmActivationMaxAttempts;
    // Loop-local: set true ONLY by the wrong-secret retry paths below, so a
    // re-prompt that follows a rejection carries a rejected-retry reason while
    // the first prompt (and any prompt on a fresh activation call) carries the
    // empty reason. Consumed at the two forPaceSecret prompt sites.
    bool previousAttemptRejected = false;
    while (retriesLeft > 0) {
        if (token.isCancellable() && token.isCancelled()) {
            return std::unexpected{ChannelActivationError::Cancelled};
        }

        if (isBac) {
            // BAC branch: consume the dedicated BacInput cache slot. On miss
            // re-prompt via the credential provider (fields: documentNumber /
            // dateOfBirth / dateOfExpiry — matching the field ids the GUI
            // emits for BAC prompts). On wrong-secret evict the slot and
            // retry. BAC
            // handshake targets the currently selected applet, so a plain
            // SELECT to the target AID precedes establish — safe here
            // because the active channel has just been reset or was already
            // null.
            if (!d->bacInput.has_value()) {
                if (!d->credentialProvider) {
                    return std::unexpected{ChannelActivationError::CredentialsRequired};
                }
                auto requirement = LibreSCRS::Auth::AuthRequirement::forPaceSecret(
                    LibreSCRS::Auth::PaceSecretKind::Mrz, previousAttemptRejected
                                                              ? LibreSCRS::Auth::ErrorKeys::preReadAuthFailed()
                                                              : LibreSCRS::LocalizedText{});
                // Snapshot the provider and drop the session mutex across the
                // callback. The provider is permitted to call back into this
                // CardSession (e.g. setBacInput / setPaceSecret) without
                // self-deadlocking on the non-recursive sessionMutex.
                auto providerSnapshot = *d->credentialProvider;
                lock.unlock();
                auto credResult = providerSnapshot(requirement);
                lock.lock();
                if (credResult.status == LibreSCRS::Auth::CredentialResult::Status::UserCancelled) {
                    return std::unexpected{ChannelActivationError::UserCancelled};
                }
                if (credResult.status != LibreSCRS::Auth::CredentialResult::Status::Ok) {
                    return std::unexpected{ChannelActivationError::CredentialsRequired};
                }
                // The provider may already have populated bacInput via a
                // re-entrant setBacInput(); honour that if so, otherwise
                // build the BacInput from the returned credResult fields.
                if (!d->bacInput.has_value()) {
                    const auto* docNo = credResult.find("documentNumber");
                    const auto* dob = credResult.find("dateOfBirth");
                    const auto* doe = credResult.find("dateOfExpiry");
                    if (docNo == nullptr || dob == nullptr || doe == nullptr || docNo->empty() || dob->empty() ||
                        doe->empty()) {
                        return std::unexpected{ChannelActivationError::CredentialsRequired};
                    }
                    LibreSCRS::SecureChannel::BacInput input;
                    // Assign Secure::String directly (copy-construct from the
                    // credential-cache slot) — no std::string materialisation
                    // that would escape cleansing on the path between credential
                    // provider and BAC handshake.
                    input.documentNumber = *docNo;
                    input.dateOfBirth = *dob;
                    input.dateOfExpiry = *doe;
                    d->bacInput = std::move(input);
                }
            }

            // The active channel has just been reset or was already null, so
            // the plain SELECT before the BAC handshake goes to the
            // connection and cannot collide with a live SM tunnel.
            if (const auto failure = selectFailure(LibreSCRS::SmartCard::Internal::dispatchCommand(
                    d->activeChannel.get(), *d->ownedConn, buildSelectAppletCommand(aid), token))) {
                return std::unexpected{*failure};
            }

            auto outcome = BacChannel::establish(*d->ownedConn, aid, *d->bacInput, token);
            if (outcome) {
                // Record the protocol that won this channel. On the BAC branch
                // `protocol` is the BacRequest the caller passed (BAC is the
                // fallback path), so the accessor reports BAC after a fallback.
                d->replaceActiveChannel(std::move(*outcome), protocol);

                // Post-BAC SM-tunnel downgrade cross-check. The
                // pre-auth "PACE absent" verdict that routed us to BAC is
                // unauthenticated and forgeable by a contactless MITM. Re-read
                // EF.CardAccess THROUGH the just-established SM channel (the
                // shared MF-scoped helper dispatched over d->activeChannel — SM-
                // wrapped by construction): an attacker who forced BAC without
                // the MRZ can garble but not forge an SM-authenticated answer.
                // The pure verdict fails closed on anything but an
                // SM-authenticated definitive absence.
                {
                    // A reader or tunnel failure that stops the cross-check
                    // is no proof of a genuine BAC-only document, so every
                    // way out but Proceed tears the tunnel down. A tunnel
                    // that cannot carry the read (closed, MAC refused) is
                    // the anomaly a forger causes: PaceDowngradeDetected.
                    using LibreSCRS::SmartCard::Internal::activationErrorFor;
                    using LibreSCRS::SmartCard::Internal::ActivationStep;
                    std::optional<ChannelActivationError> stopped;
                    const auto reread = LibreSCRS::SmartCard::Internal::readCardAccessDetailed(d->activeChannel.get(),
                                                                                               *d->ownedConn, token);
                    if (reread.transportError) {
                        stopped = activationErrorFor(*reread.transportError, ActivationStep::DowngradeCheck);
                    } else if (LibreSCRS::SmartCard::Internal::classifyPostBacCardAccess(reread) !=
                               LibreSCRS::SmartCard::Internal::PaceDowngradeVerdict::Proceed) {
                        stopped = ChannelActivationError::PaceDowngradeDetected;
                    } else {
                        // On a genuine BAC-only document the re-read left the
                        // MF selected; restore the target applet before the
                        // holder is handed back. A failed SM re-SELECT is
                        // itself an integrity anomaly on the tunnel.
                        const auto reselect = d->activeChannel->transmit(buildSelectAppletCommand(aid), token);
                        if (!reselect) {
                            stopped = activationErrorFor(reselect.error(), ActivationStep::DowngradeCheck);
                        } else if (!reselect->isSuccess()) {
                            stopped = ChannelActivationError::PaceDowngradeDetected;
                        }
                    }
                    if (stopped) {
                        // Returned, never continued, so no retry re-enters; the
                        // plugin maps PaceDowngradeDetected to a non-auth
                        // failure, never markCredentialWrong.
                        if (d->activeChannel) {
                            d->activeChannel->close();
                        }
                        d->replaceActiveChannel();
                        return std::unexpected{*stopped};
                    }
                }
                return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
            }
            if (outcome.error() == ChannelActivationError::PaceWrongSecret) {
                d->bacInput.reset();
                previousAttemptRejected = true;
                --retriesLeft;
                continue;
            }
            return std::unexpected{outcome.error()};
        }

        if (d->paceCredentialsCache[static_cast<std::size_t>(kind)].empty()) {
            if (!d->credentialProvider) {
                return std::unexpected{ChannelActivationError::CredentialsRequired};
            }
            auto requirement = LibreSCRS::Auth::AuthRequirement::forPaceSecret(
                kind,
                previousAttemptRejected ? LibreSCRS::Auth::ErrorKeys::preReadAuthFailed() : LibreSCRS::LocalizedText{});
            // Snapshot the provider and drop the session mutex across the
            // callback. The provider is permitted to call back into this
            // CardSession (e.g. setPaceSecret) without self-deadlocking on
            // the non-recursive sessionMutex.
            auto providerSnapshot = *d->credentialProvider;
            lock.unlock();
            auto credResult = providerSnapshot(requirement);
            lock.lock();
            if (credResult.status == LibreSCRS::Auth::CredentialResult::Status::UserCancelled) {
                return std::unexpected{ChannelActivationError::UserCancelled};
            }
            if (credResult.status != LibreSCRS::Auth::CredentialResult::Status::Ok) {
                return std::unexpected{ChannelActivationError::CredentialsRequired};
            }

            // If the provider re-entered to populate the cache slot directly
            // (e.g. via setPaceSecret) honour that; otherwise pull the value
            // named after the kind: "can" / "mrz" / "pin" / "puk", as
            // AuthRequirement documents for a forPaceSecret prompt.
            if (d->paceCredentialsCache[static_cast<std::size_t>(kind)].empty()) {
                const char* expectedId = "";
                switch (kind) {
                case LibreSCRS::Auth::PaceSecretKind::Can:
                    expectedId = "can";
                    break;
                case LibreSCRS::Auth::PaceSecretKind::Mrz:
                    expectedId = "mrz";
                    break;
                case LibreSCRS::Auth::PaceSecretKind::Pin:
                    expectedId = "pin";
                    break;
                case LibreSCRS::Auth::PaceSecretKind::Puk:
                    expectedId = "puk";
                    break;
                }
                const auto* found = credResult.find(expectedId);
                if (found == nullptr || found->empty()) {
                    return std::unexpected{ChannelActivationError::CredentialsRequired};
                }
                d->paceCredentialsCache[static_cast<std::size_t>(kind)] = *found;
            }
        }
        auto& cachedSecret = d->paceCredentialsCache[static_cast<std::size_t>(kind)];

        // An UNKNOWN capability read (an empty OID set the hoisted check did not
        // classify as a definitive absence) resolves to PaceUnsupported here,
        // AFTER the provider prompt — byte-identical to the pre-hoist mapping,
        // so an Unknown verdict still drives the provider-prompted PACE attempt.
        if (paceInfos.empty()) {
            return std::unexpected{ChannelActivationError::PaceUnsupported};
        }

        // PACE branch: the supported-OID set (@ref paceInfos) was read from
        // EF.CardAccess at MF once, above the loop — it is loop-invariant
        // because PACE binds session keys to the card-side SM tunnel for the
        // entire card session, not to any particular applet, so the
        // post-handshake wrapped SELECT below routes the target applet through
        // the freshly installed channel without a second handshake.
        ChannelActivationError lastError = ChannelActivationError::PaceWrongSecret;
        std::unique_ptr<PaceChannel> freshChannel;
        // The next OID is tried only when the card refused this one at
        // MSE:Set AT (PaceUnsupported from establish): nothing derived from
        // the secret reached the card, so no try was spent. Once the card
        // has taken an OID, any failure ends the walk -- another OID would
        // put the same secret to the card again, spending a PIN or PUK try
        // each time.
        for (const auto& info : paceInfos) {
            if (token.isCancellable() && token.isCancelled()) {
                return std::unexpected{ChannelActivationError::Cancelled};
            }
            LibreSCRS::SecureChannel::PaceParams params;
            params.oid = info.oid;
            params.passwordType = kind;
            params.password = cachedSecret; // deep copy; cleansed when params goes out of scope
            params.paramId = info.paramId;

            auto outcome = PaceChannel::establish(*d->ownedConn, params, token);
            if (outcome) {
                freshChannel = std::move(*outcome);
                break;
            }
            lastError = outcome.error();
            if (lastError != ChannelActivationError::PaceUnsupported)
                break;
        }
        // The card listed these OIDs in EF.CardAccess and then refused every
        // one. That is a protocol failure, not a PACE-less document: surfacing
        // PaceUnsupported would invite the BAC fallback, which a man in the
        // middle could provoke by refusing MSE:Set AT.
        if (lastError == ChannelActivationError::PaceUnsupported)
            lastError = ChannelActivationError::PaceProtocolFailure;

        if (freshChannel) {
            // Wrapped SELECT to the target applet through the freshly
            // installed channel. PACE handshake left currentApplet empty;
            // setCurrentApplet records the AID after a successful wrapped
            // SELECT so subsequent same-applet calls hit the fast path.
            if (const auto failure = selectFailure(freshChannel->transmit(buildSelectAppletCommand(aid), token))) {
                // Wrapped SELECT failed: the SM tunnel is established but
                // the target applet is not reachable. Drop the channel and
                // surface the failure; do not retry the handshake.
                freshChannel->close();
                return std::unexpected{*failure};
            }
            LibreSCRS::SecureChannel::detail::ChannelStateMutator::setCurrentApplet(*freshChannel, aid);
            // Record the protocol that won this channel. On the PACE branch
            // `protocol` is the PaceRequest the caller passed (its secretKind
            // distinguishes PACE-CAN / PACE-MRZ / PACE-PIN for label callers).
            d->replaceActiveChannel(std::move(freshChannel), protocol);
            return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
        }
        if (lastError == ChannelActivationError::PaceWrongSecret) {
            cachedSecret = LibreSCRS::Secure::String{};
            previousAttemptRejected = true;
            --retriesLeft;
            continue;
        }
        return std::unexpected{lastError};
    }

    return std::unexpected{ChannelActivationError::PaceWrongSecret};
}

namespace {

bool isCancelled(const LibreSCRS::CancelToken& token) noexcept
{
    return token.isCancellable() && token.isCancelled();
}

} // namespace

ChipAuthReport CardSession::performChipAuthentication(std::span<const std::uint8_t> dg14, AppletAid aid,
                                                      LibreSCRS::CancelToken token)
{
    using LibreSCRS::SecureChannel::ChannelState;
    using LibreSCRS::SecureChannel::ChipAuthChannel;
    using EstablishKind = LibreSCRS::SecureChannel::ChipAuthEstablishError::Kind;

    auto noVerdict = [](ChipAuthReason reason, std::string detail, std::string protocol = {}) {
        ChipAuthReport r;
        r.outcome = ChipAuthOutcome::NotPerformed;
        r.reason = reason;
        r.detail = std::move(detail);
        r.protocolOid = std::move(protocol);
        return r;
    };

    // Only the thread holding the ActiveChannelHolder may run this: it already
    // owns the session mutex and the PC/SC transaction, so the session state
    // is read without locking (locking would self-deadlock) and no other
    // command can land between the key agreement and the proof exchange.
    if (!d->callerOwnsActiveChannel()) {
        return noVerdict(ChipAuthReason::NoUsableChannel,
                         "chip authentication needs the session's active channel held");
    }
    if (!d->activeChannel || d->activeChannel->state() != ChannelState::Open) {
        return noVerdict(ChipAuthReason::NoUsableChannel, "no open channel to run chip authentication over");
    }
    if (isCancelled(token)) {
        return noVerdict(ChipAuthReason::Cancelled, "cancelled before chip authentication");
    }
    const std::vector<std::uint8_t> dg14Raw(dg14.begin(), dg14.end());

    // One reading of a failed step, for both paths. Inside a PACE/BAC tunnel
    // the chip's answer to an advertised protocol is a verdict (a refusal, or
    // a clone holding the tunnel keys could dodge Failed by answering badly);
    // on a plain channel a refusal is no evidence (a contact interface may
    // admit the protocol only under SM). A reader failure is never a verdict.
    auto reportFor = [&](EstablishKind kind, std::string detail, std::string protocol, bool inTunnel) {
        switch (kind) {
        case EstablishKind::NotSupported: {
            ChipAuthReport report;
            report.outcome = ChipAuthOutcome::NotSupported;
            report.reason = ChipAuthReason::NotOffered;
            report.protocolOid = std::move(protocol);
            if (inTunnel) {
                report.detail = std::move(detail);
            }
            return report;
        }
        case EstablishKind::ProtocolRefused:
            if (!inTunnel) {
                return noVerdict(ChipAuthReason::NotOffered, "chip refused Chip Authentication on plain channel",
                                 std::move(protocol));
            }
            break;
        case EstablishKind::Cancelled:
            return noVerdict(ChipAuthReason::Cancelled, std::move(detail), std::move(protocol));
        case EstablishKind::LocalCryptoFailure:
            return noVerdict(ChipAuthReason::LocalCryptoFailure, std::move(detail), std::move(protocol));
        case EstablishKind::ReaderError:
            return noVerdict(ChipAuthReason::ReaderError, std::move(detail), std::move(protocol));
        case EstablishKind::SmProofFailed:
            break;
        }
        ChipAuthReport report;
        report.outcome = ChipAuthOutcome::Failed;
        report.protocolOid = std::move(protocol);
        report.detail = std::move(detail);
        return report;
    };

    if (!d->activeChannel->carriesSm()) {
        // Plain channel: establish() returns a channel only after its proof
        // exchange verified under the derived keys.
        auto upgraded = ChipAuthChannel::establish(*d->ownedConn, *d->activeChannel, dg14Raw, aid, token);
        if (upgraded) {
            ChipAuthReport report;
            report.outcome = ChipAuthOutcome::Passed;
            report.protocolOid = (*upgraded)->protocolOid();
            // The card now speaks SM under the derived keys; the plain channel
            // is superseded.
            d->activeChannel->close();
            d->replaceActiveChannel(std::move(*upgraded), ChipAuthRequest{});
            return report;
        }
        // No upgrade: the plain channel stays, and its next command ends any
        // SM the card left half-open (ISO 7816-4).
        auto& error = upgraded.error();
        return reportFor(error.kind, std::move(error.detail), std::move(error.protocol), false);
    }

    // Inside a PACE/BAC tunnel: the key agreement runs wrapped, after which
    // the card answers only under the derived keys, so the tunnel takes them
    // over and must prove them with a wrapped exchange before Passed.
    auto ca = emrtd::crypto::performChipAuth(*d->activeChannel, dg14Raw, token);
    switch (ca.chipAuthentication) {
    case emrtd::crypto::ChipAuthResult::NOT_SUPPORTED:
        return reportFor(EstablishKind::NotSupported, std::move(ca.errorDetail), std::move(ca.protocol), true);
    case emrtd::crypto::ChipAuthResult::FAILED: {
        // A failure observed while the caller was cancelling says nothing
        // about the chip.
        if (isCancelled(token)) {
            return reportFor(EstablishKind::Cancelled, "cancelled during chip authentication", std::move(ca.protocol),
                             true);
        }
        EstablishKind kind = EstablishKind::LocalCryptoFailure;
        if (ca.transportError) {
            kind = LibreSCRS::SecureChannel::chipAuthKindFor(*ca.transportError);
        } else if (ca.chipRefusedProtocol) {
            kind = EstablishKind::ProtocolRefused;
        }
        return reportFor(kind, std::move(ca.errorDetail), std::move(ca.protocol), true);
    }
    case emrtd::crypto::ChipAuthResult::NOT_PERFORMED:
        // performChipAuth has no path that reports this; were one added, it
        // would be a run this side did not complete.
        return reportFor(EstablishKind::LocalCryptoFailure, std::move(ca.errorDetail), std::move(ca.protocol), true);
    case emrtd::crypto::ChipAuthResult::PASSED:
        break;
    }
    if (!ca.newSessionKeys) {
        return noVerdict(ChipAuthReason::LocalCryptoFailure, "chip authentication derived no session keys",
                         ca.protocol);
    }
    LibreSCRS::SecureChannel::SessionKeys keys;
    keys.encKey = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{ca.newSessionKeys->encKey}};
    keys.macKey = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{ca.newSessionKeys->macKey}};
    keys.ssc = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{ca.newSessionKeys->ssc}};
    keys.cipher = (ca.newAlgorithm == emrtd::crypto::SMAlgorithm::DES3) ? LibreSCRS::SecureChannel::SmCipher::Des3
                                                                        : LibreSCRS::SecureChannel::SmCipher::Aes;
    LibreSCRS::SecureChannel::detail::ChannelStateMutator::replaceKeys(*d->activeChannel, std::move(keys));
    const auto proof = LibreSCRS::SecureChannel::confirmSmAfterKeyChange(*d->activeChannel, aid, token);
    switch (proof.outcome) {
    case LibreSCRS::SecureChannel::SmKeyProof::Outcome::Proven:
        break;
    case LibreSCRS::SecureChannel::SmKeyProof::Outcome::NotProven:
        return reportFor(EstablishKind::SmProofFailed, "chip authentication key agreement did not verify", ca.protocol,
                         true);
    case LibreSCRS::SecureChannel::SmKeyProof::Outcome::Cancelled:
        return reportFor(EstablishKind::Cancelled, "cancelled during chip authentication", ca.protocol, true);
    case LibreSCRS::SecureChannel::SmKeyProof::Outcome::ReaderError: {
        auto failure = LibreSCRS::SecureChannel::proofReaderFailure(proof, ca.protocol);
        return reportFor(failure.kind, std::move(failure.detail), std::move(failure.protocol), true);
    }
    }
    // When the proof exchange selected @p aid through the tunnel, the channel
    // records it so a later activation for another applet re-selects.
    if (proof.appletSelected) {
        LibreSCRS::SecureChannel::detail::ChannelStateMutator::setCurrentApplet(*d->activeChannel, aid);
    }
    ChipAuthReport report;
    report.outcome = ChipAuthOutcome::Passed;
    report.protocolOid = ca.protocol;
    return report;
}

namespace Internal {

void ActiveChannelAccessor::markOwner(CardSession& session) noexcept
{
    session.d->activeChannelOwner.store(std::this_thread::get_id(), std::memory_order_release);
}

void ActiveChannelAccessor::clearOwner(CardSession& session) noexcept
{
    session.d->activeChannelOwner.store(std::thread::id{}, std::memory_order_release);
}

} // namespace Internal

} // namespace LibreSCRS::SmartCard
