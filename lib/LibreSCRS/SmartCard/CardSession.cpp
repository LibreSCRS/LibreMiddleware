// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <LibreSCRS_internal/SmartCard/CardSessionImpl.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS_internal/SecureChannel/BacChannel.h>
#include <LibreSCRS_internal/SecureChannel/PaceChannel.h>
#include <LibreSCRS/SecureChannel/PaceParams.h>
#include <LibreSCRS_internal/SecureChannel/PlainChannel.h>

#include <LibreSCRS_internal/SecureChannel/detail/ChannelStateMutator.h>

#include <LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h>
#include <LibreSCRS_internal/SmartCard/CardAccessReader.h>
#include <LibreSCRS_internal/SmartCard/PaceDowngradeVerdict.h>
#include <LibreSCRS_internal/SmartCard/SessionPresence.h>
#include <LibreSCRS_internal/SmartCard/SmartCardServices.h>

#include "apdu.h"
#include <pcsc_connection.h>

#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>

namespace LibreSCRS::SmartCard {

// @ref CardSession::Impl is defined in
// `lib/SmartCard/include/LibreSCRS_internal/SmartCard/CardSessionImpl.h`
// so the production translation unit and the test-helper translation unit
// (built as a separate archive, @ref LibreSCRS_SmartCard_TestHelpers) share
// the same layout. Production builds of @c libLibreSCRS_SmartCard never
// carry the test-only @ref detail::ChannelInjector::installForTesting
// symbol in their dynamic export set.

CardSession::CardSession() : d(std::make_unique<Impl>()) {}

// Private constructor — used by @ref open and @ref makeDetachedCardSession
// only. Exposes the old "throw on failure" shape internally so the existing
// PCSCConnection constructor (which throws std::runtime_error with a
// textual diagnostic) can be consumed without rewriting the transport
// layer. The public @ref open factory translates any exception into a
// structured @ref OpenError.
CardSession::CardSession(std::string readerName) : d(std::make_unique<Impl>())
{
    d->readerName = std::move(readerName);
    try {
        // CardSession is the sole sanctioned opener: the reader-name ctor is
        // private + friended to this class, so it must be reached via `new`
        // here (std::make_unique is not a friend and cannot call it).
        d->ownedConn = std::unique_ptr<LibreSCRS::SmartCard::Internal::PCSCConnection>(
            new LibreSCRS::SmartCard::Internal::PCSCConnection(d->readerName));
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string{"CardSession open failed: "} + e.what());
    }
    d->atr = d->ownedConn->getATR();
}

namespace {

// Classify a PCSCConnection-reported error message into a structured
// @ref OpenError::Kind. The internal transport raises a runtime_error with a
// human-readable diagnostic; 4.0 preserves that text as @ref
// OpenError::diagnosticDetail while projecting the category into a stable
// enum suitable for programmatic branching.
OpenError::Kind classifyOpenError(std::string_view diag) noexcept
{
    // Match substrings emitted by LibreSCRS::SmartCard::Internal::PCSCConnection — the canonical
    // strings are "reader not found", "no smartcard", and "protocol" etc.
    // The matches are intentionally permissive: PC/SC error strings vary
    // across pcsc-lite / WinSCard / CryptoTokenKit revisions. Unknown
    // diagnostics fall back to ReaderUnavailable, which is the safest
    // generic category for a host UI to render.
    auto contains = [&](std::string_view needle) noexcept { return diag.find(needle) != std::string_view::npos; };

    if (contains("no smartcard") || contains("no card") || contains("NO_SMARTCARD") || contains("REMOVED_CARD"))
        return OpenError::Kind::NoCardPresent;
    if (contains("protocol") || contains("PROTO_MISMATCH") || contains("comm"))
        return OpenError::Kind::ProtocolError;
    return OpenError::Kind::ReaderUnavailable;
}

// Shared failure message for CardSession::open(). Constructed once at load
// (LocalizedText allocates two std::strings) so open()'s noexcept body never
// runs a throwing first-call static initialisation — a load-time OOM here
// terminates before main(), never a per-call terminate in the noexcept path.
// The neutral translator-friendly key surfaces to hosts, which are free to
// refine based on @ref OpenError::kind; the defaultText is a plain sentence so
// an untranslated host still has readable text.
const LocalizedText kOpenFailedMsg{
    "librescrs.smartcard.error.openFailed",
    "Failed to open the card session. Check that the reader is connected and a card is inserted.",
    {}};

} // namespace

std::expected<CardSession, OpenError> CardSession::open(std::string readerName) noexcept
{
    // 4.0 hardening: OpenError() is deleted; construction goes
    // through the field-wise ctor so userMessage cannot be silently empty.
    // The shared failure message (@ref kOpenFailedMsg) is a load-time constant
    // so this noexcept body performs no throwing static initialisation.
    // std::expected<CardSession, OpenError> implicitly converts from a
    // CardSession rvalue (success) and from std::unexpected<OpenError>
    // (failure). No in-place tag dispatch is needed in the C++23 form.
    try {
        return CardSession{std::move(readerName)};
    } catch (const std::exception& e) {
        std::string diag = e.what();
        OpenError::Kind k = classifyOpenError(diag);
        return std::unexpected{OpenError{k, kOpenFailedMsg, std::move(diag)}};
    } catch (...) {
        return std::unexpected{OpenError{OpenError::Kind::ReaderUnavailable, kOpenFailedMsg,
                                         std::string{"unknown non-std exception during CardSession open"}}};
    }
}

CardSession::~CardSession() = default;

CardSession::CardSession(CardSession&&) noexcept = default;
CardSession& CardSession::operator=(CardSession&&) noexcept = default;

namespace detail {

// PcscBridge is the LM-internal friend that unwraps CardSession into its
// underlying PCSCConnection. LibreSCRS::SmartCard::Internal::PCSCConnection no
// longer appears in the public CardSession.h forward-declaration; LM-
// internal sources go through this bridge instead. Callers MUST NOT pass
// a moved-from CardSession; no defensive null-check (see public accessor
// invariants).
LibreSCRS::SmartCard::Internal::PCSCConnection& PcscBridge::unwrap(CardSession& session) noexcept
{
    return *session.d->ownedConn;
}

const LibreSCRS::SmartCard::Internal::PCSCConnection& PcscBridge::unwrap(const CardSession& session) noexcept
{
    return *session.d->ownedConn;
}

std::shared_ptr<CardSession> makeDetachedCardSession(std::string readerName)
{
    auto session = std::shared_ptr<CardSession>(new CardSession());
    session->d->readerName = std::move(readerName);
    session->d->ownedConn = std::make_unique<LibreSCRS::SmartCard::Internal::PCSCConnection>(
        LibreSCRS::SmartCard::Internal::PCSCConnection::DetachedTag{}, session->d->readerName);
    // atr stays empty — there is no card
    return session;
}

std::uint64_t sessionGeneration(const CardSession& session) noexcept
{
    return session.d->generation;
}

// @ref detail::ChannelInjector::installForTesting is defined in
// `lib/LibreSCRS/SmartCard/test_helpers/channel_test_helpers.cpp`, compiled
// into the build-tree-only @ref LibreSCRS_SmartCard_TestHelpers archive.

} // namespace detail

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
bool CardSession::isConnected() const noexcept
{
    return d->ownedConn != nullptr;
}

bool CardSession::hasLiveSecureChannel() const noexcept
{
    // Cross-provider coordination predicate. Locks the session mutex so the
    // read is ordered against activation paths on other threads. On lock
    // failure (allocator pressure inside std::mutex) the noexcept contract
    // is honoured by returning false — a coordination consumer that gets a
    // conservative "no live SM" answer will at worst skip a defer it could
    // have honoured; mid-activation races on the activation thread itself
    // are handled by the activation path's own invariants.
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    try {
        std::lock_guard lock(d->sessionMutex);
        if (!d->activeChannel) {
            return false;
        }
        if (d->activeChannel->state() != LibreSCRS::SecureChannel::ChannelState::Open) {
            return false;
        }
        return d->activeChannel->carriesSm();
    } catch (...) {
        return false;
    }
}

std::optional<SmProtocolRequest> CardSession::activatedProtocol() const noexcept
{
    // Reports the SM protocol that established the currently-live channel
    // (after any BAC fallback). Locks the session mutex so the read is
    // ordered against activation / teardown paths on other threads. On lock
    // failure (allocator pressure inside std::mutex) the noexcept contract is
    // honoured by returning nullopt — the conservative "no protocol" answer.
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    try {
        std::lock_guard lock(d->sessionMutex);
        // Self-consistent with hasLiveSecureChannel(): an installed SM channel
        // can transition to ChannelState::Failed on its own during a holder
        // transmit (card-side 6987/6988 / MAC-unwrap failure) with no teardown
        // call, leaving d->activeChannel set and d->activatedProtocol recorded.
        // Gate on the same live-Open-SM predicate so the recorded protocol is
        // never reported for a non-live channel.
        if (d->activeChannel && d->activeChannel->state() == LibreSCRS::SecureChannel::ChannelState::Open &&
            d->activeChannel->carriesSm()) {
            return d->activatedProtocol;
        }
        return std::nullopt;
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

// TU-local SM-aware transmit primitive. When @p activeChannel is non-null
// and reports @c ChannelState::Open the APDU is dispatched through the
// channel (which wraps + unwraps under the current SM tunnel); otherwise
// the APDU is sent plain through @p conn. Anonymous-namespace static
// linkage keeps the helper out of the dynamic symbol table — its previous
// public-internal incarnation (@c LibreSCRS::SmartCard::Internal::
// sessionTransmitImpl, exported via the @c *LibreSCRS::* version-script
// glob) is gone in 4.3 along with the free-function transmit funnel.
LibreSCRS::SmartCard::Internal::APDUResponse
dispatchOverChannelOrConn(LibreSCRS::SecureChannel::ISecureChannel* activeChannel,
                          LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                          const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token)
{
    using LibreSCRS::SecureChannel::ChannelState;
    if (activeChannel != nullptr && activeChannel->state() == ChannelState::Open) {
        return activeChannel->transmit(cmd, std::move(token));
    }
    return conn.transmit(cmd);
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

void CardSession::markDead() noexcept
{
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    d->dead.store(true, std::memory_order_release);
    // Wipe cached PACE/BAC secrets on card-removal: a long-lived LC
    // session would otherwise retain the MRZ / CAN / PIN material in RAM
    // until the session is destructed, which can be many minutes for a
    // GUI app sitting on an empty reader prompt. clearCachedPaceCredentials
    // takes the session mutex internally and zeroes both
    // paceCredentialsCache[] (Secure::String slots) and bacInput; itself
    // marked noexcept under the same noexcept-alloc contract.
    clearCachedPaceCredentials();
    // Defensive: drop the SessionPresence entry even if no subsequent
    // clearActiveChannel call fires. ~Impl will also reset presence; this
    // is the safety net for the card-removal path where the channel may
    // still be nominally Open in the session state.
    try {
        std::lock_guard lock(d->sessionMutex);
        d->presence.reset();
        // Card removed: the SM tunnel is dead, so clear the recorded protocol
        // alongside the presence entry. The active channel itself is dropped by
        // a subsequent clearActiveChannel / ~Impl; this keeps the accessor from
        // reporting a stale protocol in the window before that fires.
        d->activatedProtocol.reset();
    } catch (...) {
        // noexcept contract.
    }
}

bool CardSession::isDead() const noexcept
{
    return d->dead.load(std::memory_order_acquire);
}

void CardSession::clearActiveChannel() noexcept
{
    // Take the session mutex so the teardown is ordered against any in-
    // flight activateChannel*() / ActiveChannelAccessor::transmit on
    // another thread. close() drives the channel to ChannelState::Closed
    // and zeroises the SM key material via SecureMessaging's dtor before
    // the unique_ptr release runs the virtual destructor.
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    try {
        std::lock_guard lock(d->sessionMutex);
        if (d->activeChannel) {
            d->activeChannel->close();
            d->activeChannel.reset();
        }
        // The channel is gone; clear the recorded protocol so the accessor
        // does not report a stale SM family for a torn-down channel.
        d->activatedProtocol.reset();
        // Drop the SessionPresence entry alongside the channel: in-process
        // PKCS#11 probes must see "no live SM" once the channel is gone,
        // even if this CardSession remains alive on the host side.
        d->presence.reset();
    } catch (...) {
        // noexcept contract: swallow any exception from close()/reset().
        // The worst case is a leaked channel which is preferable to
        // std::terminate.
    }
}

// LM-internal SM-aware transmit funnel. Snapshots the active-channel slot
// + the underlying PC/SC connection pointer under the session mutex, then
// releases the mutex before dispatching. The shared_ptr snapshot pins the
// channel object's lifetime for the duration of the call so a concurrent
// clearActiveChannel on another thread cannot dangle it. The mutex is NOT
// held across the wire — that would serialise plugin reach through one
// global lock and turn CardSession into a contention bottleneck.
LibreSCRS::SmartCard::Internal::APDUResponse
CardSession::transmitInternal(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token)
{
    assert(!d->callerOwnsActiveChannel() && "CardSession re-entered on the thread holding its ActiveChannelHolder "
                                            "— would self-deadlock on the non-recursive sessionMutex. Release the "
                                            "holder before re-entering the session.");
    std::shared_ptr<LibreSCRS::SecureChannel::ISecureChannel> channelSnap;
    LibreSCRS::SmartCard::Internal::PCSCConnection* connPtr = nullptr;
    {
        std::lock_guard lock(d->sessionMutex);
        channelSnap = d->activeChannel;
        connPtr = d->ownedConn.get();
        if (connPtr == nullptr) {
            // Moved-from / detached / never-attached session: surface a
            // defined "no card available" status word rather than emitting
            // UB. Mirrors the ActiveChannelAccessor null-check shape
            // elsewhere in the SmartCard surface.
            return LibreSCRS::SmartCard::Internal::APDUResponse{.data = {}, .sw1 = 0x6F, .sw2 = 0x00};
        }
    }

    try {
        return dispatchOverChannelOrConn(channelSnap.get(), *connPtr, cmd, std::move(token));
    } catch (...) {
        // A bare std::runtime_error from PCSCConnection::transmit (reader
        // gone, card removed mid-transmit, detached test connection)
        // surfaces here. Mirror the null-conn guard above: return a
        // defined "no card" status word rather than propagating the
        // exception across the LM-internal funnel boundary, where plugin
        // callers expect a value-returning shape.
        return LibreSCRS::SmartCard::Internal::APDUResponse{.data = {}, .sw1 = 0x6F, .sw2 = 0x00};
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
    if (d->dead.load(std::memory_order_acquire)) {
        return std::unexpected{ChannelActivationError::CardRemoved};
    }
    if (!d->ownedConn) {
        return std::unexpected{ChannelActivationError::ReaderError};
    }
    // Re-entrancy guard: a caller already holding this session's
    // ActiveChannelHolder on this thread would self-deadlock on the
    // non-recursive sessionMutex below. Refuse cleanly instead of hanging.
    if (d->callerOwnsActiveChannel()) {
        return std::unexpected{ChannelActivationError::ReentrantAccess};
    }

    std::unique_lock lock(d->sessionMutex);

    if (d->dead.load(std::memory_order_acquire)) {
        return std::unexpected{ChannelActivationError::CardRemoved};
    }

    // Symmetric SM-tunnel guard, hoisted ahead of the transaction setup: a
    // plain activation must not tear down a live SM channel mid-flight —
    // issuing the plain SELECT below would desynchronise the card-side
    // send-sequence counter and corrupt the tunnel. Surface a typed
    // precondition error so callers route the request through
    // activateChannelWithSm instead. PlainChannels (no SM context) fall
    // through to the existing teardown path below; Closed and Failed
    // channels are safe to drop. Engaging a PC/SC transaction only to
    // refuse is wasteful and races against other holders that could legally
    // begin work; hoisting the check keeps the failure cheap.
    if (d->activeChannel && d->activeChannel->state() == ChannelState::Open && d->activeChannel->carriesSm()) {
        return std::unexpected{ChannelActivationError::Internal};
    }

    std::unique_ptr<LibreSCRS::SmartCard::Internal::CardTransaction> tx;
    try {
        tx = std::make_unique<LibreSCRS::SmartCard::Internal::CardTransaction>(*d->ownedConn);
    } catch (const std::exception&) {
        return std::unexpected{ChannelActivationError::ReaderError};
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

    if (d->activeChannel) {
        d->activeChannel->close();
    }

    // dispatchOverChannelOrConn short-circuits to ownedConn here because the
    // preceding close() leaves the active channel in ChannelState::Closed.
    // Routed via the helper for architectural consistency: every
    // CardSession-level APDU goes through one funnel.
    auto selectResp =
        dispatchOverChannelOrConn(d->activeChannel.get(), *d->ownedConn, buildSelectAppletCommand(aid), token);
    if (!selectResp.isSuccess()) {
        return std::unexpected{ChannelActivationError::SelectAppletFailed};
    }

    d->activeChannel = std::make_shared<PlainChannel>(*d->ownedConn, aid);
    // A freshly installed plain channel carries no SM context; clear any
    // protocol recorded for a previously closed SM channel so the accessor
    // reports nullopt for this plain activation.
    d->activatedProtocol.reset();
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
    if (d->dead.load(std::memory_order_acquire)) {
        return std::unexpected{ChannelActivationError::CardRemoved};
    }
    if (!d->ownedConn) {
        return std::unexpected{ChannelActivationError::ReaderError};
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

    if (d->dead.load(std::memory_order_acquire)) {
        return std::unexpected{ChannelActivationError::CardRemoved};
    }

    auto channelMatchesProtocol = [&](const LibreSCRS::SecureChannel::ISecureChannel& ch) noexcept {
        if (std::holds_alternative<PaceRequest>(protocol)) {
            return dynamic_cast<const PaceChannel*>(&ch) != nullptr;
        }
        return dynamic_cast<const BacChannel*>(&ch) != nullptr;
    };

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

    std::unique_ptr<LibreSCRS::SmartCard::Internal::CardTransaction> tx;
    try {
        tx = std::make_unique<LibreSCRS::SmartCard::Internal::CardTransaction>(*d->ownedConn);
    } catch (const std::exception&) {
        return std::unexpected{ChannelActivationError::ReaderError};
    }

    // Case 1: live channel of correct protocol, already on the target applet
    //         — fast path; reuse without touching the wire.
    if (d->activeChannel && d->activeChannel->currentApplet() == aid &&
        d->activeChannel->state() == ChannelState::Open && channelMatchesProtocol(*d->activeChannel)) {
        // Reused channel: re-record the protocol so a fast-path return still
        // reports the SM family that owns the live tunnel.
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
        auto wrappedSelect = d->activeChannel->transmit(buildSelectAppletCommand(aid), token);
        if (!wrappedSelect.isSuccess()) {
            return std::unexpected{ChannelActivationError::SelectAppletFailed};
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
        d->activeChannel.reset();
        // Channel torn down ahead of the fresh-handshake retry loop; clear the
        // recorded protocol. A success below re-records it; a failure leaves it
        // cleared so the accessor reports nullopt for the now-channelless session.
        d->activatedProtocol.reset();
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
    // EF.CardAccess advertising no PACE OID (exactly the pre-auth capability
    // probe's "Absent" verdict) — PaceUnsupported surfaces BEFORE the
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
                    aid, LibreSCRS::Auth::PaceSecretKind::Mrz, std::nullopt,
                    previousAttemptRejected ? LibreSCRS::Auth::ErrorKeys::preReadAuthFailed()
                                            : LibreSCRS::LocalizedText{});
                // Snapshot the provider and drop the session mutex across the
                // callback. The provider is permitted to call back into this
                // CardSession (e.g. setBacInput / setPaceSecret) without
                // self-deadlocking on the non-recursive sessionMutex.
                auto providerSnapshot = *d->credentialProvider;
                lock.unlock();
                auto credResult = providerSnapshot(requirement);
                lock.lock();
                // Re-check invariants the provider may have mutated.
                if (d->dead.load(std::memory_order_acquire)) {
                    return std::unexpected{ChannelActivationError::CardRemoved};
                }
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

            // dispatchOverChannelOrConn short-circuits to ownedConn here
            // because the active channel has just been reset or was already
            // null; the plain SELECT before BAC handshake therefore cannot
            // collide with a live SM tunnel.
            auto selectResp =
                dispatchOverChannelOrConn(d->activeChannel.get(), *d->ownedConn, buildSelectAppletCommand(aid), token);
            if (!selectResp.isSuccess()) {
                return std::unexpected{ChannelActivationError::SelectAppletFailed};
            }

            auto outcome = BacChannel::establish(*d->ownedConn, aid, *d->bacInput, token);
            if (outcome) {
                d->activeChannel = std::move(*outcome);
                // Cross-reader guard: a shared_ptr-managed CardSession with a
                // live SM channel must be visible to in-process PKCS#11
                // probes so they refuse to open a second PC/SC handle on
                // this reader (BSI TR-03110 §3 — SM is session-scoped).
                // Skip silently for value-stored sessions (LMAC bridge):
                // weak_from_this() is empty when no shared_ptr anchors the
                // session, and registering an immediately-expired weak_ptr
                // would burn a registry slot for no observable benefit.
                try {
                    Internal::ensureSessionPresenceInitialised();
                    if (auto weak = weak_from_this(); !weak.expired())
                        d->presence.emplace(Internal::sessionPresence().insert(d->readerName, std::move(weak)));
                } catch (...) {
                    // bad_alloc on insert / rehash: SM already established;
                    // losing the cross-reader guard for this one session is
                    // preferable to terminating.
                }
                // Record the protocol that won this channel. On the BAC branch
                // `protocol` is the BacRequest the caller passed (BAC is the
                // fallback path), so the accessor reports BAC after a fallback.
                d->activatedProtocol = protocol;

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
                    const auto reread = LibreSCRS::SmartCard::Internal::readCardAccessDetailed(d->activeChannel.get(),
                                                                                               *d->ownedConn, token);
                    bool proceed = LibreSCRS::SmartCard::Internal::classifyPostBacCardAccess(reread) ==
                                   LibreSCRS::SmartCard::Internal::PaceDowngradeVerdict::Proceed;
                    // On a genuine BAC-only document the re-read left the MF
                    // selected; restore the target applet before the holder is
                    // handed back (the helper documents this caller obligation).
                    // A failed SM re-SELECT is itself an integrity anomaly on the
                    // tunnel, so it fails closed too.
                    if (proceed) {
                        proceed = d->activeChannel->transmit(buildSelectAppletCommand(aid), token).isSuccess();
                    }
                    if (!proceed) {
                        // Forged downgrade (or SM anomaly): tear the tunnel down
                        // and surface PaceDowngradeDetected. This is NOT a
                        // wrong-credential condition — it is RETURNED (never
                        // continued, so no retry re-enters) and the plugin maps
                        // it to a non-auth failure, never markCredentialWrong.
                        d->presence.reset();
                        d->activatedProtocol.reset();
                        if (d->activeChannel) {
                            d->activeChannel->close();
                            d->activeChannel.reset();
                        }
                        return std::unexpected{ChannelActivationError::PaceDowngradeDetected};
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
                aid, kind, std::nullopt,
                previousAttemptRejected ? LibreSCRS::Auth::ErrorKeys::preReadAuthFailed() : LibreSCRS::LocalizedText{});
            // Snapshot the provider and drop the session mutex across the
            // callback. The provider is permitted to call back into this
            // CardSession (e.g. setPaceSecret) without self-deadlocking on
            // the non-recursive sessionMutex.
            auto providerSnapshot = *d->credentialProvider;
            lock.unlock();
            auto credResult = providerSnapshot(requirement);
            lock.lock();
            // Re-check invariants the provider may have mutated.
            if (d->dead.load(std::memory_order_acquire)) {
                return std::unexpected{ChannelActivationError::CardRemoved};
            }
            if (credResult.status == LibreSCRS::Auth::CredentialResult::Status::UserCancelled) {
                return std::unexpected{ChannelActivationError::UserCancelled};
            }
            if (credResult.status != LibreSCRS::Auth::CredentialResult::Status::Ok) {
                return std::unexpected{ChannelActivationError::CredentialsRequired};
            }

            // If the provider re-entered to populate the cache slot directly
            // (e.g. via setPaceSecret) honour that; otherwise pull the field
            // whose id matches the kind. The PACE secret factory emits ids
            // "can" / "mrz" / "pin" / "puk" — one and only one of those is
            // present in a forPaceSecret prompt.
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
            if (outcome.error() != ChannelActivationError::PaceWrongSecret &&
                outcome.error() != ChannelActivationError::PaceProtocolFailure) {
                // Hard terminal categories surface immediately; only the
                // soft "wrong secret" / "protocol failure" categories
                // justify trying the next OID.
                break;
            }
        }

        if (freshChannel) {
            // Wrapped SELECT to the target applet through the freshly
            // installed channel. PACE handshake left currentApplet empty;
            // setCurrentApplet records the AID after a successful wrapped
            // SELECT so subsequent same-applet calls hit the fast path.
            auto wrappedSelect = freshChannel->transmit(buildSelectAppletCommand(aid), token);
            if (!wrappedSelect.isSuccess()) {
                // Wrapped SELECT failed: the SM tunnel is established but
                // the target applet is not reachable. Drop the channel and
                // surface SelectAppletFailed; do not retry the handshake.
                freshChannel->close();
                return std::unexpected{ChannelActivationError::SelectAppletFailed};
            }
            LibreSCRS::SecureChannel::detail::ChannelStateMutator::setCurrentApplet(*freshChannel, aid);
            d->activeChannel = std::move(freshChannel);
            // Cross-reader guard: see the matching block in the BAC success
            // branch above for the rationale and lifecycle invariants.
            try {
                Internal::ensureSessionPresenceInitialised();
                if (auto weak = weak_from_this(); !weak.expired())
                    d->presence.emplace(Internal::sessionPresence().insert(d->readerName, std::move(weak)));
            } catch (...) {
            }
            // Record the protocol that won this channel. On the PACE branch
            // `protocol` is the PaceRequest the caller passed (its secretKind
            // distinguishes PACE-CAN / PACE-MRZ / PACE-PIN for label callers).
            d->activatedProtocol = protocol;
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

namespace Internal {

APDUResponse ActiveChannelAccessor::transmit(CardSession& session, const APDUCommand& cmd, LibreSCRS::CancelToken token)
{
    auto& impl = *session.d;
    if (!impl.activeChannel) {
        APDUResponse closed;
        closed.sw1 = 0x6F;
        closed.sw2 = 0x00;
        return closed;
    }
    return impl.activeChannel->transmit(cmd, std::move(token));
}

LibreSCRS::SecureChannel::ISecureChannel* ActiveChannelAccessor::active(CardSession& session) noexcept
{
    return session.d->activeChannel.get();
}

std::optional<SmProtocolRequest> ActiveChannelAccessor::activatedProtocol(CardSession& session) noexcept
{
    // Lock-free, owner-tolerant sibling of the public CardSession::activatedProtocol
    // accessor. Reaches d through the same friendship path active() uses, gates on
    // the identical live-Open-SM predicate (so a recorded protocol is never reported
    // for a Closed/Failed channel), and returns the recorded protocol — all WITHOUT
    // locking the session mutex. Safe because the holder-owner is the only thread
    // that can mutate session state while the holder is held; this is the accessor a
    // plugin calls from inside a held ActiveChannelHolder where the public,
    // mutex-locking accessor would self-deadlock on the non-recursive sessionMutex.
    auto* d = session.d.get();
    if (d == nullptr) {
        return std::nullopt;
    }
    if (d->activeChannel && d->activeChannel->state() == LibreSCRS::SecureChannel::ChannelState::Open &&
        d->activeChannel->carriesSm()) {
        return d->activatedProtocol;
    }
    return std::nullopt;
}

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
