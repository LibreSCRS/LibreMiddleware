// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/SecureChannel/BacChannel.h>
#include <LibreSCRS/SecureChannel/PaceChannel.h>
#include <LibreSCRS/SecureChannel/PaceParams.h>
#include <LibreSCRS/SecureChannel/PlainChannel.h>

#include <LibreSCRS/SecureChannel/detail/ChannelStateMutator.h>

#include "ActiveChannelHolderInternal.h"
#include "apdu.h"
#include "smartcard/pcsc_connection.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace LibreSCRS::SmartCard {

namespace {
// Process-wide monotonic counter. Starts at 0; nextGeneration() returns the
// pre-increment value + 1 so the first CardSession's generation is 1 and 0
// is reserved for "null / moved-from".
std::uint64_t nextGeneration() noexcept
{
    static std::atomic<std::uint64_t> counter{0};
    return counter.fetch_add(1, std::memory_order_relaxed) + 1;
}
} // namespace

struct LIBRESCRS_INTERNAL CardSession::Impl
{
    std::unique_ptr<LibreSCRS::SmartCard::Internal::PCSCConnection> ownedConn;
    std::string readerName;
    std::vector<std::uint8_t> atr;
    std::uint64_t generation{nextGeneration()};

    // 4.1: cross-plugin secure-channel coordination state.
    std::unique_ptr<LibreSCRS::SecureChannel::ISecureChannel> activeChannel;
    std::array<LibreSCRS::Secure::String, LibreSCRS::Auth::kPaceSecretKindCount> paceCredentialsCache;
    // BAC consumes a structurally distinct tuple (documentNumber + two dates)
    // rather than a single secret, so it gets its own cache slot disjoint
    // from the PACE credentials cache.
    std::optional<LibreSCRS::SecureChannel::BacInput> bacInput;
    std::optional<LibreSCRS::Auth::CredentialProvider> credentialProvider;
    std::mutex sessionMutex;
    std::atomic<bool> dead{false};
};

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
        d->ownedConn = std::make_unique<LibreSCRS::SmartCard::Internal::PCSCConnection>(d->readerName);
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

} // namespace

std::expected<CardSession, OpenError> CardSession::open(std::string readerName) noexcept
{
    // 4.0 hardening: OpenError() is deleted; construction goes
    // through the field-wise ctor so userMessage cannot be silently empty.
    // The neutral translator-friendly key surfaces here — hosts are free
    // to refine based on @ref OpenError::kind. The defaultText is a
    // plain sentence so an untranslated host still has readable text.
    static const LocalizedText kOpenFailedMsg{
        "librescrs.smartcard.error.openFailed",
        "Failed to open the card session. Check that the reader is connected and a card is inserted.",
        {}};
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

void ChannelInjector::installForTesting(CardSession& session,
                                        std::unique_ptr<LibreSCRS::SecureChannel::ISecureChannel> channel) noexcept
{
    // Mirrors the locking discipline of the activation paths so the install
    // is ordered against any concurrent hasLiveSecureChannel /
    // clearActiveChannel call from another thread. Any previously installed
    // channel is dropped without an explicit close(); the regression tests
    // that use this helper own the channel lifecycle and arrange teardown
    // themselves when required.
    try {
        std::lock_guard lock(session.d->sessionMutex);
        session.d->activeChannel = std::move(channel);
    } catch (...) {
        // noexcept contract: swallow any exception. Lock acquisition
        // failure is the only realistic path here and is harmless for a
        // test-only helper — the assignment simply does not happen.
    }
}

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

// Unified SM-aware transmit helper. When a live SM channel exists (state ==
// Open) APDUs must be wrapped through it; mixing plain transmits with an
// Open SM tunnel desynchronises the card-side send-sequence counter and
// corrupts the channel. When no Open SM channel is present, APDUs are sent
// plain through the underlying PC/SC connection. Every CardSession-level
// transmit must route through here so the wrapped-vs-plain choice cannot
// drift out of sync with channel state.
//
// Takes the active-channel pointer + raw connection (rather than a
// CardSession::Impl reference) because Impl is a private member type.
LibreSCRS::SmartCard::Internal::APDUResponse sessionTransmit(LibreSCRS::SecureChannel::ISecureChannel* activeChannel,
                                                             LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                                                             const LibreSCRS::SmartCard::Internal::APDUCommand& cmd,
                                                             LibreSCRS::CancelToken token)
{
    using LibreSCRS::SecureChannel::ChannelState;
    if (activeChannel != nullptr && activeChannel->state() == ChannelState::Open) {
        return activeChannel->transmit(cmd, std::move(token));
    }
    return conn.transmit(cmd);
}

// Read EF.CardAccess (FID 011C) from the card's master file. Returns the
// raw TLV bytes ready for emrtd::crypto::parseCardAccessWithParams. An
// empty vector indicates the file is absent or unreadable (no PACE).
//
// Routes through @ref sessionTransmit so that a live PACE channel is not
// bypassed when the caller is still resolving handshake parameters and
// has not yet taken a wrapped-SELECT path. PACE SM is session-scoped at
// the card OS layer (BSI TR-03110), so MF/EF.CardAccess is reachable
// through the SM tunnel. When no SM channel exists, plain reads of
// MF/EF.CardAccess are equally safe.
std::vector<std::uint8_t> readCardAccessFromMF(LibreSCRS::SecureChannel::ISecureChannel* activeChannel,
                                               LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                                               LibreSCRS::CancelToken token) noexcept
{
    using LibreSCRS::SmartCard::Internal::APDUCommand;
    using LibreSCRS::SmartCard::Internal::selectByFileId;
    try {
        auto mfSel = sessionTransmit(activeChannel, conn, selectByFileId(0x3F, 0x00, 0x0C), token);
        if (!mfSel.isSuccess()) {
            mfSel = sessionTransmit(activeChannel, conn, selectByFileId(0x3F, 0x00), token);
        }
        if (!mfSel.isSuccess()) {
            return {};
        }
        auto efSel = sessionTransmit(activeChannel, conn, selectByFileId(0x01, 0x1C, 0x0C), token);
        if (!efSel.isSuccess()) {
            efSel = sessionTransmit(activeChannel, conn, selectByFileId(0x01, 0x1C), token);
        }
        if (efSel.sw1 != 0x90 && efSel.sw1 != 0x62) {
            return {};
        }
        auto read = sessionTransmit(activeChannel, conn, APDUCommand{0x00, 0xB0, 0x00, 0x00, {}, 0, true}, token);
        return read.data;
    } catch (...) {
        return {};
    }
}

} // namespace

void CardSession::setCredentialProvider(LibreSCRS::Auth::CredentialProvider provider)
{
    std::lock_guard lock(d->sessionMutex);
    d->credentialProvider = std::move(provider);
}

void CardSession::setPaceSecret(LibreSCRS::Auth::PaceSecretKind kind, LibreSCRS::Secure::String value)
{
    std::lock_guard lock(d->sessionMutex);
    d->paceCredentialsCache[static_cast<std::size_t>(kind)] = std::move(value);
}

void CardSession::setBacInput(LibreSCRS::SecureChannel::BacInput input)
{
    std::lock_guard lock(d->sessionMutex);
    d->bacInput = std::move(input);
}

void CardSession::clearCachedPaceCredentials()
{
    std::lock_guard lock(d->sessionMutex);
    for (auto& slot : d->paceCredentialsCache) {
        slot = LibreSCRS::Secure::String{};
    }
    d->bacInput.reset();
}

void CardSession::markDead() noexcept
{
    d->dead.store(true, std::memory_order_release);
    // Wipe cached PACE/BAC secrets on card-removal: a long-lived LC
    // session would otherwise retain the MRZ / CAN / PIN material in RAM
    // until the session is destructed, which can be many minutes for a
    // GUI app sitting on an empty reader prompt. clearCachedPaceCredentials
    // takes the session mutex internally and zeroes both
    // paceCredentialsCache[] (Secure::String slots) and bacInput.
    try {
        clearCachedPaceCredentials();
    } catch (...) {
        // Cleansing must not throw; defensively swallow to honour noexcept.
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
    try {
        std::lock_guard lock(d->sessionMutex);
        if (d->activeChannel) {
            d->activeChannel->close();
            d->activeChannel.reset();
        }
    } catch (...) {
        // noexcept contract: swallow any exception from close()/reset().
        // The worst case is a leaked channel which is preferable to
        // std::terminate.
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

    // Fast path: already on the right applet under a plain channel.
    if (d->activeChannel && d->activeChannel->currentApplet() == aid &&
        d->activeChannel->state() == ChannelState::Open &&
        dynamic_cast<const PlainChannel*>(d->activeChannel.get()) != nullptr) {
        return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
    }

    if (d->activeChannel) {
        d->activeChannel->close();
    }

    // sessionTransmit short-circuits to ownedConn here because the preceding
    // close() leaves the active channel in ChannelState::Closed. Routed via
    // the helper for architectural consistency: every CardSession-level
    // APDU goes through one funnel.
    auto selectResp = sessionTransmit(d->activeChannel.get(), *d->ownedConn, buildSelectAppletCommand(aid), token);
    if (!selectResp.isSuccess()) {
        return std::unexpected{ChannelActivationError::SelectAppletFailed};
    }

    d->activeChannel = std::make_unique<PlainChannel>(*d->ownedConn, aid);
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
    }

    int retriesLeft = kSmActivationMaxAttempts;
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
                    aid, LibreSCRS::Auth::PaceSecretKind::Mrz, std::nullopt, LibreSCRS::LocalizedText{});
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

            // sessionTransmit short-circuits to ownedConn here because the
            // active channel has just been reset or was already null; the
            // plain SELECT before BAC handshake therefore cannot collide
            // with a live SM tunnel.
            auto selectResp =
                sessionTransmit(d->activeChannel.get(), *d->ownedConn, buildSelectAppletCommand(aid), token);
            if (!selectResp.isSuccess()) {
                return std::unexpected{ChannelActivationError::SelectAppletFailed};
            }

            auto outcome = BacChannel::establish(*d->ownedConn, aid, *d->bacInput, token);
            if (outcome) {
                d->activeChannel = std::move(*outcome);
                return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
            }
            if (outcome.error() == ChannelActivationError::PaceWrongSecret) {
                d->bacInput.reset();
                --retriesLeft;
                continue;
            }
            return std::unexpected{outcome.error()};
        }

        if (d->paceCredentialsCache[static_cast<std::size_t>(kind)].empty()) {
            if (!d->credentialProvider) {
                return std::unexpected{ChannelActivationError::CredentialsRequired};
            }
            auto requirement =
                LibreSCRS::Auth::AuthRequirement::forPaceSecret(aid, kind, std::nullopt, LibreSCRS::LocalizedText{});
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

        // PACE branch: discover supported OIDs from EF.CardAccess at MF.
        // The handshake itself runs at MF level — PACE binds session keys
        // to the card-side SM tunnel for the entire card session, not to
        // any particular applet, so the post-handshake wrapped SELECT
        // below routes the target applet through the freshly installed
        // channel without a second handshake.
        std::vector<std::pair<std::string, int>> oidParamPairs;
        try {
            auto cardAccess = readCardAccessFromMF(d->activeChannel.get(), *d->ownedConn, token);
            oidParamPairs = LibreSCRS::SecureChannel::parsePaceOidsFromCardAccess(cardAccess);
        } catch (const std::exception&) {
            return std::unexpected{ChannelActivationError::PaceProtocolFailure};
        }
        if (oidParamPairs.empty()) {
            return std::unexpected{ChannelActivationError::PaceUnsupported};
        }

        ChannelActivationError lastError = ChannelActivationError::PaceWrongSecret;
        std::unique_ptr<PaceChannel> freshChannel;
        for (const auto& [oid, paramId] : oidParamPairs) {
            if (token.isCancellable() && token.isCancelled()) {
                return std::unexpected{ChannelActivationError::Cancelled};
            }
            LibreSCRS::SecureChannel::PACEParams params;
            params.oid = oid;
            params.passwordType = kind;
            params.password = cachedSecret; // deep copy; cleansed when params goes out of scope
            params.paramId = paramId;

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
            return Internal::makeActiveChannelHolder(this, std::move(lock), std::move(tx));
        }
        if (lastError == ChannelActivationError::PaceWrongSecret) {
            cachedSecret = LibreSCRS::Secure::String{};
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

} // namespace Internal

} // namespace LibreSCRS::SmartCard
