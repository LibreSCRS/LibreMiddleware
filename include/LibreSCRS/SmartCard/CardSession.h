// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SmartCard::CardSession — pimpl-backed PC/SC
///        session handle — with the noexcept factory
///        @ref LibreSCRS::SmartCard::CardSession::open and the structured
///        @ref LibreSCRS::SmartCard::OpenError.

#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SecureChannel/BacParams.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/ChipAuthentication.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard {

class CardSession;

// Forward-declare the library-internal access points the public CardSession
// befriends. Their definitions live in headers that are never installed, so
// external consumers see neither the structs' members nor any symbol of
// theirs. A friend declaration targeting `Namespace::Type` still needs the
// enclosing namespace to exist for the friend lookup to match.
/// @cond internal
namespace Internal {
// Friend-only access struct through which the holder records which thread
// holds the session's lock (<LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h>).
struct ActiveChannelAccessor;
} // namespace Internal

namespace detail {
// Friend-only access struct for the test-channel injection seam. Method
// is declared and defined in the internal-build-guarded header
// `LibreSCRS/SmartCard/detail/ChannelInjection.h`. Forward-declared here
// so @c CardSession can befriend it without exporting the helper symbol
// or its parameter type into the public SDK surface.
struct ChannelInjector;
} // namespace detail
namespace Testing {
// Friend-only access struct for the declared test support in
// <LibreSCRS/SmartCard/testing/CardSessionTesting.h>. Defined in the static
// LibreSCRS::SmartCardTesting archive, never in a shipped shared library.
struct SessionAccess;
} // namespace Testing
/// @endcond

/// @brief Structured error describing why @ref CardSession::open failed.
///
/// @since 4.0
struct OpenError
{
    /// @brief Failure category.
    enum class Kind : std::uint8_t {
        /// Reader does not exist, was unplugged, or the PC/SC service could
        /// not be reached.
        ReaderUnavailable,
        /// Reader is present but carries no card, or the card was removed
        /// between enumeration and the open attempt.
        NoCardPresent,
        /// Card is present but the PC/SC protocol negotiation failed (T=0 /
        /// T=1 mismatch, reader fault, driver bug).
        ProtocolError,
        /// Card is present but another client holds it, or the platform
        /// refused this process a session (PC/SC
        /// `SCARD_E_SHARING_VIOLATION`; CryptoTokenKit refusing or not
        /// yet granting the session). Usually passes: a retry may succeed.
        /// @since 5.0
        SessionRefused,
    };

    /// @brief Failure category.
    Kind kind;
    /// @brief Translator-friendly message suitable for a user notification.
    ///
    /// Always populated by producers. Callers without a card-specific text
    /// should use one of the @ref LibreSCRS::Auth::ErrorKeys generic
    /// builders.
    LocalizedText userMessage;
    /// @brief Optional dev-facing diagnostic (PC/SC return code text, etc.).
    ///        Never includes secret material.
    std::optional<std::string> diagnosticDetail;

    /// @brief Default constructor is deleted.
    ///
    /// A default-constructed @c LocalizedText (empty key, empty fallback)
    /// is structurally a valid @ref userMessage but renders as an empty
    /// string. Deleting the default ctor forces every production site to
    /// go through the field-wise constructor below or named factories so
    /// the type's invariants (kind classified, userMessage populated) are
    /// established at construction.
    OpenError() = delete;

    /// @brief Field-wise constructor.
    ///
    /// Mirrors the @ref ReadResult / @ref SigningResult policy: the type's
    /// invariants (kind classified, userMessage populated) are established
    /// at construction time and cannot be silently bypassed.
    OpenError(Kind k, LocalizedText msg, std::optional<std::string> diag = std::nullopt) noexcept
        : kind(k), userMessage(std::move(msg)), diagnosticDetail(std::move(diag))
    {}

    /// @brief Defaulted byte-identity equality.
    [[nodiscard]] bool operator==(const OpenError&) const noexcept = default;
};

/// @brief Opaque handle for an active PC/SC session against a reader.
///
/// Construct via the noexcept factory @ref CardSession::open with the reader
/// name a LibreSCRS::SmartCard::MonitorEvent reported. Move-only; not
/// copyable. Internally wraps LibreMiddleware's PC/SC connection
/// primitive behind a pimpl so consumers see no dependency on PC/SC headers.
///
/// Lifetime of the underlying hardware connection matches the CardSession
/// lifetime. Destroying the CardSession closes the connection. Consumers
/// that need shared ownership (e.g. to hand the session to
/// LibreSCRS::Signing::SigningService::sign) should move the opened session
/// into a @c std::shared_ptr<CardSession> via the helper below or take the
/// session out of the @c std::expected<CardSession, OpenError> with
/// @c std::make_shared<CardSession>(std::move(*result)).
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). A CardSession represents an
/// exclusive PC/SC connection to a single reader/card and is NOT internally
/// synchronised: concurrent operations against the same session from
/// multiple threads are undefined. Callers
/// that need to dispatch work from several threads must serialise APDUs
/// externally (e.g. by holding the session under a mutex) or allocate one
/// session per worker. The pure accessors (@ref readerName, @ref atr) read
/// immutable post-construction state and may be called concurrently. Sibling pimpl-backed types
/// (@ref LibreSCRS::Signing::SigningService) take a
/// @c std::shared_ptr<CardSession> by value and assume the caller has
/// already established that exclusivity for the duration of the call.
///
/// @par Smart-pointer integration (since 4.2)
/// Inherits @c std::enable_shared_from_this<CardSession>. @c shared_from_this()
/// is callable only when the session is owned by a @c std::shared_ptr;
/// value-stored sessions trigger @c std::bad_weak_ptr per the standard
/// contract. Use @c weak_from_this() (safe in either case; returns empty on
/// value storage) when only the lookup half is needed.
///
/// @since 4.0
class LIBRESCRS_PUBLIC_API CardSession final : public std::enable_shared_from_this<CardSession>
{
public:
    /// @brief Opens a session with the card in the named reader.
    /// @return On success, the opened session. On failure, a fully
    /// populated @ref OpenError carrying classification, user-facing
    /// message, and dev-facing diagnostic.
    /// @since 4.0
    /// @par macOS
    /// The session reaches the card through CryptoTokenKit and holds it
    /// exclusively until the @c CardSession is destroyed: other applications
    /// and token drivers wait for it, so keep a session no longer than the
    /// work it is opened for. The process must be signed with the
    /// @c com.apple.security.smartcard entitlement; without it the open fails
    /// with an @ref OpenError whose @c diagnosticDetail names the entitlement.
    /// On Linux the session goes through PC/SC.
    /// @par C++23 Idiom
    /// @code
    /// // On macOS the card stays held by this process until `session` goes.
    /// auto result = CardSession::open(readerName);
    /// if (!result) {
    ///     log("Open failed: {}", result.error().userMessage.defaultText);
    ///     return;
    /// }
    /// CardSession session = std::move(*result);
    /// @endcode
    [[nodiscard]] static std::expected<CardSession, OpenError> open(std::string readerName) noexcept;

    ~CardSession();
    CardSession(const CardSession&) = delete;
    CardSession& operator=(const CardSession&) = delete;
    /// @brief Move-constructible. Pimpl makes this a cheap pointer move;
    ///        the moved-from session holds no Impl and must not be used for
    ///        any operation other than destruction or move-assignment from
    ///        another CardSession. Matches the invariant of sibling
    ///        pimpl-backed classes (@ref LibreSCRS::Signing::SigningService,
    ///        @ref LibreSCRS::Signing::SigningRequest).
    CardSession(CardSession&&) noexcept;
    /// @brief Move-assignable. Same moved-from invariant as the move ctor.
    CardSession& operator=(CardSession&&) noexcept;

    /// @brief True when this object holds a valid (non-moved-from) pimpl.
    ///
    /// `if (!session)` is always well-defined; calling @ref readerName or
    /// @ref atr on a moved-from session is undefined behaviour. Consumers that move sessions into
    /// @c std::shared_ptr<CardSession> for signing should check the
    /// source-object state before the move if the source remains in scope.
    /// @since 4.0
    explicit operator bool() const noexcept
    {
        return d != nullptr;
    }

    /// @brief Name of the reader this session is bound to.
    /// @note Pure accessor, `noexcept` per API-POLICY §5.3. Calling any
    ///       accessor on a moved-from session is undefined behaviour; see
    ///       the move-ctor contract above.
    [[nodiscard]] const std::string& readerName() const noexcept;

    /// @brief ATR bytes reported by the card at session open.
    /// @note Pure accessor, `noexcept` per API-POLICY §5.3. Calling any
    ///       accessor on a moved-from session is undefined behaviour.
    [[nodiscard]] const std::vector<std::uint8_t>& atr() const noexcept;

    /// @brief True when this session currently owns an active secure-
    ///        messaging channel (PACE / BAC) in
    ///        @ref LibreSCRS::SecureChannel::ChannelState::Open.
    ///
    /// Cross-provider coordination check: hosts and PKCS#11 providers that
    /// open or consume a second PC/SC handle against the same physical
    /// reader MUST defer when this returns @c true, otherwise the card-
    /// side SM tunnel may be invalidated by reader-level multiplexing
    /// (notably observed on dual-slot contactless readers). Plain channels
    /// always read as @c false here; only channels whose
    /// @ref LibreSCRS::SecureChannel::ISecureChannel::carriesSm returns
    /// true are counted.
    ///
    /// @note Acquires the session mutex for the duration of the call so it
    ///       is safe to invoke concurrently with activation paths. On
    ///       lock acquisition failure (allocator pressure inside
    ///       @c std::mutex) the call returns @c false and skips the
    ///       check — the noexcept contract is preserved at the cost of a
    ///       conservative answer for a coordination predicate. Calling
    ///       any accessor on a moved-from session is undefined behaviour.
    /// @since 4.1
    [[nodiscard]] bool hasLiveSecureChannel() const noexcept;

    /// @brief The SM protocol that established the currently-live channel
    ///        (after any BAC fallback), or nullopt if no SM channel is active.
    ///        Recorded at activation time; cleared on channel teardown.
    ///
    /// @note Acquires the session mutex for the duration of the call so it is
    ///       safe to invoke concurrently with activation paths. On lock
    ///       acquisition failure (allocator pressure inside @c std::mutex) the
    ///       call returns @c nullopt — the noexcept contract is preserved at the
    ///       cost of a conservative answer. Calling any accessor on a moved-from
    ///       session is undefined behaviour.
    /// @since 5.0
    [[nodiscard]] std::optional<SmProtocolRequest> activatedProtocol() const noexcept;

    /// @brief True when a credential provider is installed via
    ///        @ref setCredentialProvider. Lets plugins distinguish a broker that
    ///        will supply secrets on demand from a host that pre-deposits them.
    ///
    /// @note Acquires the session mutex for the duration of the call so it is
    ///       safe to invoke concurrently with @ref setCredentialProvider on
    ///       another thread. On lock acquisition failure (allocator pressure
    ///       inside @c std::mutex) the call returns @c false — the noexcept
    ///       contract is preserved at the cost of a conservative answer.
    ///       Calling any accessor on a moved-from session is undefined
    ///       behaviour.
    /// @since 5.0
    [[nodiscard]] bool hasCredentialProvider() const noexcept;

    // -- Cross-plugin secure-channel coordination (4.1+) --------------------

    /// @brief Install or replace the credential provider used by
    ///        @ref activateChannelWithSm on cache miss. In PKCS#11 module
    ///        context (where the host supplies "CAN:PIN" directly through
    ///        @c C_Login) leave the provider unset and pre-populate the
    ///        cache via @ref setPaceSecret instead.
    ///
    /// @par Re-entrancy contract
    /// The provider is invoked WITHOUT the session mutex held — the
    /// activation path snapshots the provider, releases the mutex, calls
    /// the snapshot, then re-acquires the mutex and re-checks invariants
    /// the callback could have mutated. Implementations MAY therefore
    /// safely call back into the same @ref CardSession instance
    /// (e.g. @ref setPaceSecret, @ref setBacInput) without
    /// self-deadlocking on the non-recursive @c sessionMutex.
    /// @par noexcept contract
    /// Marked @c noexcept per the noexcept-alloc rule (API-POLICY §8): the
    /// body is wrapped in a top-level try/catch that returns a degraded
    /// no-op on lock or allocation failure (subsequent channel activations
    /// then fall through to the previously installed provider, if any).
    /// @since 4.1
    void setCredentialProvider(LibreSCRS::Auth::CredentialProvider provider) noexcept;

    /// @brief Activate the named applet under a plain (no-SM) channel.
    ///
    /// Suitable for non-PACE cards (contact PKCS#15 and equivalent).
    /// Begins a PC/SC transaction, SELECTs the AID, installs a
    /// @c PlainChannel, and returns an @ref ActiveChannelHolder whose
    /// destruction ends the transaction.
    ///
    /// @note The returned @ref ActiveChannelHolder borrows this session's
    ///       mutex and PC/SC transaction; see @ref ActiveChannelHolder
    ///       for the lifetime contract.
    ///
    /// @throws std::bad_alloc on out-of-memory during channel construction
    ///         or transaction setup. All other failure modes are surfaced
    ///         through the returned @c std::expected.
    ///
    /// @since 4.1
    [[nodiscard]] std::expected<ActiveChannelHolder, LibreSCRS::SecureChannel::ChannelActivationError>
    activateChannelFor(AppletAid aid, LibreSCRS::CancelToken token);

    /// @brief Activate the named applet under a secure-messaging channel
    ///        (PACE or BAC). On cache miss the credential provider is
    ///        invoked; on @c PaceWrongSecret the cache entry is evicted
    ///        and the prompt re-issued up to a small retry cap.
    ///
    /// @note The returned @ref ActiveChannelHolder borrows this session's
    ///       mutex and PC/SC transaction; see @ref ActiveChannelHolder
    ///       for the lifetime contract.
    ///
    /// @throws std::bad_alloc on out-of-memory during channel construction,
    ///         credential-provider snapshot copy, or transaction setup. All
    ///         other failure modes are surfaced through the returned
    ///         @c std::expected.
    ///
    /// @since 4.1
    [[nodiscard]] std::expected<ActiveChannelHolder, LibreSCRS::SecureChannel::ChannelActivationError>
    activateChannelWithSm(AppletAid aid, SmProtocolRequest protocol, LibreSCRS::CancelToken token);

    /// @brief Run eMRTD Chip Authentication (BSI TR-03110 §3.4, ICAO Doc 9303
    ///        Part 11 §6.2) over the active channel and adopt the session keys
    ///        it derives.
    ///
    /// The session chooses the path from the channel it holds:
    /// - **Plain channel** (for example a contact read): the key agreement
    ///   runs plain; on success the session installs a secure-messaging
    ///   channel under the derived keys, records @ref ChipAuthRequest as
    ///   @ref activatedProtocol and closes the plain channel. On any other
    ///   outcome the plain channel stays installed and the read can go on
    ///   plain.
    /// - **Secure-messaging channel** (PACE or BAC): the key agreement runs
    ///   inside the tunnel and the tunnel switches to the derived keys; the
    ///   recorded protocol does not change, and the channel's current applet
    ///   becomes @p aid when the proof SELECT of it succeeded.
    ///
    /// Either way @ref ChipAuthOutcome::Passed is reported only after a
    /// protected exchange (a SELECT of @p aid) has verified under the derived
    /// keys; an answer whose MAC verifies proves the keys even when its status
    /// word is an error (the applet is then not recorded as selected).
    /// @ref ChipAuthOutcome::Failed means only that the chip answered and did
    /// not prove that it holds the key — inside a tunnel this includes a
    /// refusal of the protocol and an answer that fails the tunnel's integrity
    /// check, both answers from the card (see @ref ChipAuthOutcome::Failed). A
    /// cancel, a refusal on a plain channel or a failure on this side is
    /// @ref ChipAuthOutcome::NotPerformed with the matching
    /// @ref ChipAuthReason. The derived keys never leave the library.
    ///
    /// @param dg14  Raw EF.DG14 as read from the document (the
    ///              @c SecurityInfos carrying the chip's public key).
    /// @param aid   Applet the proof exchange selects; the application the
    ///              read continues in (the eMRTD LDS application).
    /// @param token Cancellation; checked before the first command and
    ///              honoured between the commands of the run.
    /// @return The verdict, the protocol chosen and a diagnostic.
    ///
    /// @pre The calling thread holds this session's
    ///      @ref ActiveChannelHolder (from @ref activateChannelFor or
    ///      @ref activateChannelWithSm, or the one a card plugin's read runs
    ///      under), so the run cannot interleave with other commands. Without
    ///      it, or without an open channel, nothing is sent and the result is
    ///      @ref ChipAuthOutcome::NotPerformed with
    ///      @ref ChipAuthReason::NoUsableChannel.
    ///
    /// @throws std::bad_alloc on out-of-memory.
    /// @throws std::runtime_error (the transport's error type) when the reader
    ///         fails or the card goes away during the run, on either path; no
    ///         verdict is reported then. After a throw the channel's secure
    ///         messaging may be out of step with the card: clear the channel
    ///         before reusing the session.
    ///
    /// @par Example
    /// @code
    /// auto holder = session.activateChannelFor(emrtdAid, token);
    /// if (holder) {
    ///     const auto report = session.performChipAuthentication(dg14, emrtdAid, token);
    ///     if (report.outcome == ChipAuthOutcome::Failed) {
    ///         warn("chip is not genuine: {}", report.detail);
    ///     }
    /// }
    /// @endcode
    ///
    /// @since 5.0
    [[nodiscard]] ChipAuthReport performChipAuthentication(std::span<const std::uint8_t> dg14, AppletAid aid,
                                                           LibreSCRS::CancelToken token);

    /// @brief Pre-populate the per-process PACE credentials cache.
    ///        Used by the PKCS#11 module after parsing the host-supplied
    ///        "CAN:PIN" string, and by plugins that have already collected
    ///        the secret out-of-band.
    /// @par noexcept contract
    /// Marked @c noexcept per the noexcept-alloc rule (API-POLICY §8): the
    /// body is wrapped in a top-level try/catch that returns a degraded
    /// no-op (cache left unchanged) on lock or allocation failure; the
    /// next channel-activation pass then falls through to the credential
    /// provider.
    /// @since 4.1
    void setPaceSecret(LibreSCRS::Auth::PaceSecretKind kind, LibreSCRS::Secure::String value) noexcept;

    /// @brief Pre-populate the BAC handshake inputs (document number, dates
    ///        of birth + expiry from the MRZ-Z line). BAC consumes a
    ///        dedicated cache slot disjoint from the PACE credentials cache
    ///        because the three MRZ components are structurally a tuple
    ///        rather than a single shared secret.
    /// @par noexcept contract
    /// Marked @c noexcept per the noexcept-alloc rule (API-POLICY §8): the
    /// body is wrapped in a top-level try/catch that returns a degraded
    /// no-op (cache left unchanged) on lock or allocation failure.
    /// @since 4.1
    void setBacInput(LibreSCRS::SecureChannel::BacInput input) noexcept;

    /// @brief Wipe all cached PACE credentials and the BAC input. Each PACE
    ///        slot is replaced with a default-constructed @c Secure::String,
    ///        which zeroises its underlying buffer; the BAC input is reset
    ///        to a default-constructed value.
    /// @par noexcept contract
    /// Marked @c noexcept per the noexcept-alloc rule (API-POLICY §8): the
    /// body is wrapped in a top-level try/catch that returns a degraded
    /// no-op on lock acquisition failure. The reset itself is an in-place
    /// zeroise that does not allocate.
    /// @since 4.1
    void clearCachedPaceCredentials() noexcept;

    /// @brief Close and release the currently installed secure channel, if
    ///        any. The session remains usable; a subsequent
    ///        @ref activateChannelFor / @ref activateChannelWithSm call will
    ///        rebuild a fresh channel.
    ///
    /// @note This is the explicit teardown hook for callers that have
    ///       reason to drop the channel ahead of session destruction — for
    ///       example a host that keeps an idle session open between
    ///       operations and releases what the previous operation installed
    ///       before it parks the session.
    /// @since 4.1
    void clearActiveChannel() noexcept;

    // -- Byte-level transport (5.0+) ------------------------------------------

    /// @brief Send one command APDU to the card, through the secure-messaging
    ///        channel when one is open, and return the card's whole answer.
    ///
    /// The command takes the path the session's channel dictates:
    /// - an open channel (secure-messaging or plain) carries it: under secure
    ///   messaging it is wrapped, and the answer is unwrapped and verified;
    /// - an installed secure-messaging channel that is no longer open (it
    ///   failed on a bad MAC or a 6987/6988 answer, or was closed) refuses
    ///   every command, from any thread: the answer is @c 6F02 and nothing is
    ///   sent. The call never drops that channel, so a command the caller
    ///   meant to be protected never goes plain. It stays until
    ///   @ref discardFailedChannel, @ref clearActiveChannel or the activation
    ///   of another channel (@ref activateChannelFor,
    ///   @ref activateChannelWithSm) removes it;
    /// - otherwise (no channel, or a plain one that is not open) it goes to the
    ///   card plain. The reader layer completes the exchange as the card asks:
    ///   it fetches a chained answer (status word @c 61xx, GET RESPONSE) and,
    ///   on a T=0 card, resends with the length a @c 6Cxx answer names.
    ///
    /// @param apdu  The command, encoded per ISO/IEC 7816-4 (short or
    ///              extended length).
    /// @param token Cancellation, handed to the channel: an open channel
    ///              answers @c 6F01 without sending once it is cancelled.
    /// @return The answer: response data followed by SW1 SW2. @c 6F00 when the
    ///         session holds no connection to a card.
    ///
    /// @throws std::invalid_argument when @p apdu is not a well-formed command
    ///         APDU in the encoding this library produces; nothing is sent.
    /// @throws std::runtime_error when the reader fails or the card goes away
    ///         during the exchange.
    ///
    /// @par Thread-safety
    /// The call may be made by the thread that holds this session's
    /// @ref ActiveChannelHolder (it then takes no lock: no other thread can
    /// touch the session meanwhile) or by another thread. That one waits for
    /// the holder to be released, then chooses the path and sends the command
    /// under the session's lock, so no secure-messaging handshake started on
    /// another thread can come between the two.
    ///
    /// @par Example
    /// @code
    /// // SELECT the eMRTD application, no answer data wanted.
    /// const std::uint8_t select[] = {0x00, 0xA4, 0x04, 0x0C, 0x07,
    ///                                0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    /// const auto answer = session.transmit(select);
    /// const bool ok = answer.size() >= 2 && answer[answer.size() - 2] == 0x90 && answer.back() == 0x00;
    /// @endcode
    ///
    /// @since 5.0
    [[nodiscard]] std::vector<std::uint8_t> transmit(std::span<const std::uint8_t> apdu,
                                                     LibreSCRS::CancelToken token = {});

    /// @brief Send one command APDU to the card exactly as given, as a single
    ///        exchange, unless a secure-messaging channel is live.
    ///
    /// For callers that do their own APDU handling (a status word @c 61xx or
    /// @c 6Cxx comes back as is; no GET RESPONSE follows). While the session
    /// holds an open secure-messaging channel (see @ref hasLiveSecureChannel)
    /// nothing is sent and the answer is @c 6F02: a plain command would end the
    /// card's secure-messaging session. Use @ref transmit to reach the card
    /// through that channel. A secure-messaging channel that is no longer open
    /// refuses the bytes too (@c 6F02, nothing sent), from any thread, until
    /// it is removed (see @ref transmit).
    ///
    /// @param apdu The command bytes, sent unchanged.
    /// @return The answer: response data followed by SW1 SW2. @c 6F02 when a
    ///         secure-messaging channel refuses it (see above); @c 6F00 when the
    ///         session holds no connection to a card.
    ///
    /// @throws std::runtime_error when the reader fails or the card goes away
    ///         during the exchange.
    ///
    /// @par Thread-safety
    /// As @ref transmit.
    ///
    /// @since 5.0
    [[nodiscard]] std::vector<std::uint8_t> transmitRaw(std::span<const std::uint8_t> apdu);

    /// @brief Remove a secure-messaging channel that is no longer open, so
    ///        that plain commands reach the card again.
    ///
    /// A channel that failed (a bad MAC, a 6987/6988 answer) or was closed
    /// makes @ref transmit and @ref transmitRaw refuse every command
    /// (@c 6F02); the card has ended, or will end on its next answer, that
    /// secure-messaging session. A host calls this at a point where it starts
    /// a new, plain interaction with the card and no earlier operation's
    /// commands can follow -- before it identifies the card, say.
    /// @ref Plugin::CardPluginService::findAllCandidates does so before it
    /// probes the plugins. An open channel, a plain channel, or no channel
    /// is left as it is.
    ///
    /// @return @c true when a channel was removed.
    ///
    /// @par Thread-safety
    /// The check and the removal happen under the session's lock, so a
    /// channel another thread activates meanwhile is never removed. Called on
    /// the thread that holds this session's @ref ActiveChannelHolder it does
    /// nothing and returns @c false: the operation running over the channel
    /// keeps it, and its commands stay refused.
    ///
    /// @par Example
    /// @code
    /// // A host that probes one plugin itself, on a session whose earlier
    /// // tunnel may have failed.
    /// (void)session.discardFailedChannel();
    /// const bool handles = plugin->canHandleConnection(session.atr(), session);
    /// @endcode
    ///
    /// @since 5.0
    bool discardFailedChannel() noexcept;

    /// @brief Identity of this session among all sessions of the process.
    ///
    /// Every opened session gets a value no other session of the process has
    /// had or will have; a moved-to session keeps the value of the session it
    /// was moved from. @ref LibreSCRS::Plugin::makeSessionKey pairs it with
    /// the reader name to key per-session state.
    ///
    /// @note Pure accessor. Calling it on a moved-from session is undefined
    ///       behaviour.
    /// @since 5.0
    [[nodiscard]] std::uint64_t generation() const noexcept;

    /// @brief Re-establish the connection to the card in the reader without
    ///        resetting it.
    ///
    /// For a card whose context was lost (it answers every command with an
    /// error after an interruption). The card is not reset, so other
    /// applications' connections to it and an open secure-messaging channel
    /// survive.
    ///
    /// @throws std::runtime_error when the card cannot be reached.
    /// @since 5.0
    void reconnect();

    /// @brief Take exclusive use of the card: no other application's commands
    ///        reach it until @ref endTransaction.
    ///
    /// Not counted: one @ref endTransaction ends it however many times it was
    /// begun. @ref activateChannelFor and @ref activateChannelWithSm take one
    /// for the lifetime of the @ref ActiveChannelHolder they return; while
    /// @ref isTransactionHeld is true, do not begin another.
    ///
    /// @throws std::runtime_error when the reader refuses (the card was removed
    ///         or reset, or another application holds it).
    /// @since 5.0
    void beginTransaction();

    /// @brief End the exclusive use @ref beginTransaction took. Does nothing
    ///        when none is held.
    /// @since 5.0
    void endTransaction() noexcept;

    /// @brief True while this session holds exclusive use of the card, taken
    ///        by @ref beginTransaction or by an @ref ActiveChannelHolder.
    /// @since 5.0
    [[nodiscard]] bool isTransactionHeld() const noexcept;

    /// @brief State of the channel the session currently holds, or @c nullopt
    ///        when it holds none.
    ///
    /// A plain channel as well as a secure-messaging one: see
    /// @ref carriesSecureMessaging to tell them apart.
    ///
    /// @note Owner-tolerant: called by the thread that holds this session's
    ///       @ref ActiveChannelHolder it reads the channel without locking;
    ///       from another thread it takes the session mutex. On lock failure
    ///       it returns @c nullopt.
    /// @since 5.0
    [[nodiscard]] std::optional<LibreSCRS::SecureChannel::ChannelState> channelState() const noexcept;

    /// @brief True when the channel the session holds wraps commands in secure
    ///        messaging (PACE, BAC or Chip Authentication), whatever its state.
    ///
    /// Unlike @ref hasLiveSecureChannel this stays true for a secure-messaging
    /// channel that has failed: the card still expects secure messaging, and
    /// @ref transmit refuses to bypass it. False with no channel or a plain
    /// one.
    ///
    /// @note Owner-tolerant, as @ref channelState. On lock failure it returns
    ///       @c false.
    /// @since 5.0
    [[nodiscard]] bool carriesSecureMessaging() const noexcept;

    /// @brief Forget which application the session's channel has selected.
    ///
    /// For a caller that selected another file or application through
    /// @ref transmit: the channel no longer records the application it was
    /// activated for, so the next @ref activateChannelFor or
    /// @ref activateChannelWithSm selects it again instead of reusing the
    /// channel as it stands. Does nothing when the session holds no channel.
    ///
    /// @note Owner-tolerant, as @ref channelState. On lock failure it does
    ///       nothing.
    /// @since 5.0
    void forgetCurrentApplet() noexcept;

private:
    // The access structs are the internal access points for the holder's
    // owner record and the test seams (ChannelInjector, Testing::SessionAccess). Their
    // declarations live outside this header; friend declarations here inject
    // the names at enclosing-namespace scope without leaking any prototypes
    // into the public include tree.
    friend struct detail::ChannelInjector;
    friend struct Testing::SessionAccess;
    friend struct Internal::ActiveChannelAccessor;

    /// @brief Private; a session over a detached connection (no handle, no
    ///        card), used by @ref Testing::makeDetachedCardSession.
    CardSession();
    /// @brief Private constructor used by @ref open and the detail factories.
    ///        Not part of the public surface.
    explicit CardSession(std::string readerName);

    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::SmartCard
