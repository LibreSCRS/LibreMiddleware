// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Concrete @ref LibreSCRS::Pkcs11::Internal::PKCS11Card backed
///        by the existing @ref pkcs15::PKCS15Card APDU helper. One
///        @ref Pkcs15Slot per AODF user PIN is published.

#include <internal/PKCS11Card.h>
#include <internal/PKCS11CardProvider.h>

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/CardMap.h>

#include <expected>
#include <memory>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard {
class CardSession;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::Pkcs11::Internal {
class SessionRegistry;
} // namespace LibreSCRS::Pkcs11::Internal

namespace pkcs15 {
class PKCS15Card;
struct PKCS15Profile;
struct PinInfo;
} // namespace pkcs15

namespace LibreSCRS::Pkcs15::Pkcs11 {

/// @brief Concrete @ref LibreSCRS::Pkcs11::Internal::PKCS11Card backed
///        by the existing @ref pkcs15::PKCS15Card APDU helper.
///
/// Wraps a single PC/SC reader's bound PKCS#15 surface and surfaces one
/// @ref Pkcs15Slot per user PIN object discovered in the AODF.
/// Single-PIN card families yield one slot; multi-PIN families yield one
/// slot per AUTH PIN. PUK and CAN PINs are filtered.
///
/// @par Transport ownership
/// Owns a @ref LibreSCRS::SmartCard::CardSession for the card's lifetime.
/// Every operation that touches the card acquires a fresh
/// @ref LibreSCRS::SmartCard::ActiveChannelHolder via @ref acquireChannel
/// — non-PACE families take the @c PlainChannel path, PACE-gated
/// contactless families take the @c PaceChannel path with the CAN
/// deposited into the session's per-process cache through
/// @ref onCachedCanChanged.
/// No long-lived @c pkcs15::PKCS15Card helper / @c PCSCConnection /
/// @c SecureMessaging is held; each holder constructs the helper from
/// @c holder.activeChannel() and discards it on scope exit. Mirrors the
/// @c pkcs15-plugin pattern (one PCSCConnection per CardSession in the
/// LM consumer; one holder per operation).
///
/// @par Thread-safety
/// Inherits @c cardMutex from the base; APDU exchange is therefore
/// serialised across slots of the same physical card. Slots reach the
/// transport via @c friend access on the base class as documented in
/// @ref PKCS11Card; the per-op holder additionally locks the session's
/// internal mutex (project lock order: slotMutex → cardMutex →
/// sessionMutex).
///
/// @since 4.1
class Pkcs15Slot;

class Pkcs15Card final : public LibreSCRS::Pkcs11::Internal::PKCS11Card
{
    // Slots reach the parent's session and profile through controlled
    // friend access; keeps the per-op transport surface narrow.
    friend class Pkcs15Slot;

public:
    /// @brief Construct an unbound card. Call @ref bind() exactly once.
    /// @param cardMap Optional shared cache of per-card discovered state
    ///                (PKCS#15 path / SELECT P2 / PIN labels). When
    ///                non-null, @ref bind() reuses any previously probed
    ///                state; when null, no cache is consulted. Reserved
    ///                for future cache-driven optimisations — currently
    ///                unused now that holders SELECT the AID directly.
    /// @since 4.1
    explicit Pkcs15Card(std::shared_ptr<LibreSCRS::SmartCard::CardMap> cardMap = nullptr);

    /// @brief Drops this card's reference to @ref session after slots
    ///        (declared LAST in the base) have been destroyed. The PC/SC
    ///        handle is released only when the last shared reference
    ///        drops — host-side references (e.g. LibreCelik display) may
    ///        keep the session alive past this destructor.
    /// @since 4.1
    ~Pkcs15Card() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::bind
    /// @par Thread-safety
    /// Internally synchronised; takes @c cardMutex for the duration.
    /// @since 4.1
    [[nodiscard]] unsigned long bind(const std::string& readerName) override;

    /// @brief Bind by adopting an externally-supplied live CardSession
    ///        rather than opening a fresh PC/SC handle.
    ///
    /// Intended for in-process hosts (LibreCelik via @c SessionAttachment)
    /// that already hold a live @c CardSession for the same reader. The
    /// adopted session may already carry a live PACE SM context that the
    /// host's display flow established earlier; the probe order is
    /// designed to preserve that tunnel rather than destroy it.
    ///
    /// @par Probe order
    /// Step 1 calls @c activateChannelWithSm with @c PaceRequest{Can}.
    /// When the session has a live @c PaceChannel, this hits Case 1
    /// (target applet) or Case 2 (different applet, wrapped SELECT) and
    /// reuses the SM tunnel without any plain APDU. With a warm PACE
    /// cache but no live channel it performs a full PACE handshake.
    /// Otherwise the preflight returns @c CredentialsRequired cheaply
    /// (no wire I/O) and Step 2 attempts @c activateChannelFor
    /// (PlainChannel): a non-PACE card succeeds; a PACE-gated card with
    /// no deposited CAN surfaces @c SelectAppletFailed which is mapped
    /// to @c Crv::PinIncorrect so the consumer's normal "wrong PIN, try
    /// again" flow re-prompts for the CAN. The truthful invariant is
    /// "preserve a live SM tunnel by trying SM first; fall back to
    /// plain only when SM has no credentials".
    ///
    /// @par Limitation
    /// v1 hardcodes @c PaceSecretKind::Can — correct for the
    /// contactless PKCS#15 families currently supported via the inject
    /// path. Cards using PIN/PUK as the PACE secret would require
    /// querying the session's deposited secret kind or accepting it as
    /// a parameter.
    ///
    /// @par Thread-safety
    /// Internally synchronised; takes @c cardMutex for the duration.
    /// @since 4.1
    [[nodiscard]] unsigned long bindFromInjectedSession(const std::string& readerName,
                                                        std::shared_ptr<LibreSCRS::SmartCard::CardSession> injected);

protected:
    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::establishPACE
    /// @par Implementation
    /// Validates that PACE works on the freshly-deposited CAN by
    /// acquiring an @ref ActiveChannelHolder via @ref acquireChannel and
    /// immediately releasing it. The session's PACE cache retains the
    /// derived SM keys for subsequent per-op holders. Returns
    /// @c Crv::PinIncorrect on @c PaceWrongSecret, @c Crv::PinLocked on
    /// @c PacePinBlocked, @c Crv::DeviceError on transport failures.
    /// @par Thread-safety
    /// Caller must hold @c cardMutex.
    /// @since 4.1
    [[nodiscard]] unsigned long establishPACE() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::completeBind
    /// @par Thread-safety
    /// Caller must hold @c cardMutex. Builds slots from the PKCS#15
    /// profile read at @ref bind() time (one slot per user PIN).
    /// @since 4.1
    [[nodiscard]] unsigned long completeBind() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::resumePostCan
    /// @par Implementation
    /// Delegates to @ref resumeBind, which runs the post-CAN tail of
    /// @ref bind (acquire SM holder, read profile). The placeholder slot
    /// self-transforms in @ref Pkcs15Slot::login after this hook returns
    /// @c Crv::Ok.
    /// @since 4.1
    [[nodiscard]] unsigned long resumePostCan() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::onCachedCanChanged
    /// @par Implementation
    /// Mirrors the inherited @c cachedCan into @ref session's per-process
    /// PACE cache via @c CardSession::setPaceSecret (or
    /// @c clearCachedPaceCredentials when the field was wiped) so the
    /// per-op @ref acquireChannel finds the secret on its first call. No-op
    /// when @ref session has not yet been opened.
    void onCachedCanChanged() noexcept override;

private:
    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::reconnectInline
    /// @par Implementation
    /// Closes and reopens @ref session against the same @ref readerName.
    /// Any prior PACE session keys are correctly discarded — the
    /// card-side context was lost on RESET. Re-deposits @c cachedCan into
    /// the fresh session via the @ref onCachedCanChanged hook so PACE-
    /// gated cards can re-PACE on the next @ref acquireChannel.
    /// @since 4.1
    [[nodiscard]] unsigned long reconnectInline() override;

    /// @brief Acquire a per-operation @ref ActiveChannelHolder against
    ///        the PKCS#15 AID.
    ///
    /// Routes to @c CardSession::activateChannelWithSm with
    /// @c PaceRequest{Can} when @ref needsPace, otherwise
    /// @c CardSession::activateChannelFor (PlainChannel). The CAN — when
    /// required — must already have been deposited via the inherited
    /// @c parentCacheCan / @ref onCachedCanChanged path; cache miss
    /// surfaces as @c ChannelActivationError::CredentialsRequired.
    /// @par Thread-safety
    /// Caller must hold @c cardMutex (slots acquire it via
    /// @c parentTransportMutex). The holder additionally locks the
    /// session's own mutex; project lock order is preserved
    /// (slotMutex → cardMutex → sessionMutex).
    /// @since 4.1
    [[nodiscard]] std::expected<LibreSCRS::SmartCard::ActiveChannelHolder,
                                LibreSCRS::SecureChannel::ChannelActivationError>
    acquireChannel(LibreSCRS::CancelToken token = {});

    /// @brief Common tail of @ref bind and @ref bindFromInjectedSession:
    ///        read the PKCS#15 profile under the supplied holder, store
    ///        on @c profile, and dispatch to @ref completeBind. The
    ///        holder must reference a live channel.
    /// @par Thread-safety
    /// Caller must hold @c cardMutex.
    /// @since 4.1
    [[nodiscard]] unsigned long readProfileAndComplete(LibreSCRS::SmartCard::ActiveChannelHolder& holder);

    /// @brief Resume bind after @ref Pkcs15Slot::login supplied a CAN.
    ///
    /// Acquires a holder via @ref acquireChannel (which drives the PACE
    /// handshake on the deposited CAN), reads the PKCS#15 profile under
    /// the holder's lifetime, and stores it on @c profile so the
    /// placeholder slot can self-transform from the freshly-discovered
    /// pins / keys / certs. Does NOT touch @c slots — the caller (a
    /// self-transforming placeholder slot) populates its own state.
    /// @return @ref Crv constant; @ref Crv::Ok on success.
    /// @par Thread-safety
    /// Caller (the placeholder slot) must hold @c cardMutex.
    /// @since 4.1
    [[nodiscard]] unsigned long resumeBind();

    /// @brief PC/SC session. Owned outright when produced by
    ///        @ref bind via @c CardSession::open (refcount 1, equivalent
    ///        to @c unique_ptr semantics). Shared with the caller when
    ///        produced by @ref bindFromInjectedSession — the host's
    ///        display flow keeps a parallel reference so the underlying
    ///        PC/SC handle outlives a sign-only @c Pkcs15Card. Destroyed
    ///        before the inherited @c slots vector via natural
    ///        reverse-declaration order.
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> session;

    /// @brief PKCS#15 profile cached after the first successful read.
    ///        Populated by @ref bind() (eager) or @ref resumeBind()
    ///        (placeholder self-transform tail). Slots borrow this via
    ///        @ref Pkcs15Slot::parentProfile to discover their
    ///        per-operation pin / keys / certs without re-reading
    ///        the AODF on every call.
    std::unique_ptr<pkcs15::PKCS15Profile> profile;

    /// @brief When @c true the parent applet refuses PKCS#15 directory
    ///        reads pre-login. @ref bind() therefore publishes ONE
    ///        placeholder slot and defers the real profile read to that
    ///        slot's first @ref Pkcs15Slot::login. Distinct from the
    ///        inherited @c placeholderState which marks the
    ///        PACE-CAN-deferred path.
    bool needsDeferredProfile{false};

    /// @brief Optional shared cache of per-card discovered state.
    ///        Reserved for cross-instance reuse on the same physical card.
    std::shared_ptr<LibreSCRS::SmartCard::CardMap> cardMap;
};

/// @brief @ref LibreSCRS::Pkcs11::Internal::PKCS11CardProvider for the
///        PKCS#15 family.
///
/// @ref probe constructs a @ref Pkcs15Card and returns it on successful
/// bind. The canonical PKCS#15 provider on the multi-PIN
/// @ref LibreSCRS::Pkcs11::Internal::PKCS11CardProvider surface.
///
/// @since 4.1
class Pkcs15PKCS11Provider final : public LibreSCRS::Pkcs11::Internal::PKCS11CardProvider
{
public:
    /// @brief Construct the provider with optional shared caches.
    /// @param cardMap        Per-card discovered-state cache threaded
    ///                       through every @c Pkcs15Card created by
    ///                       @ref probe. Pass @c nullptr to disable.
    /// @param sessionRegistry In-process session registry consulted at
    ///                        probe time. A registry hit means an
    ///                        in-process host (LibreCelik) parked a live
    ///                        @c CardSession for the reader; @ref probe
    ///                        adopts it instead of opening a fresh PC/SC
    ///                        handle. @c nullptr disables the inject
    ///                        path — every probe falls through to the
    ///                        standalone @c bind() that opens its own
    ///                        PC/SC handle, which is the normal mode for
    ///                        external consumers loading the module via
    ///                        dlopen without inject support.
    /// @since 4.1
    Pkcs15PKCS11Provider(
        std::shared_ptr<LibreSCRS::SmartCard::CardMap> cardMap,
        std::shared_ptr<LibreSCRS::Pkcs11::Internal::SessionRegistry> sessionRegistry = nullptr) noexcept;
    ~Pkcs15PKCS11Provider() override = default;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11CardProvider::probe
    /// @since 4.1
    [[nodiscard]] std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card>
    probe(const std::string& readerName) override;

private:
    std::shared_ptr<LibreSCRS::SmartCard::CardMap> cardMap;
    std::shared_ptr<LibreSCRS::Pkcs11::Internal::SessionRegistry> sessionRegistry;
};

} // namespace LibreSCRS::Pkcs15::Pkcs11
