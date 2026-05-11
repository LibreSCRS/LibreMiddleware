// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Abstract base for one logical PKCS#11 slot — the unit of
///        per-PIN gating in the multi-PIN refactor.

#include "PKCS11ObjectInfo.h"
#include "PKCS11TokenInfo.h"

#include <LibreSCRS/Secure/String.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal {

class PKCS11Card;

/// @brief Abstract base for a single logical PKCS#11 slot.
///
/// In the multi-PIN model a physical card surfaces one slot per
/// authenticator (one PIN ⇒ one slot ⇒ one token). Each slot owns its
/// own login state and PIN cache; cross-slot leakage of authentication
/// is forbidden. Concrete subclasses implement the per-card-family
/// transport (CardEdge, PKCS#15, PIV, …).
///
/// @par Thread-safety
/// Each slot has a private @ref slotMutex guarding @ref cachedPin,
/// @ref loggedIn, and @ref cachedTokenInfo. Sibling slots (under the
/// same @ref PKCS11Card) hold independent mutexes; the surrounding
/// @ref PKCS11Card serialises card-level transport via its own mutex.
/// Public methods of this class are expected to acquire @ref slotMutex
/// internally; callers must NOT hold any slot mutex when invoking
/// methods on a different slot to avoid lock-order inversion.
///
/// @par Lock order
/// @ref slotMutex MUST be acquired before the parent card's
/// @c cardMutex (project-wide invariant). Card-level paths must
/// therefore NEVER hold @c cardMutex while reaching into any
/// @ref slotMutex; if a card-level operation needs to notify
/// or invalidate slots it MUST release @c cardMutex first.
/// Reconnect / RESET handling stays inside @c cardMutex and
/// surfaces back to slots via the APDU return path — slots are
/// not reached top-down.
///
/// @since 4.1
class PKCS11Slot
{
public:
    /// @brief Construct a slot bound to an owning card.
    /// @param parentCard Weak handle to the owning card. Stored as
    ///        @c weak_ptr to avoid an ownership cycle.
    /// @param pinId      PKCS#15 PIN reference ID (path or ID byte
    ///                   string). Empty for card families that gate by
    ///                   reference number rather than PIN object.
    /// @param pinLabel   Human-readable label for this slot's PIN
    ///                   (e.g. @c "Auth PIN"). Surfaced via
    ///                   @ref tokenInfo() to UI and to @c CKA_LABEL.
    PKCS11Slot(std::weak_ptr<PKCS11Card> parentCard, std::vector<std::uint8_t> pinId, std::string pinLabel);

    PKCS11Slot(const PKCS11Slot&) = delete;
    PKCS11Slot& operator=(const PKCS11Slot&) = delete;
    PKCS11Slot(PKCS11Slot&&) = delete;
    PKCS11Slot& operator=(PKCS11Slot&&) = delete;

    /// @brief Cleanses any cached PIN before destruction.
    /// @par Thread-safety
    /// Destruction of a slot is structurally serialised by its owning
    /// @ref PKCS11Card: the card declares @c slots LAST, so the slot
    /// vector is destroyed first (under exclusive ownership of the card
    /// destructor). The slot dtor itself does NOT take @ref slotMutex —
    /// it would be a self-pin against an about-to-die object — so it is
    /// the OWNER's contract (the @ref PKCS11Card destructor) to ensure
    /// no concurrent thread is still observing through this slot.
    /// @ref cachedPin is cleansed via @ref Secure::String's destructor.
    /// @since 4.1
    virtual ~PKCS11Slot();

    /// @brief Snapshot of token attributes published to PKCS#11 clients.
    /// @return Copy of the cached @ref PKCS11TokenInfo. Acquires
    ///         @ref slotMutex briefly.
    /// @par Thread-safety
    /// Internally synchronised. Safe from any thread.
    /// @since 4.1
    [[nodiscard]] PKCS11TokenInfo tokenInfo() const;

    /// @brief Authenticate to this slot with the supplied PIN.
    /// @param userType PKCS#11 user type (@c CKU_USER, @c CKU_SO).
    /// @param pin      PIN bytes; storage owned by the caller. The slot
    ///                 copies into its own cleansing buffer on
    ///                 @ref Crv::Ok and zeroises on logout / destruction.
    /// @return @ref Crv constant — @ref Crv::Ok on success.
    /// @par Thread-safety
    /// Internally synchronised; takes @ref slotMutex and the parent
    /// card's transport mutex in that order.
    /// @since 4.1
    [[nodiscard]] virtual unsigned long login(unsigned long userType, std::span<const std::uint8_t> pin) = 0;

    /// @brief Drop authentication for this slot.
    /// @return @ref Crv constant.
    /// @par Thread-safety
    /// Internally synchronised.
    /// @since 4.1
    [[nodiscard]] virtual unsigned long logout() = 0;

    /// @brief Enumerate token-resident objects visible under this slot.
    /// @return Snapshot of @ref PKCS11ObjectInfo entries.
    /// @par Thread-safety
    /// Internally synchronised. May trigger card I/O on first call.
    /// @since 4.1
    [[nodiscard]] virtual std::vector<PKCS11ObjectInfo> enumerateObjects() = 0;

    /// @brief Sign @p data with the on-card key referenced by
    ///        @p keyId using @p mechanism.
    /// @param data      Bytes to sign (raw or pre-hashed depending on
    ///                  the mechanism).
    /// @param mechanism @c CK_MECHANISM_TYPE numeric value.
    /// @param keyId     CKA_ID of the on-card private key.
    /// @return Signature bytes on success; empty on failure (the @ref
    ///         Crv error path travels via the surrounding library
    ///         layer).
    /// @par Thread-safety
    /// Internally synchronised; serialises card transport.
    /// @since 4.1
    [[nodiscard]] virtual std::vector<std::uint8_t>
    signData(std::span<const std::uint8_t> data, unsigned long mechanism, std::span<const std::uint8_t> keyId) = 0;

    /// @brief Sign with a card that may hash internally — caller passes
    ///        BOTH the pre-built PKCS#1 v1.5 DigestInfo prefix AND the
    ///        raw message bytes, leaving the slot to choose the
    ///        underlying APDU strategy.
    ///
    /// Combined hash+sign mechanisms (e.g. @c CKM_SHA256_RSA_PKCS) and
    /// PSS mechanisms reach the slot through this entry point: the
    /// library layer builds the DigestInfo (or leaves it empty for
    /// PSS) and the raw data once, and the slot dispatches to
    /// pre-hashed or hash-on-card APDUs based on the family. RSA-PSS
    /// padding is performed by the card; @p digestInfo is empty for
    /// PSS mechanisms.
    /// @param digestInfo PKCS#1 v1.5 DigestInfo prefix (algId + hash);
    ///                   empty for PSS mechanisms or when the slot is
    ///                   expected to hash internally.
    /// @param rawData    Raw (unhashed) message bytes; provided for
    ///                   cards that hash on-chip.
    /// @param mechanism  PKCS#11 @c CK_MECHANISM_TYPE numeric value.
    /// @param keyId      @c CKA_ID of the on-card private key.
    /// @return Signature bytes on success; empty on failure.
    /// @par Thread-safety
    /// Internally synchronised; serialises card transport.
    /// @since 4.1
    [[nodiscard]] virtual std::vector<std::uint8_t> signWithDigestInfo(std::span<const std::uint8_t> digestInfo,
                                                                       std::span<const std::uint8_t> rawData,
                                                                       unsigned long mechanism,
                                                                       std::span<const std::uint8_t> keyId) = 0;

    /// @brief Pre-IO signature size for a key referenced by @p keyId.
    ///
    /// For RSA keys this is the modulus length in bytes; for ECDSA it
    /// is twice the curve component size (P-256 → 64, P-384 → 96, …).
    /// The PKCS#11 library layer queries this before issuing
    /// @c C_Sign so it can return @c CKR_BUFFER_TOO_SMALL with the
    /// correct length without consuming the active sign state.
    /// @param keyId @c CKA_ID of the target key.
    /// @return Signature size in bytes; @c 0 when the key is not
    ///         enumerated under this slot.
    /// @par Thread-safety
    /// Lock-free in the common case; reads from the post-bind /
    /// post-enumeration cache the subclass populates from
    /// @ref enumerateObjects.
    /// @since 4.1
    [[nodiscard]] virtual std::size_t signatureSize(std::span<const std::uint8_t> keyId) const = 0;

    /// @brief Snapshot of this slot's authentication state.
    /// @return @c true once @ref login has succeeded and before the
    ///         next @ref logout / reset.
    /// @par Thread-safety
    /// Internally synchronised; reads @ref loggedIn under
    /// @ref slotMutex. The default implementation suffices for
    /// subclasses whose only login bookkeeping is the inherited
    /// @ref loggedIn flag; subclasses with additional per-key or
    /// per-mode authentication state may override.
    /// @note The @c noexcept decoration relies on the implementation
    ///       guarantee that @c std::mutex::lock() does not throw on an
    ///       uncontended acquisition (libstdc++ ≥ 9, libc++ ≥ 7). The
    ///       C++ standard permits @c std::system_error from @c lock();
    ///       if a strictly-conforming standard library is ever targeted,
    ///       drop the @c noexcept on this declaration (and the matching
    ///       definition in @c pkcs11_slot.cpp).
    /// @since 4.1
    [[nodiscard]] virtual bool isLoggedIn() const noexcept;

    /// @brief Mechanisms advertised by this slot.
    /// @return PKCS#11 @c CK_MECHANISM_TYPE values supported on the
    ///         token-keys reachable through this slot's PIN.
    /// @par Thread-safety
    /// Internally synchronised. Each slot may advertise a different
    /// mechanism set in the multi-PIN model (auth slot ≠ sign slot).
    /// @since 4.1
    [[nodiscard]] virtual std::vector<unsigned long> mechanisms() const = 0;

    /// @brief Invalidate per-slot authentication after the parent card
    ///        has been reconnected / reset.
    ///
    /// PC/SC RESET drops the card-side security context, so any cached
    /// PIN and the @ref loggedIn flag are no longer correct: PKCS#11
    /// consumers must re-login before sign operations succeed. The base
    /// implementation cleanses @ref cachedPin and clears @ref loggedIn
    /// under @ref slotMutex; subclasses with extra authentication state
    /// override and chain to the base.
    /// @par Thread-safety
    /// Caller MUST NOT hold the parent card's @c cardMutex when
    /// invoking this method — it acquires @ref slotMutex, and the
    /// project lock order is @c slotMutex → @c cardMutex.
    /// @ref PKCS11Card::handleReset enforces this by releasing
    /// @c cardMutex before walking the slot list.
    /// @since 4.1
    virtual void onCardReset() noexcept;

    /// @brief Stable slot ID (FNV-1a of reader || pinId || slotKind).
    /// @return Stable @c CK_SLOT_ID surfaced through the PKCS#11 ABI.
    ///         Populated by subclasses during bind via the FNV-1a hash
    ///         in @ref slot_id_hash.h; defaults to 0 before bind.
    /// @par Thread-safety
    /// Lock-free; @ref stableSlotId is written exactly once during
    /// construction / bind and read-only thereafter.
    /// @since 4.1
    [[nodiscard]] unsigned long stableId() const noexcept
    {
        return stableSlotId;
    }

    /// @brief Lock the parent card weak pointer for outside-the-slot
    ///        consumers (e.g. the library layer that needs the parent's
    ///        @c reader() name to fill @c CK_SLOT_INFO::slotDescription).
    /// @return Strong reference to the parent card, or @c nullptr when
    ///         the parent has been destroyed.
    /// @par Thread-safety
    /// Lock-free; the @c weak_ptr itself is immutable post-construction.
    /// @since 4.1
    [[nodiscard]] std::shared_ptr<PKCS11Card> lockParentCard() const noexcept
    {
        return parentCard.lock();
    }

protected:
    /// @brief Borrow the parent card's transport mutex.
    ///
    /// Subclasses use this to acquire the card-level lock under the
    /// project-wide lock order (slotMutex → cardMutex). Implemented in
    /// the base TU because @ref PKCS11Slot is a @c friend of
    /// @ref PKCS11Card; concrete slot subclasses are NOT friends and
    /// must reach the parent's protected state through this surface.
    /// @param parent Locked parent obtained from @c parentCard.lock().
    /// @return Reference to the parent's transport mutex.
    /// @par Thread-safety
    /// Returns a reference; caller must lock and release it themselves.
    /// @since 4.1
    [[nodiscard]] static std::mutex& parentTransportMutex(PKCS11Card& parent) noexcept;

    /// @brief Whether the parent card requires PACE before applet
    ///        select (Serbian eID family).
    /// @since 4.1
    [[nodiscard]] static bool parentNeedsPace(const PKCS11Card& parent) noexcept;

    /// @brief Whether the parent's @c cachedCan is currently empty.
    /// @par Thread-safety
    /// Caller must hold the parent's @c cardMutex (acquired via
    /// @ref parentTransportMutex).
    /// @since 4.1
    [[nodiscard]] static bool parentCanIsEmpty(const PKCS11Card& parent) noexcept;

    /// @brief Move @p can into the parent's @c cachedCan slot.
    /// @par Thread-safety
    /// Caller must hold the parent's @c cardMutex. Replaces any
    /// previously-cached value; the old @ref Secure::String cleanses on
    /// destruction.
    /// @since 4.1
    static void parentCacheCan(PKCS11Card& parent, Secure::String can) noexcept;

    /// @brief Cleanse the parent's @c cachedCan (after PACE failure).
    /// @par Thread-safety
    /// Caller must hold the parent's @c cardMutex.
    /// @since 4.1
    static void parentClearCan(PKCS11Card& parent) noexcept;

    /// @brief Trigger the parent's PACE handshake.
    /// @par Thread-safety
    /// Caller must hold the parent's @c cardMutex; the call delegates
    /// to the parent's @c establishPACE() override.
    /// @since 4.1
    [[nodiscard]] static unsigned long parentEstablishPACE(PKCS11Card& parent);

    /// @brief Weak back-reference to the owning card.
    std::weak_ptr<PKCS11Card> parentCard;

    /// @brief PKCS#15 PIN identifier or empty for ref-only schemes.
    std::vector<std::uint8_t> pinId;

    /// @brief Human-readable PIN label (e.g. @c "Auth PIN").
    std::string pinLabel;

    /// @brief Per-slot serialisation lock. Mutable to allow @c const
    ///        methods (@ref tokenInfo) to acquire it.
    mutable std::mutex slotMutex;

    /// @brief Cached PIN material between login and logout.
    /// @guarded_by slotMutex
    Secure::String cachedPin;

    /// @brief Whether @c login() has succeeded since the last
    ///        @c logout().
    /// @guarded_by slotMutex
    bool loggedIn = false;

    /// @brief Most recent token-info snapshot. Subclasses populate
    ///        directly under @ref slotMutex during bind.
    /// @guarded_by slotMutex
    PKCS11TokenInfo cachedTokenInfo;

    /// @brief Stable PKCS#11 @c CK_SLOT_ID. Populated by the concrete
    ///        slot subclass via the FNV-1a hash helper during bind;
    ///        zero-initialised before bind.
    unsigned long stableSlotId{0};
};

} // namespace LibreSCRS::Pkcs11::Internal
