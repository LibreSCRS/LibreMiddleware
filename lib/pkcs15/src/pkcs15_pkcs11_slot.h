// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Concrete @ref LibreSCRS::Pkcs11::Internal::PKCS11Slot for the
///        PKCS#15 card family. One slot per AODF user PIN.

#include "pkcs15_types.h"

#include <internal/PKCS11ObjectInfo.h>
#include <internal/PKCS11Slot.h>
#include <internal/PKCS11TokenInfo.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace pkcs15 {
class PKCS15Card;
struct PKCS15Profile;
} // namespace pkcs15

namespace LibreSCRS::Pkcs15::Pkcs11 {

/// @brief Concrete @ref LibreSCRS::Pkcs11::Internal::PKCS11Slot bound to
///        a single PKCS#15 user PIN.
///
/// Holds the slot's authentication identity (one @ref pkcs15::PinInfo)
/// and the subset of @ref pkcs15::PrivateKeyInfo / @ref pkcs15::CertificateInfo
/// objects whose @c authId references this PIN. The owning
/// @ref Pkcs15Card retains the underlying @ref pkcs15::PKCS15Card APDU
/// helper; slots borrow it by reference under the parent's @c cardMutex.
///
/// @par Thread-safety
/// Inherits @c slotMutex from the base. Login / sign paths acquire
/// @c slotMutex first, then the parent card's @c cardMutex (project-wide
/// lock order; see @ref PKCS11Slot @par Lock order).
///
/// @since 4.1
class Pkcs15Slot final : public LibreSCRS::Pkcs11::Internal::PKCS11Slot
{
public:
    /// @brief Construct a slot bound to @p parent's PKCS#15 surface.
    /// @param parent  Weak handle to the owning card.
    /// @param pinId   PKCS#15 PIN object identifier (CKA_ID gating
    ///                source). Mirrored into the base's @c pinId.
    /// @param pinLabel Human-readable PIN label.
    /// @param apdu    Borrowed reference to the parent's bound APDU
    ///                helper. Validity is bounded by parent lifetime;
    ///                the slot is destroyed first by base-class layout
    ///                so the reference cannot dangle on teardown.
    ///                Across @ref Pkcs15Card::reconnectInline the parent
    ///                rebuilds the owned @c unique_ptr; the slot's
    ///                borrow is refreshed via @ref rebindApdu before
    ///                any post-reconnect operation observes it.
    /// @param pinInfo Snapshot of the AODF entry for this PIN.
    /// @param keys    Subset of @c profile.privateKeys whose @c authId
    ///                references this PIN's @c id (single-PIN cards may
    ///                pass the unfiltered set).
    /// @param certs   Subset of @c profile.certificates paired with
    ///                @p keys (typically by matching @c id).
    /// @param tokenInfo Pre-populated token snapshot; copied into the
    ///                base's @c cachedTokenInfo.
    /// @param slotId  Stable @c CK_SLOT_ID derived by the parent card
    ///                (FNV-1a of @c reader || @c pinId || @c slotKind);
    ///                installed into the base's @c stableSlotId.
    /// @since 4.1
    Pkcs15Slot(std::weak_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> parent, std::vector<std::uint8_t> pinId,
               std::string pinLabel, pkcs15::PKCS15Card* apdu, pkcs15::PinInfo pinInfo,
               std::vector<pkcs15::PrivateKeyInfo> keys, std::vector<pkcs15::CertificateInfo> certs,
               LibreSCRS::Pkcs11::Internal::PKCS11TokenInfo tokenInfo, unsigned long slotId);

    /// @brief Construct a slot in @b deferred-profile mode.
    ///
    /// Some PKCS#15 applets (e.g. AET SafeSign / Posta Srbija eID) refuse
    /// to expose @c TokenInfo / @c AODF / @c PrKDF / @c CDF before the
    /// user has authenticated. For those cards the parent @ref Pkcs15Card
    /// pushes a single placeholder slot at @c bind() time; @ref login()
    /// then reads the PKCS#15 profile post-PIN-verify and finalises the
    /// slot's @c pinInfo / @c keys / @c certs / @c cachedTokenInfo state.
    /// @par Lifecycle
    /// Until @ref login succeeds the slot's @c keys and @c certs are
    /// empty, @c pinInfo is @c nullopt, and @c apdu is @c nullptr;
    /// @ref enumerateObjects returns an empty list and @ref signatureSize
    /// returns 0. After successful login they take their final values
    /// and the slot behaves identically to an eager-profile @ref Pkcs15Slot.
    /// @since 4.1
    Pkcs15Slot(std::weak_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> parent, std::string placeholderLabel,
               LibreSCRS::Pkcs11::Internal::PKCS11TokenInfo placeholderTokenInfo, unsigned long slotId);

    /// @brief Cleanses cached PIN; the inherited @c cachedPin destructor
    ///        runs after this body.
    /// @since 4.1
    ~Pkcs15Slot() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::mechanisms
    /// @since 4.1
    [[nodiscard]] std::vector<unsigned long> mechanisms() const override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::enumerateObjects
    /// @par Thread-safety
    /// Internally synchronised; reads @ref keys / @ref certs only,
    /// pre-populated at construction time.
    /// @since 4.1
    [[nodiscard]] std::vector<LibreSCRS::Pkcs11::Internal::PKCS11ObjectInfo> enumerateObjects() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::login
    /// @par Thread-safety
    /// Takes @c slotMutex then the parent card's @c cardMutex (lock
    /// order). Triggers PACE through the parent if the card requires it
    /// and @c cachedCan is empty (CAN-in-PIN parsing path).
    /// @since 4.1
    [[nodiscard]] unsigned long login(unsigned long userType, std::span<const std::uint8_t> pin) override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::logout
    /// @since 4.1
    [[nodiscard]] unsigned long logout() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::signData
    /// @since 4.1
    [[nodiscard]] std::vector<std::uint8_t> signData(std::span<const std::uint8_t> data, unsigned long mechanism,
                                                     std::span<const std::uint8_t> keyId) override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::signWithDigestInfo
    /// @par Implementation
    /// The underlying @ref pkcs15::PKCS15Card::sign accepts both the
    /// DigestInfo prefix and the raw data, so this is a direct delegate.
    /// The slot does NOT default to @ref signData because PKCS#15 cards
    /// may dispatch on the mechanism (e.g. hash-on-card for combined
    /// hash mechanisms), and the dual-buffer surface preserves that
    /// choice.
    /// @since 4.1
    [[nodiscard]] std::vector<std::uint8_t> signWithDigestInfo(std::span<const std::uint8_t> digestInfo,
                                                               std::span<const std::uint8_t> rawData,
                                                               unsigned long mechanism,
                                                               std::span<const std::uint8_t> keyId) override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::signatureSize
    /// @par Implementation
    /// Returns the modulus byte length for RSA keys and 2× the
    /// component size for ECDSA (derived from the key's curve OID).
    /// Reads from the immutable post-construction @ref keys vector;
    /// no card I/O.
    /// @since 4.1
    [[nodiscard]] std::size_t signatureSize(std::span<const std::uint8_t> keyId) const override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::onCardReset
    /// @par Implementation
    /// Extends the base implementation: in addition to clearing the
    /// cached PIN / @c loggedIn flag, refreshes the borrowed parent
    /// @c apdu pointer because @ref Pkcs15Card::reconnectInline rebuilt
    /// the parent's @c std::unique_ptr<pkcs15::PKCS15Card> from scratch.
    /// Without this refresh every slot would dereference a dangling
    /// pointer on the next @ref signData / @ref enumerateObjects.
    /// Mirrors @c OpenScSlot::rebindObjects on the OpenSC provider.
    /// @par Thread-safety
    /// Acquires @c slotMutex (project lock order: @c slotMutex →
    /// @c cardMutex). The base contract requires the caller (the parent
    /// card's @c handleReset) to have released @c cardMutex before
    /// invoking this method.
    /// @since 4.1
    void onCardReset() noexcept override;

private:
    /// @brief Borrow the parent @ref Pkcs15Card's APDU helper. Used by
    ///        deferred-profile mode to wire @ref apdu lazily at first
    ///        @ref login. Static so the friend boundary on @ref Pkcs15Card
    ///        only needs to grant Pkcs15Slot, not free functions.
    /// @par Thread-safety Caller must hold the parent's @c cardMutex.
    [[nodiscard]] static pkcs15::PKCS15Card*
    parentApduHelper(LibreSCRS::Pkcs11::Internal::PKCS11Card& parentBase) noexcept;

    /// @brief Borrow the parent @ref Pkcs15Card's PKCS#15 profile (read
    ///        by @ref Pkcs15Card::resumeBind). Used by the placeholder
    ///        self-transform path to discover user PINs / keys / certs
    ///        without re-issuing APDUs.
    /// @par Thread-safety Caller must hold the parent's @c cardMutex.
    [[nodiscard]] static const pkcs15::PKCS15Profile*
    parentProfile(LibreSCRS::Pkcs11::Internal::PKCS11Card& parentBase) noexcept;

    pkcs15::PKCS15Card* apdu{
        nullptr}; ///< Borrowed; owned by parent @ref Pkcs15Card. @c nullptr in deferred-profile mode pre-login.
    std::optional<pkcs15::PinInfo> pinInfo;   ///< @c nullopt in deferred-profile mode pre-login.
    std::vector<pkcs15::PrivateKeyInfo> keys; ///< Empty in deferred-profile mode pre-login.
    std::vector<pkcs15::CertificateInfo> certs;
    bool deferredProfile{false}; ///< True if pinInfo/keys/certs/apdu must be lazily populated at first @ref login.
};

} // namespace LibreSCRS::Pkcs15::Pkcs11
