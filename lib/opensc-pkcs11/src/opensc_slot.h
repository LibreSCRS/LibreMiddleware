// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Concrete @ref LibreSCRS::Pkcs11::Internal::PKCS11Slot backed by
///        the vendored OpenSC archive. One slot per AODF user-auth PIN.

#include <internal/PKCS11ObjectInfo.h>
#include <internal/PKCS11Slot.h>
#include <internal/PKCS11TokenInfo.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

// Opaque libopensc forward declarations — full definitions pulled inside
// the .cpp only.
struct sc_pkcs15_object;
typedef struct sc_pkcs15_object sc_pkcs15_object_t;

namespace LibreSCRS::OpenSc::Pkcs11 {

/// @brief Concrete @ref LibreSCRS::Pkcs11::Internal::PKCS11Slot bound to
///        a single AODF user PIN on an OpenSC-bound card.
///
/// Borrows a non-owning pointer to the parent's @c sc_pkcs15_card_t and
/// the per-PIN AODF object. Filtered key + certificate object pointers are
/// captured at construction time so per-slot enumeration is independent of
/// sibling slots.
///
/// @par Thread-safety
/// Inherits @c slotMutex from the base. Login / sign paths acquire
/// @c slotMutex first, then the parent card's @c cardMutex (project-wide
/// lock order).
///
/// @since 4.1
class OpenScSlot final : public LibreSCRS::Pkcs11::Internal::PKCS11Slot
{
public:
    /// @brief Construct a slot bound to the parent's PKCS#15 surface.
    /// @param parent     Weak handle to the owning card.
    /// @param pinId      PKCS#15 PIN object identifier (CKA_ID gating
    ///                   source). Mirrored into the base's @c pinId.
    /// @param pinLabel   Human-readable PIN label.
    /// @param pinObject  Non-owning pointer to the AODF PIN object
    ///                   (owned by the parent's @c sc_pkcs15_card_t).
    /// @param keyObjects Subset of the card's PrKey objects whose
    ///                   @c auth_id references this PIN.
    /// @param certObjects Subset of the card's Cert objects paired with
    ///                   @p keyObjects (matched on PKCS#15 ID).
    /// @param tokenInfo  Pre-populated token snapshot; copied into the
    ///                   base's @c cachedTokenInfo.
    /// @param slotId     Stable @c CK_SLOT_ID (FNV-1a of @c reader ||
    ///                   @c pinId || @c slotKind); installed into the
    ///                   base's @c stableSlotId.
    /// @since 4.1
    OpenScSlot(std::weak_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> parent, std::vector<std::uint8_t> pinId,
               std::string pinLabel, sc_pkcs15_object_t* pinObject, std::vector<sc_pkcs15_object_t*> keyObjects,
               std::vector<sc_pkcs15_object_t*> certObjects, LibreSCRS::Pkcs11::Internal::PKCS11TokenInfo tokenInfo,
               unsigned long slotId);

    ~OpenScSlot() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::mechanisms
    /// @since 4.1
    [[nodiscard]] std::vector<unsigned long> mechanisms() const override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::enumerateObjects
    /// @since 4.1
    [[nodiscard]] std::vector<LibreSCRS::Pkcs11::Internal::PKCS11ObjectInfo> enumerateObjects() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::login
    /// @par Implementation
    /// Verifies @p pin via @c sc_pkcs15_verify_pin. CAN-in-PIN parsing is
    /// NOT performed — OpenSC handles PACE internally.
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
    /// @since 4.1
    [[nodiscard]] std::vector<std::uint8_t> signWithDigestInfo(std::span<const std::uint8_t> digestInfo,
                                                               std::span<const std::uint8_t> rawData,
                                                               unsigned long mechanism,
                                                               std::span<const std::uint8_t> keyId) override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Slot::signatureSize
    /// @since 4.1
    [[nodiscard]] std::size_t signatureSize(std::span<const std::uint8_t> keyId) const override;

    /// @brief Re-resolve the borrowed PKCS#15 object pointers after the
    ///        owning card rebound a fresh @c sc_pkcs15_card_t.
    ///
    /// After @c sc_pkcs15_unbind(), every @c sc_pkcs15_object_t* held by
    /// this slot is freed. @ref OpenScCard::reconnectInline walks the
    /// rebound card's AODF and calls this on each owned slot to refresh
    /// pointers, matching by stored PKCS#15 IDs (@c pinId for the AUTH PIN
    /// object, @ref keyIds for PrKey objects, @ref certIds for paired
    /// certs).
    ///
    /// @param freshPinObject  AODF AUTH PIN object whose @c auth_id
    ///                        matches @c pinId. May be @c nullptr if not
    ///                        found on the rebound card (caller decides
    ///                        whether to fail the reconnect).
    /// @param freshKeyObjects PrKey objects whose IDs are in @ref keyIds.
    /// @param freshCertObjects Cert objects whose IDs are in @ref certIds.
    ///
    /// @par Thread-safety
    /// Caller (@ref OpenScCard::reconnectInline) holds the parent
    /// @c cardMutex; no concurrent slot reads can race here per the
    /// documented contract of @ref PKCS11Card::handleReset (caller must
    /// not hold any @c slotMutex).
    /// @since 4.1
    void rebindObjects(sc_pkcs15_object_t* freshPinObject, std::vector<sc_pkcs15_object_t*> freshKeyObjects,
                       std::vector<sc_pkcs15_object_t*> freshCertObjects) noexcept;

    /// @brief PKCS#15 IDs of the @ref keyObjects, captured at construction
    ///        time so @ref rebindObjects can re-resolve pointers after
    ///        an unbind/rebind cycle.
    [[nodiscard]] const std::vector<std::vector<std::uint8_t>>& keyIds() const noexcept
    {
        return keyIdsCache;
    }
    [[nodiscard]] const std::vector<std::vector<std::uint8_t>>& certIds() const noexcept
    {
        return certIdsCache;
    }
    /// @brief Public accessor for the base's @c pinId (cross-namespace,
    ///        used by @ref OpenScCard::rebindSlotObjects).
    [[nodiscard]] std::span<const std::uint8_t> pinIdBytes() const noexcept
    {
        return {pinId.data(), pinId.size()};
    }

private:
    sc_pkcs15_object_t* pinObject{nullptr};
    std::vector<sc_pkcs15_object_t*> keyObjects;
    std::vector<sc_pkcs15_object_t*> certObjects;
    std::vector<std::vector<std::uint8_t>> keyIdsCache;
    std::vector<std::vector<std::uint8_t>> certIdsCache;
};

} // namespace LibreSCRS::OpenSc::Pkcs11
