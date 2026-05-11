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

#include <LibreSCRS/SmartCard/CardMap.h>

#include <memory>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {
class PCSCConnection;
}

namespace emrtd::crypto {
class SecureMessaging;
}

namespace pkcs15 {
class PKCS15Card;
struct PKCS15Profile;
} // namespace pkcs15

namespace LibreSCRS::Pkcs15::Pkcs11 {

/// @brief Concrete @ref LibreSCRS::Pkcs11::Internal::PKCS11Card backed
///        by the existing @ref pkcs15::PKCS15Card APDU helper.
///
/// Wraps a single PC/SC reader's bound PKCS#15 surface and surfaces one
/// @ref Pkcs15Slot per user PIN object discovered in the AODF. Single-PIN
/// cards (Serbian eID, NAM) yield one slot; multi-PIN cards (GEO) yield
/// one slot per AUTH PIN. PUK and CAN PINs are filtered.
///
/// @par Thread-safety
/// Inherits @c cardMutex from the base; APDU exchange and the underlying
/// @ref pkcs15::PKCS15Card helper are therefore serialised. Slots reach
/// the transport via @c friend access on the base class as documented in
/// @ref PKCS11Card.
///
/// @since 4.1
class Pkcs15Slot;

class Pkcs15Card final : public LibreSCRS::Pkcs11::Internal::PKCS11Card
{
    // Slots in deferred-profile mode borrow the parent's APDU helper at
    // first login; controlled friend access keeps the boundary narrow.
    friend class Pkcs15Slot;

public:
    /// @brief Construct an unbound card. Call @ref bind() exactly once.
    /// @param cardMap Optional shared cache of per-card discovered state
    ///                (PKCS#15 path / SELECT P2 / PIN labels). When
    ///                non-null, @ref bind() reuses any previously probed
    ///                state to avoid redundant EF.DIR fallback after
    ///                PACE; if the entry is absent, @ref bind() probes
    ///                normally and populates the map. When null, no
    ///                cache is consulted (legacy single-shot behaviour).
    /// @since 4.1
    explicit Pkcs15Card(std::shared_ptr<LibreSCRS::SmartCard::CardMap> cardMap = nullptr);

    /// @brief Releases PC/SC and wipes the cached PKCS#15 profile. Slots
    ///        (declared LAST in the base) are destroyed first.
    /// @since 4.1
    ~Pkcs15Card() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::bind
    /// @par Thread-safety
    /// Internally synchronised; takes @c cardMutex for the duration.
    /// @since 4.1
    [[nodiscard]] unsigned long bind(const std::string& readerName) override;

protected:
    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::establishPACE
    /// @par Thread-safety
    /// Caller must hold @c cardMutex. Reads @c cachedCan; never logs it.
    /// @since 4.1
    [[nodiscard]] unsigned long establishPACE() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::completeBind
    /// @par Thread-safety
    /// Caller must hold @c cardMutex. Populates @c slots from the
    /// PKCS#15 profile (one slot per user PIN).
    /// @since 4.1
    [[nodiscard]] unsigned long completeBind() override;

private:
    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::reconnectInline
    /// @since 4.1
    [[nodiscard]] unsigned long reconnectInline() override;

    /// @brief Probe whether this card requires PACE (Serbian eID family).
    ///
    /// Reads EF.CardAccess from MF without authentication; presence of
    /// PACE security infos signals a contactless or PACE-gated card.
    /// On success, @ref cardAccessData is populated. Does not run PACE.
    [[nodiscard]] bool probeForPace();

    /// @brief Wire @ref sm into @ref conn as a transmit filter so all
    ///        subsequent APDUs ride the established secure channel.
    void installSmFilter();

    std::unique_ptr<LibreSCRS::SmartCard::Internal::PCSCConnection> conn;
    std::unique_ptr<pkcs15::PKCS15Card> apdu;
    std::unique_ptr<pkcs15::PKCS15Profile> profile;

    /// @brief When @c true the parent applet refuses PKCS#15 directory
    ///        reads pre-login (e.g. AET SafeSign / Posta Srbija eID).
    ///        @ref bind() therefore publishes ONE placeholder slot and
    ///        defers the real profile read to that slot's first
    ///        @ref Pkcs15Slot::login.
    bool needsDeferredProfile{false};

    /// @brief Raw EF.CardAccess bytes captured at probe time. Populated
    ///        only when PACE is required; consumed by @ref establishPACE.
    std::vector<std::uint8_t> cardAccessData;

    /// @brief Active SM channel after a successful PACE handshake.
    std::unique_ptr<emrtd::crypto::SecureMessaging> sm;

    /// @brief Optional shared cache of per-card discovered state.
    ///        Consulted by @ref bind() to skip EF.DIR fallback when
    ///        the same physical card has been probed earlier in the
    ///        process (e.g. by the in-tree pkcs15 card plugin). @c
    ///        nullptr disables caching.
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
    /// @brief Construct the provider with an optional shared card map.
    /// @param cardMap Threaded through every @c Pkcs15Card created by
    ///                @ref probe so per-card discovered state survives
    ///                across operations on the same physical card (e.g.
    ///                EF.DIR fallback after PACE). @c nullptr disables
    ///                caching, matching the pre-4.1 single-shot probe.
    /// @since 4.1
    explicit Pkcs15PKCS11Provider(std::shared_ptr<LibreSCRS::SmartCard::CardMap> cardMap = nullptr) noexcept;
    ~Pkcs15PKCS11Provider() override = default;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11CardProvider::probe
    /// @since 4.1
    [[nodiscard]] std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card>
    probe(const std::string& readerName) override;

private:
    std::shared_ptr<LibreSCRS::SmartCard::CardMap> cardMap;
};

} // namespace LibreSCRS::Pkcs15::Pkcs11
