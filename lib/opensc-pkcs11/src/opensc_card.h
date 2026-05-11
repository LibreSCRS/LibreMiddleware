// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Concrete @ref LibreSCRS::Pkcs11::Internal::PKCS11Card backed by
///        the vendored OpenSC static archive (libopensc.a).

#include <internal/PKCS11Card.h>

#include <string>

// Forward-declared to avoid pulling libopensc headers into consumers of
// this header. The full definitions live in src/opensc_card.cpp.
struct sc_context;
typedef struct sc_context sc_context_t;
struct sc_card;
typedef struct sc_card sc_card_t;
struct sc_reader;
typedef struct sc_reader sc_reader_t;
struct sc_pkcs15_card;
typedef struct sc_pkcs15_card sc_pkcs15_card_t;

namespace LibreSCRS::OpenSc::Pkcs11 {

class OpenScSlot;

/// @brief Concrete @ref LibreSCRS::Pkcs11::Internal::PKCS11Card backed by
///        the vendored libopensc static archive.
///
/// One card per (reader, inserted card) tuple. Owns:
///   * @c sc_context_t* — established once per Card lifetime via
///     @c sc_establish_context;
///   * @c sc_reader_t*  — looked up by name via
///     @c sc_ctx_get_reader_by_name (borrowed; owned by the context);
///   * @c sc_card_t*    — connected via @c sc_connect_card;
///   * @c sc_pkcs15_card_t* — bound via @c sc_pkcs15_bind.
///
/// One owned @ref OpenScSlot per AODF user PIN is published in
/// @c slots; PrKey and Cert objects are filtered per-PIN by
/// @c auth_id matching.
///
/// @par PACE
/// @ref needsPace is hard-coded false; OpenSC owns PACE internally where
/// applicable. The CAN-in-PIN path is intentionally NOT exposed through
/// this provider — that is the custom PKCS#15 provider's responsibility.
///
/// @since 4.1
class OpenScCard final : public LibreSCRS::Pkcs11::Internal::PKCS11Card
{
public:
    OpenScCard();
    ~OpenScCard() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::bind
    /// @since 4.1
    [[nodiscard]] unsigned long bind(const std::string& readerName) override;

    /// @brief Borrow the bound PKCS#15 card pointer for slot operations.
    /// @return Underlying @c sc_pkcs15_card_t pointer; @c nullptr before a
    ///         successful @ref bind() or after teardown.
    /// @par Thread-safety
    /// Caller must hold @c cardMutex (acquired via the inherited base
    /// @c parentTransportMutex helper). The pointer is stable across the
    /// card's bound lifetime; it is reset only inside @ref reconnectInline
    /// (also under @c cardMutex).
    /// @since 4.1
    [[nodiscard]] sc_pkcs15_card_t* p15Card() const noexcept
    {
        return p15;
    }

protected:
    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::establishPACE
    /// @par Implementation
    /// Returns @ref Crv::FunctionFailed unconditionally. OpenSC handles
    /// PACE internally where applicable; the CAN-in-PIN slot path is not
    /// exposed through this provider.
    /// @since 4.1
    [[nodiscard]] unsigned long establishPACE() override;

    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::completeBind
    /// @par Implementation
    /// No-op; the slot population and PACE bring-up happen inline inside
    /// @ref bind() while @c cardMutex is held.
    /// @since 4.1
    [[nodiscard]] unsigned long completeBind() override;

private:
    /// @copydoc LibreSCRS::Pkcs11::Internal::PKCS11Card::reconnectInline
    /// @since 4.1
    [[nodiscard]] unsigned long reconnectInline() override;

    /// @brief Walk the AODF and publish one @ref OpenScSlot per
    ///        user-auth PIN.
    /// @par Thread-safety
    /// Caller must hold @c cardMutex. Mutates @c slots; must run exactly
    /// once per bound card (per @ref PKCS11Card slot-vector invariant).
    [[nodiscard]] unsigned long populateSlotsFromAodf();

    /// @brief Re-resolve each owned @ref OpenScSlot's borrowed
    ///        @c sc_pkcs15_object_t pointers after @ref reconnectInline
    ///        rebinds a fresh PKCS#15 surface.
    ///
    /// Matches on PKCS#15 IDs captured at construction; never mutates
    /// the @c slots vector. Returns @c Crv::DeviceError when the rebound
    /// card's AODF no longer carries an object that an existing slot
    /// previously referenced (treated as a hard reconnect failure).
    /// @par Thread-safety
    /// Caller must hold @c cardMutex; no slot operation may be in flight
    /// (caller of @ref PKCS11Card::handleReset must not hold any
    /// @c slotMutex per project-wide lock order).
    [[nodiscard]] unsigned long rebindSlotObjects();

    /// @brief Tear down libopensc state (in safe order).
    void releaseOpenSc() noexcept;

    sc_context_t* ctx{nullptr};
    sc_reader_t* reader{nullptr};
    sc_card_t* card{nullptr};
    sc_pkcs15_card_t* p15{nullptr};
};

} // namespace LibreSCRS::OpenSc::Pkcs11
