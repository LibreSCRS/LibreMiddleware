// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Abstract base for a single physical card surfaced through
///        N PIN-gated PKCS#11 slots.

#include "PKCS11Slot.h"

#include <LibreSCRS/Secure/String.h>

#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal {

/// @brief Abstract base for a physical smart card surfaced through one
///        or more @ref PKCS11Slot instances.
///
/// One @ref PKCS11Card per inserted card. The card owns the underlying
/// PC/SC connection, the PACE handshake (when @ref needsPaceFlag) and the
/// CAN cache; per-PIN state is delegated to each owned @ref PKCS11Slot.
/// Subclasses must inherit @c std::enable_shared_from_this so slots
/// can hold a @c weak_ptr back at the card without an ownership cycle.
///
/// @par Thread-safety
/// The card owns @ref cardMutex which serialises low-level transport
/// (APDU exchange, reconnect). Slots acquire it through controlled
/// accessors mediated by friendship: @ref PKCS11Slot is a @c friend so
/// the boundary can be established without exposing transport
/// internals through the public API.
///
/// @par Destruction order
/// @ref slots is declared LAST among data members so it is destroyed
/// FIRST. @ref cachedCan precedes it and is therefore destroyed
/// (cleansed) AFTER the slots have released any references.
///
/// @since 4.1
class PKCS11Card : public std::enable_shared_from_this<PKCS11Card>
{
public:
    PKCS11Card();

    PKCS11Card(const PKCS11Card&) = delete;
    PKCS11Card& operator=(const PKCS11Card&) = delete;
    PKCS11Card(PKCS11Card&&) = delete;
    PKCS11Card& operator=(PKCS11Card&&) = delete;

    /// @brief Virtual destructor. Slots are destroyed first by
    ///        construction order (see class @par Destruction order).
    /// @since 4.1
    virtual ~PKCS11Card();

    /// @brief Bind to a PC/SC reader and populate this card's slots.
    /// @param readerName Reader name as reported by PC/SC.
    /// @return @ref Crv constant — @ref Crv::Ok on success.
    /// @par Thread-safety
    /// Internally synchronised. Must be called exactly once before any
    /// slot is used.
    /// @since 4.1
    [[nodiscard]] virtual unsigned long bind(const std::string& readerName) = 0;

    /// @brief Live view of this card's owned slots.
    /// @return Span over the @ref slots vector. Validity is bounded by
    ///         the lifetime of @c *this; do NOT retain past
    ///         destruction.
    /// @par Invariant
    /// The @c slots vector is populated EXACTLY ONCE inside @ref bind()
    /// (under @ref cardMutex) and MUST NOT be mutated afterward.
    /// Subclasses violate this invariant at their peril; consumers
    /// observing through this @c span rely on it for lock-free reads.
    /// @par Thread-safety
    /// Snapshot pointer; safe for concurrent readers post-@ref bind().
    /// Concurrent readers do not need external synchronisation as long
    /// as @ref bind() has returned and the invariant above holds.
    /// @since 4.1
    [[nodiscard]] std::span<const std::shared_ptr<PKCS11Slot>> enumerateSlots() const noexcept;

    /// @brief PC/SC reader this card is bound to (empty pre-@ref bind).
    [[nodiscard]] const std::string& reader() const noexcept
    {
        return readerName;
    }

    /// @brief Whether the card requires PACE before applet selection
    ///        (Serbian eID family).
    [[nodiscard]] bool needsPaceFlag() const noexcept
    {
        return needsPace;
    }

    /// @brief Recovery hook for transport-level faults (e.g.
    ///        @c SCARD_W_RESET_CARD) at the library layer.
    ///
    /// Acquires @ref cardMutex and re-runs the concrete card's
    /// @ref reconnectInline path, re-establishing the PC/SC handle and
    /// (if @ref needsPaceFlag) PACE. The library layer invokes this
    /// in its @c handleCardError path so per-family transports do not
    /// leak through. The method does NOT touch slot state directly:
    /// per the project lock order (@c slotMutex → @c cardMutex), slot
    /// invalidation is the caller's responsibility once @ref handleReset
    /// returns.
    /// @return @ref Crv constant; @ref Crv::Ok on a successful reattach.
    /// @par Thread-safety
    /// Internally synchronised; takes @ref cardMutex briefly. Must NOT
    /// be called while any @c slotMutex is held.
    /// @since 4.1
    [[nodiscard]] unsigned long handleReset();

protected:
    /// @brief Run a PACE handshake using @ref cachedCan.
    /// @return @ref Crv constant.
    /// @par Thread-safety
    /// Caller must hold @ref cardMutex. Implementations must not log
    /// @ref cachedCan.
    /// @since 4.1
    [[nodiscard]] virtual unsigned long establishPACE() = 0;

    /// @brief Concrete-card hook run after @ref bind() establishes the
    ///        connection (and PACE, if applicable). Implementations
    ///        populate @ref slots here.
    /// @return @ref Crv constant.
    /// @par Thread-safety
    /// Caller must hold @ref cardMutex.
    /// @since 4.1
    [[nodiscard]] virtual unsigned long completeBind() = 0;

    /// @brief PC/SC reader name; populated by @ref bind().
    std::string readerName;

    /// @brief Whether this card family requires PACE before applet
    ///        select. Defaulted false; concrete subclasses override.
    bool needsPace = false;

    /// @brief Card-level transport serialisation. Mutable so const
    ///        observers may take it.
    mutable std::mutex cardMutex;

    /// @brief Cached CAN (Card Access Number) used by PACE. Declared
    ///        BEFORE @ref slots so it outlives slot destruction during
    ///        teardown — its cleansing destructor runs only after
    ///        every slot has released its weak_ptr to *this.
    /// @guarded_by cardMutex
    Secure::String cachedCan;

    /// @brief Whether this card is currently in placeholder-slot mode
    ///        (PACE-required card whose CAN has not been supplied yet).
    ///        Subclasses that publish a placeholder slot during @ref
    ///        bind set this to @c true; the @ref PKCS11Slot::login
    ///        dispatcher reads it to choose the CAN-in-PIN parse path
    ///        and to delegate to @ref resumePostCan.
    /// @guarded_by cardMutex
    bool placeholderState = false;

    /// @brief Resume bind after the slot's @ref login has cached a CAN.
    ///
    /// Concrete cards that publish a placeholder slot **override this hook**
    /// to run their post-discovery tail (PACE establish + applet select +
    /// profile read). The default returns @c Crv::FunctionFailed so
    /// non-PACE families remain unaffected; the slot dispatcher checks
    /// @ref placeholderState before invoking this hook.
    ///
    /// Concrete subclasses may name their private implementation freely
    /// (e.g., @c Pkcs15Card::resumeBind is the Pkcs15 family's internal
    /// helper). The contract honored by callers is on @ref resumePostCan;
    /// internal helpers are an implementation detail.
    /// @par Thread-safety
    /// Caller must hold @ref cardMutex.
    /// @since 4.1
    [[nodiscard]] virtual unsigned long resumePostCan();

    /// @brief Hook fired by @ref PKCS11Slot::parentCacheCan and
    ///        @ref PKCS11Slot::parentClearCan after @ref cachedCan has
    ///        been mutated.
    ///
    /// Subclasses that own a secondary credential cache (e.g. a
    /// @c LibreSCRS::SmartCard::CardSession with its own per-process PACE
    /// cache via @c CardSession::setPaceSecret) override this to keep both
    /// caches in sync without re-introducing a separate friend boundary.
    /// The default is a no-op; non-PACE families ignore it. An empty
    /// @ref cachedCan means "wipe the secondary cache".
    /// @par Thread-safety
    /// Caller (the @c parentCacheCan / @c parentClearCan static helper)
    /// holds @ref cardMutex; overrides may assume that lock state.
    /// @since 4.1
    virtual void onCachedCanChanged() noexcept;

    /// @brief Owned PIN-gated slots. MUST be the last data member so
    ///        it is destroyed first; see class @par Destruction order.
    std::vector<std::shared_ptr<PKCS11Slot>> slots;

    friend class PKCS11Slot;

private:
    /// @brief Inline reconnect after a transient transport fault.
    /// @return @ref Crv constant.
    /// @par Thread-safety
    /// Caller must hold @ref cardMutex. Implementations re-establish
    /// the PC/SC connection and re-run PACE / applet-select.
    /// @since 4.1
    [[nodiscard]] virtual unsigned long reconnectInline() = 0;
};

} // namespace LibreSCRS::Pkcs11::Internal
