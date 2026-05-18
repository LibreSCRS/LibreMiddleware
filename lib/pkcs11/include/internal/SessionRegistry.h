// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief Process-local registry of CardSessions handed to the PKCS#11
///        module by an in-process host (e.g. LibreCelik) before
///        C_GetSlotList. Providers consult the registry at probe time;
///        a hit means "a live host session is parked here". Owned by
///        the per-module ModuleContext; lifetime tied to
///        C_Initialize / C_Finalize.
///
/// The registry is a cross-provider service: every PKCS#11 provider in
/// the module may consult it. Lookups are non-consuming so that bind
/// failure in one provider does not lose the parked session for the
/// next provider or a subsequent retry.

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace LibreSCRS::SmartCard {
class CardSession;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::Pkcs11::Internal {

/// @brief Cross-provider registry of host-injected CardSessions, keyed
///        by reader name.
///
/// @par Lookup semantics
/// @ref peek returns a fresh @c std::shared_ptr copy without removing
/// the entry. The caller (typically a @c PKCS11CardProvider::probe)
/// inspects the session and decides whether to adopt it; on adoption
/// the caller invokes @ref remove. Bind-failure paths leave the entry
/// in place so the next provider can still find it.
///
/// @par Thread-safety
/// All public methods are internally synchronised. @ref peek copies
/// the @c shared_ptr under the lock, so callers can safely use the
/// returned session even if another thread concurrently @ref remove
/// s the entry.
///
/// @since 4.1
class SessionRegistry
{
public:
    SessionRegistry();
    ~SessionRegistry();

    SessionRegistry(const SessionRegistry&) = delete;
    SessionRegistry& operator=(const SessionRegistry&) = delete;

    /// @brief Insert or replace the session bound to @p readerName.
    /// @par Throws std::bad_alloc on insert failure; caller (the
    ///      C-linkage hook) catches and translates to OUT_OF_MEMORY.
    /// @since 4.1
    void put(std::string readerName, std::shared_ptr<LibreSCRS::SmartCard::CardSession> session);

    /// @brief Non-consuming view of the session parked under
    ///        @p readerName.
    /// @return Shared pointer to the parked session, or @c nullptr if
    ///         no entry exists. Multiple peekers can hold refs to the
    ///         same session simultaneously.
    /// @par Thread-safe; never throws.
    /// @since 4.1
    [[nodiscard]] std::shared_ptr<LibreSCRS::SmartCard::CardSession> peek(const std::string& readerName) const noexcept;

    /// @brief Presence check for a session parked under @p readerName.
    /// @par Thread-safe; never throws.
    /// @since 4.1
    [[nodiscard]] bool contains(const std::string& readerName) const noexcept;

    /// @brief Idempotent removal. Never throws.
    /// @since 4.1
    void remove(const std::string& readerName) noexcept;

    /// @brief Drop every entry. Called from C_Finalize.
    /// @since 4.1
    void clearAll() noexcept;

private:
    mutable std::mutex mu;
    std::unordered_map<std::string, std::shared_ptr<LibreSCRS::SmartCard::CardSession>> entries;
};

} // namespace LibreSCRS::Pkcs11::Internal
