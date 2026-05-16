// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief Process-local registry of CardSessions handed to the PKCS#11
///        module by an in-process host (e.g. LibreCelik) before
///        C_GetSlotList. Pkcs15PKCS11Provider::probe consults the
///        registry; a hit means "adopt this live session, do not open a
///        new PC/SC handle". Owned by the per-module ModuleContext;
///        lifetime tied to C_Initialize / C_Finalize.

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace LibreSCRS::SmartCard {
class CardSession;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::Pkcs15::Pkcs11 {

class AttachRegistry
{
public:
    AttachRegistry();
    ~AttachRegistry();

    AttachRegistry(const AttachRegistry&) = delete;
    AttachRegistry& operator=(const AttachRegistry&) = delete;

    /// @brief Insert or replace the session bound to @p readerName.
    /// @par Throws std::bad_alloc on insert failure; caller (the C-linkage
    ///      hook) catches and translates to OUT_OF_MEMORY.
    void put(std::string readerName, std::shared_ptr<LibreSCRS::SmartCard::CardSession> session);

    /// @brief Remove and return the session bound to @p readerName.
    /// @return The session pointer or nullptr if no entry exists.
    /// @par Thread-safe; never throws.
    [[nodiscard]] std::shared_ptr<LibreSCRS::SmartCard::CardSession> tryAdopt(const std::string& readerName) noexcept;

    /// @brief Idempotent removal. Never throws.
    void remove(const std::string& readerName) noexcept;

    /// @brief Drop every entry. Called from C_Finalize.
    void clearAll() noexcept;

private:
    mutable std::mutex mu;
    std::unordered_map<std::string, std::shared_ptr<LibreSCRS::SmartCard::CardSession>> entries;
};

} // namespace LibreSCRS::Pkcs15::Pkcs11
