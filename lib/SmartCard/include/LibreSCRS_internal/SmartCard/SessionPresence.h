// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/SessionPresence.h is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Export.h>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace LibreSCRS::SmartCard {
class CardSession;
}

namespace LibreSCRS::SmartCard::Internal {

/// @brief Process-local registry of CardSessions with live secure-messaging
///        channels. Populated by CardSession auto-registration; consulted by
///        in-process PKCS#11 probe paths to refuse opening parallel PC/SC
///        handles on readers that already carry a live SM channel.
///
/// @note Single-process invariant only. Cross-process scenarios (Firefox
///       loading librescrs-pkcs11.so, macOS CryptoTokenKit XPC appex,
///       gpg-agent, etc.) fall back to the detect-and-reprompt path.
///
/// @par Storage
/// Entries are @c std::weak_ptr — the registry does not extend session
/// lifetime. A session destroyed while still nominally registered (e.g. when
/// the RAII Registration handle is still alive on a value-stored session)
/// causes @ref peek to return an empty pointer; @ref hasLiveSm therefore
/// reports @c false.
///
/// @par ABI
/// Annotated @ref LIBRESCRS_PUBLIC_API so cross-`.so` consumers (the in-tree
/// PKCS#11 module, plugin shared libraries, libresign) resolve the symbol
/// against the single shared LibreMiddleware instance rather than each carrying their own
/// statically-linked copy of the registry — the ODR failure that defeats
/// the auto-register design without exported symbols. The map + mutex live
/// inline because the header is `LIBRESCRS_INTERNAL_BUILD`-gated (no external
/// SDK consumer ever sees the layout) and the SHARED `.so` SOVERSION is the
/// stable surface for the 4.x cycle — pimpl would not buy additional ABI
/// stability inside that cycle.
///
/// @since 4.2
class LIBRESCRS_PUBLIC_API SessionPresence
{
public:
    /// @brief RAII handle returned from @ref insert. Destruction removes the
    ///        entry from the registry. Move-only; default-constructible to a
    ///        no-op handle for std::optional storage.
    class LIBRESCRS_PUBLIC_API Registration
    {
    public:
        Registration() noexcept = default;
        Registration(SessionPresence* o, std::string r) noexcept;
        Registration(Registration&& other) noexcept;
        Registration& operator=(Registration&& other) noexcept;
        Registration(const Registration&) = delete;
        Registration& operator=(const Registration&) = delete;
        ~Registration();

    private:
        SessionPresence* owner{nullptr};
        std::string readerName{};
    };

    SessionPresence() = default;
    ~SessionPresence() = default;
    SessionPresence(const SessionPresence&) = delete;
    SessionPresence& operator=(const SessionPresence&) = delete;
    SessionPresence(SessionPresence&&) = delete;
    SessionPresence& operator=(SessionPresence&&) = delete;

    /// @brief Register a session under its reader name. Returns a RAII handle
    ///        that auto-removes on destruction. Storage is @c weak_ptr — the
    ///        registry does not extend session lifetime.
    [[nodiscard]] Registration insert(std::string readerName, std::weak_ptr<CardSession> session);

    /// @brief Look up the live session for a reader, if any. Returns a
    ///        momentary @c shared_ptr (locked from the stored @c weak_ptr);
    ///        empty if no entry, or if the session has been destroyed but
    ///        its registration has not yet run.
    [[nodiscard]] std::shared_ptr<CardSession> peek(const std::string& readerName) const noexcept;

    /// @brief True iff a session is registered for the reader and reports
    ///        @c hasLiveSecureChannel() == true at the moment of the call.
    [[nodiscard]] bool hasLiveSm(const std::string& readerName) const noexcept;

    /// @brief Remove all entries. Test fixture support.
    void clearAll() noexcept;

private:
    friend class Registration;

    void remove(const std::string& readerName) noexcept;

    mutable std::mutex mu;
    std::unordered_map<std::string, std::weak_ptr<CardSession>> entries;
};

} // namespace LibreSCRS::SmartCard::Internal
