// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Pkcs11::SessionAttachment — RAII guard that
///        forwards a live LibreSCRS CardSession into a loaded
///        librescrs-pkcs11 module via its versioned C ABI inject hook.

#include <LibreSCRS/Export.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>

namespace LibreSCRS::Pkcs11 {

/// @brief RAII guard for a process-local CardSession injection into a
///        loaded librescrs-pkcs11 module.
///
/// Construct after @c C_Initialize on the target module has succeeded;
/// the destructor calls the matching detach hook before releasing the
/// module mapping retained via @c RTLD_NOLOAD. The session @c shared_ptr
/// is kept alive at least as long as the attachment so the module-side
/// registry's reference is always backed by a live caller-side ref.
///
/// @par Thread-safety
/// Distinct @ref SessionAttachment instances are independent and may be
/// constructed and destroyed from different threads concurrently. A
/// single instance is not internally synchronised; callers must not race
/// @ref detach against the destructor on the same instance. Move
/// operations are noexcept and leave the moved-from object in a detached
/// state (subsequent destruction is a no-op).
///
/// @par Example
/// @code
/// auto session = LibreSCRS::SmartCard::CardSession::open(...).value();
/// auto attached = LibreSCRS::Pkcs11::SessionAttachment::attach(
///     "/usr/lib/librescrs-pkcs11.so", "Reader 0", session);
/// if (!attached) {
///     // Fall back to standalone PKCS#11 path; sign may still succeed
///     // for non-PACE cards.
/// }
/// // PKCS#11 sign here adopts the injected session via probe().
/// // attached.~SessionAttachment() detaches on scope exit.
/// @endcode
///
/// @since 4.1
class LIBRESCRS_PUBLIC_API SessionAttachment final
{
public:
    /// @brief Categorised failure reason returned from @ref attach.
    enum class Error : std::uint8_t {
        ModuleNotLoaded,  ///< @p modulePath could not be opened by the dynamic loader.
        DlsymFailed,      ///< Module is loaded but does not export the inject hook (older module).
        InvalidArguments, ///< Empty @p modulePath / empty @p readerName / null @p session.
        Rejected,         ///< Module returned a non-OK numeric status from the inject hook.
        OutOfMemory,      ///< @c std::bad_alloc surfaced from internal copy / allocation.
    };

    /// @brief Attach @p session under @p readerName to the module at
    ///        @p modulePath.
    ///
    /// @c C_Initialize must have succeeded on the target module prior to
    /// this call; the registered session is consulted by the next
    /// @c C_GetSlotList probe.
    ///
    /// @par noexcept contract
    /// Marked @c noexcept; allocations and dynamic-loader failures are
    /// wrapped in a function-try-block that translates @c std::bad_alloc
    /// to @ref Error::OutOfMemory and other unexpected exceptions to the
    /// same. No exception ever escapes this entry point.
    ///
    /// @par Example
    /// @code
    /// auto attached = LibreSCRS::Pkcs11::SessionAttachment::attach(
    ///     modulePath, "Reader 0", std::move(session));
    /// if (attached) {
    ///     // attached->readerName() == "Reader 0"
    /// } else {
    ///     switch (attached.error()) {
    ///         case Error::ModuleNotLoaded: ...; break;
    ///         case Error::DlsymFailed:     ...; break;
    ///         // ...
    ///     }
    /// }
    /// @endcode
    ///
    /// @return On success a @ref SessionAttachment whose destructor
    ///         detaches automatically. On failure, the structured @ref Error.
    /// @since 4.1
    [[nodiscard]] static std::expected<SessionAttachment, Error>
    attach(const std::filesystem::path& modulePath, std::string readerName,
           std::shared_ptr<LibreSCRS::SmartCard::CardSession> session) noexcept;

    SessionAttachment(const SessionAttachment&) = delete;
    SessionAttachment& operator=(const SessionAttachment&) = delete;

    SessionAttachment(SessionAttachment&&) noexcept;
    SessionAttachment& operator=(SessionAttachment&&) noexcept;
    ~SessionAttachment();

    /// @brief Explicit early detach. Idempotent; subsequent destructor
    ///        invocations are no-ops.
    ///
    /// @par Thread-safety
    /// Not internally synchronised against the destructor on the same
    /// instance; callers must serialise.
    ///
    /// @since 4.1
    void detach() noexcept;

    /// @brief Reader this attachment was bound to.
    /// @return The reader name passed to @ref attach, or an empty string
    ///         after @ref detach has been called (including via the
    ///         destructor or a moved-from state).
    /// @since 4.1
    [[nodiscard]] const std::string& readerName() const noexcept
    {
        return reader;
    }

private:
    SessionAttachment() noexcept = default;

    void* moduleHandle{nullptr}; ///< RTLD_NOLOAD retain; pinned while alive.
    std::string reader;
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> heldSession;
};

} // namespace LibreSCRS::Pkcs11
