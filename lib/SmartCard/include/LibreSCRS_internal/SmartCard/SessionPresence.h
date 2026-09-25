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
/// @note Single-process invariant only, and there is no fallback. A second
///       process — Firefox with the direct module loaded, a CryptoTokenKit
///       appex, gpg-agent — sees an empty registry, so its provider binds the
///       card: plain APDUs on a card whose secure channel this process holds,
///       and the channel is gone. Nothing detects that and nothing re-establishes
///       it; the user is asked for the CAN again at the next operation. Keeping
///       one provider per host is a packaging property, not a code one.
///
/// @par What this registry does not protect against
/// It is consulted per reader, at the moment a provider is about to bind, and
/// that is the whole of its reach. Three things follow. The handle counts below
/// are measured (@c test/pcsc_handle_census_test.cpp); what those handles do to
/// a card is read off the reader driver's source and is NOT measured on
/// hardware.
///  - A reader with NO live secure channel is not protected at all: a provider
///    that finds no entry for it opens its own handle to that card and BINDS
///    it, even while the host holds a session on it. The bind sends APDUs, so
///    an operation the host is running on that reader can see card state it did
///    not set -- a selected file, a changed security state -- and, where the
///    driver has to change protocol, an unpowered card.
///  - A reader WITH a live entry is protected from the bind, not from the
///    handle. Establishing a PC/SC context for any other reader makes the
///    bundled OpenSC enumerate every reader and open a transient shared handle
///    on each one holding a card, to read its features. By the driver's source
///    that handle is a shared connect, one reader-level control call and a
///    @c SCARD_LEAVE_CARD disconnect, both hardcoded for that path rather than
///    read from the driver's configuration: no APDU, and no power cycle of a card
///    that is already powered. A live secure channel is therefore EXPECTED to
///    survive it. Not yet measured on a card, and no test here can measure it —
///    treat it as the reason the guard is where it is, not as a guarantee.
///  - It says nothing about the card. A card swapped in a reader whose entry is
///    still live remains, to this registry, the same reader with the same
///    session.
///  - It holds ONE entry per reader name, and the newest registration wins it.
///    Nothing prevents two sessions from naming one reader, and when that
///    happens the reader's answer is the newer session's, even if the older one
///    is the one carrying a live secure channel. A registration only ever
///    removes the entry it put there (see @ref Registration), so the two no
///    longer delete each other's, but the newer one still shadows the older.
///    Which session a reader should answer for when two claim it is not decided
///    here, and deciding it means deciding what @ref peek returns to the adopt
///    path as well — so it is a specification question, not a local one.
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
/// @warning @ref Registration is returned BY VALUE from @ref insert, which is an
/// exported symbol, so its size is part of what a caller was compiled against.
/// Neither ABI gate can see that: the symbol snapshot compares mangled names,
/// which a return type's layout does not change, and the layout snapshot builds
/// its translation unit from the PUBLIC include root only, so no type declared
/// in `LibreSCRS_internal/` has ever been in it. The @c static_assert below is
/// the only thing that notices, and a change to it means every consumer in the
/// tree must be rebuilt, not relinked.
///
/// @since 4.2
class LIBRESCRS_PUBLIC_API SessionPresence
{
public:
    /// @brief RAII handle returned from @ref insert. Destruction removes the
    ///        entry from the registry. Move-only; default-constructible to a
    ///        no-op handle for std::optional storage.
    ///
    /// @par Why it carries the session and not just the reader name
    /// A reader name is not an identity: two sessions can name one reader, and a
    /// registration that removed by name alone deleted whichever entry happened
    /// to be there — its own or somebody else's. That is how the one guarantee
    /// this registry exists for could be switched off without a second process:
    /// one session's registration going away took the other session's live-SM
    /// entry with it, and the provider stopped refusing to bind the card. A
    /// registration therefore remembers WHICH session it registered and removes
    /// only that entry.
    class LIBRESCRS_PUBLIC_API Registration
    {
    public:
        Registration() noexcept = default;
        Registration(SessionPresence* o, std::string r, std::weak_ptr<CardSession> s) noexcept;
        Registration(Registration&& other) noexcept;
        Registration& operator=(Registration&& other) noexcept;
        Registration(const Registration&) = delete;
        Registration& operator=(const Registration&) = delete;
        ~Registration();

    private:
        SessionPresence* owner{nullptr};
        std::string readerName{};
        /// The entry this registration owns. Compared by control block, so it
        /// still identifies the entry after the session itself is gone.
        std::weak_ptr<CardSession> session{};
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

    /// @brief Remove @p readerName's entry only if it is @p session's.
    ///
    /// There is deliberately no by-name-alone overload: removing an entry without
    /// asking whose it is was the defect, and leaving the door open invites it
    /// back.
    void remove(const std::string& readerName, const std::weak_ptr<CardSession>& session) noexcept;

    mutable std::mutex mu;
    std::unordered_map<std::string, std::weak_ptr<CardSession>> entries;
};

// Registration crosses an exported signature by value and no gate measures its
// layout; see the @warning on SessionPresence.
static_assert(sizeof(SessionPresence::Registration) ==
                  sizeof(SessionPresence*) + sizeof(std::string) + sizeof(std::weak_ptr<CardSession>),
              "SessionPresence::Registration layout is part of the ABI its consumers were built against");

} // namespace LibreSCRS::SmartCard::Internal
