// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>

#include <smartcard/pcsc_connection.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace LibreSCRS::SmartCard {

namespace {
// Process-wide monotonic counter. Starts at 0; nextGeneration() returns the
// pre-increment value + 1 so the first CardSession's generation is 1 and 0
// is reserved for "null / moved-from".
std::uint64_t nextGeneration() noexcept
{
    static std::atomic<std::uint64_t> counter{0};
    return counter.fetch_add(1, std::memory_order_relaxed) + 1;
}
} // namespace

struct LIBRESCRS_INTERNAL CardSession::Impl
{
    std::unique_ptr<LibreSCRS::SmartCard::Internal::PCSCConnection> ownedConn;
    std::string readerName;
    std::vector<std::uint8_t> atr;
    std::uint64_t generation{nextGeneration()};
};

CardSession::CardSession() : d(std::make_unique<Impl>()) {}

// Private constructor — used by @ref open and @ref makeDetachedCardSession
// only. Exposes the old "throw on failure" shape internally so the existing
// PCSCConnection constructor (which throws std::runtime_error with a
// textual diagnostic) can be consumed without rewriting the transport
// layer. The public @ref open factory translates any exception into a
// structured @ref OpenError.
CardSession::CardSession(std::string readerName) : d(std::make_unique<Impl>())
{
    d->readerName = std::move(readerName);
    try {
        d->ownedConn = std::make_unique<LibreSCRS::SmartCard::Internal::PCSCConnection>(d->readerName);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string{"CardSession open failed: "} + e.what());
    }
    d->atr = d->ownedConn->getATR();
}

namespace {

// Classify a PCSCConnection-reported error message into a structured
// @ref OpenError::Kind. The internal transport raises a runtime_error with a
// human-readable diagnostic; 4.0 preserves that text as @ref
// OpenError::diagnosticDetail while projecting the category into a stable
// enum suitable for programmatic branching.
OpenError::Kind classifyOpenError(std::string_view diag) noexcept
{
    // Match substrings emitted by LibreSCRS::SmartCard::Internal::PCSCConnection — the canonical
    // strings are "reader not found", "no smartcard", and "protocol" etc.
    // The matches are intentionally permissive: PC/SC error strings vary
    // across pcsc-lite / WinSCard / CryptoTokenKit revisions. Unknown
    // diagnostics fall back to ReaderUnavailable, which is the safest
    // generic category for a host UI to render.
    auto contains = [&](std::string_view needle) noexcept { return diag.find(needle) != std::string_view::npos; };

    if (contains("no smartcard") || contains("no card") || contains("NO_SMARTCARD") || contains("REMOVED_CARD"))
        return OpenError::Kind::NoCardPresent;
    if (contains("protocol") || contains("PROTO_MISMATCH") || contains("comm"))
        return OpenError::Kind::ProtocolError;
    return OpenError::Kind::ReaderUnavailable;
}

} // namespace

std::expected<CardSession, OpenError> CardSession::open(std::string readerName) noexcept
{
    // 4.0 hardening: OpenError() is deleted; construction goes
    // through the field-wise ctor so userMessage cannot be silently empty.
    // The neutral translator-friendly key surfaces here — hosts are free
    // to refine based on @ref OpenError::kind. The defaultText is a
    // plain sentence so an untranslated host still has readable text.
    static const LocalizedText kOpenFailedMsg{
        "librescrs.smartcard.error.openFailed",
        "Failed to open the card session. Check that the reader is connected and a card is inserted.",
        {}};
    // std::expected<CardSession, OpenError> implicitly converts from a
    // CardSession rvalue (success) and from std::unexpected<OpenError>
    // (failure). No in-place tag dispatch is needed in the C++23 form.
    try {
        return CardSession{std::move(readerName)};
    } catch (const std::exception& e) {
        std::string diag = e.what();
        OpenError::Kind k = classifyOpenError(diag);
        return std::unexpected{OpenError{k, kOpenFailedMsg, std::move(diag)}};
    } catch (...) {
        return std::unexpected{OpenError{OpenError::Kind::ReaderUnavailable, kOpenFailedMsg,
                                         std::string{"unknown non-std exception during CardSession open"}}};
    }
}

CardSession::~CardSession() = default;

CardSession::CardSession(CardSession&&) noexcept = default;
CardSession& CardSession::operator=(CardSession&&) noexcept = default;

namespace detail {

// PcscBridge is the LM-internal friend that unwraps CardSession into its
// underlying PCSCConnection. LibreSCRS::SmartCard::Internal::PCSCConnection no
// longer appears in the public CardSession.h forward-declaration; LM-
// internal sources go through this bridge instead. Callers MUST NOT pass
// a moved-from CardSession; no defensive null-check (see public accessor
// invariants).
LibreSCRS::SmartCard::Internal::PCSCConnection& PcscBridge::unwrap(CardSession& session) noexcept
{
    return *session.d->ownedConn;
}

const LibreSCRS::SmartCard::Internal::PCSCConnection& PcscBridge::unwrap(const CardSession& session) noexcept
{
    return *session.d->ownedConn;
}

std::shared_ptr<CardSession> makeDetachedCardSession(std::string readerName)
{
    auto session = std::shared_ptr<CardSession>(new CardSession());
    session->d->readerName = std::move(readerName);
    session->d->ownedConn =
        std::make_unique<LibreSCRS::SmartCard::Internal::PCSCConnection>(LibreSCRS::SmartCard::Internal::PCSCConnection::DetachedTag{}, session->d->readerName);
    // atr stays empty — there is no card
    return session;
}

std::uint64_t sessionGeneration(const CardSession& session) noexcept
{
    return session.d->generation;
}

} // namespace detail

// Accessors unconditionally dereference `d`. Calling any of these on a
// moved-from session is undefined behaviour (see header); this matches the
// invariant of sibling pimpl-backed classes (SigningService, SigningRequest).
const std::string& CardSession::readerName() const noexcept
{
    return d->readerName;
}
const std::vector<std::uint8_t>& CardSession::atr() const noexcept
{
    return d->atr;
}
bool CardSession::isConnected() const noexcept
{
    return d->ownedConn != nullptr;
}

} // namespace LibreSCRS::SmartCard
