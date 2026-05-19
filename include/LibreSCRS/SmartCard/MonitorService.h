// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SmartCard::MonitorService — PC/SC reader and card-event
///        listener with multi-subscriber fan-out; @ref
///        LibreSCRS::SmartCard::MonitorEvent event payload; and the opaque
///        @ref LibreSCRS::SmartCard::MonitorService::SubscriptionId token type.

#include <LibreSCRS/Export.h>

#include <compare>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard {

namespace detail {
class MonitorFactory;
}

/// @brief Event delivered to a @ref MonitorService subscriber callback.
///
/// @since 4.0
struct MonitorEvent
{
    /// @brief Event category; determines which other fields are populated.
    /// @note Append-only: new event kinds may be added in future minor
    ///       releases. Consumer @c switch statements must include a
    ///       @c default branch.
    enum class Kind : std::uint8_t {
        ReaderAdded,   ///< A PC/SC reader was plugged into the host.
        ReaderRemoved, ///< A PC/SC reader was unplugged.
        CardInserted,  ///< A card was inserted into a known reader.
        CardRemoved,   ///< A card was removed from a known reader.
        Error          ///< MonitorService encountered an error.
    };

    /// @brief Event category.
    Kind kind;
    /// @brief PC/SC reader name the event refers to.
    std::string readerName;
    /// @brief Human-readable error description for @ref Kind::Error events.
    std::optional<std::string> diagnosticDetail;
    /// @brief ATR bytes for @ref Kind::CardInserted events, empty otherwise.
    /// Reader-list events (Added/Removed) never carry an ATR.
    std::optional<std::vector<std::uint8_t>> atr;
};

/// @brief PC/SC reader and card-event listener with multi-subscriber fan-out.
///
/// One MonitorService owns one PC/SC `SCardContext` and one poll thread.
/// Subscribe multiple callbacks to a single MonitorService instance via
/// @ref subscribe for fan-out to several listeners within one consumer.
///
/// Multiple MonitorService instances in the same process are correct but
/// wasteful: each gets its own context and sees the same events
/// independently, causing duplicate callback invocations for a
/// consumer that accidentally holds more than one. A single
/// consumer should create one MonitorService and use `subscribe()` for
/// multi-listener needs. Independent SDK consumers coexisting in
/// the same host process may each own their MonitorService without issue.
///
/// The poll thread starts on the first subscribe and stops after
/// the last unsubscribe — no explicit lifecycle management by
/// consumers.
///
/// @par Thread-safety
/// Thread-safe (see API-POLICY §8). Public methods — @ref subscribe,
/// @ref unsubscribe, @ref listReaders, @ref isRunning — may be called
/// concurrently from multiple consumer threads. Subscriber callbacks are
/// invoked on the MonitorService's internal poll thread, never on the caller's
/// thread; consumers integrating with a GUI toolkit MUST marshal events back
/// to the UI thread (e.g. `QMetaObject::invokeMethod` with
/// `Qt::QueuedConnection`, GLib's `g_idle_add`). Callback bodies should
/// return promptly — blocking the poll thread delays subsequent events.
/// Subscriber callbacks that throw are caught and logged to `stderr` but do
/// not abort the poll thread; misbehaving subscribers cannot tear down the
/// MonitorService for unrelated subscribers in the same process.
///
/// Non-copyable, non-movable. A MonitorService owns a live poll thread and
/// a subscription table keyed by stable @ref SubscriptionId tokens;
/// subscribers installed before any move would still reference the
/// source @c MonitorService* via that table, so move-semantics cannot
/// preserve the lifetime coupling cleanly. Consumers needing shared
/// ownership should construct via @c std::make_shared<MonitorService>() and
/// pass a @c std::shared_ptr<MonitorService>. This mirrors
/// @ref LibreSCRS::Plugin::AutoReaderService, which explicitly takes a
/// @c std::shared_ptr<MonitorService> for the same reason.
///
/// @since 4.0
class LIBRESCRS_PUBLIC_API MonitorService
{
private:
    // Forward-declare Impl at the top so the nested SubscriptionId class
    // below can name it in a friend declaration. Definition stays in
    // `lib/LibreSCRS/SmartCard/MonitorService.cpp`.
    struct Impl;

public:
    /// @brief Host-supplied callback invoked for each @ref MonitorEvent.
    using EventCallback = std::function<void(const MonitorEvent&)>;

    /// @brief Opaque subscription handle. Returned by @ref subscribe, passed
    ///        to @ref unsubscribe. Comparable (ordered/equal) and hashable
    ///        via the @c std::hash specialisation defined below.
    ///
    /// The internal counter value is not part of the public API: the only
    /// operations external code should perform on a `SubscriptionId` are
    /// pass-through to @ref unsubscribe, comparison, and storing in
    /// associative containers.
    class SubscriptionId
    {
    public:
        /// @brief Default-construct a sentinel token (never equal to a real
        ///        subscription). Lets consumers declare zero-initialised
        ///        members and later assign from @ref subscribe.
        constexpr SubscriptionId() noexcept = default;

        /// @brief Defaulted three-way comparison (ordered/equal).
        ///
        /// C++20 synthesises @c operator== from a defaulted three-way
        /// comparison; no explicit equality operator is required (and a
        /// hand-written one would only duplicate the synthesised body).
        auto operator<=>(const SubscriptionId&) const = default;

    private:
        /// @brief Raw token accessor — visible only to friends below.
        ///
        /// External consumers MUST treat @ref SubscriptionId as opaque.
        /// The raw counter value is NOT part of the stable API contract:
        /// it exists because the @c std::hash specialisation below and the
        /// @ref LibreSCRS::SmartCard::MonitorService subscription map need a
        /// trivially-hashable token, and because the internal test factory
        /// in `detail/MonitorInjection.h` mints well-known tokens for
        /// fixture setup.
        ///
        /// @since 4.0 — accessor moved from public to private and exposed
        /// to @c std::hash via a friend declaration. The previous public
        /// "DON'T USE" accessor was a footgun; hidden-friend equivalence
        /// preserves the hash specialisation without inviting external use.
        [[nodiscard]] constexpr std::uint64_t rawValue() const noexcept
        {
            return valueInternal;
        }

        /// @brief Construct from a raw counter value. Private to the
        ///        @ref MonitorService implementation and to the internal test
        ///        factory in @c detail/MonitorInjection.h. External callers
        ///        obtain tokens only via @ref subscribe returns — per ABI
        ///        4.0 there is no public way to mint a
        ///        `SubscriptionId` from an arbitrary integer, removing a
        ///        class of "guess the next token" foot-shooting.
        ///
        /// The friend declarations below grant access to @ref MonitorService
        /// itself (so its member functions can mint tokens), to its nested
        /// `Impl` (which manages the subscription map), and to the
        /// detail-namespace `MonitorFactory` used by test code.
        explicit constexpr SubscriptionId(std::uint64_t v) noexcept : valueInternal(v) {}

        friend class MonitorService;
        friend struct MonitorService::Impl;
        friend class LibreSCRS::SmartCard::detail::MonitorFactory;
        friend struct std::hash<SubscriptionId>;

        std::uint64_t valueInternal = 0;
    };

    MonitorService();
    ~MonitorService();
    MonitorService(const MonitorService&) = delete;
    MonitorService& operator=(const MonitorService&) = delete;

    /// @brief Non-movable: see class-level Doxygen. Use
    ///        @c std::make_shared<MonitorService>() for shared ownership.
    MonitorService(MonitorService&&) = delete;
    /// @brief Non-movable: see class-level Doxygen.
    MonitorService& operator=(MonitorService&&) = delete;

    /// @brief True when this object holds a valid pimpl.
    ///
    /// @ref MonitorService is non-movable, so in practice `d` is non-null for the
    /// whole lifetime of a successfully-constructed instance. The
    /// conversion is provided for uniformity with the other pimpl-backed
    /// public types (@ref LibreSCRS::Signing::SigningService,
    /// @ref LibreSCRS::SmartCard::CardSession, @ref SubscriptionId) so
    /// downstream generic code can `if (obj)` without special-casing
    /// MonitorService.
    /// @since 4.0.
    explicit operator bool() const noexcept;

    /// @brief List currently available readers. Snapshot at call time.
    ///
    /// @return @c std::nullopt if the PC/SC subsystem is unavailable
    ///         (service not running, resource manager unreachable). An
    ///         engaged optional carries the reader snapshot — an empty
    ///         vector is a valid reading (no readers plugged in), distinct
    ///         from the nullopt case.
    /// @note noexcept: the plugin/signing ABI eliminates exceptions at the
    ///       LibreSCRS public boundary in 4.0. See @ref CardSession::open
    ///       and @ref Plugin::CardPlugin::readCard for the sibling cases.
    [[nodiscard]] std::optional<std::vector<std::string>> listReaders() const noexcept;

    /// @brief Register @p callback to receive events.
    /// @return Handle for @ref unsubscribe.
    /// @note First subscriber triggers auto-start of the polling thread.
    /// @note @ref isRunning may briefly return false immediately after this
    ///       call returns, until the poll thread completes its internal
    ///       initialization. Consumers that need a "ready" signal should
    ///       observe their first event delivery, not @ref isRunning.
    [[nodiscard]] SubscriptionId subscribe(EventCallback callback);

    /// @brief Cancellation policy for in-flight callbacks during unsubscribe.
    ///
    /// Selected by @ref unsubscribe's @p policy parameter. The default
    /// preserves the historical fast-path semantics; pass @ref Drain when
    /// the callback captures resources whose destruction must outlive any
    /// outstanding dispatch.
    ///
    /// @since 4.1
    enum class DrainPolicy : std::uint8_t {
        /// Return immediately; in-flight callbacks for this subscription may
        /// still fire after unsubscribe returns.
        FireAndForget = 0,
        /// Block until every in-flight callback for this subscription has
        /// returned. Safe to destroy callback captures after the call.
        Drain = 1,
    };

    /// @brief Unregister the subscription identified by @p id.
    /// @param id Subscription handle obtained from @ref subscribe.
    /// @param policy Selects whether to wait for in-flight callbacks for
    ///        this subscription to complete (@ref DrainPolicy::Drain) or
    ///        return immediately (@ref DrainPolicy::FireAndForget, default).
    /// @note After return, NEW events will not be delivered to this callback.
    /// @note With @ref DrainPolicy::FireAndForget, a dispatch that snapshotted
    ///       the subscriber set before this call may still invoke the callback
    ///       once after @ref unsubscribe returns. Callbacks that access
    ///       resources destroyed shortly afterwards should pass
    ///       @ref DrainPolicy::Drain, use weak ownership (e.g. a `weak_ptr`
    ///       to their state), or rely on an explicit cancellation flag.
    /// @note With @ref DrainPolicy::Drain, this call blocks until the poll
    ///       thread's current dispatch cycle (if any) has finished invoking
    ///       the callback for this subscription; after return, the callback
    ///       is guaranteed never to be invoked again. Must not be called from
    ///       within the callback itself in @ref DrainPolicy::Drain mode
    ///       (deadlock).
    /// @note The last unsubscribe stops the polling thread and blocks until
    ///       the in-flight PC/SC syscall completes (independent of @p policy).
    /// @note Unknown @p id → no-op.
    void unsubscribe(SubscriptionId id, DrainPolicy policy = DrainPolicy::FireAndForget) noexcept;

    /// @brief True when the polling thread is active.
    /// @note See @ref subscribe note about a brief false window immediately
    ///       after the first subscribe returns.
    /// @note Returns @c false when the internal mutex cannot be acquired
    ///       (@c std::mutex::lock may throw @c std::system_error per
    ///       [thread.req.exception]); the degraded result is documented to
    ///       preserve the @c noexcept contract per API-POLICY §5.3. POSIX /
    ///       Win32 mutexes do not fail in practice, but the abstraction
    ///       allows it.
    [[nodiscard]] bool isRunning() const noexcept;

private:
    friend class detail::MonitorFactory;
    // Impl is forward-declared above (near the top of this class body) so
    // that SubscriptionId's friend declaration can name it. Definition lives
    // in `lib/LibreSCRS/SmartCard/MonitorService.cpp`.
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::SmartCard

namespace std {

/// @brief Hash specialisation so @ref LibreSCRS::SmartCard::MonitorService::SubscriptionId
///        can be used as a key in `std::unordered_map` / `std::unordered_set`.
template <>
struct hash<LibreSCRS::SmartCard::MonitorService::SubscriptionId>
{
    /// @brief Hash by forwarding to `std::hash<std::uint64_t>` on the opaque counter value.
    std::size_t operator()(const LibreSCRS::SmartCard::MonitorService::SubscriptionId& id) const noexcept
    {
        return std::hash<std::uint64_t>{}(id.rawValue());
    }
};

} // namespace std
