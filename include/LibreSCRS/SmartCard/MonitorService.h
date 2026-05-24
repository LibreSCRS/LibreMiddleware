// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SmartCard::MonitorService — PC/SC reader and card-event
///        listener with multi-subscriber fan-out; @ref
///        LibreSCRS::SmartCard::MonitorEvent event payload; and the opaque
///        @ref LibreSCRS::SmartCard::MonitorService::SubscriptionId token type.

#include <LibreSCRS/Export.h>

#include <chrono>
#include <compare>
#include <cstddef>
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

    /// @brief Event category. Default-initialised to @ref Kind::Error so
    ///        a default-constructed @ref MonitorEvent has a deterministic
    ///        identity for `std::vector<MonitorEvent>` resize sentinels and
    ///        `std::optional<MonitorEvent>` empty-value queries; the
    ///        defaulted @ref operator== would otherwise read an
    ///        indeterminate byte. Error is the worst-case interpretation —
    ///        a defaulted event MUST NOT be silently treated as a
    ///        CardInserted / CardRemoved by a consumer that forgot to
    ///        populate the field.
    Kind kind = Kind::Error;
    /// @brief PC/SC reader name the event refers to.
    std::string readerName;
    /// @brief Human-readable error description for @ref Kind::Error events.
    std::optional<std::string> diagnosticDetail;
    /// @brief ATR bytes for @ref Kind::CardInserted events; @c std::nullopt
    ///        on every other @ref Kind value (@ref ReaderAdded,
    ///        @ref ReaderRemoved, @ref CardRemoved, @ref Error).
    std::optional<std::vector<std::uint8_t>> atr;

    /// @brief Defaulted byte-identity equality.
    [[nodiscard]] bool operator==(const MonitorEvent&) const noexcept = default;
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

    /// @brief Host-supplied callback invoked with the full post-change
    ///        reader-list snapshot whenever the aggregate set of PC/SC
    ///        readers known to this MonitorService changes.
    ///
    /// Delivered in addition to (not instead of) the per-reader
    /// @ref MonitorEvent::Kind::ReaderAdded / @ref MonitorEvent::Kind::ReaderRemoved
    /// stream surfaced via @ref EventCallback. Use this listener variant
    /// when the consumer needs the authoritative reader-list snapshot
    /// after each change without maintaining its own running set (the
    /// previous-to-4.2 idiom was to subscribe with @ref EventCallback and
    /// fold per-reader Added / Removed events into a host-managed
    /// `std::set<std::string>` to recover the snapshot for downstream
    /// signalling).
    ///
    /// @since 4.2
    using ReaderListCallback = std::function<void(const std::vector<std::string>&)>;

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

    /// @brief Tunable parameters for event coalescing and flood handling.
    ///
    /// The default-constructed @ref Config matches the values returned by
    /// @ref fromEnv when no environment overrides are set. Construct with
    /// designated initialisers to override individual fields, e.g.
    /// @code
    /// MonitorService svc{MonitorService::Config{
    ///     .coalesceWindow = std::chrono::milliseconds(100)}};
    /// @endcode
    ///
    /// @since 4.1
    struct Config
    {
        /// @brief Inserted+Removed (or Removed+Inserted) pairs on the same
        ///        reader within this window are suppressed as transient
        ///        phantoms. Set to zero to disable coalescing entirely.
        std::chrono::milliseconds coalesceWindow{250};

        /// @brief Per-reader event-rate ceiling; reserved for the rate
        ///        limiter wired in a follow-up change. Unused by the
        ///        coalescer.
        std::size_t maxEventsPerSecond{20};

        /// @brief Cool-down applied once the rate limiter trips; reserved
        ///        for the rate limiter wired in a follow-up change.
        std::chrono::milliseconds backoffOnFlood{5000};

        /// @brief Build a @ref Config from process environment overrides.
        ///        @c LIBRESCRS_MONITOR_COALESCE_MS replaces
        ///        @ref coalesceWindow when set to a non-negative integer.
        ///        The literal value @c "0" disables coalescing. Unset or
        ///        malformed values preserve the defaults.
        [[nodiscard]] static Config fromEnv() noexcept;
    };

    /// @brief Construct a MonitorService. @p config tunes coalescing and
    ///        flood handling; the default reads tunables from the
    ///        process environment (see @ref Config::fromEnv).
    explicit MonitorService(Config config = Config::fromEnv());
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
    /// @since 4.0
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

    /// @brief Register @p callback to receive the full post-change reader-list
    ///        snapshot whenever the aggregate set of PC/SC readers changes.
    ///
    /// Fires once on registration with the current snapshot (which may be
    /// empty when no readers are plugged in), then on every subsequent
    /// change with the post-change snapshot. The first-fire bootstrap lets
    /// consumers that join late still observe the initial reader inventory
    /// without polling @ref listReaders themselves.
    ///
    /// Within a single reader-list change, the per-reader
    /// @ref MonitorEvent::Kind::ReaderAdded / @ref MonitorEvent::Kind::ReaderRemoved
    /// events are dispatched FIRST through any @ref subscribe callbacks,
    /// and the aggregated post-change snapshot is dispatched AFTERWARDS
    /// through every @ref subscribeReaderList callback. Consumers that
    /// register both kinds of callback can therefore rely on the snapshot
    /// observing every prior per-reader event for the same change.
    ///
    /// @return Handle for @ref unsubscribeReaderList. The returned handle
    ///         shares the same token space as @ref subscribe — handles
    ///         minted by either method are pairwise distinct and must be
    ///         passed to their matching unsubscribe overload.
    ///
    /// @note First subscriber (counting both @ref subscribe and
    ///       @ref subscribeReaderList) triggers auto-start of the polling
    ///       thread. The brief "isRunning may return false" window
    ///       documented on @ref subscribe applies here too.
    ///
    /// @par Example
    /// @code
    /// LibreSCRS::SmartCard::MonitorService monitor;
    /// // LC-style consumer: receive the authoritative reader list after
    /// // each change without maintaining a local std::set<std::string>.
    /// auto id = monitor.subscribeReaderList(
    ///     [](const std::vector<std::string>& readers) {
    ///         // marshal to GUI thread, e.g. via QMetaObject::invokeMethod
    ///         emitReaderListChanged(readers);
    ///     });
    /// // ... later, on shutdown:
    /// monitor.unsubscribeReaderList(id);
    /// @endcode
    ///
    /// @since 4.2
    // TODO(docs): add Hugo dev-guide page at /docs/api/monitor-reader-list.md (EN+SR) before 4.2 release
    [[nodiscard]] SubscriptionId subscribeReaderList(ReaderListCallback callback);

    /// @brief Unregister the reader-list snapshot subscription identified by @p id.
    /// @param id Subscription handle obtained from @ref subscribeReaderList.
    /// @param policy Selects whether to wait for in-flight callbacks for this
    ///        subscription to complete (@ref DrainPolicy::Drain) or return
    ///        immediately (@ref DrainPolicy::FireAndForget, default).
    /// @note After return, NEW snapshots will not be delivered to this callback.
    /// @note Drain / FireAndForget semantics mirror @ref unsubscribe verbatim.
    /// @note Unknown @p id → no-op. Passing a handle minted by @ref subscribe
    ///       (i.e. a per-event subscription) is treated as unknown and is a
    ///       no-op as well; consumers must pair each subscribe variant with
    ///       its matching unsubscribe.
    /// @since 4.2
    void unsubscribeReaderList(SubscriptionId id, DrainPolicy policy = DrainPolicy::FireAndForget) noexcept;

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

    /// @brief Test seam: inject a synthetic @ref MonitorEvent through the
    ///        same dispatch funnel real PC/SC events use.
    ///
    /// Bypasses the PC/SC source so unit tests can exercise the dispatch
    /// path (coalescing, fan-out, callback shielding) without a live
    /// reader. Not for production use; the public ABI exposes it because
    /// the alternative — a friend declaration on the internal Impl —
    /// requires the consumer to include the @c LIBRESCRS_INTERNAL_BUILD
    /// header, defeating the test-from-public-headers contract.
    ///
    /// @since 4.1
    void publishForTest(const MonitorEvent& ev);

    /// @brief Test seam: drive the reader-list diff path with a synthetic
    ///        snapshot. Synthesises @ref MonitorEvent::Kind::ReaderAdded /
    ///        @ref MonitorEvent::Kind::ReaderRemoved against the previously
    ///        seen set, and evicts coalescer state for removed readers.
    ///
    /// Not for production use; mirrors @ref publishForTest as a way to
    /// exercise the diff path without a live PC/SC source.
    ///
    /// @since 4.1
    void publishReaderListForTest(const std::vector<std::string>& readers);

    /// @brief Test seam: number of per-reader coalescer state entries.
    ///        Used by eviction tests to assert that vanished readers no
    ///        longer occupy a slot in @c Impl::coalesceState.
    ///
    /// @since 4.1
    [[nodiscard]] std::size_t coalesceStateSizeForTest() const noexcept;

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
