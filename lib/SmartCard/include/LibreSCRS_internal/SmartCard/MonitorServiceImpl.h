// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/MonitorServiceImpl.h is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Export.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <ipcsc_scan_provider.h>
#include <monitor.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace LibreSCRS::SmartCard {

/// @brief Private state of @ref MonitorService. Lives in an LM-internal
///        header so that both the production translation unit and the
///        test-helper translation unit (built as a separate archive,
///        @ref LibreSCRS_SmartCard_TestHelpers) can manipulate the same
///        layout without re-exporting test-only entry points through the
///        production shared library's dynamic symbol table.
struct LIBRESCRS_INTERNAL MonitorService::Impl
{
    std::unique_ptr<::LibreSCRS::SmartCard::Internal::Monitor> internal;

    std::mutex cbMtx;
    std::map<SubscriptionId, EventCallback> callbacks;
    // Snapshot-style subscribers registered via subscribeReaderList. Keyed
    // by the same opaque SubscriptionId token as `callbacks` so the same
    // unsubscribe-arity disambiguates by lookup (a token is in exactly one
    // map). Sharing the nextId counter guarantees the per-event and
    // reader-list maps never collide on a token value.
    std::map<SubscriptionId, MonitorService::ReaderListCallback> readerListCallbacks;
    std::optional<::LibreSCRS::SmartCard::Internal::Monitor::SubscriptionId> internalSubId;
    std::atomic<std::uint64_t> nextId{1};

    std::mutex readersMtx;
    std::set<std::string> knownReaders;

    /// @brief True once the internal poll thread has completed its first
    ///        @ref diffReadersAndDispatch invocation in the current polling
    ///        session (i.e. `knownReaders` reflects an actual PC/SC scan
    ///        outcome, even if the outcome was "zero readers").
    ///
    /// Gates the bootstrap-fire branch in @ref MonitorService::subscribeReaderList:
    /// late joiners only receive a synchronous bootstrap snapshot once we
    /// know the cached `knownReaders` set reflects a real enumeration
    /// result, not the empty post-`clear()` state held while the poll
    /// thread starts up. Late joiners arriving in the race window between
    /// poll-thread start and first scan completion receive nothing
    /// synchronously; they will receive a snapshot via the poll thread's
    /// next dispatch — which fires whenever membership actually changes
    /// (per @ref diffReadersAndDispatch's suppress-when-unchanged guard).
    /// In the steady-state zero-readers-at-boot scenario specifically,
    /// such late joiners receive nothing until a reader is plugged in;
    /// this is acceptable because once `initialPollComplete` is set, any
    /// FURTHER subscriber will hit the bootstrap branch and learn the
    /// current (possibly-empty) membership synchronously.
    ///
    /// @par Lifecycle (monotonic per polling session, NOT per object lifetime)
    /// - Constructed `false`.
    /// - Set `true` at the end of `diffReadersAndDispatch` after the first
    ///   successful enumerate-cycle in a polling session.
    /// - Reset to `false` whenever the poll thread stops and `knownReaders`
    ///   is cleared (i.e. inside the `firstSubscriber == true` branch of
    ///   `subscribe` / `subscribeReaderList`, paired with `knownReaders.clear()`).
    ///
    /// @par Memory ordering
    /// The atomic provides the synchronisation edge that gates whether
    /// `subscribeReaderList` even attempts the bootstrap branch. The actual
    /// `knownReaders` data race-freedom is provided by `readersMtx`: the
    /// poll thread mutates `knownReaders` under `readersMtx`, releases it,
    /// then later release-stores the flag; the subscriber acquire-loads
    /// the flag, then takes `readersMtx` to read `knownReaders`. The mutex
    /// alone is sufficient to publish the data; the acquire/release pair
    /// is load-bearing only as a one-way gate ("has the poll thread
    /// produced a real enumeration yet?").
    ///
    /// @since 4.2 — fix for the subscribeReaderList bootstrap-race
    /// regression.
    std::atomic<bool> initialPollComplete{false};

    // Held for the full snapshot-and-invoke phase of @ref dispatch so that
    // @ref MonitorService::unsubscribe (with @ref DrainPolicy::Drain) can
    // block until any currently-running dispatch completes. Separate from
    // cbMtx because subscribers must be free to call subscribe/unsubscribe
    // from inside a callback, which would deadlock if dispatch held cbMtx
    // across invocation.
    std::mutex dispatchMtx;

    /// @brief Per-reader coalescer state.
    ///
    /// A Card event is buffered for @ref Config::coalesceWindow before
    /// being forwarded to subscribers. If the opposite kind arrives on the
    /// same reader during that window, both the buffered event and the
    /// arriving one are dropped as a transient phantom (PC/SC
    /// dual-interface readers can emit dozens of Inserted+Removed pairs in
    /// sub-second bursts). A same-kind repeat refreshes the buffered event
    /// without emitting a duplicate.
    struct ReaderCoalesceState
    {
        std::optional<MonitorEvent> heldEvent;
        std::chrono::steady_clock::time_point heldUntil{};
        MonitorEvent::Kind lastEmittedKind{MonitorEvent::Kind::Error};
        std::chrono::steady_clock::time_point lastEventAt{};

        // Per-reader rate-limit window: timestamps of card events that
        // entered the dispatch path in the rolling 1-second trailing
        // window. Entries older than 1s are evicted on every dispatch.
        // When the window count first crosses @ref Config::maxEventsPerSecond
        // the reader enters a @ref Config::backoffOnFlood cool-down during
        // which further card events are dropped at the gate (never reach
        // the coalescer or subscribers). @c floodLogged squelches the
        // one-shot warning to a single line per flood episode; it resets
        // on the first healthy event after the backoff expires so a
        // recurring flood logs again.
        std::deque<std::chrono::steady_clock::time_point> eventWindow;
        std::chrono::steady_clock::time_point backoffUntil{};
        bool floodLogged{false};

        // The most recent card event dropped while the reader was inside its
        // flood backoff. A dual-interface contactless reader can burst dozens
        // of bogus Inserted/Removed pairs when a card lands, tripping the
        // backoff, and then SETTLE with the card present — that terminal
        // CardInserted arrives during the cool-down and would otherwise be
        // dropped forever (the card is present but invisible until a manual
        // re-seat / restart). When the backoff expires the flusher reconciles:
        // if this pending terminal state disagrees with @c lastEmittedKind
        // about card presence, it is delivered. Transients are still
        // suppressed — only the settled final state survives. A genuine
        // event accepted after the backoff expires supersedes it (the
        // healthy path in dispatch() resets it), so a coexisting heldEvent
        // is always older than the floodPending.
        std::optional<MonitorEvent> floodPending;
    };

    mutable std::mutex coalesceMtx;
    std::condition_variable coalesceCv;
    std::unordered_map<std::string, ReaderCoalesceState> coalesceState;
    MonitorService::Config config;
    std::thread coalesceFlusher;
    bool coalesceStop{false};

    // Ctor and dtor bodies live out-of-line in MonitorService.cpp so the
    // std::thread::_State_impl<&Impl::runCoalesceFlusher, Impl*> template
    // instantiation triggered by the coalescer thread spawn happens in a
    // single TU compiled with -fvisibility=hidden default, instead of in
    // every header includer. GCC computes std-template instantiation
    // visibility from the instantiation context (not the LIBRESCRS_INTERNAL
    // attribute on the template argument), so an inline ctor in this
    // header would leak the vtable/typeinfo of that instantiation into the
    // SHARED-build libLibreSCRS_SmartCard.so dynamic export table.
    Impl(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider, MonitorService::Config cfg);

    // Backwards-compatible single-arg ctor used by the test-helper factory
    // and any internal call site that did not pre-date the Config addition.
    // Defaults the Config to the env-driven baseline.
    explicit Impl(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider);

    ~Impl();

    // Snapshot currently-registered (id, callback) pairs under the cbMtx lock.
    // Dispatch outside cbMtx so subscribers can re-enter subscribe/unsubscribe
    // from within a callback without deadlocking.
    std::vector<std::pair<SubscriptionId, EventCallback>> snapshotCallbacks();

    // Snapshot currently-registered (id, reader-list callback) pairs under
    // cbMtx. Mirrors @ref snapshotCallbacks for the reader-list subscriber
    // population so dispatch can run outside the cbMtx lock.
    std::vector<std::pair<SubscriptionId, MonitorService::ReaderListCallback>> snapshotReaderListCallbacks();

    // Dispatch a full post-change reader-list snapshot to every
    // @ref MonitorService::subscribeReaderList subscriber under the
    // dispatchMtx serialisation gate (so Drain semantics extend to the
    // snapshot callback population uniformly). Subscriber callbacks that
    // throw are caught and logged; the dispatch loop continues.
    void dispatchReaderListSnapshot(const std::vector<std::string>& snapshot);

    // Full snapshot-and-invoke runs under dispatchMtx so @ref
    // MonitorService::unsubscribe with @ref DrainPolicy::Drain can block on
    // it to guarantee no callback is currently in flight.
    void dispatch(const MonitorEvent& event);

    // Bypasses the coalescer and pushes an event straight to subscribers.
    // Used by the flusher thread when a held event's window expires.
    void dispatchImmediate(const MonitorEvent& event);

    // Background flusher loop: wakes on the earliest pending deadline (a
    // held-event's coalesce window or a flood backoff's expiry), releases
    // events whose window has expired and reconciles suppressed terminal
    // states. Recomputes the earliest deadline on every wake — deadlines
    // are not monotonic across the two sources. Exits when coalesceStop is
    // set in the destructor.
    void runCoalesceFlusher();

    // Reader-list diff: synthesise ReaderAdded / ReaderRemoved events.
    // Shared by the subscribe-time initial snapshot path and the internal
    // ReaderListCallback path. knownReaders is updated under readersMtx.
    void diffReadersAndDispatch(const std::vector<std::string>& readers);

    // First-subscriber bootstrap, shared verbatim by subscribe() and
    // subscribeReaderList(): clear knownReaders, reset the initial-poll latch,
    // wire the internal monitor's event + reader-list callbacks, then perform
    // TOCTOU orphan-recovery if a concurrent unsubscribe emptied the subscriber
    // population between the caller's first cbMtx release and this start. Call
    // ONLY when firstSubscriber is true, and OUTSIDE cbMtx — it takes
    // readersMtx and cbMtx itself. Register-first ordering is mandatory: callers
    // MUST emplace their callback into the subscriber map (under cbMtx) BEFORE
    // calling this, so the internal monitor's initial bootstrap dispatch never
    // observes an empty subscriber population.
    void startInternalMonitor();
};

namespace detail {

/// @brief Friend-only access seam to @ref MonitorService for the
///        test-helper archive @ref LibreSCRS_SmartCard_TestHelpers.
///
/// The class is declared (and befriended by @ref MonitorService) so that
/// its static methods can construct a service with an injected scan
/// provider and synthesise a @ref MonitorService::SubscriptionId from a
/// raw counter value — both seams that the production public surface
/// deliberately closes. Method bodies live in the test-helper archive,
/// not in the production library, so the symbols never enter the
/// production shared object's dynamic export set.
class MonitorFactory
{
public:
    static std::shared_ptr<MonitorService>
    withProvider(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider);

    // 4.0 hardening: raw-int ctor on SubscriptionId is private. Test code
    // that needs to probe unknown-id behaviour (e.g. unsubscribe(9999) on a
    // never-issued value) goes through this factory, which is befriended by
    // SubscriptionId. External SDK consumers never see this header
    // (MonitorServiceImpl.h is guarded by #error against LIBRESCRS_INTERNAL_BUILD).
    static constexpr MonitorService::SubscriptionId makeSubscriptionId(std::uint64_t value) noexcept
    {
        return MonitorService::SubscriptionId{value};
    }
};

} // namespace detail

} // namespace LibreSCRS::SmartCard
