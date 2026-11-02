// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/MonitorServiceImpl.h is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Export.h>
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/SmartCard/detail/MonitorInjection.h>

#include <ipcsc_scan_provider.h>
#include <monitor.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
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
    std::optional<::LibreSCRS::SmartCard::Internal::Monitor::SubscriptionId> internalSubId;
    std::atomic<std::uint64_t> nextId{1};

    std::mutex readersMtx;
    std::set<std::string> knownReaders;

    // Held for the full snapshot-and-invoke phase of @ref dispatch so that
    // @ref MonitorService::unsubscribe (with @ref DrainPolicy::Drain) can
    // block until any currently-running dispatch completes. Separate from
    // cbMtx because subscribers must be free to call subscribe/unsubscribe
    // from inside a callback, which would deadlock if dispatch held cbMtx
    // across invocation.
    std::mutex dispatchMtx;

    /// @brief Per-reader coalescer state.
    ///
    /// A Card event is buffered for @ref detail::MonitorConfig::coalesceWindow before
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
        // When the window count first crosses @ref detail::MonitorConfig::maxEventsPerSecond
        // the reader enters a @ref detail::MonitorConfig::backoffOnFlood cool-down during
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
    detail::MonitorConfig config;
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
    // The scan provider is always the default one: a test that needs another
    // swaps `internal` afterwards (MonitorFactory::withProvider).
    explicit Impl(detail::MonitorConfig cfg);

    ~Impl();

    // Snapshot currently-registered (id, callback) pairs under the cbMtx lock.
    // Dispatch outside cbMtx so subscribers can re-enter subscribe/unsubscribe
    // from within a callback without deadlocking.
    std::vector<std::pair<SubscriptionId, EventCallback>> snapshotCallbacks();

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

    // Reader-list diff: synthesise ReaderAdded / ReaderRemoved events from
    // the internal monitor's reader-list callback. knownReaders is updated
    // under readersMtx.
    void diffReadersAndDispatch(const std::vector<std::string>& readers);

    // First-subscriber bootstrap, run by subscribe(): clear knownReaders,
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

    // Drive @p service the way its scan thread does: through the callbacks
    // it registered on its internal monitor. Impl::dispatch and
    // Impl::diffReadersAndDispatch are hidden in the shared library, so a
    // test executable cannot call them; the registered callbacks are data it
    // can reach. Both return the number of callbacks that ran — 0 when the
    // service has no subscriber yet (nothing registered).
    static std::size_t publishEvent(MonitorService& service,
                                    const ::LibreSCRS::SmartCard::Internal::MonitorEvent& event);
    static std::size_t publishReaderList(MonitorService& service, const std::vector<std::string>& readers);
    static std::size_t coalesceStateSize(const MonitorService& service) noexcept;
    static bool isPolling(const MonitorService& service) noexcept;

    // Replaces the default configuration of a service nothing has
    // subscribed to yet; stops the coalescer's flusher when the new window
    // disables coalescing, as a service constructed with it never starts one.
    static std::shared_ptr<MonitorService> withConfig(const MonitorConfig& config);
};

} // namespace detail

} // namespace LibreSCRS::SmartCard
