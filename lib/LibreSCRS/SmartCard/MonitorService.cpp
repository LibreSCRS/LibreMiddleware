// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS_internal/SmartCard/MonitorServiceImpl.h>

#include <ipcsc_scan_provider.h>
#include <monitor.h>
#include <smartcard/monitor_event.h>
#include <pcsc_connection.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <exception>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace LibreSCRS::SmartCard {

namespace {

// Internal LibreSCRS::SmartCard::Internal::MonitorEvent has only Card{Inserted,Removed} types.
// Reader-list changes arrive via a separate ReaderListCallback — they are
// diffed against the previous snapshot to synthesise Reader{Added,Removed}
// public events. MonitorEvent::Kind::Error is reserved for future use (no
// internal event maps onto it today).
MonitorEvent::Kind mapCardEventKind(::LibreSCRS::SmartCard::Internal::MonitorEvent::Type t)
{
    switch (t) {
    case ::LibreSCRS::SmartCard::Internal::MonitorEvent::Type::CardInserted:
        return MonitorEvent::Kind::CardInserted;
    case ::LibreSCRS::SmartCard::Internal::MonitorEvent::Type::CardRemoved:
        return MonitorEvent::Kind::CardRemoved;
    }
    return MonitorEvent::Kind::Error;
}

} // namespace

// @ref MonitorService::Impl is defined in
// `lib/SmartCard/include/LibreSCRS_internal/SmartCard/MonitorServiceImpl.h`
// so the production translation unit and the test-helper translation unit
// (built as a separate archive, @ref LibreSCRS_SmartCard_TestHelpers) share
// the same layout. The dispatch / snapshot / reader-diff method bodies
// remain in the production translation unit; they are not test-only.
//
// Ctor / dtor bodies are also out-of-line here (instead of inline in the
// internal header) so the std::thread::_State_impl<...> template
// instantiation triggered by `std::thread(&Impl::runCoalesceFlusher, this)`
// is emitted only in this TU. The header's includers (the test-helper TU
// and any future internal consumer) therefore do not each emit a copy of
// that std-template vtable/typeinfo at default visibility, which would
// otherwise leak through the SHARED-build libLibreSCRS_SmartCard.so
// dynamic export table.
MonitorService::Impl::Impl(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider,
                           MonitorService::Config cfg)
    : internal(std::make_unique<::LibreSCRS::SmartCard::Internal::Monitor>(std::move(provider))), config(cfg)
{
    if (config.coalesceWindow.count() > 0) {
        // Spawn via a local lambda so the std::thread::_State_impl<...>
        // template instantiation is parameterised over the lambda's
        // anonymous closure type (local to this TU, emitted hidden) rather
        // than over `void (Impl::*)()` (which carries MonitorService::Impl
        // as a template arg and triggers a vtable/typeinfo emission whose
        // visibility GCC computes from the std-namespace instantiation
        // context, not from Impl's LIBRESCRS_INTERNAL attribute — that is
        // how the std::thread::_State_impl-over-Impl symbols would
        // otherwise leak into the SHARED-build libLibreSCRS_SmartCard.so
        // dynamic export table). Mirrors the allow-listed pattern in
        // lib/smartcard/src/monitor.cpp's internal poller thread spawn.
        coalesceFlusher = std::thread([this] { runCoalesceFlusher(); });
    }
}

MonitorService::Impl::Impl(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider)
    : Impl(std::move(provider), MonitorService::Config::fromEnv())
{}

MonitorService::Impl::~Impl()
{
    if (coalesceFlusher.joinable()) {
        {
            std::scoped_lock lk(coalesceMtx);
            coalesceStop = true;
        }
        coalesceCv.notify_all();
        coalesceFlusher.join();
    }
}

std::vector<std::pair<MonitorService::SubscriptionId, MonitorService::EventCallback>>
MonitorService::Impl::snapshotCallbacks()
{
    std::lock_guard<std::mutex> lock(cbMtx);
    std::vector<std::pair<SubscriptionId, EventCallback>> out;
    out.reserve(callbacks.size());
    for (const auto& [id, cb] : callbacks) {
        out.emplace_back(id, cb);
    }
    return out;
}

std::vector<std::pair<MonitorService::SubscriptionId, MonitorService::ReaderListCallback>>
MonitorService::Impl::snapshotReaderListCallbacks()
{
    std::lock_guard<std::mutex> lock(cbMtx);
    std::vector<std::pair<SubscriptionId, MonitorService::ReaderListCallback>> out;
    out.reserve(readerListCallbacks.size());
    for (const auto& [id, cb] : readerListCallbacks) {
        out.emplace_back(id, cb);
    }
    return out;
}

void MonitorService::Impl::dispatchReaderListSnapshot(const std::vector<std::string>& snapshot)
{
    // Runs under dispatchMtx so unsubscribe(..., DrainPolicy::Drain) can
    // block on an in-flight snapshot dispatch identically to how it blocks
    // on an in-flight per-event dispatch (see @ref dispatchImmediate).
    std::lock_guard<std::mutex> dispatchLock(dispatchMtx);
    auto subs = snapshotReaderListCallbacks();
    for (const auto& [id, cb] : subs) {
        (void)id;
        if (!cb)
            continue;
        try {
            cb(snapshot);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "LibreSCRS MonitorService: reader-list subscriber callback threw: %s\n", e.what());
        } catch (...) {
            std::fprintf(stderr, "LibreSCRS MonitorService: reader-list subscriber callback threw unknown exception\n");
        }
    }
}

// Each subscriber callback runs inside a try/catch shield. A subscriber
// that throws will not propagate out of the poll thread — that would
// otherwise terminate the program (an exception escaping the std::thread
// entry point invokes std::terminate). Error tokens are written to stderr
// as a defense-in-depth fallback because the SDK does not currently inject
// a logger across the public ABI boundary; the contract is documented on
// `MonitorService`'s @par Thread-safety section in the header.
void MonitorService::Impl::dispatchImmediate(const MonitorEvent& event)
{
    std::lock_guard<std::mutex> dispatchLock(dispatchMtx);
    auto snapshot = snapshotCallbacks();
    for (const auto& [id, cb] : snapshot) {
        (void)id;
        if (!cb)
            continue;
        try {
            cb(event);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "LibreSCRS MonitorService: subscriber callback threw: %s\n", e.what());
        } catch (...) {
            std::fprintf(stderr, "LibreSCRS MonitorService: subscriber callback threw unknown exception\n");
        }
    }
}

void MonitorService::Impl::dispatch(const MonitorEvent& event)
{
    // Per-reader transient-pair coalescer.
    //
    // Card events on a given reader are buffered for
    // config.coalesceWindow before being forwarded to subscribers. If the
    // opposite kind arrives on the same reader during the hold window, the
    // buffered event and the arriving event are both dropped as a transient
    // phantom. Some PC/SC readers (notably dual-interface contactless
    // readers when a contact card is inserted) emit dozens of bogus
    // Inserted+Removed pairs in sub-second bursts; surfacing them would
    // thrash the UI and re-trigger expensive plugin probes for every flap.
    //
    // A same-kind repeat within the window refreshes the hold without
    // double-emitting. Window of zero disables coalescing entirely — used
    // by diagnostic builds that need the raw event stream. Reader-list
    // events (ReaderAdded/Removed) and Error events always pass through
    // and bypass both the rate-limit gate and the coalescer.
    const bool isCardEvent =
        (event.kind == MonitorEvent::Kind::CardInserted || event.kind == MonitorEvent::Kind::CardRemoved);
    if (!isCardEvent) {
        dispatchImmediate(event);
        return;
    }

    const auto now = std::chrono::steady_clock::now();

    // Per-reader event-flood rate-limit safety net.
    //
    // Belt-and-suspenders behind the opposite-pair coalescer above: if a
    // single reader emits more than config.maxEventsPerSecond card events
    // in a rolling 1-second trailing window, drop subsequent events for
    // config.backoffOnFlood and log a single warning. Catches the
    // pathological case where the transient pattern is not strictly
    // alternating (e.g. a flood of same-kind events the coalescer would
    // happily refresh on without ever cancelling). The gate fires BEFORE
    // any held-event manipulation so suppressed-by-flood events never
    // enter the coalescer state and never reach dispatchImmediate.
    {
        std::scoped_lock lk(coalesceMtx);
        auto& state = coalesceState[event.readerName];

        // Evict timestamps older than the 1-second trailing window.
        while (!state.eventWindow.empty() && (now - state.eventWindow.front()) > std::chrono::seconds(1)) {
            state.eventWindow.pop_front();
        }

        // Inside an active backoff window: drop the event.
        if (state.backoffUntil > now) {
            return;
        }

        // Window count just crossed the ceiling: enter backoff, log
        // once, drop this event.
        if (state.eventWindow.size() >= config.maxEventsPerSecond) {
            state.backoffUntil = now + config.backoffOnFlood;
            if (!state.floodLogged) {
                // LM core is Qt-free per workspace conventions, so emit
                // to std::clog with a category prefix instead of
                // qCWarning. The category mirrors the LC-side
                // lcProbeQuieting Qt logging category so a downstream
                // grep across both layers stays consistent.
                std::clog << "[librescrs.monitor] reader event flood: " << event.readerName
                          << " (>= " << config.maxEventsPerSecond << "/s) backing off " << config.backoffOnFlood.count()
                          << "ms\n";
                state.floodLogged = true;
            }
            return;
        }

        // Healthy event: record its timestamp in the rolling window and
        // clear the one-shot flood-log latch so a future flood logs
        // again rather than silently re-tripping.
        state.eventWindow.push_back(now);
        state.floodLogged = false;
    }

    // Coalescer disabled — forward immediately. The rate-limit gate
    // above has already accepted this event into the 1s window.
    if (config.coalesceWindow.count() <= 0) {
        dispatchImmediate(event);
        return;
    }

    bool wakeFlusher = false;
    {
        std::scoped_lock lk(coalesceMtx);
        auto& state = coalesceState[event.readerName];
        if (state.heldEvent.has_value()) {
            const bool opposite = (state.heldEvent->kind == MonitorEvent::Kind::CardInserted &&
                                   event.kind == MonitorEvent::Kind::CardRemoved) ||
                                  (state.heldEvent->kind == MonitorEvent::Kind::CardRemoved &&
                                   event.kind == MonitorEvent::Kind::CardInserted);
            if (opposite) {
                // Cancel the held event; drop the arriving one too. The
                // pair is treated as a transient phantom — neither reaches
                // subscribers.
                state.heldEvent.reset();
                state.lastEventAt = now;
                return;
            }
            // Same-kind repeat — refresh the hold window so a follow-up
            // opposite can still cancel within the original timeline.
            state.heldEvent = event;
            state.heldUntil = now + config.coalesceWindow;
            state.lastEventAt = now;
            wakeFlusher = true;
        } else {
            state.heldEvent = event;
            state.heldUntil = now + config.coalesceWindow;
            state.lastEventAt = now;
            wakeFlusher = true;
        }
    }
    if (wakeFlusher) {
        coalesceCv.notify_all();
    }
}

void MonitorService::Impl::runCoalesceFlusher()
{
    std::unique_lock<std::mutex> lk(coalesceMtx);
    while (!coalesceStop) {
        // Find the earliest pending hold deadline.
        auto nextDeadline = std::chrono::steady_clock::time_point::max();
        for (const auto& [name, state] : coalesceState) {
            (void)name;
            if (state.heldEvent.has_value() && state.heldUntil < nextDeadline) {
                nextDeadline = state.heldUntil;
            }
        }
        if (nextDeadline == std::chrono::steady_clock::time_point::max()) {
            coalesceCv.wait(lk, [this] {
                if (coalesceStop)
                    return true;
                for (const auto& [name, state] : coalesceState) {
                    (void)name;
                    if (state.heldEvent.has_value())
                        return true;
                }
                return false;
            });
            continue;
        }
        if (coalesceCv.wait_until(lk, nextDeadline, [this] { return coalesceStop; })) {
            // coalesceStop became true.
            continue;
        }
        // Deadline reached — collect and emit every event whose hold has
        // expired. Snapshot the events while holding the lock; emit after
        // releasing it so subscriber callbacks cannot deadlock against
        // dispatch re-entry.
        std::vector<MonitorEvent> toEmit;
        const auto now = std::chrono::steady_clock::now();
        for (auto& [name, state] : coalesceState) {
            (void)name;
            if (state.heldEvent.has_value() && state.heldUntil <= now) {
                toEmit.push_back(*state.heldEvent);
                state.lastEmittedKind = state.heldEvent->kind;
                state.heldEvent.reset();
            }
        }
        lk.unlock();
        for (const auto& ev : toEmit) {
            dispatchImmediate(ev);
        }
        lk.lock();
    }
}

void MonitorService::Impl::diffReadersAndDispatch(const std::vector<std::string>& readers)
{
    std::set<std::string> current(readers.begin(), readers.end());
    std::vector<std::string> added;
    std::vector<std::string> removed;
    {
        std::lock_guard<std::mutex> lock(readersMtx);
        for (const auto& r : current) {
            if (knownReaders.find(r) == knownReaders.end())
                added.push_back(r);
        }
        for (const auto& r : knownReaders) {
            if (current.find(r) == current.end())
                removed.push_back(r);
        }
        knownReaders = std::move(current);
    }
    for (const auto& r : added)
        dispatch(MonitorEvent{MonitorEvent::Kind::ReaderAdded, r, std::nullopt, std::nullopt});
    if (!removed.empty()) {
        // Evict per-reader coalescer entries for vanished readers so
        // coalesceState does not accumulate forever across long-running
        // sessions with USB reader churn (replug, Windows auto-renumbering,
        // virtual readers). ReaderRemoved is the canonical "this reader is
        // gone" signal — once the OS has dropped it from the list, any
        // still-held Card event for it is referring to a now-absent device
        // and must not surface to subscribers either.
        std::scoped_lock lk(coalesceMtx);
        for (const auto& r : removed) {
            coalesceState.erase(r);
        }
    }
    for (const auto& r : removed)
        dispatch(MonitorEvent{MonitorEvent::Kind::ReaderRemoved, r, std::nullopt, std::nullopt});

    // Fire the aggregated post-change reader-list snapshot AFTER every
    // per-reader Added/Removed event has been dispatched (see
    // @ref MonitorService::subscribeReaderList contract). When neither
    // added nor removed produced any entries the membership is unchanged
    // and we suppress the snapshot to avoid spurious fan-out on every PnP
    // probe; the explicit first-subscribe bootstrap in
    // @ref MonitorService::subscribeReaderList handles the late-join case.
    if (!added.empty() || !removed.empty()) {
        std::vector<std::string> snapshot;
        {
            std::lock_guard<std::mutex> lock(readersMtx);
            snapshot.assign(knownReaders.begin(), knownReaders.end());
        }
        dispatchReaderListSnapshot(snapshot);
    }
}

MonitorService::Config MonitorService::Config::fromEnv() noexcept
{
    Config c{};
    if (const char* v = std::getenv("LIBRESCRS_MONITOR_COALESCE_MS")) {
        try {
            const auto ms = std::stoi(v);
            if (ms >= 0) {
                c.coalesceWindow = std::chrono::milliseconds(ms);
            }
        } catch (...) {
            // Malformed value: keep default. Diagnostic env knob is
            // intentionally forgiving so a stray export never breaks the
            // service.
        }
    }
    return c;
}

MonitorService::MonitorService(Config config) : d(std::make_unique<Impl>(nullptr, config)) {}

void MonitorService::publishForTest(const MonitorEvent& ev)
{
    d->dispatch(ev);
}

void MonitorService::publishReaderListForTest(const std::vector<std::string>& readers)
{
    d->diffReadersAndDispatch(readers);
}

std::size_t MonitorService::coalesceStateSizeForTest() const noexcept
{
    try {
        std::scoped_lock lk(d->coalesceMtx);
        return d->coalesceState.size();
    } catch (...) {
        return 0;
    }
}

MonitorService::operator bool() const noexcept
{
    return d != nullptr;
}

MonitorService::~MonitorService()
{
    // Non-movable (see header): MonitorService always owns its Impl. Clear public
    // subscribers (both per-event and reader-list flavours), then explicitly
    // unsubscribe from the internal MonitorService.
    // The internal unsubscribe calls stopThread() (see
    // smartcard/src/monitor.cpp) which joins the poll thread — that join is
    // what actually blocks until the in-flight PC/SC syscall completes. The
    // subsequent Impl destruction then releases the internal MonitorService cleanly.
    std::optional<::LibreSCRS::SmartCard::Internal::Monitor::SubscriptionId> subToDrop;
    {
        std::lock_guard<std::mutex> lock(d->cbMtx);
        d->callbacks.clear();
        d->readerListCallbacks.clear();
        subToDrop = d->internalSubId;
        d->internalSubId.reset();
    }
    if (subToDrop) {
        d->internal->unsubscribe(*subToDrop);
    }
}

std::optional<std::vector<std::string>> MonitorService::listReaders() const noexcept
{
    // The internal PC/SC transport throws std::runtime_error when the
    // subsystem is unavailable (service not running, resource manager
    // unreachable). The 4.0 public ABI translates that failure into a
    // disengaged optional — an exception here would cross the LibreSCRS
    // public boundary, which is undefined behaviour for consumers loaded
    // across a mismatched C++ standard library.
    try {
        return ::LibreSCRS::SmartCard::Internal::PCSCConnection::listReaders();
    } catch (...) {
        return std::nullopt;
    }
}

MonitorService::SubscriptionId MonitorService::subscribe(EventCallback callback)
{
    // Mint a new SubscriptionId. 4.0 hardening privatised the raw-int
    // ctor; MonitorService and its nested Impl retain access (they are members of
    // the enclosing class, which has full access to its own nested
    // SubscriptionId class's privates per [class.access.nest]). External
    // callers get tokens only via this subscribe() return.
    SubscriptionId newId{d->nextId.fetch_add(1)};

    bool firstSubscriber = false;
    {
        std::lock_guard<std::mutex> lock(d->cbMtx);
        d->callbacks.emplace(newId, std::move(callback));
        // Auto-start applies to the union of per-event and reader-list
        // subscriber populations: the poll thread is required whenever
        // any subscriber (of either flavour) exists.
        firstSubscriber = (d->callbacks.size() + d->readerListCallbacks.size() == 1);
    }

    if (firstSubscriber) {
        {
            std::lock_guard<std::mutex> lock(d->readersMtx);
            d->knownReaders.clear();
        }
        auto* impl = d.get();
        auto eventCb = [impl](const ::LibreSCRS::SmartCard::Internal::MonitorEvent& e) {
            MonitorEvent pub{
                mapCardEventKind(e.type),
                e.readerName,
                std::nullopt,
                std::nullopt,
            };
            // Always populate atr on CardInserted (even when the card returns
            // an empty ATR byte sequence) — the header contract promises
            // `atr.has_value()` on CardInserted, and consumers rely on it
            // (e.g. AutoReaderService dereferences via `event.atr.value()`).
            if (pub.kind == MonitorEvent::Kind::CardInserted) {
                pub.atr = e.atr;
            }
            impl->dispatch(pub);
        };
        // Poll-thread entry: shield against std::bad_alloc from the
        // std::set construction, snapshot.assign, snapshotReaderListCallbacks
        // reserve/emplace, and added/removed vector push_back inside
        // diffReadersAndDispatch. The per-subscriber-callback bodies are
        // already shielded inside dispatchReaderListSnapshot /
        // dispatchImmediate, but an allocation failure outside those
        // bodies would escape the std::thread entry and invoke
        // std::terminate. Same rationale as the noexcept catch on
        // unsubscribe()/[thread.req.exception].
        auto readersCb = [impl](const std::vector<std::string>& readers) {
            try {
                impl->diffReadersAndDispatch(readers);
            } catch (const std::exception& e) {
                std::fprintf(stderr, "LibreSCRS MonitorService: reader-list dispatch threw: %s\n", e.what());
            } catch (...) {
                std::fprintf(stderr, "LibreSCRS MonitorService: reader-list dispatch threw unknown exception\n");
            }
        };
        auto internalId = d->internal->subscribe(std::move(eventCb), std::move(readersCb));
        std::lock_guard<std::mutex> lock(d->cbMtx);
        d->internalSubId = internalId;
    }

    return newId;
}

void MonitorService::unsubscribe(SubscriptionId id, DrainPolicy policy) noexcept
{
    try {
        std::optional<::LibreSCRS::SmartCard::Internal::Monitor::SubscriptionId> subToDrop;
        // DrainPolicy::Drain acquires dispatchMtx first: this blocks until any
        // currently-running dispatch completes (dispatch() takes dispatchMtx
        // across the full snapshot-and-invoke phase). Once we hold it, no
        // callback is running and no new snapshot can form until we release it.
        // FireAndForget skips dispatchMtx so a concurrent dispatch may still
        // fire the callback once after this returns; the header documents
        // this trade-off.
        std::unique_lock<std::mutex> dispatchLock(d->dispatchMtx, std::defer_lock);
        if (policy == DrainPolicy::Drain) {
            dispatchLock.lock();
        }
        {
            std::lock_guard<std::mutex> cbLock(d->cbMtx);
            auto it = d->callbacks.find(id);
            if (it == d->callbacks.end())
                return;
            d->callbacks.erase(it);
            // Auto-stop the internal Monitor only when BOTH the per-event
            // and reader-list subscriber populations are empty.
            if (d->callbacks.empty() && d->readerListCallbacks.empty()) {
                subToDrop = d->internalSubId;
                d->internalSubId.reset();
            }
        }
        if (subToDrop) {
            // Unsubscribe outside cbMtx; internal MonitorService may block
            // for an in-flight dispatch which itself re-enters
            // snapshotCallbacks. The Drain branch additionally holds
            // dispatchMtx for the duration so the join is race-free.
            d->internal->unsubscribe(*subToDrop);
        }
    } catch (...) {
        // noexcept contract: mutex acquisition may throw std::system_error
        // per [thread.req.exception]. Degraded-but-valid result here is "the
        // call was a no-op"; the caller will observe the subscription still
        // active on next dispatch and may retry. POSIX/Win32 mutexes do not
        // fail in practice.
    }
}

MonitorService::SubscriptionId MonitorService::subscribeReaderList(ReaderListCallback callback)
{
    SubscriptionId newId{d->nextId.fetch_add(1)};

    bool firstSubscriber = false;
    std::vector<std::string> bootstrapSnapshot;
    bool haveBootstrap = false;
    {
        std::lock_guard<std::mutex> lock(d->cbMtx);
        d->readerListCallbacks.emplace(newId, std::move(callback));
        firstSubscriber = (d->callbacks.size() + d->readerListCallbacks.size() == 1);
        // Bootstrap fire path: when joining after the internal monitor has
        // already produced an initial knownReaders snapshot, deliver the
        // current snapshot immediately so the late-joining subscriber does
        // not have to wait for the next reader-list change to observe the
        // baseline membership.
        if (!firstSubscriber) {
            std::lock_guard<std::mutex> readersLock(d->readersMtx);
            bootstrapSnapshot.assign(d->knownReaders.begin(), d->knownReaders.end());
            haveBootstrap = true;
        }
    }

    if (firstSubscriber) {
        // First subscriber (counting both per-event and reader-list
        // populations) — wire up the internal monitor identically to the
        // per-event subscribe path. The internal readersCb will fire on
        // the initial PnP probe and synthesise the bootstrap snapshot
        // through @ref Impl::diffReadersAndDispatch on its own.
        {
            std::lock_guard<std::mutex> lock(d->readersMtx);
            d->knownReaders.clear();
        }
        auto* impl = d.get();
        auto eventCb = [impl](const ::LibreSCRS::SmartCard::Internal::MonitorEvent& e) {
            MonitorEvent pub{
                mapCardEventKind(e.type),
                e.readerName,
                std::nullopt,
                std::nullopt,
            };
            if (pub.kind == MonitorEvent::Kind::CardInserted) {
                pub.atr = e.atr;
            }
            impl->dispatch(pub);
        };
        // Poll-thread entry: shield against std::bad_alloc from the
        // std::set construction, snapshot.assign, snapshotReaderListCallbacks
        // reserve/emplace, and added/removed vector push_back inside
        // diffReadersAndDispatch. The per-subscriber-callback bodies are
        // already shielded inside dispatchReaderListSnapshot /
        // dispatchImmediate, but an allocation failure outside those
        // bodies would escape the std::thread entry and invoke
        // std::terminate. Same rationale as the noexcept catch on
        // unsubscribe()/[thread.req.exception].
        auto readersCb = [impl](const std::vector<std::string>& readers) {
            try {
                impl->diffReadersAndDispatch(readers);
            } catch (const std::exception& e) {
                std::fprintf(stderr, "LibreSCRS MonitorService: reader-list dispatch threw: %s\n", e.what());
            } catch (...) {
                std::fprintf(stderr, "LibreSCRS MonitorService: reader-list dispatch threw unknown exception\n");
            }
        };
        auto internalId = d->internal->subscribe(std::move(eventCb), std::move(readersCb));
        std::lock_guard<std::mutex> lock(d->cbMtx);
        d->internalSubId = internalId;
    } else if (haveBootstrap) {
        // Deliver the current snapshot to the new subscriber only (not the
        // entire population — others have already been notified of the
        // current state via prior diffReadersAndDispatch calls). Look the
        // callback up by token to avoid racing with a concurrent
        // unsubscribeReaderList.
        ReaderListCallback toFire;
        {
            std::lock_guard<std::mutex> lock(d->cbMtx);
            if (auto it = d->readerListCallbacks.find(newId); it != d->readerListCallbacks.end()) {
                toFire = it->second;
            }
        }
        if (toFire) {
            std::lock_guard<std::mutex> dispatchLock(d->dispatchMtx);
            try {
                toFire(bootstrapSnapshot);
            } catch (const std::exception& e) {
                std::fprintf(stderr, "LibreSCRS MonitorService: reader-list subscriber callback threw: %s\n", e.what());
            } catch (...) {
                std::fprintf(stderr,
                             "LibreSCRS MonitorService: reader-list subscriber callback threw unknown exception\n");
            }
        }
    }

    return newId;
}

void MonitorService::unsubscribeReaderList(SubscriptionId id, DrainPolicy policy) noexcept
{
    try {
        std::optional<::LibreSCRS::SmartCard::Internal::Monitor::SubscriptionId> subToDrop;
        std::unique_lock<std::mutex> dispatchLock(d->dispatchMtx, std::defer_lock);
        if (policy == DrainPolicy::Drain) {
            dispatchLock.lock();
        }
        {
            std::lock_guard<std::mutex> cbLock(d->cbMtx);
            auto it = d->readerListCallbacks.find(id);
            if (it == d->readerListCallbacks.end())
                return;
            d->readerListCallbacks.erase(it);
            if (d->callbacks.empty() && d->readerListCallbacks.empty()) {
                subToDrop = d->internalSubId;
                d->internalSubId.reset();
            }
        }
        if (subToDrop) {
            d->internal->unsubscribe(*subToDrop);
        }
    } catch (...) {
        // noexcept contract: see @ref unsubscribe for the rationale.
    }
}

bool MonitorService::isRunning() const noexcept
{
    // noexcept with degraded result: std::mutex::lock is permitted to throw
    // std::system_error per [thread.req.exception]; return false in that
    // case so callers' "ready?" probes degrade safely. POSIX/Win32 mutexes
    // do not fail in practice.
    try {
        std::lock_guard<std::mutex> lock(d->cbMtx);
        return d->internalSubId.has_value();
    } catch (...) {
        return false;
    }
}

// @ref detail::MonitorFactory and the test-helper free functions
// (@ref detail::makeMonitorWithProvider, @ref detail::makeSubscriptionIdForTest)
// are defined in `lib/LibreSCRS/SmartCard/test_helpers/monitor_test_helpers.cpp`,
// compiled into the build-tree-only @ref LibreSCRS_SmartCard_TestHelpers
// archive. Production builds of @c libLibreSCRS_SmartCard never carry those
// symbols in their dynamic export set; test executables that need them
// link the archive alongside the production target.

} // namespace LibreSCRS::SmartCard
