// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/SmartCard/detail/MonitorInjection.h>

#include <ipcsc_scan_provider.h>
#include <smartcard/monitor.h>
#include <smartcard/monitor_event.h>
#include <smartcard/pcsc_connection.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
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

    explicit Impl(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider)
        : internal(std::make_unique<::LibreSCRS::SmartCard::Internal::Monitor>(std::move(provider)))
    {}

    // Snapshot currently-registered (id, callback) pairs under the cbMtx lock.
    // Dispatch outside cbMtx so subscribers can re-enter subscribe/unsubscribe
    // from within a callback without deadlocking.
    std::vector<std::pair<SubscriptionId, EventCallback>> snapshotCallbacks()
    {
        std::lock_guard<std::mutex> lock(cbMtx);
        std::vector<std::pair<SubscriptionId, EventCallback>> out;
        out.reserve(callbacks.size());
        for (const auto& [id, cb] : callbacks) {
            out.emplace_back(id, cb);
        }
        return out;
    }

    // Full snapshot-and-invoke runs under dispatchMtx so @ref
    // MonitorService::unsubscribe with @ref DrainPolicy::Drain can block on
    // it to guarantee no callback is currently in flight.
    //
    // Each subscriber callback runs inside a try/catch shield. A
    // subscriber that throws will not propagate out of the poll thread —
    // that would otherwise terminate the program (an exception escaping
    // the std::thread entry point invokes std::terminate). Error tokens
    // are written to stderr as a defense-in-depth fallback because the
    // SDK does not currently inject a logger across the public ABI
    // boundary; the contract is documented on `MonitorService`'s @par
    // Thread-safety section in the header.
    void dispatch(const MonitorEvent& event)
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

    // Reader-list diff: synthesise ReaderAdded / ReaderRemoved events.
    // Shared by the subscribe-time initial snapshot path and the internal
    // ReaderListCallback path. knownReaders is updated under readersMtx.
    void diffReadersAndDispatch(const std::vector<std::string>& readers)
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
        for (const auto& r : removed)
            dispatch(MonitorEvent{MonitorEvent::Kind::ReaderRemoved, r, std::nullopt, std::nullopt});
    }
};

MonitorService::MonitorService() : d(std::make_unique<Impl>(nullptr)) {}

MonitorService::operator bool() const noexcept
{
    return d != nullptr;
}

MonitorService::~MonitorService()
{
    // Non-movable (see header): MonitorService always owns its Impl. Clear public
    // subscribers, then explicitly unsubscribe from the internal MonitorService.
    // The internal unsubscribe calls stopThread() (see
    // smartcard/src/monitor.cpp) which joins the poll thread — that join is
    // what actually blocks until the in-flight PC/SC syscall completes. The
    // subsequent Impl destruction then releases the internal MonitorService cleanly.
    std::optional<::LibreSCRS::SmartCard::Internal::Monitor::SubscriptionId> subToDrop;
    {
        std::lock_guard<std::mutex> lock(d->cbMtx);
        d->callbacks.clear();
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
        firstSubscriber = (d->callbacks.size() == 1);
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
        auto readersCb = [impl](const std::vector<std::string>& readers) { impl->diffReadersAndDispatch(readers); };
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
            if (d->callbacks.empty()) {
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

namespace detail {

class MonitorFactory
{
public:
    static std::shared_ptr<MonitorService>
    withProvider(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider)
    {
        auto mon = std::shared_ptr<MonitorService>(new MonitorService());
        // Replace the default-constructed internal MonitorService with one wired to
        // the caller's provider. No subscribers yet, so no race.
        mon->d->internal = std::make_unique<::LibreSCRS::SmartCard::Internal::Monitor>(std::move(provider));
        return mon;
    }

    // 4.0 hardening: raw-int ctor on SubscriptionId is private. Test code
    // that needs to probe unknown-id behaviour (e.g. unsubscribe(9999) on a
    // never-issued value) goes through this factory, which is befriended by
    // SubscriptionId. External SDK consumers never see this header
    // (MonitorInjection.h is guarded by #error against LIBRESCRS_INTERNAL_BUILD).
    static constexpr MonitorService::SubscriptionId makeSubscriptionId(std::uint64_t value) noexcept
    {
        return MonitorService::SubscriptionId{value};
    }
};

std::shared_ptr<MonitorService>
makeMonitorWithProvider(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider)
{
    return MonitorFactory::withProvider(std::move(provider));
}

MonitorService::SubscriptionId makeSubscriptionIdForTest(std::uint64_t value) noexcept
{
    return MonitorFactory::makeSubscriptionId(value);
}

} // namespace detail

} // namespace LibreSCRS::SmartCard
