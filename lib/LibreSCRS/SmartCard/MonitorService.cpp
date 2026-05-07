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

// Internal smartcard::MonitorEvent has only Card{Inserted,Removed} types.
// Reader-list changes arrive via a separate ReaderListCallback — they are
// diffed against the previous snapshot to synthesise Reader{Added,Removed}
// public events. MonitorEvent::Kind::Error is reserved for future use (no
// internal event maps onto it today).
MonitorEvent::Kind mapCardEventKind(::smartcard::MonitorEvent::Type t)
{
    switch (t) {
    case ::smartcard::MonitorEvent::Type::CardInserted:
        return MonitorEvent::Kind::CardInserted;
    case ::smartcard::MonitorEvent::Type::CardRemoved:
        return MonitorEvent::Kind::CardRemoved;
    }
    return MonitorEvent::Kind::Error;
}

} // namespace

struct LIBRESCRS_INTERNAL MonitorService::Impl
{
    std::unique_ptr<::smartcard::Monitor> internal;

    std::mutex cbMtx;
    std::map<SubscriptionId, EventCallback> callbacks;
    std::optional<::smartcard::Monitor::SubscriptionId> internalSubId;
    std::atomic<std::uint64_t> nextId{1};

    std::mutex readersMtx;
    std::set<std::string> knownReaders;

    // Held for the full snapshot-and-invoke phase of @ref dispatch so that
    // @ref MonitorService::unsubscribeAndDrain can block until any currently-running
    // dispatch completes. Separate from cbMtx because subscribers must be
    // free to call subscribe/unsubscribe from inside a callback, which would
    // deadlock if dispatch held cbMtx across invocation.
    std::mutex dispatchMtx;

    explicit Impl(std::unique_ptr<::smartcard::IPCSCScanProvider> provider)
        : internal(std::make_unique<::smartcard::Monitor>(std::move(provider)))
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

    // Full snapshot-and-invoke runs under dispatchMtx so unsubscribeAndDrain
    // can block on it to guarantee no callback is currently in flight.
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
    std::optional<::smartcard::Monitor::SubscriptionId> subToDrop;
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
        return ::smartcard::PCSCConnection::listReaders();
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
        auto eventCb = [impl](const ::smartcard::MonitorEvent& e) {
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

void MonitorService::unsubscribe(SubscriptionId id)
{
    std::optional<::smartcard::Monitor::SubscriptionId> subToDrop;
    {
        std::lock_guard<std::mutex> lock(d->cbMtx);
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
        // Unsubscribe outside cbMtx; internal MonitorService may block for an
        // in-flight dispatch which itself re-enters snapshotCallbacks.
        d->internal->unsubscribe(*subToDrop);
    }
}

void MonitorService::unsubscribeAndDrain(SubscriptionId id)
{
    // Acquire dispatchMtx first: this blocks until any currently-running
    // dispatch completes (dispatch() takes dispatchMtx across the full
    // snapshot-and-invoke phase). Once we hold it, no callback is running
    // and no new snapshot can form until we release it.
    std::optional<::smartcard::Monitor::SubscriptionId> subToDrop;
    {
        std::lock_guard<std::mutex> dispatchLock(d->dispatchMtx);
        std::lock_guard<std::mutex> cbLock(d->cbMtx);
        auto it = d->callbacks.find(id);
        if (it == d->callbacks.end())
            return;
        d->callbacks.erase(it);
        if (d->callbacks.empty()) {
            subToDrop = d->internalSubId;
            d->internalSubId.reset();
        }
        // Release both locks on scope exit: subsequent dispatches will no
        // longer see this subscription in the snapshot.
    }
    if (subToDrop) {
        // Unsubscribe outside both locks; internal MonitorService's unsubscribe
        // joins the poll thread, which itself may be about to acquire
        // dispatchMtx for a final dispatch cycle.
        d->internal->unsubscribe(*subToDrop);
    }
}

bool MonitorService::isRunning() const
{
    // Not noexcept: std::mutex::lock is permitted to throw std::system_error
    // per [thread.req.exception]. Honest contract — POSIX/Win32 mutexes
    // don't fail in practice, but the abstraction allows it.
    std::lock_guard<std::mutex> lock(d->cbMtx);
    return d->internalSubId.has_value();
}

namespace detail {

class MonitorFactory
{
public:
    static std::shared_ptr<MonitorService> withProvider(std::unique_ptr<::smartcard::IPCSCScanProvider> provider)
    {
        auto mon = std::shared_ptr<MonitorService>(new MonitorService());
        // Replace the default-constructed internal MonitorService with one wired to
        // the caller's provider. No subscribers yet, so no race.
        mon->d->internal = std::make_unique<::smartcard::Monitor>(std::move(provider));
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

std::shared_ptr<MonitorService> makeMonitorWithProvider(std::unique_ptr<::smartcard::IPCSCScanProvider> provider)
{
    return MonitorFactory::withProvider(std::move(provider));
}

MonitorService::SubscriptionId makeSubscriptionIdForTest(std::uint64_t value) noexcept
{
    return MonitorFactory::makeSubscriptionId(value);
}

} // namespace detail

} // namespace LibreSCRS::SmartCard
