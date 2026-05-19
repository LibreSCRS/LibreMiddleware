// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS_internal/SmartCard/MonitorServiceImpl.h>

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

// @ref MonitorService::Impl is defined in
// `lib/SmartCard/include/LibreSCRS_internal/SmartCard/MonitorServiceImpl.h`
// so the production translation unit and the test-helper translation unit
// (built as a separate archive, @ref LibreSCRS_SmartCard_TestHelpers) share
// the same layout. The dispatch / snapshot / reader-diff method bodies
// remain in the production translation unit; they are not test-only.

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

// Each subscriber callback runs inside a try/catch shield. A subscriber
// that throws will not propagate out of the poll thread — that would
// otherwise terminate the program (an exception escaping the std::thread
// entry point invokes std::terminate). Error tokens are written to stderr
// as a defense-in-depth fallback because the SDK does not currently inject
// a logger across the public ABI boundary; the contract is documented on
// `MonitorService`'s @par Thread-safety section in the header.
void MonitorService::Impl::dispatch(const MonitorEvent& event)
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
    for (const auto& r : removed)
        dispatch(MonitorEvent{MonitorEvent::Kind::ReaderRemoved, r, std::nullopt, std::nullopt});
}

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

// @ref detail::MonitorFactory and the test-helper free functions
// (@ref detail::makeMonitorWithProvider, @ref detail::makeSubscriptionIdForTest)
// are defined in `lib/LibreSCRS/SmartCard/test_helpers/monitor_test_helpers.cpp`,
// compiled into the build-tree-only @ref LibreSCRS_SmartCard_TestHelpers
// archive. Production builds of @c libLibreSCRS_SmartCard never carry those
// symbols in their dynamic export set; test executables that need them
// link the archive alongside the production target.

} // namespace LibreSCRS::SmartCard
