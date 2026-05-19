// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#include <LibreSCRS/Plugin/AutoReaderService.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include "probe_trace.h"

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace LibreSCRS::Plugin {

namespace {

// -----------------------------------------------------------------------------
// AutoReaderWorker — TU-local worker state.
//
// This type deliberately lives in the anonymous namespace (NOT nested inside
// AutoReaderService::Impl) so that every std-library template instantiation that
// mentions it — std::thread::_State_impl<...>, std::shared_ptr counted-ptr
// nodes, etc. — carries the `(anonymous namespace)::AutoReaderWorker` token
// in its demangled symbol name instead of `::Impl`. Anonymous-namespace
// types have internal linkage (no cross-TU symbol collision) and their
// template instantiations therefore do not show up as W/V-binding vtable/
// typeinfo leaks matching the `::Impl` guard in
// ci/scripts/check-impl-visibility.sh.
//
// Why this matters: GCC does NOT propagate the `LIBRESCRS_INTERNAL`
// (hidden) attribute on AutoReaderService::Impl outward to std-template
// instantiations that take Impl as a template argument — template-
// instantiation visibility is computed from the instantiation context,
// not from the template arguments (see gcc bugzilla #36870 discussion
// and the C++ ABI rules for linkage of anonymous namespaces). Moving the
// async work to an anonymous-namespace type avoids the issue entirely.
// -----------------------------------------------------------------------------

struct AutoReaderWorker : std::enable_shared_from_this<AutoReaderWorker>
{
    // Shared ownership: the worker holds the MonitorService and the
    // CardPluginService alive for its own lifetime. The subscribe lambda
    // installed in ::AutoReaderService's ctor captures a weak_ptr<AutoReaderWorker>,
    // so the triple {worker, monitor, registry} can be torn down in any
    // order without a UAF — the lambda promotes and, if the promotion
    // fails, becomes a safe no-op. This mirrors the shared_ptr contract
    // applied to SigningService::sign and is the project-wide rule for all
    // public LibreSCRS services.
    std::shared_ptr<LibreSCRS::SmartCard::MonitorService> monitor;
    std::shared_ptr<CardPluginService> registry;
    AutoReaderService::OnCardData onData;
    AutoReaderService::OnError onError;
    LibreSCRS::SmartCard::MonitorService::SubscriptionId subscriptionId{};

    struct PendingRead
    {
        std::thread worker;
        std::shared_ptr<std::atomic<bool>> cancelled;
    };

    std::mutex pendingMtx;
    std::map<std::string, PendingRead> pendingByReader;

    // Set by ~AutoReaderService before draining; differentiates "card removed
    // mid-read" (surfaces AutoReaderError::Kind::Cancelled to the host) from
    // "host is tearing down" (silent return, no callback fire — destructor
    // requires full callback quiescence on return).
    std::atomic<bool> destroying{false};

    AutoReaderWorker(std::shared_ptr<LibreSCRS::SmartCard::MonitorService> monitor,
                     std::shared_ptr<CardPluginService> registry, AutoReaderService::OnCardData onData,
                     AutoReaderService::OnError onError)
        : monitor(std::move(monitor)), registry(std::move(registry)), onData(std::move(onData)),
          onError(std::move(onError))
    {}
};

// Free function at file scope — its type is `void(*)(shared_ptr<Worker>, ...)`,
// which does not embed AutoReaderService::Impl anywhere. The std::thread
// instantiations below parameterise on this function pointer + its argument
// types, keeping `::Impl` out of every resulting weak-symbol name.
// Helper: surface a cooperative-cancellation error to the host. Skipped when
// the worker is being torn down (destructor path) — that flow demands full
// callback quiescence on return, so a late onError fire would race with the
// host's own destruction of the captured closure state.
void emitCancelledIfObservable(const std::shared_ptr<AutoReaderWorker>& worker, const std::string& readerName)
{
    if (worker->destroying.load(std::memory_order_acquire))
        return;
    if (!worker->onError)
        return;
    AutoReaderService::AutoReaderError err;
    err.kind = AutoReaderService::AutoReaderError::Kind::Cancelled;
    err.userMessage = LibreSCRS::Auth::ErrorKeys::cancelled();
    err.diagnosticDetail = std::string{"Read cancelled before completion"};
    worker->onError(readerName, err);
}

void performCardRead(std::shared_ptr<AutoReaderWorker> worker, std::string readerName, std::vector<std::uint8_t> atr,
                     std::shared_ptr<std::atomic<bool>> cancelFlag)
{
    constexpr int maxAttempts = 2;
    constexpr auto retryDelay = std::chrono::milliseconds(300);

    // Resolve registry-empty before any session work — surface
    // RegistryEmpty distinctly from "no plugin matched this card".
    // A "broken-by-ABI" plugin set (size()>0 but loadReport flags failures)
    // also presents as not-usable, so the user gets an actionable
    // "no plugins installed / all plugins failed to load" diagnostic
    // instead of "no compatible plugin".
    if (!worker->registry->isUsable()) {
        if (worker->onError) {
            AutoReaderService::AutoReaderError err;
            err.kind = AutoReaderService::AutoReaderError::Kind::RegistryEmpty;
            err.diagnosticDetail = std::string{"CardPluginService has no usable plugins"};
            err.userMessage = LibreSCRS::Auth::ErrorKeys::registryEmpty();
            worker->onError(readerName, err);
        }
        return;
    }

    for (int attempt = 0; attempt < maxAttempts; ++attempt) {
        if (cancelFlag->load()) {
            emitCancelledIfObservable(worker, readerName);
            return;
        }

        // Open the session via the 4.0 noexcept factory. On failure, retry
        // a couple of times (transient card-insertion settling) before
        // reporting to the host.
        auto opened = LibreSCRS::SmartCard::CardSession::open(readerName);
        if (!opened.has_value()) {
            if (attempt + 1 < maxAttempts) {
                std::this_thread::sleep_for(retryDelay);
                continue;
            }
            if (worker->onError) {
                const auto& openErr = opened.error();
                AutoReaderService::AutoReaderError err;
                err.kind = AutoReaderService::AutoReaderError::Kind::ReaderDisconnected;
                // Forward the OpenError's translator-friendly userMessage if
                // the open path produced one; otherwise fall back to the
                // generic readerUnavailable key. ErrorKeys::readerUnavailable
                // matches the "could not connect to reader" UX bucket.
                err.userMessage = !openErr.userMessage.key.empty() ? openErr.userMessage
                                                                   : LibreSCRS::Auth::ErrorKeys::readerUnavailable();
                err.diagnosticDetail = openErr.diagnosticDetail
                                           ? std::string{"Card connection failed: "} + *openErr.diagnosticDetail
                                           : std::string{"Card connection failed"};
                worker->onError(readerName, err);
            }
            return;
        }

        auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
        LibreSCRS::Internal::probeTrace(std::string{"PROBE-CALL caller=AutoReaderService reader="} + readerName +
                                        " attempt=" + std::to_string(attempt));
        auto candidates = worker->registry->findAllCandidates(atr, *session);

        if (candidates.empty()) {
            if (worker->onError) {
                AutoReaderService::AutoReaderError err;
                err.kind = AutoReaderService::AutoReaderError::Kind::PluginError;
                err.userMessage = LibreSCRS::Auth::ErrorKeys::noCompatiblePlugin();
                err.diagnosticDetail = std::string{"No compatible plugin found"};
                worker->onError(readerName, err);
            }
            return;
        }

        // Note: onData/onError callbacks are invoked from this background thread.
        // Callers must ensure thread safety (e.g., use QMetaObject::invokeMethod).
        //
        // plugin->readCard now returns a ReadResult (non-throwing per 4.0 ABI v6).
        // Iterate candidates; the first Ok wins. A defensive catch-all
        // remains so a buggy plugin that still throws (e.g. loaded across a
        // mismatched stdlib) cannot abort the host.
        for (const auto& plugin : candidates) {
            if (cancelFlag->load()) {
                emitCancelledIfObservable(worker, readerName);
                return;
            }
            try {
                auto result = plugin->readCard(*session);
                if (result.status == LibreSCRS::Plugin::ReadResult::Status::Ok && result.data.has_value()) {
                    if (worker->onData)
                        worker->onData(readerName, *result.data);
                    return;
                }
                // Any other status — try next candidate.
            } catch (...) {
                // ABI-safe catch: log nothing (plugin is misbehaving) and try next.
            }
        }

        if (worker->onError) {
            AutoReaderService::AutoReaderError err;
            err.kind = AutoReaderService::AutoReaderError::Kind::CardReadFailed;
            err.userMessage = LibreSCRS::Auth::ErrorKeys::cardReadFailed();
            err.diagnosticDetail = std::string{"All plugins failed to read card"};
            worker->onError(readerName, err);
        }
        return;
    }
}

// Free function at file scope — dispatches a MonitorEvent against the
// Worker. Kept free (not a member) so its type is not Impl-dependent.
void dispatchMonitorEvent(std::shared_ptr<AutoReaderWorker> worker, const LibreSCRS::SmartCard::MonitorEvent& event)
{
    using Kind = LibreSCRS::SmartCard::MonitorEvent::Kind;

    if (event.kind == Kind::CardRemoved) {
        std::lock_guard lock(worker->pendingMtx);
        auto it = worker->pendingByReader.find(event.readerName);
        if (it != worker->pendingByReader.end()) {
            it->second.cancelled->store(true);
        }
        return;
    }

    if (event.kind != Kind::CardInserted)
        return;

    // MonitorService's contract promises `event.atr.has_value()` on
    // CardInserted, but a future MonitorService regression (or a synthetic
    // event injected by test code via the internal injection header) could
    // dispatch a CardInserted with a disengaged optional. `.value()` would
    // throw `std::bad_optional_access` from the poll-thread context, which
    // is caught by the dispatch try/catch shield in MonitorService — but
    // skipping cleanly here is preferable to surfacing a logged exception
    // for what is effectively a malformed event.
    if (!event.atr.has_value())
        return;

    auto readerName = event.readerName;
    auto atr = *event.atr;

    auto cancelFlag = std::make_shared<std::atomic<bool>>(false);

    // Spawn a worker thread on a free function. The std::thread::_State_impl
    // instantiation parameterises on `void(*)(shared_ptr<AutoReaderWorker>, ...)`
    // — `::Impl` does not appear anywhere in the resulting symbol names.
    std::thread thr(&performCardRead, worker, std::move(readerName), std::move(atr), cancelFlag);

    // Extract any previous pending read under the mutex, THEN release the mutex
    // before joining the previous worker thread. The scope of the lock_guard
    // below is deliberately narrow: only the map manipulation runs under the
    // lock, and `previous.worker.join()` happens after the lock_guard has gone
    // out of scope. A future maintainer adding pendingMtx acquisition inside
    // performCardRead would therefore not deadlock — the join can block for
    // the worker's full read cycle without holding the mutex.
    AutoReaderWorker::PendingRead previous;
    bool hadPrevious = false;
    {
        std::lock_guard lock(worker->pendingMtx);
        auto it = worker->pendingByReader.find(event.readerName);
        if (it != worker->pendingByReader.end()) {
            it->second.cancelled->store(true);
            previous = std::move(it->second);
            worker->pendingByReader.erase(it);
            hadPrevious = true;
        }
        worker->pendingByReader[event.readerName] =
            AutoReaderWorker::PendingRead{std::move(thr), std::move(cancelFlag)};
    }

    // Lock released. Detach (don't join) the previous worker.
    //
    // Joining here would block the dispatch thread for the full duration
    // of the previous read cycle.
    // On Linux SCardCancel() does not abort an in-progress SCardTransmit,
    // so cooperative cancelFlag-based cancellation can still leave the worker pinned for
    // up to ~30s waiting on the kernel-side PC/SC stack. Joining at this
    // seam serialised the whole monitor event loop behind that wait.
    //
    // AutoReaderService::~AutoReaderService uses unsubscribe with
    // DrainPolicy::Drain, which iterates pendingByReader and joins every
    // *current* worker before the host's destructor returns. Detached
    // previous workers are no longer tracked in that map (they were moved
    // out at line 238) and are intentionally NOT joined by the dtor — they
    // self-clean up after cancelFlag releases the cooperative-cancel path
    // and the kernel returns from SCardTransmit. At process exit the OS
    // reaps any still-running threads. This is the async-cleanup pattern
    // for the Linux SCardCancel limitation noted above.
    if (hadPrevious && previous.worker.joinable())
        previous.worker.detach();
}

} // namespace

// -----------------------------------------------------------------------------
// AutoReaderService::Impl — thin pimpl shell holding the anon-ns worker.
//
// Keep `LIBRESCRS_INTERNAL` and the inline-in-body body-definition pattern
// (gcc bugzilla #36870 workaround — GCC does not reliably propagate
// nested-class visibility to out-of-line member definitions). All
// non-trivial state and all async work live on
// AutoReaderWorker above, NOT on Impl — so neither Impl nor any
// std-template instantiation parameterised on Impl leaks as a W/V weak
// symbol from the static archive.
// -----------------------------------------------------------------------------
struct LIBRESCRS_INTERNAL AutoReaderService::Impl
{
    std::shared_ptr<AutoReaderWorker> worker;

    Impl(std::shared_ptr<LibreSCRS::SmartCard::MonitorService> monitor, std::shared_ptr<CardPluginService> registry,
         AutoReaderService::OnCardData onData, AutoReaderService::OnError onError)
        : worker(std::make_shared<AutoReaderWorker>(std::move(monitor), std::move(registry), std::move(onData),
                                                    std::move(onError)))
    {}
};

AutoReaderService::AutoReaderService(std::shared_ptr<LibreSCRS::SmartCard::MonitorService> monitor,
                                     std::shared_ptr<CardPluginService> registry, OnCardData onData, OnError onError)
    : d(std::make_unique<Impl>(std::move(monitor), std::move(registry), std::move(onData), std::move(onError)))
{
    // Capture a weak_ptr<AutoReaderWorker> rather than `this` or `d.get()`.
    // MonitorService::unsubscribe does not guarantee synchronization with a
    // concurrent dispatch that snapshotted the callback set before the
    // unsubscribe (see MonitorService.h); a raw capture would UAF if a late
    // dispatch fires after ~AutoReaderService has already destroyed the worker.
    // weak.lock() atomically yields either a live shared_ptr (keeping the
    // worker alive for the call) or nullptr (skip). The captured type is
    // weak_ptr<AutoReaderWorker> (anon-ns) rather than weak_ptr<Impl>, so
    // the std::function target type does not carry `::Impl` in its symbol.
    //
    // The MonitorService and CardPluginService themselves are held by shared_ptr
    // on the worker, so no separate "must outlive" contract applies — any
    // destruction order between the caller's pointers and the AutoReaderService
    // is safe.
    std::weak_ptr<AutoReaderWorker> weakWorker = d->worker;
    d->worker->subscriptionId =
        d->worker->monitor->subscribe([weakWorker](const LibreSCRS::SmartCard::MonitorEvent& e) {
            if (auto worker = weakWorker.lock()) {
                dispatchMonitorEvent(std::move(worker), e);
            }
        });
}

bool AutoReaderService::isReading(std::string_view readerName) const noexcept
{
    // pendingByReader is keyed by the reader name. A simple lookup under the
    // worker's mutex gives a point-in-time snapshot of "is there a PendingRead
    // entry for this reader" — the entry is created before performCardRead
    // is dispatched and cleared either in dispatchMonitorEvent (superseded)
    // or in the destructor (teardown). The lock-and-lookup path is
    // noexcept: std::map::find over std::string keys cannot throw.
    try {
        std::lock_guard lock(d->worker->pendingMtx);
        return d->worker->pendingByReader.find(std::string{readerName}) != d->worker->pendingByReader.end();
    } catch (...) {
        // Defensive: lock_guard can technically throw, and std::string
        // construction from string_view allocates. Return a conservative
        // "not reading" on any unexpected failure rather than letting an
        // exception escape — the accessor is noexcept.
        return false;
    }
}

AutoReaderService::~AutoReaderService()
{
    // Unsubscribe-and-drain so no new dispatches OR in-flight dispatches
    // can spawn a `performCardRead` thread after we return.
    //
    // The earlier non-draining unsubscribe() path was incorrect: while the
    // ctor's lambda captures `std::weak_ptr<AutoReaderWorker>` and is itself
    // safe under late dispatch, the lambda BODY calls
    // `dispatchMonitorEvent(worker, e)` which spawns
    //   std::thread thr(&performCardRead, worker, ...);
    // The thread's argument list keeps the worker (and therefore its
    // captured `OnCardData` / `OnError` closures) alive past
    // ~AutoReaderService — so a host that has just torn down the state its
    // closures reference can still observe a `worker->onData(...)` call.
    //
    // unsubscribe with DrainPolicy::Drain blocks until any in-flight
    // dispatch finishes running through MonitorService, closing the
    // spawn-after-dtor window. Pending reads we already started are then
    // drained below by joining their std::threads, ensuring full callback
    // quiescence on return.
    d->worker->monitor->unsubscribe(d->worker->subscriptionId,
                                    LibreSCRS::SmartCard::MonitorService::DrainPolicy::Drain);

    // Signal destruction BEFORE we set per-read cancelFlags so any pending
    // performCardRead body that observes cancellation knows to return silently
    // rather than firing the new Kind::Cancelled error path (which would
    // breach the destructor's full-callback-quiescence contract by racing
    // with the host's own teardown of the captured closure state).
    d->worker->destroying.store(true, std::memory_order_release);

    // Drain pending reads: cancel them, join their threads, then drop.
    std::map<std::string, AutoReaderWorker::PendingRead> pending;
    {
        std::lock_guard lock(d->worker->pendingMtx);
        pending = std::move(d->worker->pendingByReader);
    }
    for (auto& [name, pr] : pending) {
        pr.cancelled->store(true);
        if (pr.worker.joinable())
            pr.worker.join();
    }
}

} // namespace LibreSCRS::Plugin
