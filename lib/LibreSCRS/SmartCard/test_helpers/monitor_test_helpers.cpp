// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Test-only injection seam for @ref LibreSCRS::SmartCard::MonitorService.
///
/// This translation unit is compiled into the build-tree-only
/// @ref LibreSCRS_SmartCard_TestHelpers archive — it is never installed and
/// never linked into the production @c libLibreSCRS_SmartCard shared
/// library. Production builds therefore never carry the test-only symbols
/// (@ref detail::makeMonitorWithProvider, @ref detail::makeMonitorWithConfig,
/// @ref detail::makeSubscriptionIdForTest,
/// @ref detail::publishForTest, @ref detail::publishReaderListForTest,
/// @ref detail::coalesceStateSizeForTest, @ref detail::isPollingForTest,
/// @ref detail::MonitorFactory) in
/// their dynamic export set, which closes
/// the @c dlsym-reachable path against the documented 4.0 raw-int-ctor
/// foot-shoot mitigation on @c MonitorService::SubscriptionId.

#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/SmartCard/detail/MonitorInjection.h>
#include <LibreSCRS_internal/SmartCard/MonitorServiceImpl.h>

#include <ipcsc_scan_provider.h>
#include <monitor.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::SmartCard::detail {

std::shared_ptr<MonitorService>
MonitorFactory::withProvider(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider)
{
    auto mon = std::shared_ptr<MonitorService>(new MonitorService());
    // Replace the default-constructed internal MonitorService with one
    // wired to the caller's provider. No subscribers yet, so no race.
    mon->d->internal = std::make_unique<::LibreSCRS::SmartCard::Internal::Monitor>(std::move(provider));
    return mon;
}

std::shared_ptr<MonitorService>
makeMonitorWithProvider(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider)
{
    return MonitorFactory::withProvider(std::move(provider));
}

std::shared_ptr<MonitorService> MonitorFactory::withConfig(const MonitorConfig& config)
{
    auto mon = std::shared_ptr<MonitorService>(new MonitorService());
    auto& impl = *mon->d;
    // Nothing has subscribed, so no thread dispatches yet; the flusher only
    // waits on coalesceCv and never reads the configuration.
    const bool stopFlusher = config.coalesceWindow.count() <= 0;
    {
        std::scoped_lock lock(impl.coalesceMtx);
        impl.config = config;
        if (stopFlusher)
            impl.coalesceStop = true;
    }
    if (stopFlusher && impl.coalesceFlusher.joinable()) {
        impl.coalesceCv.notify_all();
        impl.coalesceFlusher.join();
    }
    return mon;
}

std::shared_ptr<MonitorService> makeMonitorWithConfig(const MonitorConfig& config)
{
    return MonitorFactory::withConfig(config);
}

MonitorService::SubscriptionId makeSubscriptionIdForTest(std::uint64_t value) noexcept
{
    return MonitorFactory::makeSubscriptionId(value);
}

// The callbacks are copied out under the monitor's lock and run outside it,
// as Internal::Monitor::notifyEvent / notifyReaders do on the scan thread.
std::size_t MonitorFactory::publishEvent(MonitorService& service,
                                         const ::LibreSCRS::SmartCard::Internal::MonitorEvent& event)
{
    auto& monitor = *service.d->internal;
    std::vector<::LibreSCRS::SmartCard::Internal::MonitorCallback> callbacks;
    {
        std::lock_guard lock(monitor.subscribersMtx);
        for (const auto& [id, sub] : monitor.subscribers) {
            if (sub.onEvent) {
                callbacks.push_back(sub.onEvent);
            }
        }
    }
    for (const auto& cb : callbacks) {
        cb(event);
    }
    return callbacks.size();
}

std::size_t MonitorFactory::publishReaderList(MonitorService& service, const std::vector<std::string>& readers)
{
    auto& monitor = *service.d->internal;
    std::vector<::LibreSCRS::SmartCard::Internal::ReaderListCallback> callbacks;
    {
        std::lock_guard lock(monitor.subscribersMtx);
        for (const auto& [id, sub] : monitor.subscribers) {
            if (sub.onReaders) {
                callbacks.push_back(sub.onReaders);
            }
        }
    }
    for (const auto& cb : callbacks) {
        cb(readers);
    }
    return callbacks.size();
}

std::size_t MonitorFactory::coalesceStateSize(const MonitorService& service) noexcept
{
    try {
        std::scoped_lock lock(service.d->coalesceMtx);
        return service.d->coalesceState.size();
    } catch (...) {
        return 0;
    }
}

bool MonitorFactory::isPolling(const MonitorService& service) noexcept
{
    try {
        std::lock_guard lock(service.d->cbMtx);
        return service.d->internalSubId.has_value();
    } catch (...) {
        return false;
    }
}

bool publishForTest(MonitorService& service, const MonitorEvent& event)
{
    using Internal = ::LibreSCRS::SmartCard::Internal::MonitorEvent;
    Internal internal{};
    switch (event.kind) {
    case MonitorEvent::Kind::CardInserted:
        internal.type = Internal::Type::CardInserted;
        internal.atr = event.atr.value_or(std::vector<std::uint8_t>{});
        break;
    case MonitorEvent::Kind::CardRemoved:
        internal.type = Internal::Type::CardRemoved;
        break;
    case MonitorEvent::Kind::Error:
        internal.type = Internal::Type::Error;
        internal.detail = event.diagnosticDetail.value_or(std::string{});
        break;
    case MonitorEvent::Kind::ReaderAdded:
    case MonitorEvent::Kind::ReaderRemoved:
        return false; // the scan thread reports membership as a list
    }
    internal.readerName = event.readerName;
    return MonitorFactory::publishEvent(service, internal) > 0;
}

bool publishReaderListForTest(MonitorService& service, const std::vector<std::string>& readers)
{
    return MonitorFactory::publishReaderList(service, readers) > 0;
}

std::size_t coalesceStateSizeForTest(const MonitorService& service) noexcept
{
    return MonitorFactory::coalesceStateSize(service);
}

bool isPollingForTest(const MonitorService& service) noexcept
{
    return MonitorFactory::isPolling(service);
}

} // namespace LibreSCRS::SmartCard::detail
