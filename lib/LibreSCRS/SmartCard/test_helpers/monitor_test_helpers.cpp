// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Test-only injection seam for @ref LibreSCRS::SmartCard::MonitorService.
///
/// This translation unit is compiled into the build-tree-only
/// @ref LibreSCRS_SmartCard_TestHelpers archive — it is never installed and
/// never linked into the production @c libLibreSCRS_SmartCard shared
/// library. Production builds therefore never carry the test-only symbols
/// (@ref detail::makeMonitorWithProvider, @ref detail::makeSubscriptionIdForTest,
/// @ref detail::MonitorFactory) in their dynamic export set, which closes
/// the @c dlsym-reachable path against the documented 4.0 raw-int-ctor
/// foot-shoot mitigation on @c MonitorService::SubscriptionId.

#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/SmartCard/detail/MonitorInjection.h>
#include <LibreSCRS_internal/SmartCard/MonitorServiceImpl.h>

#include <ipcsc_scan_provider.h>
#include <monitor.h>

#include <cstdint>
#include <memory>
#include <utility>

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

MonitorService::SubscriptionId makeSubscriptionIdForTest(std::uint64_t value) noexcept
{
    return MonitorFactory::makeSubscriptionId(value);
}

} // namespace LibreSCRS::SmartCard::detail
