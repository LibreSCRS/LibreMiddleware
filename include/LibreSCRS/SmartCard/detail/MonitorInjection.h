// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS/SmartCard/detail/MonitorInjection.h is internal to LibreMiddleware"
#endif

#include <LibreSCRS/SmartCard/MonitorService.h>

#include <memory>

namespace smartcard {
class IPCSCScanProvider;
} // namespace smartcard

namespace LibreSCRS::SmartCard::detail {

/// @brief Construct a @ref MonitorService backed by an injected PC/SC scan provider.
///
/// Test-only factory — external consumers never see this header because of
/// the `#error` guard above. The full @c MonitorFactory definition lives in
/// `lib/LibreSCRS/SmartCard/MonitorService.cpp`; this header forwards the two
/// entry-points test code needs.
std::shared_ptr<MonitorService> makeMonitorWithProvider(std::unique_ptr<smartcard::IPCSCScanProvider>);

/// @brief Construct a `MonitorService::SubscriptionId` from a raw counter value.
///        Test-only; external callers obtain tokens exclusively via
///        `MonitorService::subscribe` returns (4.0 hardening privatised the raw-int
///        ctor on the public surface).
///
/// The body is `constexpr` and lives out-of-line in `MonitorService.cpp` (same TU
/// as the rest of `MonitorFactory`). Because `MonitorFactory` is declared
/// as a friend of `MonitorService::SubscriptionId` it can invoke the private ctor;
/// the wrapper function here is the test's entry point.
MonitorService::SubscriptionId makeSubscriptionIdForTest(std::uint64_t value) noexcept;

} // namespace LibreSCRS::SmartCard::detail
