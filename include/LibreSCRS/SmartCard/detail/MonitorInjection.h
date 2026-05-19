// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS/SmartCard/detail/MonitorInjection.h is internal to LibreMiddleware"
#endif

#include <LibreSCRS/Export.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <memory>

namespace LibreSCRS::SmartCard::Internal {
class IPCSCScanProvider;
} // namespace LibreSCRS::SmartCard::Internal

namespace LibreSCRS::SmartCard::detail {

/// @brief Construct a @ref MonitorService backed by an injected PC/SC scan provider.
///
/// Test-only factory — external consumers never see this header because of
/// the `#error` guard above. The full @c MonitorFactory definition lives in
/// `lib/LibreSCRS/SmartCard/MonitorService.cpp`; this header forwards the two
/// entry-points test code needs.
///
/// @note Tagged @ref LIBRESCRS_INTERNAL (hidden visibility): the symbol is
///       reachable by test executables that link the LibreSCRS_SmartCard
///       static archive directly, but is not exported from any
///       production-distributed shared library. The pre-existing
///       `LIBRESCRS_INTERNAL_BUILD` `#error` guard above blocks source-level
///       inclusion from external consumers; this visibility tag closes the
///       complementary runtime `dlsym` path.
LIBRESCRS_INTERNAL std::shared_ptr<MonitorService>
    makeMonitorWithProvider(std::unique_ptr<LibreSCRS::SmartCard::Internal::IPCSCScanProvider>);

/// @brief Construct a `MonitorService::SubscriptionId` from a raw counter value.
///        Test-only; external callers obtain tokens exclusively via
///        `MonitorService::subscribe` returns (4.0 hardening privatised the raw-int
///        ctor on the public surface).
///
/// The body is `constexpr` and lives out-of-line in `MonitorService.cpp` (same TU
/// as the rest of `MonitorFactory`). Because `MonitorFactory` is declared
/// as a friend of `MonitorService::SubscriptionId` it can invoke the private ctor;
/// the wrapper function here is the test's entry point.
///
/// @note Tagged @ref LIBRESCRS_INTERNAL (hidden visibility) — see the
///       sibling note on @ref makeMonitorWithProvider for the rationale.
LIBRESCRS_INTERNAL MonitorService::SubscriptionId makeSubscriptionIdForTest(std::uint64_t value) noexcept;

} // namespace LibreSCRS::SmartCard::detail
