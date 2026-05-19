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
/// the `#error` guard above. The function body lives in the build-tree-only
/// @c LibreSCRS_SmartCard_TestHelpers archive, not in the production
/// @c libLibreSCRS_SmartCard shared library: production builds therefore
/// never carry the symbol in their dynamic export set. Test executables that
/// need this seam link the archive alongside the production target.
///
/// @note Tagged @ref LIBRESCRS_INTERNAL so the symbol carries hidden
///       visibility wherever it is defined; the `LIBRESCRS_INTERNAL_BUILD`
///       `#error` guard above is the compile-time hardening that blocks
///       external SDK consumers from seeing the declaration at all, and the
///       per-symbol version-script `local:` strip plus Darwin
///       `-unexported_symbol` glob keep the helper out of the public dylib
///       export set on the off-chance it ever leaks into a production
///       compilation unit.
LIBRESCRS_INTERNAL std::shared_ptr<MonitorService>
    makeMonitorWithProvider(std::unique_ptr<LibreSCRS::SmartCard::Internal::IPCSCScanProvider>);

/// @brief Construct a `MonitorService::SubscriptionId` from a raw counter value.
///        Test-only; external callers obtain tokens exclusively via
///        `MonitorService::subscribe` returns (4.0 hardening privatised the raw-int
///        ctor on the public surface).
///
/// The body lives in the @c LibreSCRS_SmartCard_TestHelpers archive (see
/// `lib/LibreSCRS/SmartCard/test_helpers/monitor_test_helpers.cpp`). Because
/// @c detail::MonitorFactory is declared as a friend of
/// @c MonitorService::SubscriptionId it can invoke the private ctor; the
/// wrapper function here is the test's entry point.
///
/// @note Tagged @ref LIBRESCRS_INTERNAL — see the sibling note on
///       @ref makeMonitorWithProvider for the rationale.
LIBRESCRS_INTERNAL MonitorService::SubscriptionId makeSubscriptionIdForTest(std::uint64_t value) noexcept;

} // namespace LibreSCRS::SmartCard::detail
