// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS/SmartCard/detail/MonitorInjection.h is internal to LibreMiddleware"
#endif

#include <LibreSCRS/Export.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {
class IPCSCScanProvider;
} // namespace LibreSCRS::SmartCard::Internal

namespace LibreSCRS::SmartCard::detail {

/// @brief Event coalescing and flood handling of a @ref MonitorService.
///
/// A default-constructed value is what every @ref MonitorService runs with;
/// other values reach a service only through @ref makeMonitorWithConfig.
struct MonitorConfig
{
    /// @brief Inserted+Removed (or Removed+Inserted) pairs on the same
    ///        reader within this window are suppressed as transient
    ///        phantoms. Zero disables coalescing entirely.
    std::chrono::milliseconds coalesceWindow{250};

    /// @brief Per-reader card-event-rate ceiling. Once a single reader
    ///        produces this many card events inside a rolling 1-second
    ///        window, the reader enters a @ref backoffOnFlood cool-down
    ///        during which further card events are suppressed at the
    ///        gate (only the most recent one is remembered for
    ///        reconciliation).
    std::size_t maxEventsPerSecond{20};

    /// @brief Cool-down applied once the @ref maxEventsPerSecond flood
    ///        gate trips. Card events arriving during the cool-down are
    ///        suppressed; when it expires, the last suppressed event is
    ///        reconciled to subscribers if it changes the card-presence
    ///        belief. This duration therefore also bounds how long a
    ///        settled terminal card state can stay invisible to
    ///        subscribers after a flood.
    std::chrono::milliseconds backoffOnFlood{5000};
};

/// @brief Construct a @ref MonitorService that coalesces and throttles card
///        events as @p config says, before anything subscribes to it.
/// @note Tagged @ref LIBRESCRS_INTERNAL — see @ref makeMonitorWithProvider.
LIBRESCRS_INTERNAL std::shared_ptr<MonitorService> makeMonitorWithConfig(const MonitorConfig& config);

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
///       external SDK consumers from seeing the declaration at all. On Linux
///       the version script's per-symbol `local:` entry also strips it should
///       a definition ever reach a production compilation unit; on Darwin the
///       hidden attribute is the only guard (the export list is an allowlist
///       glob over `LibreSCRS::`, with no per-symbol exclusions).
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

/// @brief Feed @p event into @p service's dispatch as if its scan thread had
///        reported it: coalescing, flood gate and fan-out all apply.
///
/// Card and error events only (@ref MonitorEvent::Kind::CardInserted,
/// @ref MonitorEvent::Kind::CardRemoved, @ref MonitorEvent::Kind::Error) —
/// the scan thread reports nothing else; reader membership goes through
/// @ref publishReaderListForTest. The event reaches the service only once it
/// has a subscriber, because only then is it wired to its scan source.
///
/// @return @c false when the event did not reach the dispatch: an unsupported
///         kind, or a service without a subscriber.
/// @note Tagged @ref LIBRESCRS_INTERNAL — see @ref makeMonitorWithProvider.
[[nodiscard]] LIBRESCRS_INTERNAL bool publishForTest(MonitorService& service, const MonitorEvent& event);

/// @brief Feed a reader-list snapshot into @p service's membership diff
///        (synthesised @ref MonitorEvent::Kind::ReaderAdded /
///        @ref MonitorEvent::Kind::ReaderRemoved, coalescer eviction), as its
///        scan thread does.
///
/// @return @c false when @p service has no subscriber, so nothing was fed.
/// @note Tagged @ref LIBRESCRS_INTERNAL — see @ref makeMonitorWithProvider.
[[nodiscard]] LIBRESCRS_INTERNAL bool publishReaderListForTest(MonitorService& service,
                                                               const std::vector<std::string>& readers);

/// @brief Number of per-reader coalescer entries @p service holds, for
///        eviction tests.
/// @note Tagged @ref LIBRESCRS_INTERNAL — see @ref makeMonitorWithProvider.
LIBRESCRS_INTERNAL std::size_t coalesceStateSizeForTest(const MonitorService& service) noexcept;

/// @brief Whether @p service's poll thread is wired to its scan source:
///        true from the first subscribe until the last unsubscribe.
/// @note Tagged @ref LIBRESCRS_INTERNAL — see @ref makeMonitorWithProvider.
[[nodiscard]] LIBRESCRS_INTERNAL bool isPollingForTest(const MonitorService& service) noexcept;

} // namespace LibreSCRS::SmartCard::detail
