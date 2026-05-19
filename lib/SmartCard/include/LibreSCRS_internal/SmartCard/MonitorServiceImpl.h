// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/MonitorServiceImpl.h is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Export.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <ipcsc_scan_provider.h>
#include <smartcard/monitor.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::SmartCard {

/// @brief Private state of @ref MonitorService. Lives in an LM-internal
///        header so that both the production translation unit and the
///        test-helper translation unit (built as a separate archive,
///        @ref LibreSCRS_SmartCard_TestHelpers) can manipulate the same
///        layout without re-exporting test-only entry points through the
///        production shared library's dynamic symbol table.
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
    std::vector<std::pair<SubscriptionId, EventCallback>> snapshotCallbacks();

    // Full snapshot-and-invoke runs under dispatchMtx so @ref
    // MonitorService::unsubscribe with @ref DrainPolicy::Drain can block on
    // it to guarantee no callback is currently in flight.
    void dispatch(const MonitorEvent& event);

    // Reader-list diff: synthesise ReaderAdded / ReaderRemoved events.
    // Shared by the subscribe-time initial snapshot path and the internal
    // ReaderListCallback path. knownReaders is updated under readersMtx.
    void diffReadersAndDispatch(const std::vector<std::string>& readers);
};

namespace detail {

/// @brief Friend-only access seam to @ref MonitorService for the
///        test-helper archive @ref LibreSCRS_SmartCard_TestHelpers.
///
/// The class is declared (and befriended by @ref MonitorService) so that
/// its static methods can construct a service with an injected scan
/// provider and synthesise a @ref MonitorService::SubscriptionId from a
/// raw counter value — both seams that the production public surface
/// deliberately closes. Method bodies live in the test-helper archive,
/// not in the production library, so the symbols never enter the
/// production shared object's dynamic export set.
class MonitorFactory
{
public:
    static std::shared_ptr<MonitorService>
    withProvider(std::unique_ptr<::LibreSCRS::SmartCard::Internal::IPCSCScanProvider> provider);

    // 4.0 hardening: raw-int ctor on SubscriptionId is private. Test code
    // that needs to probe unknown-id behaviour (e.g. unsubscribe(9999) on a
    // never-issued value) goes through this factory, which is befriended by
    // SubscriptionId. External SDK consumers never see this header
    // (MonitorServiceImpl.h is guarded by #error against LIBRESCRS_INTERNAL_BUILD).
    static constexpr MonitorService::SubscriptionId makeSubscriptionId(std::uint64_t value) noexcept
    {
        return MonitorService::SubscriptionId{value};
    }
};

} // namespace detail

} // namespace LibreSCRS::SmartCard
