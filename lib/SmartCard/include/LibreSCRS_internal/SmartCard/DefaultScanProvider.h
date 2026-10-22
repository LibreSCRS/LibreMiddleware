// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/DefaultScanProvider.h is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Export.h>

#include <ipcsc_scan_provider.h>

#include <memory>

namespace LibreSCRS::SmartCard::Internal {

/// The reader-event source a MonitorService uses when it is given none:
/// PC/SC everywhere but macOS, where readers are followed through
/// CryptoTokenKit. Chosen when the library is built.
[[nodiscard]] LIBRESCRS_INTERNAL std::unique_ptr<IPCSCScanProvider> makeDefaultScanProvider();

} // namespace LibreSCRS::SmartCard::Internal
