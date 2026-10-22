// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS_internal/SmartCard/DefaultScanProvider.h>

#ifdef __APPLE__
#include <ctk_scan_provider.h>
#else
#include <pcsc_scan_provider.h>
#endif

namespace LibreSCRS::SmartCard::Internal {

std::unique_ptr<IPCSCScanProvider> makeDefaultScanProvider()
{
#ifdef __APPLE__
    // Apple PCSC.framework corrupts its in-process handle table when
    // SCardReleaseContext overlaps any other PC/SC call; on macOS this
    // library therefore reaches cards only through CryptoTokenKit.
    return std::make_unique<CtkScanProvider>();
#else
    return std::make_unique<PCSCScanProvider>();
#endif
}

} // namespace LibreSCRS::SmartCard::Internal
