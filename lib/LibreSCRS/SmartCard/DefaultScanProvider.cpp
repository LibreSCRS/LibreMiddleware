// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS_internal/SmartCard/DefaultScanProvider.h>

#include <pcsc_scan_provider.h>

namespace LibreSCRS::SmartCard::Internal {

std::unique_ptr<IPCSCScanProvider> makeDefaultScanProvider()
{
    return std::make_unique<PCSCScanProvider>();
}

} // namespace LibreSCRS::SmartCard::Internal
