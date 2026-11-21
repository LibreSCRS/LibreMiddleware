// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// In a file of its own so the service's test copy can replace it: the copy
// names the certificate of a list served on loopback, which this one never
// can (test_helpers/trust_service_test_seam.cpp).

#include "internal/TrustStoreServiceImpl.h"

namespace LibreSCRS::Trust {

libresign::TrustedListEntry TrustStoreService::Impl::entryFor(const TrustedListSource& src) const
{
    libresign::TrustedListEntry entry;
    entry.url = src.url;
    entry.isLotl = src.lotl;
    entry.eager = src.eager;
    return entry;
}

} // namespace LibreSCRS::Trust
