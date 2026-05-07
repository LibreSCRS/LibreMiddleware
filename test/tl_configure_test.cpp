// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The pre-4.0 TrustStoreManager-driven configure() flow was retired in
// favour of TrustStoreService. The Serbian-TL eager-fetch coverage now
// lives in TrustStoreServiceTests::LiveSerbianTlEagerFetch (also network-
// gated by LIBRESIGN_NETWORK_TESTS=1). This file keeps a stub test only
// so the CTest target stays defined.

#include <gtest/gtest.h>

TEST(TlConfigureTest, MovedToTrustStoreServiceTests)
{
    GTEST_SKIP() << "Coverage migrated to TrustStoreServiceTests.LiveSerbianTlEagerFetch";
}
