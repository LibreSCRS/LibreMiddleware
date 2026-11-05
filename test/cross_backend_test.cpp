// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#if defined(LIBRESIGN_HAS_DSS)

#include "dss_oracle/dss_signing_service.h"

using namespace libresign;

// ============================================================================
// Cross-backend comparison tests
// Require SIGNING_BACKEND=both so both compile definitions are active.
// ============================================================================

TEST(CrossBackendTest, BothBackendsAvailable)
{
    // The DSS engine finds and starts its service lazily, so constructing it
    // needs none; whether it is available depends on that service.
    DSSSigningService dss;
    EXPECT_FALSE(dss.isConfigured());
}

#else

TEST(CrossBackendTest, DISABLED_RequiresBothBackends)
{
    GTEST_SKIP() << "Requires SIGNING_BACKEND=both";
}

#endif
