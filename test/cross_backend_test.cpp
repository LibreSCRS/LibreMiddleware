// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#if defined(LIBRESIGN_HAS_NATIVE) && defined(LIBRESIGN_HAS_DSS)

#include "signing_service_factory.h"

using namespace libresign;

// ============================================================================
// Cross-backend comparison tests
// Require SIGNING_BACKEND=both so both compile definitions are active.
// ============================================================================

TEST(CrossBackendTest, BothBackendsAvailable)
{
    auto native = createSigningService(Backend::Native);
    ASSERT_NE(native, nullptr);
    EXPECT_TRUE(native->isAvailable());

    auto dss = createSigningService(Backend::DSS);
    ASSERT_NE(dss, nullptr);
    // DSS isAvailable() depends on DSSServiceManager — just verify factory returns non-null
}

TEST(CrossBackendTest, NativeServiceIsAvailable)
{
    auto native = createSigningService(Backend::Native);
    ASSERT_NE(native, nullptr);
    EXPECT_TRUE(native->isAvailable()) << "Native backend should always be available when compiled";
}

#else

TEST(CrossBackendTest, DISABLED_RequiresBothBackends)
{
    GTEST_SKIP() << "Requires SIGNING_BACKEND=both";
}

#endif
