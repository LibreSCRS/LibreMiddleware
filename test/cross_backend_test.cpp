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

TEST(CrossBackendTest, BothBackendsRejectInvalidModule)
{
    SigningRequest req;
    req.document = {'T', 'e', 's', 't'};
    req.fileName = "test.txt";
    req.format = SignatureFormat::Cades;
    req.level = SignatureLevel::B_B;

    auto native = createSigningService(Backend::Native);
    ASSERT_NE(native, nullptr);
    auto nativeResult = native->sign(req, "/nonexistent/pkcs11.so", libresign::as_pin("0000"), "key", "");
    EXPECT_FALSE(nativeResult.success);
    EXPECT_FALSE(nativeResult.errorMessage.empty());

    auto dss = createSigningService(Backend::DSS);
    ASSERT_NE(dss, nullptr);
    SigningResult dssResult;
    try {
        dssResult = dss->sign(req, "/nonexistent/pkcs11.so", libresign::as_pin("0000"), "key", "");
    } catch (const std::runtime_error& e) {
        // The DSS path resolver throws when the service JAR isn't built.
        // The test's intent is graceful-rejection of bogus inputs, not JAR
        // availability — skip rather than fail. Build with
        // `mvn -f tools/dss-service package` to exercise this path.
        if (std::string_view(e.what()).find("JAR not found") != std::string_view::npos) {
            GTEST_SKIP() << "DSS service JAR not built — run 'mvn -f tools/dss-service package'";
        }
        throw;
    }
    EXPECT_FALSE(dssResult.success);
    EXPECT_FALSE(dssResult.errorMessage.empty());
}

#else

TEST(CrossBackendTest, DISABLED_RequiresBothBackends)
{
    GTEST_SKIP() << "Requires SIGNING_BACKEND=both";
}

#endif
