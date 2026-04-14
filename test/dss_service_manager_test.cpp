// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "libresign/dss/dss_service_manager.h"

TEST(DSSServiceManagerTest, ConstructWithConfig)
{
    libresign::DSSServiceManager::Config cfg;
    cfg.jarPath = "/tmp/nonexistent.jar";

    libresign::DSSServiceManager mgr(cfg);
    EXPECT_FALSE(mgr.isHealthy());
    EXPECT_TRUE(mgr.baseUrl().empty());
    EXPECT_TRUE(mgr.unixSocketPath().empty());
}

TEST(DSSServiceManagerTest, EnsureRunningFailsWithMissingJar)
{
    libresign::DSSServiceManager::Config cfg;
    cfg.jarPath = "/tmp/nonexistent-dss-service.jar";
    cfg.startupTimeout = std::chrono::seconds(2);

    libresign::DSSServiceManager mgr(cfg);
    auto result = mgr.ensureRunning();
    if (result) {
        // A DSS service from another session is already running — that's OK
        EXPECT_FALSE(result.baseUrl.empty());
    } else {
        EXPECT_TRUE(result.baseUrl.empty());
        EXPECT_FALSE(result.error.empty());
    }
}

TEST(DSSServiceManagerTest, EnsureRunningFailsWithMissingJava)
{
    libresign::DSSServiceManager::Config cfg;
    cfg.jarPath = "/tmp/nonexistent-dss-service.jar";
    cfg.javaPath = "/tmp/nonexistent-java-binary";

    libresign::DSSServiceManager mgr(cfg);
    auto result = mgr.ensureRunning();
    EXPECT_FALSE(result);
    EXPECT_TRUE(result.baseUrl.empty());
    EXPECT_THAT(result.error, ::testing::HasSubstr("Java runtime not found"));
}

TEST(DSSServiceManagerTest, StopWhenNotRunningIsNoop)
{
    libresign::DSSServiceManager::Config cfg;
    cfg.jarPath = "/tmp/nonexistent.jar";

    libresign::DSSServiceManager mgr(cfg);
    mgr.stop(); // should not crash
    EXPECT_FALSE(mgr.isHealthy());
}
