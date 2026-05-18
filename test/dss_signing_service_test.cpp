// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "dss/dss_signing_service.h"
#include "dss/dss_service_manager.h"

class DSSSigningServiceTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        libresign::DSSServiceManager::Config cfg;
        cfg.jarPath = "/tmp/nonexistent.jar";
        cfg.startupTimeout = std::chrono::seconds(1);
        manager = std::make_unique<libresign::DSSServiceManager>(cfg);
    }

    std::unique_ptr<libresign::DSSServiceManager> manager;
};

TEST_F(DSSSigningServiceTest, IsNotAvailableWhenServiceDown)
{
    libresign::DSSSigningService svc(*manager);
    EXPECT_FALSE(svc.isAvailable());
}

TEST_F(DSSSigningServiceTest, Pkcs11SignFailsWhenServiceDown)
{
    libresign::DSSSigningService svc(*manager);
    libresign::SigningRequest req;
    req.document = {0x25, 0x50, 0x44, 0x46}; // %PDF
    req.format = libresign::SignatureFormat::Pades;
    req.level = libresign::SignatureLevel::B_B;

    auto result = svc.sign(req, "/path/to/pkcs11.so", libresign::as_pin("1234"), "key1", "");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.errorMessage.empty());
}

TEST_F(DSSSigningServiceTest, FormatAndLevelStrings)
{
    // Verify the service constructs valid JSON with format/level strings
    // (tested indirectly through sign failure — the error should mention connection, not parse errors)
    libresign::DSSSigningService svc(*manager);
    libresign::SigningRequest req;
    req.document = {0x01};
    req.format = libresign::SignatureFormat::Cades;
    req.level = libresign::SignatureLevel::B_LTA;

    auto result = svc.sign(req, "/p11.so", libresign::as_pin("pin"), "key", "");
    EXPECT_FALSE(result.success);
    // Error should be about service unavailability, not JSON/format issues
    EXPECT_TRUE(result.errorMessage.find("service") != std::string::npos ||
                result.errorMessage.find("connect") != std::string::npos ||
                result.errorMessage.find("running") != std::string::npos);
}
