// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "libresign/types.h"
#include "libresign/trust_store_manager.h"
#include "libresign/signing_service.h"
#include <openssl/x509.h>
#include <filesystem>

namespace fs = std::filesystem;

// --- Types tests ---

TEST(LibreSignTypes, SignatureFormatEnum)
{
    EXPECT_NE(libresign::SignatureFormat::PAdES, libresign::SignatureFormat::CAdES);
}

TEST(LibreSignTypes, SignatureLevelOrdering)
{
    EXPECT_LT(static_cast<int>(libresign::SignatureLevel::B_B), static_cast<int>(libresign::SignatureLevel::B_T));
    EXPECT_LT(static_cast<int>(libresign::SignatureLevel::B_T), static_cast<int>(libresign::SignatureLevel::B_LT));
    EXPECT_LT(static_cast<int>(libresign::SignatureLevel::B_LT), static_cast<int>(libresign::SignatureLevel::B_LTA));
}

TEST(LibreSignTypes, SigningRequestDefaults)
{
    libresign::SigningRequest req;
    EXPECT_EQ(req.format, libresign::SignatureFormat::PAdES);
    EXPECT_EQ(req.level, libresign::SignatureLevel::B_T);
    EXPECT_TRUE(req.document.empty());
    EXPECT_TRUE(req.fileName.empty());
    EXPECT_FALSE(req.visual.enabled);
    EXPECT_EQ(req.visual.page, -1);
}

TEST(LibreSignTypes, SigningResultDefaults)
{
    libresign::SigningResult res;
    EXPECT_FALSE(res.success);
    EXPECT_TRUE(res.signedDocument.empty());
    EXPECT_TRUE(res.errorMessage.empty());
}

// --- TrustStoreManager tests ---

class TrustStoreManagerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Use the real bundled certificates directory
        bundledDir = std::string(LIBREMIDDLEWARE_CERT_DIR);
        ASSERT_TRUE(fs::exists(bundledDir)) << "Bundled cert dir not found: " << bundledDir;
    }

    std::string bundledDir;
};

TEST_F(TrustStoreManagerTest, ConstructWithBundledDir)
{
    libresign::TrustStoreManager mgr(bundledDir);
    EXPECT_EQ(mgr.bundledDir(), bundledDir);
}

TEST_F(TrustStoreManagerTest, CardVerificationScopeLoadsOnlyBundled)
{
    libresign::TrustStoreManager mgr(bundledDir);
    auto store = mgr.buildStore(libresign::StoreScope::CARD_VERIFICATION);
    ASSERT_NE(store, nullptr);
    // Store should have certs loaded from bundled dir
}

TEST_F(TrustStoreManagerTest, ChainDisplayScopeIncludesSystemStore)
{
    libresign::TrustStoreManager mgr(bundledDir);
    auto store = mgr.buildStore(libresign::StoreScope::CHAIN_DISPLAY);
    ASSERT_NE(store, nullptr);
}

TEST_F(TrustStoreManagerTest, EmrtdScopeReturnsNullWithoutCscaPath)
{
    libresign::TrustStoreManager mgr(bundledDir);
    auto store = mgr.buildStore(libresign::StoreScope::EMRTD_PASSIVE_AUTH);
    // No CSCA path configured — store should be null
    EXPECT_EQ(store, nullptr);
}

TEST_F(TrustStoreManagerTest, CertPathsForCardVerification)
{
    libresign::TrustStoreManager mgr(bundledDir);
    auto paths = mgr.certPathsForScope(libresign::StoreScope::CARD_VERIFICATION);
    EXPECT_FALSE(paths.empty());
    // Should return subdirectories of bundled dir that exist
    bool foundRsMup = false;
    for (const auto& p : paths) {
        EXPECT_TRUE(fs::exists(p)) << "Path does not exist: " << p;
        if (p.find("rs-mup") != std::string::npos)
            foundRsMup = true;
    }
    EXPECT_TRUE(foundRsMup) << "Expected at least one path containing 'rs-mup'";
}

TEST_F(TrustStoreManagerTest, SigningScopeIncludesUserPaths)
{
    libresign::TrustStoreManager mgr(bundledDir);
    mgr.addUserStorePath("/tmp/nonexistent-test-path");
    auto paths = mgr.certPathsForScope(libresign::StoreScope::SIGNING);
    // Should include bundled paths + user path
    bool foundUserPath = false;
    for (const auto& p : paths) {
        if (p == "/tmp/nonexistent-test-path")
            foundUserPath = true;
    }
    EXPECT_TRUE(foundUserPath);
}

TEST_F(TrustStoreManagerTest, NonexistentBundledDirProducesEmptyStore)
{
    libresign::TrustStoreManager mgr("/tmp/nonexistent-cert-dir-12345");
    auto store = mgr.buildStore(libresign::StoreScope::CARD_VERIFICATION);
    // Should return an empty store, not null (still valid, just no certs)
    ASSERT_NE(store, nullptr);
}
