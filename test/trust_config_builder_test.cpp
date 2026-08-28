// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Unit tests for @ref LibreSCRS::Trust::TrustConfig::Builder
///

#include <LibreSCRS/Trust/TrustConfig.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

using LibreSCRS::Trust::TrustConfig;

TEST(TrustConfigBuilderTest, DefaultBuildMatchesAggregateDefaults)
{
    auto cfg = std::move(TrustConfig::Builder{}).build();
    EXPECT_TRUE(cfg.trustedListSources.empty());
    EXPECT_FALSE(cfg.cacheDirectory.has_value());
    EXPECT_TRUE(cfg.includeSystemTrustStore); // aggregate default
    EXPECT_FALSE(cfg.trustedListFile.has_value());
    EXPECT_FALSE(cfg.trustedListFileSigningCert.has_value());
}

TEST(TrustConfigBuilderTest, AddTrustedListSourceAcceptsHttpsUrl)
{
    TrustConfig::Builder b;
    b.addTrustedListSource("https://example.org/tl.xml", false, true);
    auto cfg = std::move(b).build();
    ASSERT_EQ(cfg.trustedListSources.size(), 1U);
    EXPECT_EQ(cfg.trustedListSources[0].url, "https://example.org/tl.xml");
    EXPECT_FALSE(cfg.trustedListSources[0].lotl);
    EXPECT_TRUE(cfg.trustedListSources[0].eager);
}

TEST(TrustConfigBuilderTest, AddTrustedListSourceRejectsEmptyUrl)
{
    TrustConfig::Builder b;
    EXPECT_THROW(b.addTrustedListSource(""), std::invalid_argument);
}

TEST(TrustConfigBuilderTest, AddTrustedListSourceRejectsBadScheme)
{
    TrustConfig::Builder b;
    EXPECT_THROW(b.addTrustedListSource("file:///etc/passwd"), std::invalid_argument);
    EXPECT_THROW(b.addTrustedListSource("example.org/tl.xml"), std::invalid_argument);
}

TEST(TrustConfigBuilderTest, AddTrustedListSourceRejectsDuplicate)
{
    TrustConfig::Builder b;
    b.addTrustedListSource("https://example.org/tl.xml");
    EXPECT_THROW(b.addTrustedListSource("https://example.org/tl.xml"), std::invalid_argument);
}

TEST(TrustConfigBuilderTest, SetIncludeSystemTrustStoreToggles)
{
    TrustConfig::Builder bF;
    bF.setIncludeSystemTrustStore(false);
    auto cfgFalse = std::move(bF).build();
    EXPECT_FALSE(cfgFalse.includeSystemTrustStore);
    TrustConfig::Builder bT;
    bT.setIncludeSystemTrustStore(true);
    auto cfgTrue = std::move(bT).build();
    EXPECT_TRUE(cfgTrue.includeSystemTrustStore);
}

TEST(TrustConfigBuilderTest, SetCacheDirectoryAcceptsExistingParent)
{
    auto tmp = std::filesystem::temp_directory_path();
    auto cacheDir = tmp / "librescrs-trustconfig-builder-cache";
    TrustConfig::Builder b;
    b.setCacheDirectory(cacheDir);
    auto cfg = std::move(b).build();
    ASSERT_TRUE(cfg.cacheDirectory.has_value());
    EXPECT_EQ(*cfg.cacheDirectory, cacheDir);
}

TEST(TrustConfigBuilderTest, SetCacheDirectoryEmptyClears)
{
    auto tmp = std::filesystem::temp_directory_path();
    TrustConfig::Builder b;
    b.setCacheDirectory(tmp / "first");
    b.setCacheDirectory({});
    auto cfg = std::move(b).build();
    EXPECT_FALSE(cfg.cacheDirectory.has_value());
}

TEST(TrustConfigBuilderTest, SetCacheDirectoryRejectsNonExistentParent)
{
    TrustConfig::Builder b;
    EXPECT_THROW(b.setCacheDirectory("/this/path/does/not/exist/cache"), std::invalid_argument);
}

TEST(TrustConfigBuilderTest, SetTrustedListFileAcceptsExistingFile)
{
    auto tmp = std::filesystem::temp_directory_path() / "librescrs-tcb-test.xml";
    {
        std::ofstream out(tmp);
        out << "<TrustServiceStatusList/>\n";
    }
    TrustConfig::Builder b;
    b.setTrustedListFile(tmp);
    auto cfg = std::move(b).build();
    ASSERT_TRUE(cfg.trustedListFile.has_value());
    EXPECT_EQ(*cfg.trustedListFile, tmp);
    std::filesystem::remove(tmp);
}

TEST(TrustConfigBuilderTest, SetTrustedListFileRejectsMissingFile)
{
    TrustConfig::Builder b;
    EXPECT_THROW(b.setTrustedListFile("/no/such/tl.xml"), std::invalid_argument);
}

TEST(TrustConfigBuilderTest, SetTrustedListFileSigningCertAcceptsExistingFile)
{
    auto tmp = std::filesystem::temp_directory_path() / "librescrs-tcb-test-cert.pem";
    {
        std::ofstream out(tmp);
        out << "-----BEGIN CERTIFICATE-----\n";
    }
    TrustConfig::Builder b;
    b.setTrustedListFileSigningCert(tmp);
    auto cfg = std::move(b).build();
    ASSERT_TRUE(cfg.trustedListFileSigningCert.has_value());
    EXPECT_EQ(*cfg.trustedListFileSigningCert, tmp);
    std::filesystem::remove(tmp);
}

TEST(TrustConfigBuilderTest, SetTrustedListFileSigningCertRejectsMissingFile)
{
    TrustConfig::Builder b;
    EXPECT_THROW(b.setTrustedListFileSigningCert("/no/such/cert.pem"), std::invalid_argument);
}

TEST(TrustConfigBuilderTest, FluentChainProducesCompleteConfig)
{
    auto tmp = std::filesystem::temp_directory_path();
    TrustConfig::Builder b;
    b.addTrustedListSource("https://lotl.example.org/lotl.xml", true, false)
        .addTrustedListSource("https://tl.example.org/tl.xml", false, true)
        .setCacheDirectory(tmp / "trust-cache")
        .setIncludeSystemTrustStore(false);
    auto cfg = std::move(b).build();
    EXPECT_EQ(cfg.trustedListSources.size(), 2U);
    EXPECT_TRUE(cfg.cacheDirectory.has_value());
    EXPECT_FALSE(cfg.includeSystemTrustStore);
}
