// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStoreService.h>

#include <gtest/gtest.h>

#include <filesystem>

namespace tt = LibreSCRS::Trust;

TEST(TrustStoreServiceCreate, ValidConfigReturnsExpected)
{
    tt::TrustConfig cfg;
    cfg.includeSystemTrustStore = false;
    auto result = tt::TrustStoreService::create(std::move(cfg));
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(*result, nullptr);
}

TEST(TrustStoreServiceCreate, NonexistentCacheDirectoryRejected)
{
    tt::TrustConfig cfg;
    cfg.cacheDirectory = std::filesystem::path{"/this/path/definitely/does/not/exist/xy12"};
    auto result = tt::TrustStoreService::create(std::move(cfg));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, tt::TrustStoreService::CreateError::Kind::InvalidConfig);
    EXPECT_EQ(result.error().userMessage.key, "librescrs.error.trust.configInvalid");
    EXPECT_TRUE(result.error().diagnosticDetail.has_value());
}

TEST(CreateErrorBuilderTest, TrustConfigInvalidCarriesCanonicalKey)
{
    auto lt = LibreSCRS::Auth::ErrorKeys::trustConfigInvalid();
    EXPECT_EQ(lt.key, "librescrs.error.trust.configInvalid");
    EXPECT_FALSE(lt.defaultText.empty());
}

TEST(CreateErrorBuilderTest, TrustAllocationFailedCarriesCanonicalKey)
{
    auto lt = LibreSCRS::Auth::ErrorKeys::trustAllocationFailed();
    EXPECT_EQ(lt.key, "librescrs.error.trust.allocationFailed");
    EXPECT_FALSE(lt.defaultText.empty());
}
