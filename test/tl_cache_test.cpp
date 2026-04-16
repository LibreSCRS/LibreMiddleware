// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

// Include internal header directly (test has PRIVATE include path)
#include "tl_cache.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

using namespace libresign;
namespace fs = std::filesystem;

namespace {

const std::string kTestUrl = "https://example.com/test-tl.xml";
const std::string kTestUrl2 = "https://example.com/other-tl.xml";
const std::vector<uint8_t> kTestData = {'<', 'x', 'm', 'l', '/', '>'};
const std::string kTestEtag = "\"abc123\"";
const std::string kTestLastModified = "Wed, 01 Jan 2025 00:00:00 GMT";

class TlCacheTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        cacheDir = fs::temp_directory_path() / "libresign_tl_cache_test";
        fs::remove_all(cacheDir);
    }

    void TearDown() override
    {
        std::error_code ec;
        fs::remove_all(cacheDir, ec);
    }

    fs::path cacheDir;
};

TEST_F(TlCacheTest, StoreAndLoad)
{
    TlCache cache(cacheDir.string());

    cache.store(kTestUrl, kTestData, kTestEtag, kTestLastModified);

    auto loaded = cache.load(kTestUrl);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->data, kTestData);
    EXPECT_EQ(loaded->etag, kTestEtag);
    EXPECT_EQ(loaded->lastModified, kTestLastModified);
}

TEST_F(TlCacheTest, LoadMissReturnsNullopt)
{
    TlCache cache(cacheDir.string());
    auto loaded = cache.load(kTestUrl);
    EXPECT_FALSE(loaded.has_value());
}

TEST_F(TlCacheTest, DifferentUrlsAreSeparate)
{
    TlCache cache(cacheDir.string());

    const std::vector<uint8_t> data2 = {'a', 'b', 'c'};

    cache.store(kTestUrl, kTestData, kTestEtag, kTestLastModified);
    cache.store(kTestUrl2, data2, "\"other\"", "Thu, 02 Jan 2025 00:00:00 GMT");

    auto loaded1 = cache.load(kTestUrl);
    auto loaded2 = cache.load(kTestUrl2);

    ASSERT_TRUE(loaded1.has_value());
    ASSERT_TRUE(loaded2.has_value());
    EXPECT_EQ(loaded1->data, kTestData);
    EXPECT_EQ(loaded2->data, data2);
    EXPECT_EQ(loaded1->etag, kTestEtag);
    EXPECT_EQ(loaded2->etag, "\"other\"");
}

TEST_F(TlCacheTest, ExpiredEntryReturnsNullopt)
{
    // Use zero TTL — entries are always considered expired
    TlCache cache(cacheDir.string(), std::chrono::hours(0));

    cache.store(kTestUrl, kTestData, kTestEtag, kTestLastModified);

    // With a 0-hour TTL, any positive age should expire immediately
    // The timestamp is stored as seconds since epoch, and the check is now - timestamp > ttlSeconds
    // With ttl=0, ttlSeconds=0, so any stored entry with timestamp <= now is expired.
    // We need a tiny sleep to ensure time has advanced past the stored timestamp.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto loaded = cache.load(kTestUrl);
    EXPECT_FALSE(loaded.has_value());
}

TEST_F(TlCacheTest, OverwriteExistingEntry)
{
    TlCache cache(cacheDir.string());

    cache.store(kTestUrl, kTestData, kTestEtag, kTestLastModified);

    const std::vector<uint8_t> newData = {'n', 'e', 'w'};
    cache.store(kTestUrl, newData, "\"new-etag\"", "Fri, 03 Jan 2025 00:00:00 GMT");

    auto loaded = cache.load(kTestUrl);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->data, newData);
    EXPECT_EQ(loaded->etag, "\"new-etag\"");
}

TEST_F(TlCacheTest, EmptyDataNotStored)
{
    TlCache cache(cacheDir.string());

    std::vector<uint8_t> empty;
    cache.store(kTestUrl, empty, kTestEtag, kTestLastModified);

    auto loaded = cache.load(kTestUrl);
    EXPECT_FALSE(loaded.has_value());
}

TEST_F(TlCacheTest, CreatesDirectoryIfNeeded)
{
    auto nestedDir = cacheDir / "nested" / "deep";
    ASSERT_FALSE(fs::exists(nestedDir));

    TlCache cache(nestedDir.string());
    cache.store(kTestUrl, kTestData, kTestEtag, kTestLastModified);

    EXPECT_TRUE(fs::exists(nestedDir));
    auto loaded = cache.load(kTestUrl);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->data, kTestData);
}

TEST_F(TlCacheTest, LoadMetaReturnsEtagAndLastModified)
{
    TlCache cache(cacheDir.string());
    cache.store(kTestUrl, kTestData, kTestEtag, kTestLastModified);

    auto meta = cache.loadMeta(kTestUrl);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->etag, kTestEtag);
    EXPECT_EQ(meta->lastModified, kTestLastModified);
}

TEST_F(TlCacheTest, LoadMetaOnMissingReturnsNullopt)
{
    TlCache cache(cacheDir.string());
    auto meta = cache.loadMeta(kTestUrl);
    EXPECT_FALSE(meta.has_value());
}

TEST_F(TlCacheTest, LoadMetaIgnoresTtl)
{
    // Even with 0-hour TTL, loadMeta should still return metadata
    TlCache cache(cacheDir.string(), std::chrono::hours(0));
    cache.store(kTestUrl, kTestData, kTestEtag, kTestLastModified);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // load() should fail (expired)
    EXPECT_FALSE(cache.load(kTestUrl).has_value());

    // loadMeta() should succeed (ignores TTL)
    auto meta = cache.loadMeta(kTestUrl);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->etag, kTestEtag);
}

TEST_F(TlCacheTest, RefreshTimestampRevalidatesEntry)
{
    // Use a 1-second TTL so we can test expiry + refresh
    TlCache cache(cacheDir.string(), std::chrono::hours(0));
    cache.store(kTestUrl, kTestData, kTestEtag, kTestLastModified);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Entry is expired
    EXPECT_FALSE(cache.load(kTestUrl).has_value());

    // Create a new cache with generous TTL and refresh
    TlCache cache2(cacheDir.string(), std::chrono::hours(24));
    EXPECT_TRUE(cache2.refreshTimestamp(kTestUrl));

    // Now load should succeed with the new cache's TTL
    auto loaded = cache2.load(kTestUrl);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->data, kTestData);
}

TEST_F(TlCacheTest, RefreshTimestampReturnsFalseForMissing)
{
    TlCache cache(cacheDir.string());
    EXPECT_FALSE(cache.refreshTimestamp(kTestUrl));
}

} // namespace

#else // !LIBRESIGN_HAS_NATIVE

TEST(TlCacheTest, SkippedNoNativeBackend)
{
    GTEST_SKIP() << "Native signing backend not enabled";
}

#endif // LIBRESIGN_HAS_NATIVE
