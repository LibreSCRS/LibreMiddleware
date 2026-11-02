// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

// Include internal header directly (test has PRIVATE include path)
#include "tl_cache.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <unistd.h>
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
        // Per-test unique cacheDir — bare PID would collide if gtest runs
        // multiple TEST_Fs in the same process (different ctest -j4 worker
        // re-invokes happen as separate processes, but defence-in-depth here
        // is cheap). The test name is captured from gtest's TestInfo.
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string name = info != nullptr ? info->name() : "anon";
        cacheDir = fs::temp_directory_path() / ("libresign_tl_cache_test_" + std::to_string(::getpid()) + "_" + name);
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

// An expired entry is no longer served, but keeps its validators for the
// conditional request that replaces it.
TEST_F(TlCacheTest, ExpireEndsTheLifetimeAndKeepsTheValidators)
{
    TlCache cache(cacheDir.string());
    cache.store(kTestUrl, kTestData, kTestEtag, kTestLastModified);
    ASSERT_TRUE(cache.load(kTestUrl).has_value());

    EXPECT_TRUE(cache.expire(kTestUrl));

    EXPECT_FALSE(cache.load(kTestUrl).has_value());
    const auto meta = cache.loadMeta(kTestUrl);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->etag, kTestEtag);
    EXPECT_EQ(meta->lastModified, kTestLastModified);
    EXPECT_FALSE(cache.expire("https://example.invalid/none.xml"));
}

} // namespace

// The directory holds only what the cache writes. A file under any other
// name (an earlier naming scheme, a stray file) is never read again, and an
// entry untouched for many lifetimes belongs to a list nobody configures;
// both are removed when a cache is opened on the directory.
TEST_F(TlCacheTest, OpeningTheCacheSweepsForeignAndStaleFiles)
{
    {
        TlCache cache(cacheDir.string());
        std::vector<uint8_t> xml = {'<', 'x', '/', '>'};
        cache.store("https://example.com/fresh.xml", xml, "", "");
        cache.store("https://example.com/old.xml", xml, "", "");
    }
    const auto foreign = cacheDir / "https___example_com_tl_xml";
    std::ofstream(foreign) << "<stale/>";
    // Age the second entry well past thirty lifetimes.
    const auto old = std::filesystem::file_time_type::clock::now() - std::chrono::hours(24 * 60);
    std::size_t ours = 0;
    for (const auto& entry : std::filesystem::directory_iterator(cacheDir)) {
        if (entry.path() == foreign)
            continue;
        ++ours;
    }
    ASSERT_EQ(ours, 4U);

    TlCache probe(cacheDir.string());
    std::filesystem::path oldXml;
    for (const auto& entry : std::filesystem::directory_iterator(cacheDir)) {
        if (entry.path().extension() == ".xml") {
            std::ifstream in(entry.path());
            oldXml = entry.path();
            break;
        }
    }
    ASSERT_FALSE(oldXml.empty());
    auto oldMeta = oldXml;
    oldMeta.replace_extension(".meta");
    std::filesystem::last_write_time(oldXml, old);
    std::filesystem::last_write_time(oldMeta, old);

    TlCache reopened(cacheDir.string());

    EXPECT_FALSE(std::filesystem::exists(foreign)) << "a file under another name is swept";
    EXPECT_FALSE(std::filesystem::exists(oldXml)) << "an entry thirty lifetimes old is swept";
    EXPECT_FALSE(std::filesystem::exists(oldMeta));
    std::size_t left = 0;
    for ([[maybe_unused]] const auto& entry : std::filesystem::directory_iterator(cacheDir))
        ++left;
    EXPECT_EQ(left, 2U) << "the fresh entry stays";
}
