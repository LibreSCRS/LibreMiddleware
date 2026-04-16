// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace libresign {

/// Disk-backed cache for fetched Trust List XML data.
/// Each URL is stored as two files keyed by SHA-256(url):
///   <hash>.xml  -- raw XML bytes
///   <hash>.meta -- JSON with etag, lastModified, timestamp
class TlCache
{
public:
    explicit TlCache(const std::string& cacheDir, std::chrono::hours ttl = std::chrono::hours(24));

    struct CacheEntry
    {
        std::vector<uint8_t> data;
        std::string etag;
        std::string lastModified;
    };

    struct CacheMeta
    {
        std::string etag;
        std::string lastModified;
    };

    /// Load a cached entry for the given URL. Returns nullopt if not cached or expired.
    std::optional<CacheEntry> load(const std::string& url) const;

    /// Load just the etag/lastModified metadata for a URL, ignoring TTL.
    /// Returns nullopt if no cache entry exists at all.
    std::optional<CacheMeta> loadMeta(const std::string& url) const;

    /// Refresh the timestamp on a cached entry (e.g. after a 304 Not Modified).
    /// Returns false if no cached entry exists for the URL.
    bool refreshTimestamp(const std::string& url);

    /// Store XML data and HTTP conditional-request metadata for a URL.
    void store(const std::string& url, std::span<const uint8_t> data, const std::string& etag,
               const std::string& lastModified);

private:
    std::string cacheDir;
    std::chrono::hours ttl;

    /// Map a URL to a hex-encoded SHA-256 hash for use as a filename stem.
    std::string urlToFilename(const std::string& url) const;
};

} // namespace libresign
