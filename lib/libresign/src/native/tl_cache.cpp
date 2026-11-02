// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "tl_cache.h"
#include "native_utils.h"

#include <algorithm>
#include <json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

namespace libresign {

TlCache::TlCache(const std::string& cacheDir, std::chrono::hours ttl) : cacheDir(cacheDir), ttl(ttl)
{
    sweep();
}

void TlCache::sweep() noexcept
{
    if (cacheDir.empty())
        return;
    // The directory holds only what store() writes: <sha256 of the URL>.xml
    // and .meta. Anything else (an earlier naming scheme, a stray file) is
    // never read again, and an entry untouched for many lifetimes belongs to
    // a list nobody configures any more; both would otherwise stay forever.
    const auto isOurs = [](const fs::path& name) {
        const auto stem = name.stem().string();
        const auto ext = name.extension().string();
        if (ext != ".xml" && ext != ".meta")
            return false;
        if (stem.size() != 64)
            return false;
        return std::all_of(stem.begin(), stem.end(),
                           [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
    };
    const auto maxAge = std::chrono::duration_cast<fs::file_time_type::duration>(ttl * kSweepTtlMultiple);
    const auto now = fs::file_time_type::clock::now();
    std::error_code ec;
    for (fs::directory_iterator it(cacheDir, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code entryEc;
        if (!it->is_regular_file(entryEc) || entryEc)
            continue;
        const auto name = it->path().filename();
        bool stale = !isOurs(name);
        if (!stale && ttl.count() > 0) {
            const auto written = it->last_write_time(entryEc);
            stale = !entryEc && now - written > maxAge;
        }
        if (stale)
            fs::remove(it->path(), entryEc);
    }
}

std::string TlCache::urlToFilename(const std::string& url) const
{
    auto hash = native_utils::sha256(url);
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (auto byte : hash)
        hex << std::setw(2) << static_cast<unsigned>(byte);
    return hex.str();
}

std::optional<TlCache::CacheEntry> TlCache::load(const std::string& url) const
{
    auto stem = urlToFilename(url);
    auto xmlPath = fs::path(cacheDir) / (stem + ".xml");
    auto metaPath = fs::path(cacheDir) / (stem + ".meta");

    if (!fs::exists(xmlPath) || !fs::exists(metaPath))
        return std::nullopt;

    // Read meta JSON
    std::ifstream metaFile(metaPath);
    if (!metaFile)
        return std::nullopt;

    nlohmann::json meta;
    try {
        metaFile >> meta;
    } catch (const nlohmann::json::exception&) {
        return std::nullopt;
    }

    // Check TTL
    auto timestamp = meta.value("timestamp", int64_t{0});
    auto now =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto ttlSeconds = std::chrono::duration_cast<std::chrono::seconds>(ttl).count();
    if (ttlSeconds == 0 || now - timestamp > ttlSeconds)
        return std::nullopt;

    // Read XML data
    std::ifstream xmlFile(xmlPath, std::ios::binary);
    if (!xmlFile)
        return std::nullopt;

    CacheEntry entry;
    entry.data = std::vector<uint8_t>(std::istreambuf_iterator<char>(xmlFile), std::istreambuf_iterator<char>());
    entry.etag = meta.value("etag", std::string{});
    entry.lastModified = meta.value("lastModified", std::string{});

    if (entry.data.empty())
        return std::nullopt;

    return entry;
}

std::optional<TlCache::CacheMeta> TlCache::loadMeta(const std::string& url) const
{
    auto stem = urlToFilename(url);
    auto metaPath = fs::path(cacheDir) / (stem + ".meta");

    if (!fs::exists(metaPath))
        return std::nullopt;

    std::ifstream metaFile(metaPath);
    if (!metaFile)
        return std::nullopt;

    nlohmann::json meta;
    try {
        metaFile >> meta;
    } catch (const nlohmann::json::exception&) {
        return std::nullopt;
    }

    CacheMeta result;
    result.etag = meta.value("etag", std::string{});
    result.lastModified = meta.value("lastModified", std::string{});
    return result;
}

bool TlCache::refreshTimestamp(const std::string& url)
{
    return writeTimestamp(
        url,
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

bool TlCache::expire(const std::string& url)
{
    return writeTimestamp(url, 0);
}

bool TlCache::writeTimestamp(const std::string& url, std::int64_t timestamp)
{
    auto stem = urlToFilename(url);
    auto metaPath = fs::path(cacheDir) / (stem + ".meta");
    auto xmlPath = fs::path(cacheDir) / (stem + ".xml");

    if (!fs::exists(metaPath) || !fs::exists(xmlPath))
        return false;

    // Read existing meta
    nlohmann::json meta;
    {
        std::ifstream metaFile(metaPath);
        if (!metaFile)
            return false;
        try {
            metaFile >> meta;
        } catch (const nlohmann::json::exception&) {
            return false;
        }
    }

    meta["timestamp"] = timestamp;

    std::ofstream metaFile(metaPath);
    if (!metaFile)
        return false;
    metaFile << meta.dump(2);
    return true;
}

void TlCache::store(const std::string& url, std::span<const uint8_t> data, const std::string& etag,
                    const std::string& lastModified)
{
    if (data.empty())
        return;

    // Ensure cache directory exists
    std::error_code ec;
    fs::create_directories(cacheDir, ec);
    if (ec)
        return;

    auto stem = urlToFilename(url);
    auto xmlPath = fs::path(cacheDir) / (stem + ".xml");
    auto metaPath = fs::path(cacheDir) / (stem + ".meta");

    // Write XML data
    std::ofstream xmlFile(xmlPath, std::ios::binary);
    if (!xmlFile)
        return;
    xmlFile.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    xmlFile.close();

    // Write meta JSON
    auto now =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    nlohmann::json meta;
    meta["etag"] = etag;
    meta["lastModified"] = lastModified;
    meta["timestamp"] = now;

    std::ofstream metaFile(metaPath);
    if (!metaFile)
        return;
    metaFile << meta.dump(2);
}

} // namespace libresign
