// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "tl_cache.h"
#include "native_utils.h"

#include <json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

namespace libresign {

TlCache::TlCache(const std::string& cacheDir, std::chrono::hours ttl)
    : cacheDir(cacheDir), ttl(ttl)
{
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
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto ttlSeconds = std::chrono::duration_cast<std::chrono::seconds>(ttl).count();
    if (ttlSeconds == 0 || now - timestamp > ttlSeconds)
        return std::nullopt;

    // Read XML data
    std::ifstream xmlFile(xmlPath, std::ios::binary);
    if (!xmlFile)
        return std::nullopt;

    CacheEntry entry;
    entry.data = std::vector<uint8_t>(std::istreambuf_iterator<char>(xmlFile),
                                      std::istreambuf_iterator<char>());
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

    // Update timestamp
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    meta["timestamp"] = now;

    std::ofstream metaFile(metaPath);
    if (!metaFile)
        return false;
    metaFile << meta.dump(2);
    return true;
}

void TlCache::store(const std::string& url, std::span<const uint8_t> data,
                    const std::string& etag, const std::string& lastModified)
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
    xmlFile.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    xmlFile.close();

    // Write meta JSON
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

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
