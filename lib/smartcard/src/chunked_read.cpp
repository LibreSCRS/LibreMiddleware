// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <smartcard/chunked_read.h>

#include "apdu.h"
#include <smartcard/i_connection.h>

#include <algorithm>
#include <stdexcept>

namespace LibreSCRS::SmartCard::Internal {

namespace {

// Default header parser driven by HeaderLengthSpec: little-endian
// content-length word at a fixed offset, optional "empty file" marker.
std::optional<HeaderParseResult> parseHeaderFromSpec(std::span<const uint8_t> header, const HeaderLengthSpec& spec)
{
    if (header.size() < spec.headerSize) {
        return std::nullopt;
    }

    // Empty-file marker yields a fully-empty result regardless of the
    // includeHeaderInResult flag (matches Apollo's legacy behavior, where
    // a 0xFF marker at offset 4 means "no file content, no header echo").
    if (spec.hasEmptyMarker && spec.emptyMarkerOffset < spec.headerSize &&
        header[spec.emptyMarkerOffset] == spec.emptyMarkerValue) {
        return std::nullopt;
    }

    if (spec.lengthBytes == 0 || spec.lengthBytes > 4) {
        throw std::runtime_error("chunked_read: invalid HeaderLengthSpec.lengthBytes");
    }
    if (static_cast<size_t>(spec.lengthOffset) + spec.lengthBytes > spec.headerSize) {
        throw std::runtime_error("chunked_read: HeaderLengthSpec length word runs past headerSize");
    }

    uint32_t contentLen = 0;
    for (uint8_t i = 0; i < spec.lengthBytes; ++i) {
        contentLen |= static_cast<uint32_t>(header[spec.lengthOffset + i]) << (8 * i);
    }

    if (spec.maxContentLength != 0 && contentLen > spec.maxContentLength) {
        throw std::runtime_error("chunked_read: declared content length exceeds maxContentLength");
    }

    return HeaderParseResult{spec.headerSize, contentLen};
}

} // namespace

std::vector<uint8_t> readChunkedFile(IConnection& conn, const ChunkedReadOptions& opts)
{
    if (opts.chunkSize == 0) {
        throw std::runtime_error(opts.errorPrefix + ": chunkSize must be non-zero");
    }

    const uint8_t headerSize = opts.headerSpec.headerSize;

    // Step 1: obtain the header (either from caller override or by READ BINARY).
    std::vector<uint8_t> headerBytes;
    if (!opts.headerOverride.empty()) {
        headerBytes = opts.headerOverride;
    } else if (headerSize > 0) {
        auto headerResp = conn.transmit(readBinary(0, headerSize));
        if (!headerResp.isSuccess() || headerResp.data.size() < headerSize) {
            throw std::runtime_error(opts.errorPrefix + ": cannot read file header");
        }
        headerBytes = std::move(headerResp.data);
    }

    // Step 2: parse the header to get data offset + body length.
    std::optional<HeaderParseResult> parsed;
    if (opts.parseHeader) {
        parsed = opts.parseHeader(headerBytes);
    } else {
        parsed = parseHeaderFromSpec(headerBytes, opts.headerSpec);
    }
    if (!parsed.has_value()) {
        return {};
    }

    const size_t dataOffset = parsed->dataOffset;
    const size_t totalToRead = parsed->totalToRead;

    // Pre-size the result. When includeHeaderInResult is set, the header
    // bytes occupy [0, dataOffset) of the returned vector.
    std::vector<uint8_t> result;
    if (opts.includeHeaderInResult) {
        const size_t prefixLen = std::min(dataOffset, headerBytes.size());
        result.reserve(prefixLen + totalToRead);
        result.insert(result.end(), headerBytes.begin(), headerBytes.begin() + static_cast<std::ptrdiff_t>(prefixLen));
        if (totalToRead == 0) {
            return result;
        }
    } else {
        result.reserve(totalToRead);
        if (totalToRead == 0) {
            return result;
        }
    }

    // Step 3: chunked READ BINARY loop.
    uint8_t currentChunkSize = opts.chunkSize;
    uint8_t fallback = opts.fallbackChunkSize;
    size_t bodyRead = 0;
    uint32_t offset = static_cast<uint32_t>(dataOffset);

    while (bodyRead < totalToRead) {
        const size_t remaining = totalToRead - bodyRead;
        const uint8_t thisChunk = static_cast<uint8_t>(std::min(static_cast<size_t>(currentChunkSize), remaining));

        APDUResponse readResp = opts.readChunk ? opts.readChunk(static_cast<uint16_t>(offset), thisChunk)
                                               : conn.transmit(readBinary(static_cast<uint16_t>(offset), thisChunk));

        if (!readResp.isSuccess()) {
            if (fallback != 0 && currentChunkSize != fallback) {
                currentChunkSize = fallback;
                fallback = 0;
                continue;
            }
            if (opts.fallbackChunkSize != 0) {
                // Fallback exhausted: return what we have (matches EU VRC).
                break;
            }
            throw std::runtime_error(opts.errorPrefix + ": READ BINARY failed at offset " + std::to_string(offset));
        }

        if (readResp.data.empty()) {
            break;
        }

        result.insert(result.end(), readResp.data.begin(), readResp.data.end());
        bodyRead += readResp.data.size();
        offset += static_cast<uint32_t>(readResp.data.size());
    }

    return result;
}

} // namespace LibreSCRS::SmartCard::Internal
