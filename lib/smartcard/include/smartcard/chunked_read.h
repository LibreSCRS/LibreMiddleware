// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <apdu.h>
#include <smartcard/i_connection.h>

namespace LibreSCRS::SmartCard::Internal {

/// Description of where the content length lives in the file header.
/// Used by the default header parser; supply a custom parseHeader callback
/// for cards whose header layout is not a fixed offset+little-endian word.
struct HeaderLengthSpec
{
    /// Number of header bytes to read before content (also the offset at
    /// which content starts).
    uint8_t headerSize = 4;
    /// Offset within the header where the content-length word begins.
    uint8_t lengthOffset = 2;
    /// Length-word size in bytes (1 or 2). Always little-endian.
    uint8_t lengthBytes = 2;
    /// If true, treat header[emptyMarkerOffset] == emptyMarkerValue as
    /// "empty file" and return {} (matches Apollo's 0xFF-at-offset-4 marker).
    bool hasEmptyMarker = false;
    uint8_t emptyMarkerOffset = 0;
    uint8_t emptyMarkerValue = 0xFF;
    /// Optional sanity cap on declared content length (0 = no cap).
    uint32_t maxContentLength = 0;
};

/// Result returned by a custom header parser.
struct HeaderParseResult
{
    size_t dataOffset = 0;  ///< byte offset at which body reads start
    size_t totalToRead = 0; ///< total bytes to read (body, not including dataOffset)
};

/// Options controlling readChunkedFile behavior. The defaults match the
/// most common case (4-byte header, LE u16 length at offset 2, no retry,
/// 0xFF chunk size, throw on read failure, body-only result).
struct ChunkedReadOptions
{
    /// Header layout for the default parser. Ignored if parseHeader is set.
    HeaderLengthSpec headerSpec{};
    /// If true, the returned vector starts with the raw header bytes
    /// followed by the body. If false, only the body is returned.
    bool includeHeaderInResult = false;
    /// Initial READ BINARY chunk size (0x01..0xFF). 0xFF = 255 bytes.
    uint8_t chunkSize = 0xFF;
    /// If non-zero, on a READ BINARY failure the loop retries once with
    /// this smaller chunk size before giving up (matches EU VRC behavior).
    uint8_t fallbackChunkSize = 0;
    /// Prefix used in thrown std::runtime_error messages, e.g. "Apollo".
    std::string errorPrefix = "readChunkedFile";
    /// If set, called with header bytes; must return the data offset and
    /// total body length, or nullopt to abort and return an empty vector.
    /// Overrides headerSpec when present.
    std::function<std::optional<HeaderParseResult>(std::span<const uint8_t>)> parseHeader;
    /// If non-empty, the helper skips its own READ BINARY for the header
    /// and treats these bytes as the file header. Useful when the caller
    /// has already fetched the header via a card-family-specific retry
    /// path that the generic helper cannot express.
    std::vector<uint8_t> headerOverride;
    /// If set, called for each chunk read instead of conn.transmit(readBinary(...)).
    /// Allows callers to inject per-read retry/recovery (Gemalto re-select
    /// path). The callback is responsible for returning a response whose
    /// isSuccess() reflects the final outcome.
    std::function<APDUResponse(uint16_t offset, uint8_t length)> readChunk;
};

/// Generic ISO 7816-4 chunked file reader.
///
/// Steps:
///   1. Read the first headerSpec.headerSize bytes (or call parseHeader).
///   2. Determine the data offset and total body length.
///   3. Loop READ BINARY in chunks of chunkSize (with optional fallback).
///
/// The caller is expected to have already performed SELECT on the target
/// file. SELECT semantics vary too widely between card families to be
/// folded in here; this helper owns only the header + body read loop.
///
/// On READ BINARY failure with no fallback configured, throws
/// std::runtime_error using errorPrefix; with fallback, retries the
/// remaining chunks at fallbackChunkSize and returns what was read.
std::vector<uint8_t> readChunkedFile(IConnection& conn, const ChunkedReadOptions& opts);

} // namespace LibreSCRS::SmartCard::Internal
