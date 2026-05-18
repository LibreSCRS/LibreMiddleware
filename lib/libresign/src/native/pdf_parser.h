// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "pdf_value.h"

#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace libresign {

// ---------------------------------------------------------------------------
// PdfParser — lightweight parser for PDF xref tables and xref streams
// ---------------------------------------------------------------------------

class PdfParser
{
public:
    explicit PdfParser(std::span<const uint8_t> data);

    // Parse xref + trailer, build object offset table.
    // Returns false on structural errors instead of throwing.
    bool parse();

    // Read an indirect object by object number.
    // Returns Null if not found.
    PdfValue readObject(int objNum) const;

    // Accessor for the trailer dictionary.
    const PdfValue& trailer() const;

    // Follow /Root -> /Pages -> /Kids to locate a page dict by zero-based index.
    // Throws on out-of-range or structural error.
    PdfValue pageObject(int pageIndex) const; // Used by PdfParserTests

    // Return the indirect object number of the N-th page (0-based).
    // Throws on out-of-range or structural error.
    int pageObjectNumber(int pageIndex) const;

    // Find the byte offset stored after the last "startxref" keyword.
    // Static overload operates on arbitrary data; instance method delegates to it.
    static size_t findStartXref(std::span<const uint8_t> data);

    // Byte offset of the xref table that was actually parsed successfully by
    // parse(). Usually equals findStartXref() value, but may differ when the
    // Adobe-compatible fallback scan located the table at a different offset
    // (e.g. after a prefix strip changed absolute byte positions). Callers
    // that emit incremental updates should use this for /Prev rather than
    // re-reading the potentially stale startxref value. Returns 0 before
    // parse() succeeds.
    size_t resolvedXrefOffset() const
    {
        return resolvedXref;
    }

    // Encode a UTF-8 string as a PDF string token. Thin forwarder to the
    // free function pdfEscapeString in pdf_value.h, retained for source
    // compatibility with call sites that historically used the
    // PdfParser:: scope.
    static std::string escapeStringForPdf(const std::string& s)
    {
        return pdfEscapeString(s);
    }

    // Compressed object reference for type-2 xref stream entries.
    // The object lives inside an object stream; resolution is deferred.
    struct CompressedRef
    {
        int streamObjNum;
        int indexInStream;
    };

    // Objects stored in object streams (type-2 xref entries).
    // Key = object number, value = which stream and index within it.
    const std::map<int, CompressedRef>& compressedObjectRefs() const;

private:
    std::span<const uint8_t> raw;
    PdfValue trailerDict;
    std::map<int, size_t> objectOffsets;            // objNum -> byte offset in raw
    std::map<int, CompressedRef> compressedObjects; // objNum -> object stream ref
    size_t resolvedXref = 0;                        // byte offset of xref table actually parsed

    // Recursion / cycle guards against attacker-crafted PDFs.
    // parseDepth bounds parseValue → parseArray/parseDict recursion; a PDF
    // with deeply nested [[[[... triggers stack overflow otherwise, which
    // catch(...) cannot intercept. visitedXref prevents /Prev chains that
    // loop back on themselves.
    static constexpr int kMaxParseDepth = 256;
    mutable int parseDepth = 0;
    std::set<size_t> visitedXref;

    // Tokenizer / parser helpers (defined in pdf_tokens.cpp).
    void skipWhitespaceAndComments(size_t& pos) const;
    PdfValue parseValue(size_t& pos) const;
    PdfValue parseNumber(size_t& pos) const;
    PdfValue parseString(size_t& pos) const;
    PdfValue parseHexString(size_t& pos) const;
    PdfValue parseName(size_t& pos) const;
    PdfValue parseArray(size_t& pos) const;
    PdfValue parseDict(size_t& pos) const;

    // xref parsing
    size_t findStartXref() const;
    void parseXrefTable(size_t xrefOffset);
    void parseXrefStream(size_t offset);
    void parseXrefAt(size_t offset);

    // Adobe-compatible fallback: scan last ~10 KB for a standalone "xref"
    // keyword at line start when the stored startxref offset is stale.
    // Returns offset of the last valid match, or std::string_view::npos if
    // no match is found. Xref streams without the plain-text keyword are
    // not recovered by this fallback (rare; well-formed files are unaffected).
    size_t findXrefKeywordNear() const;
    void decodeXrefStreamEntries(std::span<const uint8_t> data, const std::vector<int>& w,
                                 const std::vector<std::pair<int, int>>& indexPairs);

    // Page tree traversal
    PdfValue resolvePageFromNode(const PdfValue& node, int& remaining) const;
    int resolvePageObjNumFromNode(PdfRef nodeRef, int& remaining) const;

    // Object stream support (type-2 xref entries)
    std::vector<uint8_t> extractStreamData(int objNum) const;
    PdfValue readFromObjectStream(int streamObjNum, int indexInStream) const;

    // Cache for decompressed object streams (avoid re-decompressing and re-parsing header)
    struct ObjStreamEntry
    {
        std::vector<uint8_t> data;
        size_t first = 0;                                  // /First byte offset
        std::vector<std::pair<int, size_t>> headerEntries; // (objNum, offset relative to /First)
    };
    mutable std::map<int, ObjStreamEntry> objStreamCache;

    // Utility (defined in pdf_tokens.cpp).
    bool matchAt(size_t pos, std::string_view s) const;
};

} // namespace libresign
