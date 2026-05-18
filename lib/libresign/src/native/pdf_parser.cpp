// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pdf_parser.h"
#include "native_utils.h"
#include "pdf_tokens.h"

#include <charconv>
#include <format>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace libresign {

namespace {

// Hard ceiling on the size of any single decoded PDF content stream we
// accept. A PDF crafted to compress to a few KB but inflate to several
// gigabytes (decompression bomb) is rejected at the inflater boundary,
// and a stream whose /Length attribute legitimately advertises a value
// larger than this is also refused — both arms close the same DoS
// surface.
constexpr std::size_t kMaxPdfStreamBytes = 32ULL * 1024 * 1024;

// Reject negative or absurdly-large int64 values before casting to size_t
// for use as a stream length / offset. A negative value silently wraps to
// SIZE_MAX under static_cast, which then defeats the subsequent
// `pos + streamLength > raw.size()` bounds check (the addition itself
// wraps). Both failure modes turn an attacker-supplied PDF into a
// SIZE_MAX-byte std::span fed to FlateDecode.
//
// `std::ptrdiff_t` is the largest signed type that maps cleanly to a size
// argument; cap at its max so subsequent additions cannot overflow size_t
// either (size_t is at least as large as ptrdiff_t).
[[nodiscard]] size_t safeStreamSize(int64_t value, const char* what)
{
    if (value < 0)
        throw std::runtime_error(std::format("PdfParser: {} is negative ({})", what, value));
    if (value > std::numeric_limits<std::ptrdiff_t>::max())
        throw std::runtime_error(std::format("PdfParser: {} exceeds ptrdiff_t max ({})", what, value));
    return static_cast<size_t>(value);
}

// Overflow-safe `pos + len <= total` check.
[[nodiscard]] bool fitsWithinBuffer(size_t pos, size_t len, size_t total) noexcept
{
    return pos <= total && len <= total - pos;
}

} // anonymous namespace

// ===========================================================================
// PdfParser implementation
// ===========================================================================

PdfParser::PdfParser(std::span<const uint8_t> data) : raw(data) {}

bool PdfParser::parse()
{
    size_t xrefOffset = 0;
    try {
        xrefOffset = findStartXref();
    } catch (...) {
        return false;
    }

    try {
        parseXrefAt(xrefOffset);
        resolvedXref = xrefOffset;
        return true;
    } catch (...) {
        // Adobe-compatible fallback: the stored startxref offset may be stale
        // (e.g. the file had a non-PDF prefix that was stripped, or the
        // generator wrote the wrong offset). Scan the last ~10 KB for a
        // standalone "xref" keyword at a line start, take the most recent
        // match, and retry. If that also fails, preserve the original error
        // surface by returning false (matches the previous behavior for
        // truly broken PDFs).
        //
        // Reset any partial state accumulated by the failed attempt so we
        // don't mix entries from two different xref tables.
        objectOffsets.clear();
        compressedObjects.clear();
        trailerDict = PdfValue::null();
        visitedXref.clear();

        size_t fallbackOffset = findXrefKeywordNear();
        if (fallbackOffset == std::string_view::npos)
            return false;

        try {
            parseXrefAt(fallbackOffset);
            resolvedXref = fallbackOffset;
            return true;
        } catch (...) {
            return false;
        }
    }
}

size_t PdfParser::findXrefKeywordNear() const
{
    // Search the last ~10 KB of `raw` for a standalone "xref" keyword that
    // appears at the start of a line (preceded by \n, \r, or buffer start)
    // and is followed by whitespace. Returns the offset of the keyword, or
    // std::string_view::npos if not found.
    constexpr size_t kScanWindow = 10 * 1024;
    constexpr std::string_view kKeyword = "xref";

    size_t scanStart = (raw.size() > kScanWindow) ? raw.size() - kScanWindow : 0;
    std::string_view window(reinterpret_cast<const char*>(raw.data() + scanStart), raw.size() - scanStart);

    size_t bestMatch = std::string_view::npos;
    size_t searchFrom = 0;
    while (true) {
        auto pos = window.find(kKeyword, searchFrom);
        if (pos == std::string_view::npos)
            break;

        // Must be at line start: either position 0 in the window (and also
        // at buffer start), or preceded by CR/LF.
        bool atLineStart = false;
        size_t absPos = scanStart + pos;
        if (absPos == 0) {
            atLineStart = true;
        } else {
            uint8_t prev = raw[absPos - 1];
            atLineStart = (prev == '\n' || prev == '\r');
        }

        // Must be followed by whitespace (not part of "xrefstm" or similar).
        bool okSuffix = false;
        size_t after = absPos + kKeyword.size();
        if (after < raw.size()) {
            uint8_t nx = raw[after];
            okSuffix = (nx == ' ' || nx == '\t' || nx == '\r' || nx == '\n');
        }

        // PDF token-boundary check: walk back through the EOL bytes
        // immediately preceding `xref` and confirm the line that ends
        // there is `endobj`, `endstream`, blank, or the buffer start.
        // A hostile PDF could otherwise stash the literal `\nxref `
        // inside an object's content stream and trick the fallback
        // scanner into adopting that as the xref offset.
        bool okPrelude = false;
        if (absPos == 0) {
            okPrelude = true;
        } else {
            size_t back = absPos;
            while (back > 0 && (raw[back - 1] == '\n' || raw[back - 1] == '\r'))
                --back;
            size_t lineEnd = back;
            while (back > 0 && raw[back - 1] != '\n' && raw[back - 1] != '\r')
                --back;
            std::string_view prevLine(reinterpret_cast<const char*>(raw.data() + back), lineEnd - back);
            // Trim trailing whitespace.
            while (!prevLine.empty() && (prevLine.back() == ' ' || prevLine.back() == '\t'))
                prevLine.remove_suffix(1);
            okPrelude = prevLine.empty() || prevLine == "endobj" || prevLine == "endstream";
        }

        if (atLineStart && okSuffix && okPrelude)
            bestMatch = absPos; // keep updating → final value is the last match

        searchFrom = pos + 1;
    }

    return bestMatch;
}

const std::map<int, PdfParser::CompressedRef>& PdfParser::compressedObjectRefs() const
{
    return compressedObjects;
}

void PdfParser::parseXrefAt(size_t offset)
{
    if (offset >= raw.size())
        throw std::runtime_error("PdfParser: xref offset out of range");

    // Detect format: digit means xref stream object, 'x' means classic xref table
    uint8_t c = raw[offset];
    if (c >= '0' && c <= '9')
        parseXrefStream(offset);
    else if (c == 'x')
        parseXrefTable(offset);
    else
        throw std::runtime_error("PdfParser: unexpected byte at xref offset");
}

PdfValue PdfParser::readObject(int objNum) const
{
    auto it = objectOffsets.find(objNum);
    if (it == objectOffsets.end()) {
        // Check compressed objects (type-2 xref entries)
        auto cit = compressedObjects.find(objNum);
        if (cit != compressedObjects.end())
            return readFromObjectStream(cit->second.streamObjNum, cit->second.indexInStream);
        return PdfValue::null();
    }

    size_t pos = it->second;

    // Expect: objNum genNum obj
    skipWhitespaceAndComments(pos);

    // Parse object number
    size_t numStart = pos;
    while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
        ++pos;
    if (pos == numStart)
        return PdfValue::null();

    skipWhitespaceAndComments(pos);

    // Parse generation number
    numStart = pos;
    while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
        ++pos;
    if (pos == numStart)
        return PdfValue::null();

    skipWhitespaceAndComments(pos);

    // Expect "obj"
    if (!matchAt(pos, "obj"))
        return PdfValue::null();
    pos += 3;

    // "obj" must be followed by whitespace or delimiter, not part of a longer token
    if (pos < raw.size() && !isPdfWhitespace(raw[pos]) && !isPdfDelimiter(raw[pos]))
        return PdfValue::null();

    skipWhitespaceAndComments(pos);

    // Parse the object value
    PdfValue value = parseValue(pos);

    // After the value, there may be "stream" or "endobj"
    skipWhitespaceAndComments(pos);

    if (matchAt(pos, "stream")) {
        // Stream object — the value is the stream dictionary.
        // We don't parse stream data; just return the dict.
    }
    // "endobj" — nothing more to do

    return value;
}

const PdfValue& PdfParser::trailer() const
{
    return trailerDict;
}

PdfValue PdfParser::pageObject(int pageIndex) const
{
    // Trailer -> /Root ref
    PdfValue rootRef = trailerDict.get("Root");
    if (rootRef.type() != PdfValueType::Ref)
        throw std::runtime_error("PdfParser: trailer has no /Root ref");

    PdfValue catalog = readObject(rootRef.asRef().objNum);
    if (catalog.type() != PdfValueType::Dict)
        throw std::runtime_error("PdfParser: /Root is not a dictionary");

    // Catalog -> /Pages ref
    PdfValue pagesRef = catalog.get("Pages");
    if (pagesRef.type() != PdfValueType::Ref)
        throw std::runtime_error("PdfParser: catalog has no /Pages ref");

    PdfValue pagesNode = readObject(pagesRef.asRef().objNum);
    if (pagesNode.type() != PdfValueType::Dict)
        throw std::runtime_error("PdfParser: /Pages is not a dictionary");

    int remaining = pageIndex;
    PdfValue page = resolvePageFromNode(pagesNode, remaining);
    if (page.type() == PdfValueType::Null)
        throw std::runtime_error(std::format("PdfParser: page index {} out of range", pageIndex));

    return page;
}

// ---------------------------------------------------------------------------
// Page tree traversal
// ---------------------------------------------------------------------------

PdfValue PdfParser::resolvePageFromNode(const PdfValue& node, int& remaining) const
{
    // Reuse parseDepth to guard /Kids recursion — a malformed /Pages tree
    // with deep nesting (or cycles via /Parent refs) would otherwise
    // overflow the stack. kMaxParseDepth (256) far exceeds any real page
    // tree.
    struct DepthGuard
    {
        int& d;
        explicit DepthGuard(int& depth) : d(depth)
        {
            ++d;
        }
        ~DepthGuard()
        {
            --d;
        }
    };
    if (parseDepth >= kMaxParseDepth)
        throw std::runtime_error("PdfParser: page tree too deep");
    DepthGuard guard(parseDepth);

    PdfValue typeVal = node.get("Type");
    std::string nodeType;
    if (typeVal.type() == PdfValueType::Name)
        nodeType = typeVal.asName();

    if (nodeType == "Page") {
        if (remaining == 0)
            return node;
        --remaining;
        return PdfValue::null();
    }

    // It's a Pages node — iterate /Kids
    PdfValue kids = node.get("Kids");
    if (kids.type() != PdfValueType::Array)
        throw std::runtime_error("PdfParser: /Pages node has no /Kids array");

    for (auto& kid : kids.asArray()) {
        PdfValue childNode;
        if (kid.type() == PdfValueType::Ref) {
            childNode = readObject(kid.asRef().objNum);
        } else if (kid.type() == PdfValueType::Dict) {
            childNode = kid;
        } else {
            continue;
        }

        if (childNode.type() != PdfValueType::Dict)
            continue;

        // Optimization: check /Count on intermediate Pages nodes
        PdfValue childType = childNode.get("Type");
        if (childType.type() == PdfValueType::Name && childType.asName() == "Pages") {
            PdfValue countVal = childNode.get("Count");
            if (countVal.type() == PdfValueType::Int) {
                int count = static_cast<int>(countVal.asInt());
                if (remaining >= count) {
                    remaining -= count;
                    continue;
                }
            }
        }

        PdfValue result = resolvePageFromNode(childNode, remaining);
        if (result.type() != PdfValueType::Null)
            return result;
    }

    return PdfValue::null();
}

// ---------------------------------------------------------------------------
// pageObjectNumber — return the indirect object number of the N-th page
// ---------------------------------------------------------------------------

int PdfParser::pageObjectNumber(int pageIndex) const
{
    PdfValue rootRef = trailerDict.get("Root");
    if (rootRef.type() != PdfValueType::Ref)
        throw std::runtime_error("PdfParser: trailer has no /Root ref");

    PdfValue catalog = readObject(rootRef.asRef().objNum);
    if (catalog.type() != PdfValueType::Dict)
        throw std::runtime_error("PdfParser: /Root is not a dictionary");

    PdfValue pagesRef = catalog.get("Pages");
    if (pagesRef.type() != PdfValueType::Ref)
        throw std::runtime_error("PdfParser: catalog has no /Pages ref");

    int remaining = pageIndex;
    int objNum = resolvePageObjNumFromNode(pagesRef.asRef(), remaining);
    if (objNum < 0)
        throw std::runtime_error(std::format("PdfParser: page index {} out of range", pageIndex));
    return objNum;
}

int PdfParser::resolvePageObjNumFromNode(PdfRef nodeRef, int& remaining) const
{
    // Same depth guard as resolvePageFromNode — deep /Kids nesting or
    // /Parent cycles would otherwise overflow the stack.
    struct DepthGuard
    {
        int& d;
        explicit DepthGuard(int& depth) : d(depth)
        {
            ++d;
        }
        ~DepthGuard()
        {
            --d;
        }
    };
    if (parseDepth >= kMaxParseDepth)
        throw std::runtime_error("PdfParser: page tree too deep");
    DepthGuard guard(parseDepth);

    PdfValue node = readObject(nodeRef.objNum);
    if (node.type() != PdfValueType::Dict)
        return -1;

    PdfValue typeVal = node.get("Type");
    if (typeVal.type() == PdfValueType::Name && typeVal.asName() == "Page") {
        if (remaining == 0)
            return nodeRef.objNum;
        --remaining;
        return -1;
    }

    // Pages node — iterate /Kids
    PdfValue kids = node.get("Kids");
    if (kids.type() != PdfValueType::Array)
        return -1;

    for (auto& kid : kids.asArray()) {
        if (kid.type() != PdfValueType::Ref)
            continue;
        auto childRef = kid.asRef();

        // Optimization: check /Count on intermediate Pages nodes
        PdfValue child = readObject(childRef.objNum);
        if (child.type() == PdfValueType::Dict) {
            PdfValue childType = child.get("Type");
            if (childType.type() == PdfValueType::Name && childType.asName() == "Pages") {
                PdfValue countVal = child.get("Count");
                if (countVal.type() == PdfValueType::Int && remaining >= static_cast<int>(countVal.asInt())) {
                    remaining -= static_cast<int>(countVal.asInt());
                    continue;
                }
            }
        }

        int result = resolvePageObjNumFromNode(childRef, remaining);
        if (result >= 0)
            return result;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// xref / trailer parsing
// ---------------------------------------------------------------------------

size_t PdfParser::findStartXref(std::span<const uint8_t> data)
{
    // Search backwards from end for "startxref"
    constexpr std::string_view needle = "startxref";
    if (data.size() < needle.size())
        throw std::runtime_error("PdfParser: file too small");

    // Search last 1024 bytes (PDF spec says it should be near the end)
    size_t searchStart = (data.size() > 1024) ? data.size() - 1024 : 0;
    std::string_view tail(reinterpret_cast<const char*>(data.data() + searchStart), data.size() - searchStart);
    auto found = tail.rfind(needle);
    if (found == std::string_view::npos)
        throw std::runtime_error("PdfParser: cannot find startxref");

    size_t pos = searchStart + found + needle.size();

    // Skip whitespace, parse offset number
    while (pos < data.size() && isPdfWhitespace(data[pos]))
        ++pos;

    size_t numStart = pos;
    while (pos < data.size() && data[pos] >= '0' && data[pos] <= '9')
        ++pos;

    if (pos == numStart)
        throw std::runtime_error("PdfParser: cannot parse startxref offset");

    int64_t offset = 0;
    auto [ptr, ec] = std::from_chars(reinterpret_cast<const char*>(data.data() + numStart),
                                     reinterpret_cast<const char*>(data.data() + pos), offset);
    if (ec != std::errc{})
        throw std::runtime_error("PdfParser: invalid startxref offset");

    return static_cast<size_t>(offset);
}

size_t PdfParser::findStartXref() const
{
    return findStartXref(raw);
}

void PdfParser::parseXrefTable(size_t xrefOffset)
{
    // Cycle guard: a malicious PDF can set /Prev to the current table (or
    // any already-visited offset), causing unbounded recursion on line 593.
    // Stop on re-visit rather than recurse into stack overflow.
    if (!visitedXref.insert(xrefOffset).second)
        return;

    size_t pos = xrefOffset;

    // Expect "xref"
    if (!matchAt(pos, "xref"))
        throw std::runtime_error("PdfParser: expected 'xref' at offset");
    pos += 4;
    skipWhitespaceAndComments(pos);

    // Parse subsections: startObj count
    while (pos < raw.size()) {
        // Check if we've hit "trailer"
        if (matchAt(pos, "trailer"))
            break;

        // Parse startObj
        size_t numStart = pos;
        while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
            ++pos;
        if (pos == numStart)
            break;

        int startObj = 0;
        auto [p1, e1] = std::from_chars(reinterpret_cast<const char*>(raw.data() + numStart),
                                        reinterpret_cast<const char*>(raw.data() + pos), startObj);
        if (e1 != std::errc{})
            throw std::runtime_error("PdfParser: invalid xref subsection startObj");

        skipWhitespaceAndComments(pos);

        // Parse count
        numStart = pos;
        while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
            ++pos;
        if (pos == numStart)
            break;

        int count = 0;
        auto [p2, e2] = std::from_chars(reinterpret_cast<const char*>(raw.data() + numStart),
                                        reinterpret_cast<const char*>(raw.data() + pos), count);
        if (e2 != std::errc{})
            throw std::runtime_error("PdfParser: invalid xref subsection count");

        skipWhitespaceAndComments(pos);

        // Parse each entry: offset(10) space gen(5) space status(f|n) EOL
        for (int i = 0; i < count; ++i) {
            // Each entry is exactly 20 bytes, but be tolerant of whitespace
            numStart = pos;
            while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
                ++pos;

            int64_t offset = 0;
            auto [p3, e3] = std::from_chars(reinterpret_cast<const char*>(raw.data() + numStart),
                                            reinterpret_cast<const char*>(raw.data() + pos), offset);
            if (e3 != std::errc{})
                throw std::runtime_error("PdfParser: invalid xref entry offset");

            // Skip whitespace between offset and gen
            while (pos < raw.size() && raw[pos] == ' ')
                ++pos;

            numStart = pos;
            while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
                ++pos;

            // Skip whitespace between gen and status
            while (pos < raw.size() && raw[pos] == ' ')
                ++pos;

            char status = (pos < raw.size()) ? static_cast<char>(raw[pos]) : 'f';
            ++pos;

            // Skip EOL (CR, LF, or CRLF)
            while (pos < raw.size() && (raw[pos] == '\r' || raw[pos] == '\n' || raw[pos] == ' '))
                ++pos;

            if (status == 'n') {
                // Compute objNum in int64_t before narrowing — startObj and
                // count are parsed from attacker-supplied PDF bytes and their
                // sum could overflow a signed int (undefined behavior). Cap
                // at INT32_MAX since PDF §7.5.3 limits object numbers.
                int64_t objNum64 = static_cast<int64_t>(startObj) + i;
                if (objNum64 < 0 || objNum64 > 2147483647)
                    continue;
                int objNum = static_cast<int>(objNum64);
                // Only store first occurrence (later xref sections have priority
                // in incremental updates, but we parse from the latest)
                if (objectOffsets.find(objNum) == objectOffsets.end())
                    objectOffsets[objNum] = static_cast<size_t>(offset);
            }
        }
    }

    // Now parse trailer
    if (!matchAt(pos, "trailer"))
        throw std::runtime_error("PdfParser: expected 'trailer' after xref table");
    pos += 7; // strlen("trailer")
    skipWhitespaceAndComments(pos);

    PdfValue thisTrailer = parseValue(pos);
    if (thisTrailer.type() != PdfValueType::Dict)
        throw std::runtime_error("PdfParser: trailer is not a dictionary");

    // ISO 32000-1 §7.5.6: in incrementally-updated PDFs (multiple xref
    // sections chained via /Prev) the *most recent* trailer is authoritative
    // — it carries the post-update /Size, /Root, /Info etc. parseXrefAt is
    // entered for the latest xref first, then recurses backwards through
    // /Prev, so the first trailer we see is the one to keep. Mirrors the
    // matching guard in parseXrefStream below.
    if (trailerDict.type() != PdfValueType::Dict)
        trailerDict = thisTrailer;

    // Handle /Prev — chain to previous xref (may be table or stream)
    PdfValue prev = thisTrailer.get("Prev");
    if (prev.type() == PdfValueType::Int) {
        size_t prevOffset = safeStreamSize(prev.asInt(), "/Prev offset");
        parseXrefAt(prevOffset);
    }
}

// ---------------------------------------------------------------------------
// Xref stream parsing (ISO 32000-2 §7.5.8)
// ---------------------------------------------------------------------------

void PdfParser::parseXrefStream(size_t offset)
{
    // Cycle guard
    if (!visitedXref.insert(offset).second)
        return;

    size_t pos = offset;

    // Read the indirect object header: objNum genNum obj
    skipWhitespaceAndComments(pos);
    size_t numStart = pos;
    while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
        ++pos;
    if (pos == numStart)
        throw std::runtime_error("PdfParser: xref stream missing object number");

    skipWhitespaceAndComments(pos);

    // Generation number
    numStart = pos;
    while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
        ++pos;
    if (pos == numStart)
        throw std::runtime_error("PdfParser: xref stream missing generation number");

    skipWhitespaceAndComments(pos);

    // Expect "obj"
    if (!matchAt(pos, "obj"))
        throw std::runtime_error("PdfParser: expected 'obj' in xref stream");
    pos += 3;
    skipWhitespaceAndComments(pos);

    // Parse the stream dictionary
    PdfValue streamDict = parseValue(pos);
    if (streamDict.type() != PdfValueType::Dict)
        throw std::runtime_error("PdfParser: xref stream object is not a dictionary");

    // Verify /Type /XRef
    PdfValue typeVal = streamDict.get("Type");
    if (typeVal.type() != PdfValueType::Name || typeVal.asName() != "XRef")
        throw std::runtime_error("PdfParser: xref stream /Type is not /XRef");

    // Extract /W array (3 field widths)
    PdfValue wVal = streamDict.get("W");
    if (wVal.type() != PdfValueType::Array || wVal.asArray().size() != 3)
        throw std::runtime_error("PdfParser: xref stream /W array invalid");
    std::vector<int> w;
    for (auto& v : wVal.asArray()) {
        if (v.type() != PdfValueType::Int)
            throw std::runtime_error("PdfParser: xref stream /W contains non-integer");
        w.push_back(static_cast<int>(v.asInt()));
    }

    // Extract /Size
    PdfValue sizeVal = streamDict.get("Size");
    if (sizeVal.type() != PdfValueType::Int)
        throw std::runtime_error("PdfParser: xref stream missing /Size");
    int xrefSize = static_cast<int>(sizeVal.asInt());

    // Extract /Index array (defaults to [0 Size])
    std::vector<std::pair<int, int>> indexPairs;
    PdfValue indexVal = streamDict.get("Index");
    if (indexVal.type() == PdfValueType::Array) {
        auto& arr = indexVal.asArray();
        if (arr.size() % 2 != 0)
            throw std::runtime_error("PdfParser: xref stream /Index has odd length");
        for (size_t i = 0; i + 1 < arr.size(); i += 2) {
            if (arr[i].type() != PdfValueType::Int || arr[i + 1].type() != PdfValueType::Int)
                throw std::runtime_error("PdfParser: xref stream /Index contains non-integer");
            indexPairs.emplace_back(static_cast<int>(arr[i].asInt()), static_cast<int>(arr[i + 1].asInt()));
        }
    } else {
        indexPairs.emplace_back(0, xrefSize);
    }

    // Extract /Length for raw stream bytes
    PdfValue lengthVal = streamDict.get("Length");
    if (lengthVal.type() != PdfValueType::Int)
        throw std::runtime_error("PdfParser: xref stream missing /Length");
    size_t streamLength = safeStreamSize(lengthVal.asInt(), "xref stream /Length");
    if (streamLength > kMaxPdfStreamBytes)
        throw std::runtime_error("PdfParser: xref stream /Length " + std::to_string(streamLength) + " exceeds " +
                                 std::to_string(kMaxPdfStreamBytes) + " byte cap");

    // Find "stream" keyword and advance past it
    skipWhitespaceAndComments(pos);
    if (!matchAt(pos, "stream"))
        throw std::runtime_error("PdfParser: expected 'stream' keyword in xref stream");
    pos += 6; // strlen("stream")

    // Stream data begins after the EOL following "stream"
    // PDF spec: "stream" followed by a single EOL (CR, LF, or CRLF)
    if (pos < raw.size() && raw[pos] == '\r')
        ++pos;
    if (pos < raw.size() && raw[pos] == '\n')
        ++pos;

    if (!fitsWithinBuffer(pos, streamLength, raw.size()))
        throw std::runtime_error("PdfParser: xref stream data exceeds file bounds");

    std::span<const uint8_t> rawStream(raw.data() + pos, streamLength);

    // Decompress if /Filter /FlateDecode
    std::vector<uint8_t> decompressed;
    PdfValue filterVal = streamDict.get("Filter");
    bool isFlate = false;
    if (filterVal.type() == PdfValueType::Name && filterVal.asName() == "FlateDecode")
        isFlate = true;
    else if (filterVal.type() == PdfValueType::Array && !filterVal.asArray().empty()) {
        // Single-element filter array
        auto& first = filterVal.asArray()[0];
        if (first.type() == PdfValueType::Name && first.asName() == "FlateDecode")
            isFlate = true;
    }

    std::span<const uint8_t> streamData = rawStream;
    if (isFlate) {
        auto result = native_utils::flateDecode(rawStream, 0, kMaxPdfStreamBytes);
        if (!result)
            throw std::runtime_error("PdfParser: FlateDecode failed on xref stream");
        decompressed = std::move(*result);
        streamData = decompressed;
    }

    // Apply PNG predictor reversal if /DecodeParms has /Predictor >= 10
    std::vector<uint8_t> unpredicted;
    PdfValue decodeParms = streamDict.get("DecodeParms");
    if (decodeParms.type() == PdfValueType::Dict) {
        PdfValue predictorVal = decodeParms.get("Predictor");
        if (predictorVal.type() == PdfValueType::Int && predictorVal.asInt() >= 10) {
            PdfValue columnsVal = decodeParms.get("Columns");
            int columns =
                (columnsVal.type() == PdfValueType::Int) ? static_cast<int>(columnsVal.asInt()) : (w[0] + w[1] + w[2]);
            auto result = native_utils::reversePngPredictor(streamData, columns);
            if (!result)
                throw std::runtime_error("PdfParser: reversePngPredictor failed on xref stream");
            unpredicted = std::move(*result);
            streamData = unpredicted;
        }
    }

    // Decode the xref entries
    decodeXrefStreamEntries(streamData, w, indexPairs);

    // The xref stream dict doubles as the trailer dict
    // Only store the first (most recent) trailer
    if (trailerDict.type() != PdfValueType::Dict)
        trailerDict = streamDict;

    // Follow /Prev chain — the previous xref may be either a stream or a table
    PdfValue prev = streamDict.get("Prev");
    if (prev.type() == PdfValueType::Int) {
        size_t prevOffset = safeStreamSize(prev.asInt(), "/Prev offset");
        parseXrefAt(prevOffset);
    }
}

void PdfParser::decodeXrefStreamEntries(std::span<const uint8_t> data, const std::vector<int>& w,
                                        const std::vector<std::pair<int, int>>& indexPairs)
{
    int entrySize = w[0] + w[1] + w[2];
    if (entrySize <= 0)
        throw std::runtime_error("PdfParser: xref stream entry size is zero");

    size_t dataPos = 0;

    // Helper: read a big-endian unsigned integer of `width` bytes from data at dataPos
    auto readField = [&](int width) -> int64_t {
        int64_t val = 0;
        for (int b = 0; b < width; ++b) {
            if (dataPos >= data.size())
                throw std::runtime_error("PdfParser: xref stream data truncated");
            val = (val << 8) | data[dataPos++];
        }
        return val;
    };

    for (auto& [startObj, count] : indexPairs) {
        for (int i = 0; i < count; ++i) {
            // Type field: default is 1 if W[0] == 0
            int64_t type = (w[0] == 0) ? 1 : readField(w[0]);
            int64_t field2 = readField(w[1]);
            int64_t field3 = readField(w[2]);

            int64_t objNum64 = static_cast<int64_t>(startObj) + i;
            if (objNum64 < 0 || objNum64 > 2147483647)
                continue;
            int objNum = static_cast<int>(objNum64);

            switch (type) {
            case 0:
                // Free object — skip
                break;
            case 1:
                // Uncompressed object: field2 = byte offset
                if (objectOffsets.find(objNum) == objectOffsets.end())
                    objectOffsets[objNum] = static_cast<size_t>(field2);
                break;
            case 2:
                // Compressed in object stream: field2 = stream obj num, field3 = index
                if (compressedObjects.find(objNum) == compressedObjects.end())
                    compressedObjects[objNum] = CompressedRef{static_cast<int>(field2), static_cast<int>(field3)};
                break;
            default:
                // Unknown type — skip (future PDF versions may define new types)
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Object stream support (type-2 xref entries)
// ---------------------------------------------------------------------------

std::vector<uint8_t> PdfParser::extractStreamData(int objNum) const
{
    auto it = objectOffsets.find(objNum);
    if (it == objectOffsets.end())
        throw std::runtime_error(std::format("PdfParser: object stream {} not found in objectOffsets", objNum));

    size_t pos = it->second;

    // Parse "objNum genNum obj"
    skipWhitespaceAndComments(pos);
    while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
        ++pos;
    skipWhitespaceAndComments(pos);
    while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
        ++pos;
    skipWhitespaceAndComments(pos);

    if (!matchAt(pos, "obj"))
        throw std::runtime_error("PdfParser: expected 'obj' in object stream header");
    pos += 3;
    skipWhitespaceAndComments(pos);

    // Parse the stream dictionary
    PdfValue streamDict = parseValue(pos);
    if (streamDict.type() != PdfValueType::Dict)
        throw std::runtime_error("PdfParser: object stream is not a dictionary");

    // Get /Length
    PdfValue lengthVal = streamDict.get("Length");
    if (lengthVal.type() != PdfValueType::Int)
        throw std::runtime_error("PdfParser: object stream missing /Length");
    size_t streamLength = safeStreamSize(lengthVal.asInt(), "object stream /Length");
    if (streamLength > kMaxPdfStreamBytes)
        throw std::runtime_error("PdfParser: object stream /Length " + std::to_string(streamLength) + " exceeds " +
                                 std::to_string(kMaxPdfStreamBytes) + " byte cap");

    // Find "stream" keyword
    skipWhitespaceAndComments(pos);
    if (!matchAt(pos, "stream"))
        throw std::runtime_error("PdfParser: expected 'stream' keyword in object stream");
    pos += 6;

    // Advance past EOL after "stream"
    if (pos < raw.size() && raw[pos] == '\r')
        ++pos;
    if (pos < raw.size() && raw[pos] == '\n')
        ++pos;

    if (!fitsWithinBuffer(pos, streamLength, raw.size()))
        throw std::runtime_error("PdfParser: object stream data exceeds file bounds");

    std::span<const uint8_t> rawStream(raw.data() + pos, streamLength);

    // Check /Filter for FlateDecode
    PdfValue filterVal = streamDict.get("Filter");
    bool isFlate = false;
    if (filterVal.type() == PdfValueType::Name && filterVal.asName() == "FlateDecode")
        isFlate = true;
    else if (filterVal.type() == PdfValueType::Array && !filterVal.asArray().empty()) {
        auto& first = filterVal.asArray()[0];
        if (first.type() == PdfValueType::Name && first.asName() == "FlateDecode")
            isFlate = true;
    }

    if (isFlate) {
        auto result = native_utils::flateDecode(rawStream, 0, kMaxPdfStreamBytes);
        if (!result)
            throw std::runtime_error("PdfParser: FlateDecode failed on object stream");
        return std::move(*result);
    }

    return {rawStream.begin(), rawStream.end()};
}

PdfValue PdfParser::readFromObjectStream(int streamObjNum, int indexInStream) const
{
    // Check cache — stores decompressed data + parsed header
    auto cacheIt = objStreamCache.find(streamObjNum);
    if (cacheIt == objStreamCache.end()) {
        ObjStreamEntry entry;
        entry.data = extractStreamData(streamObjNum);

        // Parse the object stream dictionary to get /N and /First
        auto it = objectOffsets.find(streamObjNum);
        if (it == objectOffsets.end())
            throw std::runtime_error(std::format("PdfParser: object stream {} not found", streamObjNum));

        size_t pos = it->second;
        skipWhitespaceAndComments(pos);
        while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
            ++pos;
        skipWhitespaceAndComments(pos);
        while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
            ++pos;
        skipWhitespaceAndComments(pos);
        if (!matchAt(pos, "obj"))
            throw std::runtime_error("PdfParser: expected 'obj' in object stream");
        pos += 3;
        skipWhitespaceAndComments(pos);

        PdfValue streamDict = parseValue(pos);
        if (streamDict.type() != PdfValueType::Dict)
            throw std::runtime_error("PdfParser: object stream dict is not a dictionary");

        PdfValue nVal = streamDict.get("N");
        if (nVal.type() != PdfValueType::Int)
            throw std::runtime_error("PdfParser: object stream missing /N");
        int n = static_cast<int>(nVal.asInt());

        PdfValue firstVal = streamDict.get("First");
        if (firstVal.type() != PdfValueType::Int)
            throw std::runtime_error("PdfParser: object stream missing /First");
        entry.first = safeStreamSize(firstVal.asInt(), "object stream /First");
        if (entry.first > entry.data.size())
            throw std::runtime_error("PdfParser: object stream /First exceeds decompressed length");

        // Parse the header: N pairs of (objNum, offset)
        PdfParser tempParser(std::span<const uint8_t>(entry.data.data(), entry.data.size()));
        size_t hdrPos = 0;
        for (int i = 0; i < n; ++i) {
            tempParser.skipWhitespaceAndComments(hdrPos);
            size_t numStart = hdrPos;
            while (hdrPos < entry.data.size() && entry.data[hdrPos] >= '0' && entry.data[hdrPos] <= '9')
                ++hdrPos;
            if (hdrPos == numStart)
                throw std::runtime_error("PdfParser: object stream header truncated");
            int entryObjNum = 0;
            // Both from_chars calls in this header parse previously
            // dropped the returned errc, so a malformed numeric token
            // (e.g. one that overflows int) silently produced the
            // last-good value and corrupted the parsed index. Surface
            // any errc as a hard parse failure instead.
            auto [pObj, ecObj] =
                std::from_chars(reinterpret_cast<const char*>(entry.data.data() + numStart),
                                reinterpret_cast<const char*>(entry.data.data() + hdrPos), entryObjNum);
            if (ecObj != std::errc{})
                throw std::runtime_error("PdfParser: object stream header objNum parse failed");

            tempParser.skipWhitespaceAndComments(hdrPos);
            numStart = hdrPos;
            while (hdrPos < entry.data.size() && entry.data[hdrPos] >= '0' && entry.data[hdrPos] <= '9')
                ++hdrPos;
            if (hdrPos == numStart)
                throw std::runtime_error("PdfParser: object stream header truncated");
            size_t entryOffset = 0;
            auto [pOff, ecOff] =
                std::from_chars(reinterpret_cast<const char*>(entry.data.data() + numStart),
                                reinterpret_cast<const char*>(entry.data.data() + hdrPos), entryOffset);
            if (ecOff != std::errc{})
                throw std::runtime_error("PdfParser: object stream header offset parse failed");

            entry.headerEntries.emplace_back(entryObjNum, entryOffset);
        }

        cacheIt = objStreamCache.emplace(streamObjNum, std::move(entry)).first;
    }

    const auto& cached = cacheIt->second;
    int n = static_cast<int>(cached.headerEntries.size());

    if (indexInStream < 0 || indexInStream >= n)
        throw std::runtime_error(
            std::format("PdfParser: index {} out of range for object stream (N={})", indexInStream, n));

    size_t objPos = cached.first + cached.headerEntries[indexInStream].second;
    if (objPos >= cached.data.size())
        throw std::runtime_error("PdfParser: object offset in stream exceeds data");

    PdfParser tempParser(std::span<const uint8_t>(cached.data.data(), cached.data.size()));
    return tempParser.parseValue(objPos);
}

} // namespace libresign
