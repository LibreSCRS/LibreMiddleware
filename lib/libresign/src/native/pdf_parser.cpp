// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pdf_parser.h"
#include "native_utils.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <format>
#include <stdexcept>

namespace libresign {

// ===========================================================================
// PdfValue implementation
// ===========================================================================

PdfValueType PdfValue::type() const
{
    return std::visit(
        [](auto&& arg) -> PdfValueType {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, std::monostate>)
                return PdfValueType::Null;
            else if constexpr (std::is_same_v<T, bool>)
                return PdfValueType::Bool;
            else if constexpr (std::is_same_v<T, int64_t>)
                return PdfValueType::Int;
            else if constexpr (std::is_same_v<T, double>)
                return PdfValueType::Real;
            else if constexpr (std::is_same_v<T, std::string>)
                return PdfValueType::String;
            else if constexpr (std::is_same_v<T, NameTag>)
                return PdfValueType::Name;
            else if constexpr (std::is_same_v<T, ArrayType>)
                return PdfValueType::Array;
            else if constexpr (std::is_same_v<T, DictType>)
                return PdfValueType::Dict;
            else if constexpr (std::is_same_v<T, PdfRef>)
                return PdfValueType::Ref;
        },
        data);
}

bool PdfValue::asBool() const
{
    if (auto* p = std::get_if<bool>(&data))
        return *p;
    throw std::runtime_error("PdfValue: not a Bool");
}

int64_t PdfValue::asInt() const
{
    if (auto* p = std::get_if<int64_t>(&data))
        return *p;
    throw std::runtime_error("PdfValue: not an Int");
}

double PdfValue::asReal() const
{
    if (auto* p = std::get_if<double>(&data))
        return *p;
    throw std::runtime_error("PdfValue: not a Real");
}

const std::string& PdfValue::asString() const
{
    if (auto* p = std::get_if<std::string>(&data))
        return *p;
    throw std::runtime_error("PdfValue: not a String");
}

const std::string& PdfValue::asName() const
{
    if (auto* p = std::get_if<NameTag>(&data))
        return p->value;
    throw std::runtime_error("PdfValue: not a Name");
}

const PdfValue::ArrayType& PdfValue::asArray() const
{
    if (auto* p = std::get_if<ArrayType>(&data))
        return *p;
    throw std::runtime_error("PdfValue: not an Array");
}

const PdfValue::DictType& PdfValue::asDict() const
{
    if (auto* p = std::get_if<DictType>(&data))
        return *p;
    throw std::runtime_error("PdfValue: not a Dict");
}

PdfRef PdfValue::asRef() const
{
    if (auto* p = std::get_if<PdfRef>(&data))
        return *p;
    throw std::runtime_error("PdfValue: not a Ref");
}

PdfValue PdfValue::get(const std::string& key) const
{
    if (auto* d = std::get_if<DictType>(&data)) {
        auto it = d->find(key);
        if (it != d->end())
            return it->second;
    }
    return PdfValue::null();
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

std::string PdfParser::escapeStringForPdf(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '(':
            out += "\\(";
            break;
        case ')':
            out += "\\)";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        default:
            out.push_back(c);
            break;
        }
    }
    return out;
}

std::string PdfValue::serialize() const
{
    return std::visit(
        [](auto&& arg) -> std::string {
            using T = std::decay_t<decltype(arg)>;

            if constexpr (std::is_same_v<T, std::monostate>) {
                return "null";
            } else if constexpr (std::is_same_v<T, bool>) {
                return arg ? "true" : "false";
            } else if constexpr (std::is_same_v<T, int64_t>) {
                return std::to_string(arg);
            } else if constexpr (std::is_same_v<T, double>) {
                // Use enough precision but strip trailing zeros.
                std::string s = std::format("{:.6f}", arg);
                if (s.find('.') != std::string::npos) {
                    size_t last = s.find_last_not_of('0');
                    if (last != std::string::npos && s[last] == '.') {
                        // Integer-valued double (e.g. "1.000000"): drop the
                        // trailing dot entirely. PDF §7.3.3 accepts "1" as
                        // a real — integers are a subset of reals — and
                        // this is the form producers like Ghostscript emit.
                        s.erase(last);
                    } else if (last != std::string::npos) {
                        s.erase(last + 1);
                    }
                }
                return s;
            } else if constexpr (std::is_same_v<T, std::string>) {
                return "(" + PdfParser::escapeStringForPdf(arg) + ")";
            } else if constexpr (std::is_same_v<T, NameTag>) {
                return "/" + arg.value;
            } else if constexpr (std::is_same_v<T, ArrayType>) {
                std::string s = "[";
                for (size_t i = 0; i < arg.size(); ++i) {
                    if (i > 0)
                        s += " ";
                    s += arg[i].serialize();
                }
                s += "]";
                return s;
            } else if constexpr (std::is_same_v<T, DictType>) {
                std::string s = "<< ";
                for (auto& [k, v] : arg) {
                    s += "/" + k + " " + v.serialize() + " ";
                }
                s += ">>";
                return s;
            } else if constexpr (std::is_same_v<T, PdfRef>) {
                return std::format("{} {} R", arg.objNum, arg.genNum);
            }
        },
        data);
}

// ===========================================================================
// PdfParser implementation
// ===========================================================================

static bool isPdfWhitespace(uint8_t c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\0' || c == '\f';
}

static bool isPdfDelimiter(uint8_t c)
{
    return c == '(' || c == ')' || c == '<' || c == '>' || c == '[' || c == ']' || c == '{' || c == '}' || c == '/' ||
           c == '%';
}

PdfParser::PdfParser(std::span<const uint8_t> data) : raw(data) {}

bool PdfParser::parse()
{
    try {
        size_t xrefOffset = findStartXref();
        parseXrefAt(xrefOffset);
        return true;
    } catch (...) {
        return false;
    }
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
        explicit DepthGuard(int& d_) : d(d_)
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
        explicit DepthGuard(int& d_) : d(d_)
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

    trailerDict = parseValue(pos);
    if (trailerDict.type() != PdfValueType::Dict)
        throw std::runtime_error("PdfParser: trailer is not a dictionary");

    // Handle /Prev — chain to previous xref (may be table or stream)
    PdfValue prev = trailerDict.get("Prev");
    if (prev.type() == PdfValueType::Int) {
        size_t prevOffset = static_cast<size_t>(prev.asInt());
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
    size_t streamLength = static_cast<size_t>(lengthVal.asInt());

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

    if (pos + streamLength > raw.size())
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
        auto result = native_utils::flateDecode(rawStream);
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
        size_t prevOffset = static_cast<size_t>(prev.asInt());
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
// Tokenizer
// ---------------------------------------------------------------------------

void PdfParser::skipWhitespaceAndComments(size_t& pos) const
{
    while (pos < raw.size()) {
        if (isPdfWhitespace(raw[pos])) {
            ++pos;
        } else if (raw[pos] == '%') {
            // Comment — skip to end of line
            while (pos < raw.size() && raw[pos] != '\n' && raw[pos] != '\r')
                ++pos;
        } else {
            break;
        }
    }
}

PdfValue PdfParser::parseValue(size_t& pos) const
{
    // Guard against pathological nesting in attacker-supplied PDFs
    // ("[[[[[..." or "<<<<..."). A stack overflow from unbounded recursion
    // is uncatchable; we bail with a runtime error instead, which is then
    // caught by parse()'s try/catch and reported as a parse failure.
    struct DepthGuard
    {
        int& d;
        explicit DepthGuard(int& d_) : d(d_)
        {
            ++d;
        }
        ~DepthGuard()
        {
            --d;
        }
    };
    if (parseDepth >= kMaxParseDepth)
        throw std::runtime_error("PdfParser: max parse depth exceeded");
    DepthGuard guard(parseDepth);

    skipWhitespaceAndComments(pos);

    if (pos >= raw.size())
        return PdfValue::null();

    uint8_t c = raw[pos];

    // Dict: <<
    if (c == '<' && pos + 1 < raw.size() && raw[pos + 1] == '<')
        return parseDict(pos);

    // Hex string: <
    if (c == '<')
        return parseHexString(pos);

    // Parenthesized string: (
    if (c == '(')
        return parseString(pos);

    // Name: /
    if (c == '/')
        return parseName(pos);

    // Array: [
    if (c == '[')
        return parseArray(pos);

    // Boolean: true, false
    if (matchAt(pos, "true")) {
        // Ensure "true" is not part of a longer token
        size_t end = pos + 4;
        if (end >= raw.size() || isPdfWhitespace(raw[end]) || isPdfDelimiter(raw[end])) {
            pos = end;
            return PdfValue::boolean(true);
        }
    }
    if (matchAt(pos, "false")) {
        size_t end = pos + 5;
        if (end >= raw.size() || isPdfWhitespace(raw[end]) || isPdfDelimiter(raw[end])) {
            pos = end;
            return PdfValue::boolean(false);
        }
    }

    // Null
    if (matchAt(pos, "null")) {
        size_t end = pos + 4;
        if (end >= raw.size() || isPdfWhitespace(raw[end]) || isPdfDelimiter(raw[end])) {
            pos = end;
            return PdfValue::null();
        }
    }

    // Number (possibly followed by another number and 'R' for a reference)
    if (c == '+' || c == '-' || c == '.' || (c >= '0' && c <= '9'))
        return parseNumber(pos);

    // Unknown token — skip it
    ++pos;
    return PdfValue::null();
}

PdfValue PdfParser::parseNumber(size_t& pos) const
{
    size_t start = pos;
    bool hasDecimal = false;
    bool hasSign = false;

    if (pos < raw.size() && (raw[pos] == '+' || raw[pos] == '-')) {
        hasSign = true;
        ++pos;
    }

    while (pos < raw.size()) {
        if (raw[pos] >= '0' && raw[pos] <= '9') {
            ++pos;
        } else if (raw[pos] == '.' && !hasDecimal) {
            hasDecimal = true;
            ++pos;
        } else {
            break;
        }
    }

    if (pos == start || (pos == start + 1 && hasSign))
        return PdfValue::null();

    std::string_view numStr(reinterpret_cast<const char*>(raw.data() + start), pos - start);

    if (hasDecimal) {
        // Apple Clang lacks std::from_chars for floating-point types
        double val = std::strtod(std::string(numStr).c_str(), nullptr);
        return PdfValue::real(val);
    }

    int64_t intVal = 0;
    std::from_chars(numStr.data(), numStr.data() + numStr.size(), intVal);

    // Look ahead for "N R" pattern (indirect reference)
    // We have parsed the first number. Check if followed by whitespace, another number,
    // whitespace, and 'R'.
    size_t savedPos = pos;
    skipWhitespaceAndComments(pos);

    if (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9') {
        size_t genStart = pos;
        while (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '9')
            ++pos;

        std::string_view genStr(reinterpret_cast<const char*>(raw.data() + genStart), pos - genStart);

        skipWhitespaceAndComments(pos);

        if (pos < raw.size() && raw[pos] == 'R') {
            // Check that R is not part of a longer token
            size_t afterR = pos + 1;
            if (afterR >= raw.size() || isPdfWhitespace(raw[afterR]) || isPdfDelimiter(raw[afterR])) {
                pos = afterR;
                int genVal = 0;
                std::from_chars(genStr.data(), genStr.data() + genStr.size(), genVal);
                return PdfValue::ref(static_cast<int>(intVal), genVal);
            }
        }

        // Not a reference — backtrack
        pos = savedPos;
    } else {
        pos = savedPos;
    }

    return PdfValue::integer(intVal);
}

PdfValue PdfParser::parseString(size_t& pos) const
{
    // pos is at '('
    ++pos;
    std::string result;
    int depth = 1;

    while (pos < raw.size() && depth > 0) {
        uint8_t c = raw[pos];

        if (c == '\\' && pos + 1 < raw.size()) {
            ++pos;
            uint8_t next = raw[pos];
            switch (next) {
            case 'n':
                result.push_back('\n');
                ++pos;
                break;
            case 'r':
                result.push_back('\r');
                ++pos;
                break;
            case 't':
                result.push_back('\t');
                ++pos;
                break;
            case 'b':
                result.push_back('\b');
                ++pos;
                break;
            case 'f':
                result.push_back('\f');
                ++pos;
                break;
            case '(':
                result.push_back('(');
                ++pos;
                break;
            case ')':
                result.push_back(')');
                ++pos;
                break;
            case '\\':
                result.push_back('\\');
                ++pos;
                break;
            case '\r':
                // Escaped newline (line continuation)
                ++pos;
                if (pos < raw.size() && raw[pos] == '\n')
                    ++pos;
                break;
            case '\n':
                // Escaped newline (line continuation)
                ++pos;
                break;
            default:
                // Octal: up to 3 digits
                if (next >= '0' && next <= '7') {
                    int octal = next - '0';
                    ++pos;
                    if (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '7') {
                        octal = octal * 8 + (raw[pos] - '0');
                        ++pos;
                        if (pos < raw.size() && raw[pos] >= '0' && raw[pos] <= '7') {
                            octal = octal * 8 + (raw[pos] - '0');
                            ++pos;
                        }
                    }
                    result.push_back(static_cast<char>(octal & 0xFF));
                } else {
                    // Unknown escape — just include the character
                    result.push_back(static_cast<char>(next));
                    ++pos;
                }
                break;
            }
        } else if (c == '(') {
            ++depth;
            result.push_back('(');
            ++pos;
        } else if (c == ')') {
            --depth;
            if (depth > 0)
                result.push_back(')');
            ++pos;
        } else {
            result.push_back(static_cast<char>(c));
            ++pos;
        }
    }

    return PdfValue::string(std::move(result));
}

PdfValue PdfParser::parseHexString(size_t& pos) const
{
    // pos is at '<'
    ++pos;
    std::string result;

    int nibble = -1;
    while (pos < raw.size()) {
        uint8_t c = raw[pos];
        if (c == '>') {
            ++pos;
            break;
        }
        if (isPdfWhitespace(c)) {
            ++pos;
            continue;
        }

        int val = 0;
        if (c >= '0' && c <= '9')
            val = c - '0';
        else if (c >= 'a' && c <= 'f')
            val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            val = c - 'A' + 10;
        else {
            ++pos;
            continue;
        } // skip invalid hex chars

        if (nibble < 0) {
            nibble = val;
        } else {
            result.push_back(static_cast<char>((nibble << 4) | val));
            nibble = -1;
        }
        ++pos;
    }

    // Odd number of hex digits: pad with 0
    if (nibble >= 0)
        result.push_back(static_cast<char>(nibble << 4));

    return PdfValue::string(std::move(result));
}

PdfValue PdfParser::parseName(size_t& pos) const
{
    // pos is at '/'
    ++pos;
    std::string name;

    while (pos < raw.size()) {
        uint8_t c = raw[pos];
        if (isPdfWhitespace(c) || isPdfDelimiter(c))
            break;

        // Handle #XX hex escape in names
        if (c == '#' && pos + 2 < raw.size()) {
            auto hexToByte = [](uint8_t h) -> int {
                if (h >= '0' && h <= '9')
                    return h - '0';
                if (h >= 'a' && h <= 'f')
                    return h - 'a' + 10;
                if (h >= 'A' && h <= 'F')
                    return h - 'A' + 10;
                return -1;
            };
            int hi = hexToByte(raw[pos + 1]);
            int lo = hexToByte(raw[pos + 2]);
            if (hi >= 0 && lo >= 0) {
                name.push_back(static_cast<char>((hi << 4) | lo));
                pos += 3;
                continue;
            }
        }

        name.push_back(static_cast<char>(c));
        ++pos;
    }

    return PdfValue::name(std::move(name));
}

PdfValue PdfParser::parseArray(size_t& pos) const
{
    // pos is at '['
    ++pos;
    PdfValue::ArrayType arr;

    while (pos < raw.size()) {
        skipWhitespaceAndComments(pos);
        if (pos >= raw.size())
            break;
        if (raw[pos] == ']') {
            ++pos;
            break;
        }
        arr.push_back(parseValue(pos));
    }

    return PdfValue::array(std::move(arr));
}

PdfValue PdfParser::parseDict(size_t& pos) const
{
    // pos is at first '<' of '<<'
    pos += 2;
    PdfValue::DictType dict;

    while (pos < raw.size()) {
        skipWhitespaceAndComments(pos);
        if (pos >= raw.size())
            break;

        // Check for >>
        if (raw[pos] == '>' && pos + 1 < raw.size() && raw[pos + 1] == '>') {
            pos += 2;
            break;
        }

        // Key must be a name
        if (raw[pos] != '/')
            break; // malformed dict

        PdfValue key = parseName(pos);
        if (key.type() != PdfValueType::Name)
            break;

        PdfValue value = parseValue(pos);
        dict[key.asName()] = std::move(value);
    }

    return PdfValue::dict(std::move(dict));
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
    size_t streamLength = static_cast<size_t>(lengthVal.asInt());

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

    if (pos + streamLength > raw.size())
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
        auto result = native_utils::flateDecode(rawStream);
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
        entry.first = static_cast<size_t>(firstVal.asInt());

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
            std::from_chars(reinterpret_cast<const char*>(entry.data.data() + numStart),
                            reinterpret_cast<const char*>(entry.data.data() + hdrPos), entryObjNum);

            tempParser.skipWhitespaceAndComments(hdrPos);
            numStart = hdrPos;
            while (hdrPos < entry.data.size() && entry.data[hdrPos] >= '0' && entry.data[hdrPos] <= '9')
                ++hdrPos;
            if (hdrPos == numStart)
                throw std::runtime_error("PdfParser: object stream header truncated");
            size_t entryOffset = 0;
            std::from_chars(reinterpret_cast<const char*>(entry.data.data() + numStart),
                            reinterpret_cast<const char*>(entry.data.data() + hdrPos), entryOffset);

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

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

bool PdfParser::matchAt(size_t pos, std::string_view s) const
{
    if (pos + s.size() > raw.size())
        return false;
    return std::memcmp(raw.data() + pos, s.data(), s.size()) == 0;
}

} // namespace libresign
