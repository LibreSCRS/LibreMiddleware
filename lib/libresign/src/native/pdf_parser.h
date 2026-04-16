// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace libresign {

// ---------------------------------------------------------------------------
// PdfRef — indirect object reference (objNum genNum R)
// ---------------------------------------------------------------------------

struct PdfRef
{
    int objNum = 0;
    int genNum = 0;

    bool operator==(const PdfRef&) const = default;
};

// ---------------------------------------------------------------------------
// PdfValueType — discriminator for PdfValue variant
// ---------------------------------------------------------------------------

enum class PdfValueType { Null, Bool, Int, Real, String, Name, Array, Dict, Ref };

// ---------------------------------------------------------------------------
// PdfValue — variant representing any PDF object value
// ---------------------------------------------------------------------------

class PdfValue
{
public:
    using ArrayType = std::vector<PdfValue>;
    using DictType = std::map<std::string, PdfValue>;

    // Default-constructed value is Null
    PdfValue() : data(std::monostate{}) {}

    // Convenience constructors
    explicit PdfValue(bool v) : data(v) {}
    explicit PdfValue(int64_t v) : data(v) {}
    explicit PdfValue(double v) : data(v) {}
    explicit PdfValue(std::string v, bool isName) : data(isName ? Data(NameTag{std::move(v)}) : Data(std::move(v))) {}
    explicit PdfValue(ArrayType v) : data(std::move(v)) {}
    explicit PdfValue(DictType v) : data(std::move(v)) {}
    explicit PdfValue(PdfRef v) : data(v) {}

    // Named factories for clarity
    static PdfValue null()
    {
        return PdfValue();
    }
    static PdfValue boolean(bool v)
    {
        return PdfValue(v);
    }
    static PdfValue integer(int64_t v)
    {
        return PdfValue(v);
    }
    static PdfValue real(double v)
    {
        return PdfValue(v);
    }
    static PdfValue string(std::string v)
    {
        return PdfValue(std::move(v), false);
    }
    static PdfValue name(std::string v)
    {
        return PdfValue(std::move(v), true);
    }
    static PdfValue array(ArrayType v)
    {
        return PdfValue(std::move(v));
    }
    static PdfValue dict(DictType v)
    {
        return PdfValue(std::move(v));
    }
    static PdfValue ref(int objNum, int genNum = 0)
    {
        return PdfValue(PdfRef{objNum, genNum});
    }

    PdfValueType type() const;

    // Type-specific accessors — throw std::runtime_error on type mismatch
    bool asBool() const;
    int64_t asInt() const;
    double asReal() const;
    const std::string& asString() const;
    const std::string& asName() const;
    const ArrayType& asArray() const;
    const DictType& asDict() const;
    PdfRef asRef() const;

    // Dict convenience: returns Null if key is absent or value is not a Dict
    PdfValue get(const std::string& key) const;

    // Serialize back to valid PDF syntax
    std::string serialize() const;

private:
    // Internal tag to distinguish Name from String (both are std::string)
    struct NameTag
    {
        std::string value;
    };

    using Data = std::variant<std::monostate, // Null
                              bool,           // Bool
                              int64_t,        // Int
                              double,         // Real
                              std::string,    // String
                              NameTag,        // Name
                              ArrayType,      // Array
                              DictType,       // Dict
                              PdfRef          // Ref
                              >;

    Data data;
};

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

    // Escape a string for use inside a PDF parenthesized string literal.
    // Handles (, ), \, CR, LF, tab, backspace, formfeed.
    static std::string escapeStringForPdf(const std::string& s);

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

    // Recursion / cycle guards against attacker-crafted PDFs.
    // parseDepth bounds parseValue → parseArray/parseDict recursion; a PDF
    // with deeply nested [[[[... triggers stack overflow otherwise, which
    // catch(...) cannot intercept. visitedXref prevents /Prev chains that
    // loop back on themselves.
    static constexpr int kMaxParseDepth = 256;
    mutable int parseDepth = 0;
    std::set<size_t> visitedXref;

    // Tokenizer / parser helpers
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

    // Utility
    bool matchAt(size_t pos, std::string_view s) const;
};

} // namespace libresign
