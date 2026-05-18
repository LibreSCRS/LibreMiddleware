// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <map>
#include <string>
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

// Encode a UTF-8 string as a PDF string token.
//
// Pure-ASCII input (every byte < 0x80) is returned in the parenthesised
// literal form "(escaped)", with PDF metacharacters ( ) \ CR LF TAB BS
// FF backslash-escaped per ISO 32000-1 §7.3.4.2.
//
// Input containing any byte >= 0x80 is returned as a hex string token
// "<FEFF...>" with the UTF-16BE byte-order mark followed by the
// UTF-16BE encoding of the input, per ISO 32000-1 §7.9.2.2.
//
// Callers receive a PDF-ready token — they must NOT wrap the result in
// an additional "(" / ")" pair.
std::string pdfEscapeString(const std::string& s);

} // namespace libresign
