// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pdf_value.h"

#include <format>
#include <stdexcept>
#include <string_view>

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

namespace {

// F21: encode UTF-8 input as a PDF hex string with UTF-16BE-with-BOM
// payload, e.g. "<FEFF041E0434...>". ISO 32000-1 §7.9.2.2 specifies that
// PDF string fields containing any non-PDFDocEncoding character must be
// emitted in this form so readers can decode the codepoints unambiguously.
// Pre-fix Cyrillic / Latin-Ext text rendered as garbled bytes when emitted
// raw into a parenthesised literal.
std::string toPdfHexStringUtf16Be(std::string_view utf8Input)
{
    std::string out = "<FEFF";
    out.reserve(8 + utf8Input.size() * 4);
    size_t i = 0;
    while (i < utf8Input.size()) {
        unsigned char c = static_cast<unsigned char>(utf8Input[i]);
        char32_t cp = 0;
        size_t n = 1;
        if ((c & 0x80) == 0x00) {
            cp = c;
            n = 1;
        } else if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1F;
            n = 2;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0F;
            n = 3;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07;
            n = 4;
        } else {
            // Invalid leading byte — substitute U+FFFD and resync on the
            // next byte.
            cp = 0xFFFD;
            n = 1;
        }
        if (i + n > utf8Input.size()) {
            cp = 0xFFFD;
            n = utf8Input.size() - i;
        } else {
            for (size_t k = 1; k < n; ++k) {
                cp = (cp << 6) | (static_cast<unsigned char>(utf8Input[i + k]) & 0x3F);
            }
        }
        i += n;

        if (cp <= 0xFFFF) {
            out += std::format("{:04X}", static_cast<uint16_t>(cp));
        } else {
            uint32_t v = cp - 0x10000;
            uint16_t high = static_cast<uint16_t>(0xD800 + (v >> 10));
            uint16_t low = static_cast<uint16_t>(0xDC00 + (v & 0x3FF));
            out += std::format("{:04X}{:04X}", high, low);
        }
    }
    out += '>';
    return out;
}

} // namespace

std::string pdfEscapeString(const std::string& s)
{
    // F21: detect non-ASCII input. PDF readers interpret parenthesised
    // string literals under PDFDocEncoding by default, so raw UTF-8 bytes
    // in `()` form render as garbage. Emit a UTF-16BE hex string for any
    // input containing a byte >= 0x80; the form is backward-compatible
    // (PDF readers accept either token form for any string field).
    bool hasNonAscii = false;
    for (unsigned char c : s) {
        if (c >= 0x80) {
            hasNonAscii = true;
            break;
        }
    }
    if (hasNonAscii)
        return toPdfHexStringUtf16Be(s);

    // Pure-ASCII path — historical parenthesised literal form.
    std::string out;
    out.reserve(s.size() + 8);
    out.push_back('(');
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
    out.push_back(')');
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
                // pdfEscapeString returns a complete PDF string token —
                // either "(escaped)" for ASCII input or "<FEFFhex>" for
                // input containing any non-ASCII byte (F21). No outer
                // wrapping required.
                return pdfEscapeString(arg);
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

} // namespace libresign
