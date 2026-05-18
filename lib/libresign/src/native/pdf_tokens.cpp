// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pdf_parser.h"
#include "pdf_tokens.h"

#include <charconv>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string_view>

namespace libresign {

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
// Utility
// ---------------------------------------------------------------------------

bool PdfParser::matchAt(size_t pos, std::string_view s) const
{
    if (pos + s.size() > raw.size())
        return false;
    return std::memcmp(raw.data() + pos, s.data(), s.size()) == 0;
}

} // namespace libresign
