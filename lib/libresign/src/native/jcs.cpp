// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/jcs.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace libresign {

namespace {

// RFC 8259 §7 string escape. Only control characters (U+0000 – U+001F),
// the quotation mark and the reverse solidus require escaping. UTF-8
// multi-byte sequences (every continuation byte has the high bit set,
// so the unsigned value is >= 0x80) pass through unchanged, which is
// permitted by RFC 8785 §3.2.4 — the canonical form is UTF-8 and does
// not require \uXXXX escaping of codepoints above U+007F.
void escape(std::string& out, const std::string& s)
{
    out += '"';
    for (char c : s) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
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
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(static_cast<unsigned char>(c)));
                out += buf;
            } else {
                out += c;
            }
        }
    }
    out += '"';
}

// Floating-point formatting. RFC 8785 §3.2.2 mandates the full
// ECMA-262 7th ed. ToString algorithm. The current call sites never
// emit raw IEEE-754 doubles into etsiU (timestamps are RFC 3339 strings
// and array indices / counters are integers), so this simplified path
// is enough — we shunt integers through the integer fast-path above
// and only ever reach this function for genuine fractional doubles.
void formatDouble(std::string& out, double n)
{
    if (!std::isfinite(n))
        throw std::runtime_error("JCS: non-finite number");
    std::ostringstream os;
    os.precision(17);
    os << n;
    out += os.str();
}

void walk(std::string& out, const nlohmann::json& j)
{
    if (j.is_null()) {
        out += "null";
        return;
    }
    if (j.is_boolean()) {
        out += j.get<bool>() ? "true" : "false";
        return;
    }
    // Integer fast paths — safer than re-routing through double and
    // re-detecting integrality with `std::trunc(n) == n`, which loses
    // precision for 64-bit values above 2^53.
    if (j.is_number_unsigned()) {
        out += std::to_string(j.get<std::uint64_t>());
        return;
    }
    if (j.is_number_integer()) {
        out += std::to_string(j.get<std::int64_t>());
        return;
    }
    if (j.is_number_float()) {
        formatDouble(out, j.get<double>());
        return;
    }
    if (j.is_string()) {
        escape(out, j.get<std::string>());
        return;
    }
    if (j.is_binary()) {
        // nlohmann::json's binary subtype (CBOR-style) has no JSON
        // representation. JCS produces JSON, so callers must convert
        // binary payloads to base64 strings upstream.
        throw std::runtime_error("JCS does not encode binary values; convert to base64-string first");
    }
    if (j.is_array()) {
        out += '[';
        bool first = true;
        for (const auto& e : j) {
            if (!first)
                out += ',';
            walk(out, e);
            first = false;
        }
        out += ']';
        return;
    }
    if (j.is_object()) {
        // RFC 8785 §3.2.3 sorts object keys as UTF-16 code-unit
        // sequences. For ASCII-only keys (every JAdES etsiU key today —
        // sigTst, xVals, rVals, arcTst, val, tstTokens, …) the
        // UTF-8 byte-order matches the UTF-16 code-unit order. Once a
        // key carries a codepoint above U+007F that equivalence breaks
        // (UTF-8 vs UTF-16 byte values diverge, and surrogate-pair
        // handling for codepoints above U+FFFF demands a real UTF-16
        // re-encoding). Implementing that correctly needs an ICU-grade
        // codecvt — out of scope. We fail-fast instead so that a
        // future caller does not silently get a wrong canonicalization.
        std::vector<std::string> keys;
        keys.reserve(j.size());
        for (auto it = j.begin(); it != j.end(); ++it) {
            const auto& k = it.key();
            for (char c : k) {
                if (static_cast<unsigned char>(c) > 0x7f)
                    throw std::runtime_error("JCS: non-ASCII key sort not supported");
            }
            keys.push_back(k);
        }
        std::sort(keys.begin(), keys.end());
        out += '{';
        bool first = true;
        for (const auto& k : keys) {
            if (!first)
                out += ',';
            escape(out, k);
            out += ':';
            walk(out, j.at(k));
            first = false;
        }
        out += '}';
        return;
    }
    throw std::runtime_error("JCS: unsupported type");
}

} // namespace

std::string jcsDump(const nlohmann::json& j)
{
    std::string s;
    walk(s, j);
    return s;
}

} // namespace libresign
