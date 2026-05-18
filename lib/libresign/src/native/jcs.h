// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <json.hpp>

#include <string>

namespace libresign {

/// @brief Serialize a JSON value per the JSON Canonicalization Scheme
///        (RFC 8785).
///
/// Differences from @c nlohmann::json::dump :
/// - Object keys emitted in lexicographic order (RFC 8785 §3.2.3).
/// - Strings JSON-escaped per RFC 8259 §7 — only control characters
///   (U+0000 – U+001F), `"` and `\` are escaped; multi-byte UTF-8
///   sequences pass through untouched.
/// - Numbers formatted per RFC 8785 §3.2.2 (ECMA-262 7th ed. ToString),
///   with the integer fast-path used whenever the JSON value carries
///   an integral subtype.
/// - No whitespace, no trailing commas.
///
/// Used by the JAdES B-LTA arcTst imprint canonicalization
/// (ETSI TS 119 182-1 §5.3.5) so that strict validators that recompute
/// the imprint over JCS-canonical etsiU entries agree with our output.
///
/// @param j The JSON value to canonicalize.
/// @return The RFC 8785 canonical UTF-8 serialization.
/// @throws std::runtime_error If @p j contains a non-finite number
///         (NaN / ±Inf), a binary value, or an object key that
///         contains a non-ASCII byte (codepoint > U+007F — see
///         implementation note in @c jcs.cpp).
[[nodiscard]] std::string jcsDump(const nlohmann::json& j);

} // namespace libresign
