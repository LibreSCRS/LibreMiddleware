// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>

namespace libresign {

// PDF lexical primitives — shared between the tokenizer (parseValue family)
// and the xref / object-header readers in PdfParser. Both predicates follow
// ISO 32000-1 §7.2 verbatim.

inline bool isPdfWhitespace(uint8_t c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\0' || c == '\f';
}

inline bool isPdfDelimiter(uint8_t c)
{
    return c == '(' || c == ')' || c == '<' || c == '>' || c == '[' || c == ']' || c == '{' || c == '}' || c == '/' ||
           c == '%';
}

} // namespace libresign
