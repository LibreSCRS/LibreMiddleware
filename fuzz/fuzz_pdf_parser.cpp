// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for the PDF xref / trailer walker.
//
// The document a user signs is the most hostile input this project reads: it
// arrives by mail or download and goes straight into the signing wizard, and
// pdf_parser.cpp is a hand-written xref-table and xref-stream walker with a
// tokenizer and a value tree behind it. All three translation units are
// compiled into this target (see fuzz/instrumented-sources.txt) because the
// sanitizer flags are private to the executable and do not reach a library
// over the link.
//
// Entry points, in the order a caller uses them: parse(), then the trailer and
// the page lookups. pageObjectNumber() and pageObject() throw by contract on a
// structural error, so catching that is a documented outcome rather than a
// swallowed fault -- the sanitizers report before the throw, and libFuzzer's
// own handlers catch a crash or an abort earlier still.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON
// Run:   ./fuzz_pdf_parser -max_total_time=60 corpus/pdf_parser

#include "native/pdf_parser.h"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size == 0) {
        return 0;
    }

    std::span<const std::uint8_t> input(data, size);

    // findStartXref is reachable without a parse and has its own scan loop. It
    // throws when there is no startxref keyword at all, which for a fuzzer is
    // the common case, so the catch is the documented outcome and not a
    // swallowed fault: a sanitizer report happens before the throw.
    try {
        (void)libresign::PdfParser::findStartXref(input);
    } catch (...) {
    }

    libresign::PdfParser parser(input);
    bool parsed = false;
    try {
        parsed = parser.parse();
    } catch (...) {
        return 0;
    }
    if (!parsed) {
        return 0;
    }

    try {
        (void)parser.trailer();
        (void)parser.resolvedXrefOffset();
    } catch (...) {
    }

    // A parsed file still gets to choose every object number it names.
    for (int page = 0; page < 3; ++page) {
        try {
            const int objNum = parser.pageObjectNumber(page);
            (void)parser.readObject(objNum);
            (void)parser.pageObject(page);
        } catch (const std::exception&) {
            break;
        } catch (...) {
            break;
        }
    }

    return 0;
}
