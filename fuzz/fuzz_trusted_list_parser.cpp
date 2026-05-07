// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for libresign::TrustedListParser::parse.
// Exercises XML structural extraction; signature verification is NOT invoked
// (see the dedicated tl_signature_verifier harness for that path).
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON.
// Run:   ./fuzz_trusted_list_parser -max_total_time=60 corpus/trusted_list_parser

// LIBRESCRS_INTERNAL_BUILD is set via target_compile_definitions in CMake.
#include "native/trusted_list_parser.h"

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    std::vector<std::uint8_t> xml(data, data + size);
    auto info = libresign::TrustedListParser::parse(xml);
    // Touch the result to keep the optimizer honest.
    (void)info.schemeTerritory.size();
    (void)info.schemeName.size();
    (void)info.services.size();
    (void)info.pointersToOtherTSL.size();
    return 0;
}
