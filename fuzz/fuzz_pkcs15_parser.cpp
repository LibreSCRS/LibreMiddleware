// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for the pkcs15 parser entry points.
// Drives every public parser overload (ODF / TokenInfo / CDF / PrKDF / AODF)
// with the same fuzz input — each must reject malformed bytes cleanly
// (no crash, no leak, no unbounded allocation).
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON; binary lands in build-fuzz/fuzz/.
// Run:   ./fuzz_pkcs15_parser -max_total_time=60 corpus/pkcs15_parser

#include "pkcs15_parser.h"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>

namespace {

template <typename Fn>
void runCatching(Fn&& fn)
{
    // The pkcs15 parsers signal malformed input by throwing std::exception
    // (BER walker raises "unexpected end of data"). Treat that as the
    // documented rejection path — a CARD-controlled byte stream MUST be
    // safely rejectable. Crashes / asserts / sanitizer hits still surface
    // because libFuzzer's signal handler catches them earlier.
    try {
        fn();
    } catch (const std::exception&) {
        // expected rejection — keep fuzzing
    } catch (...) {
        // non-std exception: re-throw so it crashes the harness and we
        // find out which non-standard type the parser is leaking.
        throw;
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    std::span<const std::uint8_t> bytes(data, size);

    runCatching([&] { (void)pkcs15::parseODF(bytes); });
    runCatching([&] { (void)pkcs15::parseTokenInfo(bytes); });
    runCatching([&] { (void)pkcs15::parseCDF(bytes); });
    runCatching([&] { (void)pkcs15::parsePrKDF(bytes); });
    runCatching([&] { (void)pkcs15::parseAODF(bytes); });

    return 0;
}
