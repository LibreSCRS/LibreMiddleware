// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for emrtd::parseDataGroups and emrtd::parseMRZ.
// External-byte attack surface: a hostile eMRTD card can return arbitrary
// bytes in any DG file slot; the DG parser dispatches per-DG sub-parsers
// (DG1 MRZ, DG2/DG7 biometric, DG11/DG12 personal data, DG13 raw).
//
// The first byte selects the DG index (mod 16) so libFuzzer can steer
// coverage between sub-parsers; remaining bytes feed the chosen DG.
// On byte sequences with size>=4 we also drive the MRZ string parser
// directly against the same payload reinterpreted as text.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON
// Run:   ./fuzz_emrtd_dg_parser -max_total_time=60 corpus/emrtd_dg_parser

#include "data_group.h"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <map>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size == 0) {
        return 0;
    }

    // Steer coverage: first byte picks the DG slot, remaining bytes are the
    // raw DG file body. Bound the index to the documented DG range.
    const int dgIndex = static_cast<int>(data[0] & 0x0F); // 0..15
    std::vector<std::uint8_t> body(data + 1, data + size);

    std::map<int, std::vector<std::uint8_t>> raw;
    raw[dgIndex] = std::move(body);

    // Card-controlled bytes must be safely rejectable: documented "garbled
    // TLV" responses surface as std::exception. Crashes / asserts /
    // sanitizer hits still abort the harness because libFuzzer catches
    // those at signal level.
    try {
        (void)emrtd::parseDataGroups(raw);
    } catch (const std::exception&) {
        // expected rejection — keep fuzzing
    }

    if (size >= 2) {
        std::string asMrz(reinterpret_cast<const char*>(data + 1), size - 1);
        try {
            (void)emrtd::parseMRZ(asMrz);
        } catch (const std::exception&) {
            // expected rejection — keep fuzzing
        }
    }

    return 0;
}
