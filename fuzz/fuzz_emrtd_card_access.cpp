// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for emrtd::crypto::parseCardAccess and
// parseCardAccessWithParams.
// EF.CardAccess is read from the master file over a plain channel so the chip
// can say how to authenticate to it. Every byte of it therefore arrives before
// any key, PIN, CAN or MRZ exists, and none of it has been authenticated.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON.
// Run:   ./fuzz_emrtd_card_access -max_total_time=60 corpus/emrtd_card_access

// LIBRESCRS_INTERNAL_BUILD is set via target_compile_definitions in CMake.
#include "pace.h"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::vector<std::uint8_t> bytes(data, data + size);
    try {
        const auto oids = emrtd::crypto::parseCardAccess(bytes);
        for (const auto& oid : oids) {
            (void)oid.size();
        }
        const auto withParams = emrtd::crypto::parseCardAccessWithParams(bytes);
        for (const auto& [oid, paramId] : withParams) {
            (void)oid.size();
            (void)paramId;
        }
    } catch (const std::exception&) {
        // documented rejection path — keep fuzzing
    }
    return 0;
}
