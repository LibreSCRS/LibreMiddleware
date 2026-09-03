// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for emrtd::crypto::parseSOD.
// EF.SOD is read from the chip and its LDSSecurityObject eContent is walked
// before any signature over it has been checked, so every byte reaching this
// parser is whatever produced the file.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON.
// Run:   ./fuzz_emrtd_sod -max_total_time=60 corpus/emrtd_sod

// LIBRESCRS_INTERNAL_BUILD is set via target_compile_definitions in CMake.
#include "passive_auth.h"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::vector<std::uint8_t> bytes(data, data + size);
    try {
        const auto sod = emrtd::crypto::parseSOD(bytes);
        if (sod) {
            // Touch the result: every field is carved out of the input, so
            // reading them is what catches a walk that handed back a range it
            // does not own.
            (void)sod->hashAlgorithm.size();
            (void)sod->ldsVersion.size();
            (void)sod->unicodeVersion.size();
            for (const auto& [dgNum, hash] : sod->dgHashes) {
                (void)dgNum;
                (void)hash.size();
            }
        }
    } catch (const std::exception&) {
        // documented rejection path — keep fuzzing
    }
    return 0;
}
