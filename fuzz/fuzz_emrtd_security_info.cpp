// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for emrtd::crypto::parseDG14 and parseDG15.
// Both data groups are read from the chip and walked before any signature over
// them has been checked, so their bytes are card-controlled. DG14 in particular
// decides which chip authentication the middleware will then attempt.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON.
// Run:   ./fuzz_emrtd_security_info -max_total_time=60 corpus/emrtd_security_info

// LIBRESCRS_INTERNAL_BUILD is set via target_compile_definitions in CMake.
#include "active_auth.h"
#include "chip_auth.h"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::vector<std::uint8_t> bytes(data, data + size);
    try {
        std::vector<emrtd::crypto::ChipAuthInfo> infos;
        std::vector<emrtd::crypto::ChipAuthPublicKey> keys;
        if (emrtd::crypto::parseDG14(bytes, infos, keys)) {
            for (const auto& info : infos) {
                (void)info.oid.size();
            }
            for (const auto& key : keys) {
                (void)key.publicKey.size();
            }
        }
        const auto aaKey = emrtd::crypto::parseDG15(bytes);
        (void)aaKey.publicKeyDER.size();
    } catch (const std::exception&) {
        // documented rejection path — keep fuzzing
    }
    return 0;
}
