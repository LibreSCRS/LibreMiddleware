// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for emrtd::crypto::parseCscaMasterList.
// A hand-written ASN.1 walk over a published CSCA master list. It runs BEFORE
// anything has verified the object — the signature is not checked here, that is
// parseAndVerifyMasterList's job — so every byte reaching this parser is
// whatever produced the file, an attacker included.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON.
// Run:   ./fuzz_csca_master_list -max_total_time=60 corpus/csca_master_list

// LIBRESCRS_INTERNAL_BUILD is set via target_compile_definitions in CMake.
#include "csca_master_list.h"

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::vector<std::uint8_t> der(data, data + size);
    const auto list = emrtd::crypto::parseCscaMasterList(der);
    if (list) {
        // Touch the result to keep the optimizer honest. Each element is a
        // slice of the input, so reading them is also what catches a walk that
        // handed back a range it does not own.
        (void)list->cscaDer.size();
        for (const auto& anchor : list->cscaDer) {
            (void)anchor.size();
        }
    }
    return 0;
}
