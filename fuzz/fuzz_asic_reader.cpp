// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for the ASiC-E container reader.
//
// The container is a file the user brings, and reading it means running a
// vendored ZIP decoder over every byte of it before anything has verified a
// signature. Both the reader and the decoder are compiled into this target
// (see fuzz/instrumented-sources.txt): a harness that only linked them would
// fuzz uninstrumented code, and the fault worth finding here -- a read past
// the end of a buffer whose length the archive header declared -- is in the
// decoder.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON
// Run:   ./fuzz_asic_reader -max_total_time=60 corpus/asic_reader

#include "native/asic_module.h"

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    // The reader takes a vector by reference; copying is the interface, not a
    // choice the harness gets to make.
    const std::vector<std::uint8_t> input(data, data + size);

    const auto parsed = libresign::detail::tryParseAsic(input);
    if (!parsed) {
        // The signing entry point does not stop when the reader refuses: it
        // probes the same bytes again to tell a recognisable ASiC-E container
        // apart from a blob. That second read is reached ONLY on this branch,
        // which is why an uncapped extraction survived beneath a capped one --
        // the harness returned here and never drove it.
        (void)libresign::detail::probeAsic(input);
        return 0;
    }

    // Touch everything the caller goes on to use, so a length the archive
    // declared and the reader believed is actually dereferenced.
    std::size_t total = parsed->dataFileBytes.size() + parsed->dataFileName.size();
    for (const auto& entry : parsed->preservedMeta) {
        total += entry.name.size() + entry.data.size();
        if (!entry.data.empty()) {
            total += entry.data.front() + entry.data.back();
        }
    }
    if (!parsed->dataFileBytes.empty()) {
        total += parsed->dataFileBytes.front() + parsed->dataFileBytes.back();
    }
    return (total == static_cast<std::size_t>(-1) && parsed->nextSigNum < 0) ? 1 : 0;
}
