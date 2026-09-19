// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for the EU vehicle-registration path.
//
// Two entry points, both over bytes the card chose:
//   * detail::deriveEuVrcHeader decides where the body starts and how many
//     bytes still have to be read. The first eight bytes of the input become
//     the size the FCI claimed -- including zero, which is the branch that
//     decodes a BER length instead of trusting the FCI.
//   * extractFields walks the merged BER tree into the fields a user sees.
//     collectNationalTags is reached through it.
//
// eu_vrc_card.cpp, ber.cpp and tlv.cpp are compiled into the target (see
// fuzz/instrumented-sources.txt), because the sanitizer flags are private to
// the executable and do not reach a library over the link.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON
// Run:   ./fuzz_eu_vrc -max_total_time=60 corpus/eu_vrc

#include "ber.h"
#include "eu_vrc_card.h"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size < 8) {
        return 0;
    }

    // First eight bytes: the size the FCI reported. Zero is deliberately
    // reachable -- it is the only way into the length-decoding branch.
    std::size_t fciFileSize = 0;
    for (int i = 0; i < 8; ++i) {
        fciFileSize = (fciFileSize << 8) | data[i];
    }

    const std::span<const std::uint8_t> hdr(data + 8, size - 8);

    std::size_t sink = 0;
    const auto header = euvrc::detail::deriveEuVrcHeader(hdr, fciFileSize);
    if (header) {
        sink += header->dataOffset + header->totalToRead;
    }

    try {
        const auto root = LibreSCRS::SmartCard::Internal::parseBER(hdr.data(), hdr.size());
        const auto fields = euvrc::extractFields(root);
        sink += fields.registrationNumber.size() + fields.vehicleMake.size() + fields.vin.size();
        for (const auto& national : fields.nationalTags) {
            sink += national.first + national.second.size();
        }
    } catch (...) {
        // parseBER throws on a truncated or indefinite length; the documented
        // rejection path, and the sanitizers report before the throw.
    }

    return sink == static_cast<std::size_t>(-1) ? 1 : 0;
}
