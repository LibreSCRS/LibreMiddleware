// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for the Serbian card TLV reader.
//
// One harness covers both Serbian families: eID and health cards read every
// field through the same little-endian 16-bit `parseTLV`, then pull named tags
// out with `findString` / `findBytes`, and `TLVField::asString` decodes UTF-16
// on the way out. Every byte here is whatever the card returned.
//
// tlv.cpp is compiled into the target (see fuzz/instrumented-sources.txt)
// because the sanitizer flags are private to the executable and do not reach a
// library over the link.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON
// Run:   ./fuzz_rs_tlv -max_total_time=60 corpus/rs_tlv

#include "tlv.h"

#include <cstddef>
#include <cstdint>

namespace {

// The tags the two Serbian readers really ask for, by value rather than by
// include: the numbers are the contract with the card, and a harness that
// looked them up through the card-protocol headers would drag a library in for
// six integers. lib/rs-eid-core/src/rs_tags.h is where they are defined.
constexpr std::uint16_t kRequestedTags[] = {
    1546, // document registration number
    1559, // surname
    1560, // given name
    1566, // date of birth
    1568, // place of birth
    1571, // address
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    using namespace LibreSCRS::SmartCard::Internal;

    const auto fields = parseTLV(data, size);

    // asString is the UTF-16 decode, and it runs on every field a reader walks.
    std::size_t sink = 0;
    for (const auto& f : fields) {
        sink += f.asString().size() + f.value.size() + f.tag;
    }

    for (const std::uint16_t tag : kRequestedTags) {
        sink += findString(fields, tag).size();
        sink += findBytes(fields, tag).size();
    }

    return sink == static_cast<std::size_t>(-1) ? 1 : 0;
}
