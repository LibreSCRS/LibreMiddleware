// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for the BER-TLV walker.
//
// This is the canonical decoder the tree consolidated its length decodes onto,
// and it had no harness at all -- which is also what would have made any later
// consolidation a change with no measurement behind it. It runs over vehicle
// registration files, EF.CardAccess and everything else that arrives as
// ISO 7816-4 BER-TLV, so the bytes are the chip's choice.
//
// ber.cpp and tlv.cpp are compiled into the target (see
// fuzz/instrumented-sources.txt): asString lives in tlv.cpp and the walker
// calls it.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON
// Run:   ./fuzz_ber -max_total_time=60 corpus/ber
//
// The recursion depth is already bounded inside parseBER (maxDepth = 32), so a
// nested input is a coverage target rather than an expected crash. Lower that
// bound and this harness finds the stack exhaustion, which is what makes the
// bound measurable rather than asserted.

#include "ber.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

std::size_t walk(const LibreSCRS::SmartCard::Internal::BERField& node)
{
    std::size_t sink = node.tag + node.value.size() + node.asString().size();
    for (const auto& child : node.children) {
        sink += walk(child);
    }
    return sink;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    using namespace LibreSCRS::SmartCard::Internal;

    std::size_t sink = 0;
    try {
        const BERField root = parseBER(data, size);
        sink += walk(root);
    } catch (...) {
        // parseBER throws on a truncated or indefinite length; that is the
        // documented rejection path, and a sanitizer reports before the throw.
        return 0;
    }

    // The flag-returning pair, straight, at every offset a caller might pick.
    for (std::size_t pos = 0; pos < size && pos < 64; ++pos) {
        const TagResult t = tryParseTag(data, size, pos);
        if (t.ok) {
            sink += t.tag + t.next;
            const LengthResult l = tryParseLength(data, size, t.next);
            if (l.ok) {
                sink += l.length + l.next;
            }
        }
    }

    return sink == static_cast<std::size_t>(-1) ? 1 : 0;
}
