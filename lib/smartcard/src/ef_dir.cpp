// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ef_dir.h"

namespace LibreSCRS::SmartCard::Internal {

std::vector<EfDirEntry> parseEfDir(std::span<const uint8_t> data)
{
    std::vector<EfDirEntry> entries;
    size_t pos = 0;

    while (pos + 2 <= data.size()) {
        if (data[pos] != 0x61) {
            ++pos;
            continue;
        }
        const size_t entryLen = data[pos + 1];
        const size_t entryEnd = pos + 2 + entryLen;
        if (entryEnd > data.size()) {
            break;
        }

        EfDirEntry entry;
        size_t f = pos + 2;
        while (f + 2 <= entryEnd) {
            const uint8_t tag = data[f];
            const size_t len = data[f + 1];
            if (f + 2 + len > entryEnd) {
                break;
            }
            const auto begin = data.begin() + static_cast<ptrdiff_t>(f + 2);
            const auto end = begin + static_cast<ptrdiff_t>(len);
            if (tag == 0x4F) {
                entry.aid.assign(begin, end);
            } else if (tag == 0x50) {
                entry.label.assign(begin, end);
            } else if (tag == 0x51) {
                entry.path.assign(begin, end);
            }
            f += 2 + len;
        }

        if (!entry.aid.empty()) {
            entries.push_back(std::move(entry));
        }
        pos = entryEnd;
    }

    return entries;
}

} // namespace LibreSCRS::SmartCard::Internal
