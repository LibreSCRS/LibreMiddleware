// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Test rig that plays the card side of the CardEdge file protocol (SELECT AID,
// SELECT file by path, READ BINARY) for a detached PCSCConnection. Install it
// with setTransmitFilter; it answers like the measured chips do.

#pragma once

#include <apdu.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace LibreSCRS::RsEId::Test {

// Shape of the SELECT-by-path reply, both measured.
enum class SelectShape {
    Long10, // FID SIZE FF FF 01 00 00 00 (C2V0 chips)
    Short4  // FID SIZE (Gemalto 2014 chips)
};

class CardEdgeFileRig
{
public:
    using Bytes = std::vector<std::uint8_t>;
    using APDUCommand = LibreSCRS::SmartCard::Internal::APDUCommand;
    using APDUResponse = LibreSCRS::SmartCard::Internal::APDUResponse;

    void acceptAid(Bytes aid)
    {
        accepted.push_back(aid);
    }

    // The status word the card gives an AID it does not host: 6700 on the
    // ID/IF/RP chip, 6A82 on the EL chip.
    void rejectOtherAidsWith(std::uint16_t sw)
    {
        rejectSw = sw;
    }

    void selectReplyShape(SelectShape shape)
    {
        replyShape = shape;
    }

    // Bytes as they stand on the card, header included when the file has one;
    // the allocation reported by SELECT is bytes.size().
    void addFile(std::uint16_t fid, Bytes bytes)
    {
        files[fid] = File{std::move(bytes), 0, false};
    }

    // SELECT answers 9000 and READ BINARY 6982.
    void protectFile(std::uint16_t fid, std::uint16_t allocation)
    {
        files[fid] = File{{}, allocation, true};
    }

    int selectsOf(std::uint16_t fid) const
    {
        const auto it = selects.find(fid);
        return it == selects.end() ? 0 : it->second;
    }

    std::vector<Bytes> selectedAids() const
    {
        return aidLog;
    }

    // A detached connection cannot reconnect, so nothing in the reader reaches
    // this yet; a test seam that observes reconnects calls noteReconnect().
    int reconnects() const
    {
        return reconnectCount;
    }
    void noteReconnect()
    {
        ++reconnectCount;
    }

    APDUResponse operator()(const APDUCommand& cmd)
    {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return selectAid(cmd);
        if (cmd.ins == 0xA4 && cmd.p1 == 0x08 && cmd.p2 == 0x00 && cmd.data.size() == 2)
            return selectPath(cmd);
        if (cmd.ins == 0xB0)
            return readBinary(cmd);
        return status(0x6D00);
    }

private:
    struct File
    {
        Bytes bytes;
        std::uint16_t allocation;
        bool protectedFile;
    };

    static APDUResponse status(std::uint16_t sw, Bytes data = {})
    {
        APDUResponse r;
        r.data = std::move(data);
        r.sw1 = static_cast<std::uint8_t>(sw >> 8);
        r.sw2 = static_cast<std::uint8_t>(sw & 0xFF);
        return r;
    }

    APDUResponse selectAid(const APDUCommand& cmd)
    {
        aidLog.push_back(cmd.data);
        current.reset();
        if (std::ranges::find(accepted, cmd.data) == accepted.end())
            return status(rejectSw);
        return status(0x9000);
    }

    APDUResponse selectPath(const APDUCommand& cmd)
    {
        const auto fid = static_cast<std::uint16_t>((cmd.data[0] << 8) | cmd.data[1]);
        ++selects[fid];
        const auto it = files.find(fid);
        if (it == files.end()) {
            current.reset();
            return status(0x6A82);
        }
        current = fid;
        const auto& f = it->second;
        const auto size = f.protectedFile ? f.allocation : static_cast<std::uint16_t>(f.bytes.size());
        Bytes reply{cmd.data[0], cmd.data[1], static_cast<std::uint8_t>(size >> 8), static_cast<std::uint8_t>(size)};
        if (replyShape == SelectShape::Long10)
            reply.insert(reply.end(), {0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00});
        return status(0x9000, std::move(reply));
    }

    APDUResponse readBinary(const APDUCommand& cmd) const
    {
        if (!current)
            return status(0x6986);
        const auto& f = files.at(*current);
        if (f.protectedFile)
            return status(0x6982);
        const auto offset = static_cast<std::size_t>(((cmd.p1 & 0x7F) << 8) | cmd.p2);
        if (offset > f.bytes.size())
            return status(0x6B00);
        const std::size_t want = cmd.le == 0 ? 256 : cmd.le;
        const std::size_t n = std::min(want, f.bytes.size() - offset);
        return status(0x9000, Bytes(f.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                    f.bytes.begin() + static_cast<std::ptrdiff_t>(offset + n)));
    }

    std::vector<Bytes> accepted;
    std::vector<Bytes> aidLog;
    std::uint16_t rejectSw = 0x6700;
    SelectShape replyShape = SelectShape::Long10;
    std::map<std::uint16_t, File> files;
    std::map<std::uint16_t, int> selects;
    std::optional<std::uint16_t> current;
    int reconnectCount = 0;
};

} // namespace LibreSCRS::RsEId::Test
