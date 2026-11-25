// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_reader_gemalto.h"
#include "apdu.h"
#include <smartcard/card_connection.h>
#include <smartcard/or_throw.h>

#include <algorithm>
#include <stdexcept>
#include <string>

namespace eidcard {

namespace Core = LibreSCRS::RsEId::Core;
namespace SC = LibreSCRS::SmartCard::Internal;
using LibreSCRS::SmartCard::CardConnection;

namespace {

constexpr std::size_t kHeaderSize = 4;         // tag(2) + declared length(2, LE)
constexpr std::size_t kMaxFileSize = 65535;    // what a 16-bit length or size can say
constexpr std::uint16_t kSwProtected = 0x6982; // security status not satisfied
constexpr std::uint16_t kSwNotFound = 0x6A82;  // file or application not found

// The card has answered; asking again, or reconnecting, cannot change it. The
// two answers are tied to their command: SELECT of a file that is not there,
// READ of one that is protected. Either status on the other command is not a
// measured answer and is retried like any other failure.
bool isFinalSelect(const SC::APDUResponse& r)
{
    return r.statusWord() == kSwNotFound;
}

bool isFinalRead(const SC::APDUResponse& r)
{
    return r.statusWord() == kSwProtected;
}

// The card's answer to a command; a transport failure is not an answer and
// throws.
SC::APDUResponse send(CardConnection& conn, const SC::APDUCommand& cmd)
{
    return SC::orThrow(conn.transmit(cmd));
}

bool selectAid(CardConnection& conn, const Core::DocumentProfile& profile)
{
    const std::vector<std::uint8_t> aid(profile.aid.begin(), profile.aid.end());
    return send(conn, SC::selectByAID(aid)).isSuccess();
}

std::uint8_t hi(std::uint16_t fid)
{
    return static_cast<std::uint8_t>(fid >> 8);
}
std::uint8_t lo(std::uint16_t fid)
{
    return static_cast<std::uint8_t>(fid & 0xFF);
}

// READ BINARY with retry: re-select application + file, then reconnect + re-select.
SC::APDUResponse readBinaryWithRetry(CardConnection& conn, const Core::DocumentProfile& profile, std::uint16_t fid,
                                     std::uint16_t offset, std::uint16_t length)
{
    auto resp = send(conn, SC::readBinary(offset, length));
    if (resp.isSuccess() || isFinalRead(resp))
        return resp;

    selectAid(conn, profile);
    static_cast<void>(send(conn, SC::selectByPath(hi(fid), lo(fid), 4)));
    resp = send(conn, SC::readBinary(offset, length));
    if (resp.isSuccess() || isFinalRead(resp))
        return resp;

    SC::orThrow(conn.reconnect());
    selectAid(conn, profile);
    static_cast<void>(send(conn, SC::selectByPath(hi(fid), lo(fid), 4)));
    return send(conn, SC::readBinary(offset, length));
}

struct Opened
{
    std::vector<std::uint8_t> first; // what the first READ returned
    std::size_t total = 0;           // size of the file as far as it is read
};

// SELECT the file and read its first bytes. The first read is where a
// protected file says so. Nothing -> the card gave a final answer.
std::optional<Opened> openFile(CardConnection& conn, const Core::DocumentProfile& profile, const Core::FileSpec& spec)
{
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (attempt == 2)
            SC::orThrow(conn.reconnect());
        if (attempt > 0)
            selectAid(conn, profile);

        const auto sel = send(conn, SC::selectByPath(hi(spec.fid), lo(spec.fid), 4));
        if (isFinalSelect(sel))
            return std::nullopt;
        if (!sel.isSuccess())
            continue;

        Opened opened;
        std::size_t firstLen;
        if (spec.mode == Core::ReadMode::Allocation) {
            if (sel.data.size() < kHeaderSize)
                continue;
            // Bytes 2-3 of the reply, big-endian: how much the chip allocated.
            opened.total = static_cast<std::size_t>((sel.data[2] << 8) | sel.data[3]);
            if (opened.total == 0)
                return opened;
            // Ask for the whole file; the card, or the transport fitting the Le
            // to it, may answer less, and the read loop goes on from there.
            firstLen = std::min<std::size_t>(opened.total, kMaxFileSize);
        } else {
            firstLen = kHeaderSize;
        }

        const auto resp = send(conn, SC::readBinary(0, static_cast<std::uint16_t>(firstLen)));
        if (isFinalRead(resp))
            return std::nullopt;
        // The header is needed whole; an Allocation file may arrive in parts.
        if (!resp.isSuccess() || resp.data.size() < (spec.mode == Core::ReadMode::Header ? firstLen : 1))
            continue;

        opened.first = resp.data;
        if (spec.mode == Core::ReadMode::Allocation && opened.first.size() > opened.total)
            opened.first.resize(opened.total);
        if (spec.mode == Core::ReadMode::Header) {
            // Declared length, little-endian, at offset 2 of the header.
            opened.total = kHeaderSize + static_cast<std::size_t>(opened.first[2] | (opened.first[3] << 8));
        }
        return opened;
    }
    throw std::runtime_error("Gemalto: cannot read file " + std::to_string(spec.fid));
}

} // namespace

const Core::DocumentProfile* CardReaderGemalto::selectApplication(CardConnection& conn)
{
    for (const auto& profile : Core::documentProfiles()) {
        if (selectAid(conn, profile))
            return &profile;
    }
    return nullptr;
}

std::optional<std::vector<std::uint8_t>>
CardReaderGemalto::readFile(CardConnection& conn, const Core::DocumentProfile& profile, const Core::FileSpec& spec)
{
    const auto opened = openFile(conn, profile, spec);
    if (!opened)
        return std::nullopt;
    if (opened->total > kMaxFileSize)
        throw std::runtime_error("Gemalto: declared file length exceeds the read cap");

    std::vector<std::uint8_t> file = opened->first;
    file.reserve(opened->total);
    while (file.size() < opened->total) {
        // The rest of the file; the card may answer less, the loop advances by
        // what arrived.
        const auto want = opened->total - file.size();
        const auto resp = readBinaryWithRetry(conn, profile, spec.fid, static_cast<std::uint16_t>(file.size()),
                                              static_cast<std::uint16_t>(want));
        if (!resp.isSuccess() || resp.data.empty())
            throw std::runtime_error("Gemalto: READ BINARY failed at offset " + std::to_string(file.size()) +
                                     ", SW=" + std::to_string(resp.statusWord()));
        file.insert(file.end(), resp.data.begin(),
                    resp.data.begin() + static_cast<std::ptrdiff_t>(std::min(want, resp.data.size())));
    }
    return file;
}

} // namespace eidcard
