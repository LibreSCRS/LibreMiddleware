// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "emrtd_card.h"

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <apdu.h>
#include <ber.h>

#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

namespace emrtd {

namespace {

using LibreSCRS::SmartCard::Internal::APDUCommand;

// READ BINARY with the even INS addresses 15 bits of offset: bit 8 of P1
// selects short-EF addressing. Beyond them ISO 7816-4 and ICAO 9303-10 use
// the odd INS B1, the offset in DO'54 and the data returned in DO'53.
constexpr std::size_t kMaxShortReadOffset = 0x7FFF;
constexpr std::size_t kMaxFileSize = 1024 * 1024;

APDUCommand readBinaryAt(std::size_t offset)
{
    if (offset <= kMaxShortReadOffset)
        return APDUCommand{0x00, 0xB0, static_cast<uint8_t>(offset >> 8), static_cast<uint8_t>(offset & 0xFF), {},
                           0x00, true};
    std::vector<uint8_t> offsetBytes;
    for (std::size_t v = offset; v != 0; v >>= 8)
        offsetBytes.insert(offsetBytes.begin(), static_cast<uint8_t>(v & 0xFF));
    std::vector<uint8_t> data{0x54, static_cast<uint8_t>(offsetBytes.size())};
    data.insert(data.end(), offsetBytes.begin(), offsetBytes.end());
    return APDUCommand{0x00, 0xB1, 0x00, 0x00, std::move(data), 0x00, true};
}

// A BER length at data[pos]: its value and the bytes it takes, or nothing.
// The decode is the shared one; the ceiling is this reader's: an eMRTD file
// header uses at most three length octets (`next - pos` up to 4).
std::optional<std::pair<std::size_t, std::size_t>> berLength(const std::vector<uint8_t>& data, std::size_t pos)
{
    const auto parsed = LibreSCRS::SmartCard::Internal::tryParseLength(data.data(), data.size(), pos);
    if (!parsed.ok || parsed.next - pos > 4)
        return std::nullopt;
    return std::pair<std::size_t, std::size_t>{parsed.length, parsed.next - pos};
}

// The data of an odd-INS READ BINARY answer: the value of its DO'53.
std::optional<std::vector<uint8_t>> oddInsReadData(const std::vector<uint8_t>& answer)
{
    if (answer.empty() || answer[0] != 0x53)
        return std::nullopt;
    const auto len = berLength(answer, 1);
    if (!len || 1 + len->second + len->first > answer.size())
        return std::nullopt;
    const auto begin = answer.begin() + static_cast<std::ptrdiff_t>(1 + len->second);
    return std::vector<uint8_t>(begin, begin + static_cast<std::ptrdiff_t>(len->first));
}

// The whole length of the TLV the file holds, once its header has been read;
// 0 while it has not.
std::size_t declaredLength(const std::vector<uint8_t>& fileData)
{
    if (fileData.empty())
        return 0;
    std::size_t pos = 1;
    if ((fileData[0] & 0x1F) == 0x1F) {
        while (pos < fileData.size() && (fileData[pos] & 0x80))
            ++pos;
        ++pos;
    }
    const auto len = berLength(fileData, pos);
    return len ? pos + len->second + len->first : 0;
}

} // namespace

EMRTDCard::EMRTDCard(LibreSCRS::SecureChannel::ISecureChannel& channel) : channel(channel) {}

std::optional<std::vector<uint8_t>> EMRTDCard::readFile(uint16_t fid, bool skipSelect)
{
    if (!skipSelect) {
        // SELECT file by FID (P2=0x04: return FCP template).
        // P2=0x04 makes this Case 4 (data + Le), ensuring DO'97 is included in SM.
        // Some PACE-family eIDs require DO'97 in CA-derived SM mode;
        // P2=0x0C (no response) would be Case 3 (no Le, no DO'97) → rejected with 6988.
        LibreSCRS::SmartCard::Internal::APDUCommand selectCmd{
            0x00, 0xA4, 0x02, 0x04, {static_cast<uint8_t>(fid >> 8), static_cast<uint8_t>(fid & 0xFF)}, 0, true};
        auto selectResp = channel.transmit(selectCmd, LibreSCRS::CancelToken{});
        // A failed SELECT leaves the PREVIOUS file current on many card OSes
        // — reading on would return the wrong file's bytes (e.g. a 6982 on
        // EF.SOD after a successful EF.COM read would re-read EF.COM and
        // hand it up as the "SOD"). Accept success and 62xx warnings only.
        if (selectResp.sw1 != 0x90 && selectResp.sw1 != 0x62)
            return std::nullopt;
    }

    // READ BINARY in chunks of up to 256 bytes until the length the file's
    // own TLV header declares has been read. Every answer is checked: a file
    // cut short by an error, or by an end of file before its declared end,
    // is no file.
    std::vector<uint8_t> fileData;
    std::size_t totalLength = 0;

    while (true) {
        const std::size_t offset = fileData.size();
        const bool beyondShortOffset = offset > kMaxShortReadOffset;
        auto resp = channel.transmit(readBinaryAt(offset), LibreSCRS::CancelToken{});
        const bool endOfFile = resp.statusWord() == 0x6282;
        if (!resp.isSuccess() && !endOfFile)
            return std::nullopt;

        std::vector<uint8_t> chunk;
        if (beyondShortOffset) {
            auto inner = oddInsReadData(resp.data);
            if (!inner)
                return std::nullopt;
            chunk = std::move(*inner);
        } else {
            chunk = std::move(resp.data);
        }
        if (chunk.empty())
            break;
        fileData.insert(fileData.end(), chunk.begin(), chunk.end());

        if (totalLength == 0)
            totalLength = declaredLength(fileData);
        if (totalLength > 0 && fileData.size() >= totalLength) {
            fileData.resize(totalLength);
            break;
        }
        if (endOfFile)
            break;
        if (fileData.size() > kMaxFileSize)
            return std::nullopt;
    }

    if (fileData.empty() || totalLength == 0 || fileData.size() < totalLength)
        return std::nullopt;
    return fileData;
}

std::vector<int> EMRTDCard::readCOM()
{
    auto comData = readFile(FID_COM);
    if (!comData)
        return {};

    // COM contains tag 0x60, with sub-tag 0x5C listing present DG tags
    std::vector<int> dgList;
    auto& data = *comData;

    // Find tag 0x5C (tag list)
    for (size_t i = 0; i + 1 < data.size(); ++i) {
        if (data[i] == 0x5C) {
            size_t lenPos = i + 1;
            size_t len = 0;
            size_t dataStart = 0;

            // The tag list is short: a short or 81 xx length, nothing longer
            // (`next - lenPos` 1 or 2). Anything else reads as an empty list.
            const auto parsed = LibreSCRS::SmartCard::Internal::tryParseLength(data.data(), data.size(), lenPos);
            if (parsed.ok && parsed.next - lenPos <= 2) {
                len = parsed.length;
                dataStart = parsed.next;
            }

            // Each byte in the tag list is a DG tag
            for (size_t j = dataStart; j < dataStart + len && j < data.size(); ++j) {
                uint8_t tag = data[j];
                // DG tags: 0x61=DG1, 0x75=DG2, 0x63=DG3, ...
                if (tag == 0x61)
                    dgList.push_back(1);
                else if (tag == 0x75)
                    dgList.push_back(2);
                else if (tag == 0x63)
                    dgList.push_back(3);
                else if (tag == 0x76)
                    dgList.push_back(4);
                else if (tag == 0x65)
                    dgList.push_back(5);
                else if (tag == 0x66)
                    dgList.push_back(6);
                else if (tag == 0x67)
                    dgList.push_back(7);
                else if (tag == 0x68)
                    dgList.push_back(8);
                else if (tag == 0x69)
                    dgList.push_back(9);
                else if (tag == 0x6A)
                    dgList.push_back(10);
                else if (tag == 0x6B)
                    dgList.push_back(11);
                else if (tag == 0x6C)
                    dgList.push_back(12);
                else if (tag == 0x6D)
                    dgList.push_back(13);
                else if (tag == 0x6E)
                    dgList.push_back(14);
                else if (tag == 0x6F)
                    dgList.push_back(15);
                else if (tag == 0x70)
                    dgList.push_back(16);
            }
            break;
        }
    }

    return dgList;
}

std::optional<std::vector<uint8_t>> EMRTDCard::readSOD()
{
    return readFile(FID_SOD);
}

std::optional<std::vector<uint8_t>> EMRTDCard::readDataGroup(int dgNumber)
{
    uint16_t fid = dgToFID(dgNumber);
    if (fid == 0)
        return std::nullopt;
    return readFile(fid);
}

DGReadResult EMRTDCard::readDataGroupSafe(int dgNumber)
{
    uint16_t fid = dgToFID(dgNumber);
    if (fid == 0)
        return {DGReadStatus::ERROR, {}};

    // SELECT file by FID via SM, then check the inner SW.
    // P2=0x04 (return FCP) ensures Le/DO'97 are present in SM — required by some
    // PACE-family eIDs in CA-derived SM mode (e.g. rejects P2=0x0C with 6988).
    LibreSCRS::SmartCard::Internal::APDUCommand selectCmd{
        0x00, 0xA4, 0x02, 0x04, {static_cast<uint8_t>(fid >> 8), static_cast<uint8_t>(fid & 0xFF)}, 0, true};
    auto selectResp = channel.transmit(selectCmd, LibreSCRS::CancelToken{});
    uint16_t sw = selectResp.statusWord();

    // Access denied (security status not satisfied / command not allowed)
    if (sw == 0x6982 || sw == 0x6986)
        return {DGReadStatus::ACCESS_DENIED, {}};

    // File not found
    if (sw == 0x6A82)
        return {DGReadStatus::NOT_PRESENT, {}};

    // Accept success and warning SWs (9000, 62xx)
    if (selectResp.sw1 != 0x90 && selectResp.sw1 != 0x62)
        return {DGReadStatus::ERROR, {}};

    // File selected successfully — read it, skipping the SELECT we already did
    auto data = readFile(fid, true);
    if (!data)
        return {DGReadStatus::ERROR, {}};

    return {DGReadStatus::OK, std::move(*data)};
}

std::vector<ContactPerson> EMRTDCard::parseDG16(const std::vector<uint8_t>& raw)
{
    std::vector<ContactPerson> persons;
    if (raw.empty())
        return persons;

    auto root = LibreSCRS::SmartCard::Internal::parseBER(raw.data(), raw.size());

    // DG16 outer tag is 0x70, containing one or more constructed entries.
    // Each entry may have sub-tags for name (5F0E), telephone (5F12), address (5F42).
    // The exact sub-tag set varies by issuing country — extract what we can.
    for (const auto& child : root.children) {
        // 0x70 is the DG16 wrapper tag
        if (child.tag == 0x70) {
            for (const auto& entry : child.children) {
                ContactPerson person;
                for (const auto& field : entry.children) {
                    if (field.tag == 0x5F0E)
                        person.name = field.asString();
                    else if (field.tag == 0x5F12)
                        person.telephone = field.asString();
                    else if (field.tag == 0x5F42)
                        person.address = field.asString();
                }
                // Also handle flat structure (fields directly under 0x70)
                if (entry.tag == 0x5F0E && person.name.empty())
                    person.name = entry.asString();
                else if (entry.tag == 0x5F12 && person.telephone.empty())
                    person.telephone = entry.asString();
                else if (entry.tag == 0x5F42 && person.address.empty())
                    person.address = entry.asString();

                if (!person.name.empty() || !person.telephone.empty() || !person.address.empty())
                    persons.push_back(std::move(person));
            }

            // Handle flat structure: fields directly under 0x70 without nesting
            if (persons.empty()) {
                ContactPerson person;
                for (const auto& field : child.children) {
                    if (field.tag == 0x5F0E)
                        person.name = field.asString();
                    else if (field.tag == 0x5F12)
                        person.telephone = field.asString();
                    else if (field.tag == 0x5F42)
                        person.address = field.asString();
                }
                if (!person.name.empty() || !person.telephone.empty() || !person.address.empty())
                    persons.push_back(std::move(person));
            }
        }
    }

    return persons;
}

} // namespace emrtd
