// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "emrtd_card.h"

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <apdu.h>
#include <ber.h>

namespace emrtd {

EMRTDCard::EMRTDCard(LibreSCRS::SecureChannel::ISecureChannel& channel) : channel(channel) {}

std::optional<std::vector<uint8_t>> EMRTDCard::readFile(uint16_t fid, bool skipSelect)
{
    if (!skipSelect) {
        // SELECT file by FID (P2=0x04: return FCP template).
        // P2=0x04 makes this Case 4 (data + Le), ensuring DO'97 is included in SM.
        // Some chips (e.g. suite-1 ePasslet eIDs) require DO'97 in CA-derived SM mode;
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

    // READ BINARY in chunks of 256 bytes (Le=0x00 = 256 in short APDU form)
    static constexpr uint8_t READ_LE = 0x00;
    std::vector<uint8_t> fileData;
    size_t offset = 0;
    bool firstChunk = true;
    size_t totalLength = 0;

    while (true) {
        uint8_t p1 = static_cast<uint8_t>((offset >> 8) & 0x7F);
        uint8_t p2 = static_cast<uint8_t>(offset & 0xFF);
        LibreSCRS::SmartCard::Internal::APDUCommand readCmd{0x00, 0xB0, p1, p2, {}, READ_LE, true};

        auto resp = channel.transmit(readCmd, LibreSCRS::CancelToken{});
        if (resp.data.empty()) {
            break;
        }

        fileData.insert(fileData.end(), resp.data.begin(), resp.data.end());

        // Parse TLV length from first chunk to know total file size
        if (firstChunk && fileData.size() >= 4) {
            firstChunk = false;
            size_t pos = 1; // skip tag byte
            // Multi-byte tag check
            if ((fileData[0] & 0x1F) == 0x1F) {
                while (pos < fileData.size() && (fileData[pos] & 0x80))
                    pos++;
                pos++; // skip last tag byte
            }
            // Parse length
            if (pos < fileData.size()) {
                uint8_t lenByte = fileData[pos];
                if (lenByte < 0x80) {
                    totalLength = pos + 1 + lenByte;
                } else if (lenByte == 0x81 && pos + 1 < fileData.size()) {
                    totalLength = pos + 2 + fileData[pos + 1];
                } else if (lenByte == 0x82 && pos + 2 < fileData.size()) {
                    totalLength = pos + 3 + (fileData[pos + 1] << 8 | fileData[pos + 2]);
                } else if (lenByte == 0x83 && pos + 3 < fileData.size()) {
                    totalLength = pos + 4 + (fileData[pos + 1] << 16 | fileData[pos + 2] << 8 | fileData[pos + 3]);
                }
            }
        }

        offset += resp.data.size();

        // Stop if we've read enough
        if (totalLength > 0 && fileData.size() >= totalLength) {
            fileData.resize(totalLength);
            break;
        }

        // Safety: stop after 1MB
        if (fileData.size() > 1024 * 1024)
            break;
    }

    if (fileData.empty())
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

            if (data[lenPos] < 0x80) {
                len = data[lenPos];
                dataStart = lenPos + 1;
            } else if (data[lenPos] == 0x81 && lenPos + 1 < data.size()) {
                len = data[lenPos + 1];
                dataStart = lenPos + 2;
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
    // chips in CA-derived SM mode (e.g. a suite-1 ePasslet eID rejects P2=0x0C with 6988).
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
