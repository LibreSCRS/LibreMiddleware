// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "eu-vrc/eu_vrc_card.h"
#include "eu_vrc_detection.h"
#include "eu_vrc_protocol.h"

#include <smartcard/apdu.h>
#include <smartcard/ber.h>
#include <smartcard/pcsc_connection.h>

#include <algorithm>
#include <stdexcept>

namespace euvrc {

std::string formatVrcDate(const std::string& raw)
{
    if (raw.size() == 8 && std::all_of(raw.begin(), raw.end(), ::isdigit))
        return raw.substr(6, 2) + "." + raw.substr(4, 2) + "." + raw.substr(0, 4);
    return raw;
}

bool EuVrcCard::probe(const std::string& readerName)
{
    try
    {
        smartcard::PCSCConnection conn(readerName);
        return probe(conn);
    }
    catch (...)
    {
        return false;
    }
}

bool EuVrcCard::probe(smartcard::PCSCConnection& conn)
{
    try
    {
        return euvrc::probe(conn);
    }
    catch (...)
    {
        return false;
    }
}

EuVrcCard::EuVrcCard(const std::string& readerName)
{
    ownedConnection = std::make_unique<smartcard::PCSCConnection>(readerName);
    conn = ownedConnection.get();

    if (!detect(*conn))
    {
        throw std::runtime_error("EU VRC card initialization failed on reader: " + readerName);
    }
}

EuVrcCard::EuVrcCard(smartcard::PCSCConnection& externalConn) : conn(&externalConn)
{
    if (!detect(*conn))
    {
        throw std::runtime_error("EU VRC card initialization failed");
    }
}

EuVrcCard::~EuVrcCard() = default;

std::vector<uint8_t> EuVrcCard::readFile(uint8_t fidHi, uint8_t fidLo)
{
    // SELECT file: P1=02 P2=04 no Le
    smartcard::APDUCommand selectCmd{
        .cla = 0x00, .ins = 0xA4, .p1 = 0x02, .p2 = 0x04,
        .data = {fidHi, fidLo}, .le = 0, .hasLe = false};
    auto selectResp = conn->transmit(selectCmd);
    if (!selectResp.isSuccess())
    {
        return {}; // File not present
    }

    // Extract file size from FCI response (tag 81 = file size in SELECT response)
    // FCI format: 62 <len> 81 02 <sizeHi> <sizeLo> ...
    size_t fileSize = 0;
    if (selectResp.data.size() >= 4)
    {
        try
        {
            auto fci = smartcard::parseBER(selectResp.data.data(), selectResp.data.size());
            for (const auto& child : fci.children)
            {
                if (child.tag == 0x62)
                {
                    for (const auto& field : child.children)
                    {
                        if (field.tag == 0x81 && field.value.size() >= 2)
                        {
                            fileSize = (static_cast<size_t>(field.value[0]) << 8) | field.value[1];
                        }
                    }
                }
                // Some cards return 81 directly (not wrapped in 62)
                if (child.tag == 0x81 && child.value.size() >= 2)
                {
                    fileSize = (static_cast<size_t>(child.value[0]) << 8) | child.value[1];
                }
            }
        }
        catch (...)
        {
        }
    }

    // Read file header to determine data offset
    auto headerResp = conn->transmit(smartcard::readBinary(0, protocol::FILE_HEADER_SIZE));
    if (!headerResp.isSuccess() || headerResp.data.size() < 2)
    {
        return {};
    }

    const auto& hdr = headerResp.data;

    // Determine data offset — try BER parse from byte 0, fallback to header-skip
    size_t dataOffset = 0;
    bool parsedFromZero = false;
    try
    {
        auto testParse = smartcard::parseBER(hdr.data(), hdr.size());
        if (!testParse.children.empty())
        {
            parsedFromZero = true;
        }
    }
    catch (...)
    {
    }

    if (!parsedFromZero)
    {
        // Header-skip fallback: offset = byte[1] + 2 (NXP eVL cards)
        dataOffset = static_cast<size_t>(hdr[1]) + 2;
        if (dataOffset >= hdr.size())
        {
            return {};
        }
    }

    // Determine total bytes to read
    size_t totalToRead = 0;
    if (fileSize > 0 && fileSize > dataOffset)
    {
        // Use FCI-reported file size (most reliable)
        totalToRead = fileSize - dataOffset;
    }
    else
    {
        // Fallback: parse BER tag/length from header to determine content length
        size_t parseOffset = dataOffset;
        if (parseOffset >= hdr.size())
        {
            return {};
        }
        // Parse tag
        size_t tagStart = parseOffset;
        if ((hdr[parseOffset] & 0x1F) == 0x1F)
        {
            parseOffset++;
            while (parseOffset < hdr.size() && (hdr[parseOffset] & 0x80))
            {
                parseOffset++;
            }
            parseOffset++;
        }
        else
        {
            parseOffset++;
        }
        size_t tagLen = parseOffset - tagStart;
        // Parse length
        if (parseOffset >= hdr.size())
        {
            return {};
        }
        size_t dataLength = 0;
        size_t lenBytes = 0;
        if (hdr[parseOffset] < 0x80)
        {
            dataLength = hdr[parseOffset];
            lenBytes = 1;
        }
        else
        {
            size_t numLenBytes = hdr[parseOffset] & 0x7F;
            lenBytes = 1 + numLenBytes;
            parseOffset++;
            for (size_t i = 0; i < numLenBytes && parseOffset < hdr.size(); i++)
            {
                dataLength = (dataLength << 8) | hdr[parseOffset++];
            }
        }
        totalToRead = tagLen + lenBytes + dataLength;
    }

    // Read the actual file data in chunks
    std::vector<uint8_t> fileData;
    fileData.reserve(totalToRead);
    uint16_t offset = static_cast<uint16_t>(dataOffset);
    uint8_t chunkSize = protocol::READ_CHUNK_LARGE;

    while (fileData.size() < totalToRead)
    {
        uint8_t thisChunk = static_cast<uint8_t>(
            std::min(static_cast<size_t>(chunkSize), totalToRead - fileData.size()));

        auto readResp = conn->transmit(smartcard::readBinary(offset, thisChunk));
        if (!readResp.isSuccess())
        {
            if (chunkSize == protocol::READ_CHUNK_LARGE)
            {
                // Fall back to smaller chunk size
                chunkSize = protocol::READ_CHUNK_SMALL;
                continue;
            }
            break;
        }

        if (readResp.data.empty())
        {
            break;
        }

        fileData.insert(fileData.end(), readResp.data.begin(), readResp.data.end());
        offset += static_cast<uint16_t>(readResp.data.size());
    }

    return fileData;
}

EuVrcData EuVrcCard::readCard()
{
    // Read all data files and merge BER trees
    smartcard::BERField merged;
    merged.tag = 0;
    merged.constructed = true;

    auto standardFids = getStandardFileFids();
    auto nationalFids = getNationalExtensionFids();

    // Collect binary file data separately
    std::vector<uint8_t> sigA, sigB, crtA, crtB;
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> addSigs, addCerts;

    auto parseBerFile = [&](const std::vector<uint8_t>& raw) {
        try
        {
            auto parsed = smartcard::parseBER(raw.data(), raw.size());
            smartcard::mergeBER(merged, parsed);
        }
        catch (...)
        {
            // If BER parse fails from byte 0, try header-skip
            if (raw.size() > 2)
            {
                size_t skipOffset = static_cast<size_t>(raw[1]) + 2;
                if (skipOffset < raw.size())
                {
                    try
                    {
                        auto parsed = smartcard::parseBER(
                            raw.data() + skipOffset, raw.size() - skipOffset);
                        smartcard::mergeBER(merged, parsed);
                    }
                    catch (...)
                    {
                    }
                }
            }
        }
    };

    // Read standard files
    for (const auto& fid : standardFids)
    {
        auto raw = readFile(fid.fidHi, fid.fidLo);
        if (raw.empty())
            continue;

        uint16_t fidWord = (static_cast<uint16_t>(fid.fidHi) << 8) | fid.fidLo;

        if (fid.isBerTlv)
        {
            parseBerFile(raw);
        }
        else
        {
            if (fidWord == 0xE001)
                sigA = std::move(raw);
            else if (fidWord == 0xE011)
                sigB = std::move(raw);
            else if (fidWord == 0xC001)
                crtA = std::move(raw);
            else if (fidWord == 0xC011)
                crtB = std::move(raw);
        }
    }

    // Probe national extension files
    for (const auto& fid : nationalFids)
    {
        auto raw = readFile(fid.fidHi, fid.fidLo);
        if (raw.empty())
            continue;

        uint16_t fidWord = (static_cast<uint16_t>(fid.fidHi) << 8) | fid.fidLo;

        if (fid.isBerTlv)
        {
            parseBerFile(raw);
        }
        else
        {
            if (fid.fidHi == 0xE0)
                addSigs.push_back({fidWord, std::move(raw)});
            else if (fid.fidHi == 0xC0)
                addCerts.push_back({fidWord, std::move(raw)});
        }
    }

    // Extract fields from merged BER tree
    EuVrcData result = extractFields(merged);

    // Attach binary data
    result.signatureA = std::move(sigA);
    result.signatureB = std::move(sigB);
    result.certA = std::move(crtA);
    result.certB = std::move(crtB);
    result.additionalSignatures = std::move(addSigs);
    result.additionalCerts = std::move(addCerts);

    return result;
}

namespace {

// Recursively collect national extension tags from all levels of a container
void collectNationalTags(const smartcard::BERField& container, EuVrcData& data)
{
    for (const auto& child : container.children)
    {
        if (protocol::isNationalExtensionTag(child.tag) && !child.value.empty())
        {
            data.nationalTags.push_back({child.tag, child.asString()});
        }
        // Recurse into constructed (container) children
        if (child.constructed && !child.children.empty())
        {
            collectNationalTags(child, data);
        }
    }
}

} // anonymous namespace

EuVrcData extractFields(const smartcard::BERField& root)
{
    EuVrcData data;

    // Metadata (can be in either 71 or 72)
    data.version = smartcard::berFindString(root, {0x71, 0x80});
    data.memberState = smartcard::berFindString(root, {0x71, 0x9F33});
    data.competentAuthority = smartcard::berFindString(root, {0x71, 0x9F35});
    data.issuingAuthority = smartcard::berFindString(root, {0x71, 0x9F36});
    data.documentNumber = smartcard::berFindString(root, {0x71, 0x9F38});
    data.previousDocument = smartcard::berFindString(root, {0x71, 0x9F34});

    // EU mandatory (tag 71)
    data.registrationNumber = smartcard::berFindString(root, {0x71, 0x81});
    data.firstRegistration = formatVrcDate(smartcard::berFindString(root, {0x71, 0x82}));
    data.holderName = smartcard::berFindString(root, {0x71, 0xA1, 0xA2, 0x83});
    data.holderOtherNames = smartcard::berFindString(root, {0x71, 0xA1, 0xA2, 0x84});
    data.holderAddress = smartcard::berFindString(root, {0x71, 0xA1, 0xA2, 0x85});
    data.ownershipStatus = smartcard::berFindString(root, {0x71, 0x86});
    data.vehicleMake = smartcard::berFindString(root, {0x71, 0xA3, 0x87});
    data.vehicleType = smartcard::berFindString(root, {0x71, 0xA3, 0x88});
    data.commercialDesc = smartcard::berFindString(root, {0x71, 0xA3, 0x89});
    data.vin = smartcard::berFindString(root, {0x71, 0x8A});
    data.maxLadenMass = smartcard::berFindString(root, {0x71, 0xA4, 0x8B});
    data.vehicleMass = smartcard::berFindString(root, {0x71, 0x8C});
    data.expiryDate = formatVrcDate(smartcard::berFindString(root, {0x71, 0x8D}));
    data.registrationDate = formatVrcDate(smartcard::berFindString(root, {0x71, 0x8E}));
    data.typeApproval = smartcard::berFindString(root, {0x71, 0x8F});
    data.engineCapacity = smartcard::berFindString(root, {0x71, 0xA5, 0x90});
    data.maxNetPower = smartcard::berFindString(root, {0x71, 0xA5, 0x91});
    data.fuelType = smartcard::berFindString(root, {0x71, 0xA5, 0x92});
    data.powerWeightRatio = smartcard::berFindString(root, {0x71, 0x93});
    data.numberOfSeats = smartcard::berFindString(root, {0x71, 0xA6, 0x94});
    data.standingPlaces = smartcard::berFindString(root, {0x71, 0xA6, 0x95});

    // EU optional (tag 72)
    data.maxLadenMassService = smartcard::berFindString(root, {0x72, 0xA4, 0x96});
    data.maxLadenMassWhole = smartcard::berFindString(root, {0x72, 0xA4, 0x97});
    data.vehicleCategory = smartcard::berFindString(root, {0x72, 0x98});
    data.numberOfAxles = smartcard::berFindString(root, {0x72, 0x99});
    data.wheelbase = smartcard::berFindString(root, {0x72, 0x9A});
    data.brakedTrailerMass = smartcard::berFindString(root, {0x72, 0x9B});
    data.unbrakedTrailerMass = smartcard::berFindString(root, {0x72, 0x9C});
    data.ratedEngineSpeed = smartcard::berFindString(root, {0x72, 0xA5, 0x9D});
    data.engineIdNumber = smartcard::berFindString(root, {0x72, 0xA5, 0x9E});
    data.colour = smartcard::berFindString(root, {0x72, 0x9F24});
    data.maxSpeed = smartcard::berFindString(root, {0x72, 0x9F25});
    data.stationarySoundLevel = smartcard::berFindString(root, {0x72, 0x9F26});
    data.engineSpeedRef = smartcard::berFindString(root, {0x72, 0x9F27});
    data.driveBySound = smartcard::berFindString(root, {0x72, 0x9F28});
    data.fuelConsumption = smartcard::berFindString(root, {0x72, 0x9F2F});
    data.co2 = smartcard::berFindString(root, {0x72, 0x9F30});
    data.envCategory = smartcard::berFindString(root, {0x72, 0x9F31});
    data.fuelTankCapacity = smartcard::berFindString(root, {0x72, 0x9F32});

    // Owner2 (C.2)
    data.owner2Name = smartcard::berFindString(root, {0x71, 0xA1, 0xA7, 0x83});

    // User (C.3) — try 71 first, fallback to 72
    data.userName = smartcard::berFindString(root, {0x71, 0xA1, 0xA9, 0x83});
    data.userOtherNames = smartcard::berFindString(root, {0x71, 0xA1, 0xA9, 0x84});
    data.userAddress = smartcard::berFindString(root, {0x71, 0xA1, 0xA9, 0x85});
    if (data.userName.empty() && data.userOtherNames.empty() && data.userAddress.empty())
    {
        data.userName = smartcard::berFindString(root, {0x72, 0xA1, 0xA9, 0x83});
        data.userOtherNames = smartcard::berFindString(root, {0x72, 0xA1, 0xA9, 0x84});
        data.userAddress = smartcard::berFindString(root, {0x72, 0xA1, 0xA9, 0x85});
    }

    // National extensions — tags >= 0xC0, search recursively in both 71 and 72 containers
    for (const auto& child : root.children)
    {
        if (child.tag == 0x71 || child.tag == 0x72)
        {
            collectNationalTags(child, data);
        }
    }

    return data;
}

} // namespace euvrc
