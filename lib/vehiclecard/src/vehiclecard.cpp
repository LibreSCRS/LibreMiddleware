// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "vehiclecard/vehiclecard.h"
#include "vehicle_protocol.h"
#include "smartcard/apdu.h"
#include "smartcard/ber.h"
#include "smartcard/pcsc_connection.h"
#include <algorithm>
#include <stdexcept>

namespace vehiclecard {

// Format "YYYYMMDD" → "DD.MM.YYYY", pass through anything else unchanged
static std::string formatDate(const std::string& raw)
{
    if (raw.size() == 8 && std::all_of(raw.begin(), raw.end(), ::isdigit))
        return raw.substr(6, 2) + "." + raw.substr(4, 2) + "." + raw.substr(0, 4);
    return raw;
}

bool VehicleCard::probe(const std::string& readerName)
{
    try {
        smartcard::PCSCConnection conn(readerName);
        return probe(conn);
    } catch (...) {
        return false;
    }
}

bool VehicleCard::probe(smartcard::PCSCConnection& conn)
{
    try {
        auto tryAID = [&conn](const std::vector<uint8_t>& aid) -> bool {
            auto resp = conn.transmit(smartcard::selectByAID(aid));
            return resp.isSuccess();
        };

        return tryAID(protocol::SEQ1_CMD1) || (tryAID(protocol::SEQ2_CMD1) && tryAID(protocol::SEQ2_CMD2)) ||
               tryAID(protocol::SEQ3_CMD1);
    } catch (...) {
        return false;
    }
}

VehicleCard::VehicleCard(const std::string& readerName)
{
    ownedConnection = std::make_unique<smartcard::PCSCConnection>(readerName);
    conn = ownedConnection.get();

    if (!initCard()) {
        throw std::runtime_error("Vehicle card initialization failed on reader: " + readerName);
    }
}

VehicleCard::VehicleCard(smartcard::PCSCConnection& externalConn) : conn(&externalConn)
{
    if (!initCard()) {
        throw std::runtime_error("Vehicle card initialization failed");
    }
}

VehicleCard::~VehicleCard() = default;

bool VehicleCard::initCard()
{
    // Try three AID selection sequences
    auto trySequence = [this](const std::vector<uint8_t>& cmd1, const std::vector<uint8_t>& cmd2,
                              const std::vector<uint8_t>& cmd3) -> bool {
        // First SELECT (P2=0x00)
        auto resp = conn->transmit(smartcard::selectByAID(cmd1));
        if (!resp.isSuccess()) {
            return false;
        }

        // Second SELECT (P2=0x00)
        resp = conn->transmit(smartcard::selectByAID(cmd2));
        // Don't check response - continue regardless

        // Third SELECT (P2=0x0C)
        smartcard::APDUCommand cmd3apdu{
            .cla = 0x00, .ins = 0xA4, .p1 = 0x04, .p2 = 0x0C, .data = cmd3, .le = 0, .hasLe = false};
        resp = conn->transmit(cmd3apdu);
        // Don't check response - continue regardless

        return true;
    };

    // Sequence 1
    if (trySequence(protocol::SEQ1_CMD1, protocol::SEQ1_CMD2, protocol::SEQ1_CMD3)) {
        return true;
    }

    // Sequence 2
    if (trySequence(protocol::SEQ2_CMD1, protocol::SEQ2_CMD2, protocol::SEQ1_CMD3)) {
        return true;
    }

    // Sequence 3
    if (trySequence(protocol::SEQ3_CMD1, protocol::SEQ3_CMD2, protocol::SEQ3_CMD3)) {
        return true;
    }

    return false;
}

std::vector<uint8_t> VehicleCard::readFile(const std::vector<uint8_t>& fileId)
{
    // SELECT file: 00 A4 02 04 <fileId> 00
    smartcard::APDUCommand selectCmd{
        .cla = 0x00, .ins = 0xA4, .p1 = 0x02, .p2 = 0x04, .data = fileId, .le = 0, .hasLe = false};
    auto selectResp = conn->transmit(selectCmd);
    if (!selectResp.isSuccess()) {
        throw std::runtime_error("Vehicle: SELECT file failed");
    }

    // Read file header (0x20 bytes)
    auto headerResp = conn->transmit(smartcard::readBinary(0, protocol::FILE_HEADER_SIZE));
    if (!headerResp.isSuccess() || headerResp.data.size() < 2) {
        throw std::runtime_error("Vehicle: Cannot read file header");
    }

    // Parse header to find data offset and length using BER
    const auto& hdr = headerResp.data;
    if (hdr.size() < 2) {
        throw std::runtime_error("Vehicle: File header too short");
    }

    size_t dataOffset = static_cast<size_t>(hdr[1]) + 2;
    if (dataOffset >= hdr.size()) {
        throw std::runtime_error("Vehicle: Invalid header offset");
    }

    // Parse BER tag and length from header to determine data length
    size_t parseOffset = dataOffset;

    // Parse tag
    size_t tagStart = parseOffset;
    if (parseOffset >= hdr.size()) {
        throw std::runtime_error("Vehicle: Header parse error at tag");
    }
    // Skip tag bytes
    if ((hdr[parseOffset] & 0x1F) == 0x1F) {
        parseOffset++;
        while (parseOffset < hdr.size() && (hdr[parseOffset] & 0x80)) {
            parseOffset++;
        }
        parseOffset++; // last byte of multi-byte tag
    } else {
        parseOffset++;
    }
    size_t tagLen = parseOffset - tagStart;

    // Parse length
    if (parseOffset >= hdr.size()) {
        throw std::runtime_error("Vehicle: Header parse error at length");
    }
    size_t dataLength = 0;
    size_t lenBytes = 0;
    if (hdr[parseOffset] < 0x80) {
        dataLength = hdr[parseOffset];
        lenBytes = 1;
    } else {
        size_t numLenBytes = hdr[parseOffset] & 0x7F;
        lenBytes = 1 + numLenBytes;
        parseOffset++;
        for (size_t i = 0; i < numLenBytes && parseOffset < hdr.size(); i++) {
            dataLength = (dataLength << 8) | hdr[parseOffset++];
        }
    }

    // Total bytes to read = tag + length encoding + value
    size_t totalToRead = tagLen + lenBytes + dataLength;

    // Read the actual file data in chunks
    std::vector<uint8_t> fileData;
    fileData.reserve(totalToRead);
    uint16_t offset = static_cast<uint16_t>(dataOffset);

    while (fileData.size() < totalToRead) {
        uint8_t chunkSize = static_cast<uint8_t>(
            std::min(static_cast<size_t>(protocol::READ_CHUNK_SIZE), totalToRead - fileData.size()));

        auto readResp = conn->transmit(smartcard::readBinary(offset, chunkSize));
        if (!readResp.isSuccess()) {
            throw std::runtime_error("Vehicle: READ BINARY failed at offset " + std::to_string(offset));
        }

        if (readResp.data.empty()) {
            break;
        }

        fileData.insert(fileData.end(), readResp.data.begin(), readResp.data.end());
        offset += static_cast<uint16_t>(readResp.data.size());
    }

    return fileData;
}

VehicleDocumentData VehicleCard::readDocumentData()
{
    // Read all 4 files and merge BER trees
    smartcard::BERField merged;
    merged.tag = 0;
    merged.constructed = true;

    const std::vector<uint8_t>* fileIds[] = {&protocol::FILE_DOCUMENT_0, &protocol::FILE_DOCUMENT_1,
                                             &protocol::FILE_DOCUMENT_2, &protocol::FILE_DOCUMENT_3};

    for (const auto* fileId : fileIds) {
        auto raw = readFile(*fileId);
        if (!raw.empty()) {
            auto parsed = smartcard::parseBER(raw.data(), raw.size());
            smartcard::mergeBER(merged, parsed);
        }
    }

    VehicleDocumentData doc;

    // Registration
    doc.registrationNumber = smartcard::berFindString(merged, {0x71, 0x81});
    doc.dateOfFirstRegistration = formatDate(smartcard::berFindString(merged, {0x71, 0x82}));

    // Vehicle identification
    doc.vehicleIdNumber = smartcard::berFindString(merged, {0x71, 0x8A});
    doc.vehicleMake = smartcard::berFindString(merged, {0x71, 0xA3, 0x87});
    doc.vehicleType = smartcard::berFindString(merged, {0x71, 0xA3, 0x88});
    doc.commercialDescription = smartcard::berFindString(merged, {0x71, 0xA3, 0x89});
    doc.vehicleCategory = smartcard::berFindString(merged, {0x72, 0x98});
    doc.colourOfVehicle = smartcard::berFindString(merged, {0x72, 0x9F24});
    doc.yearOfProduction = smartcard::berFindString(merged, {0x72, 0xC5});

    // Engine
    doc.engineIdNumber = smartcard::berFindString(merged, {0x72, 0xA5, 0x9E});
    doc.engineCapacity = smartcard::berFindString(merged, {0x71, 0xA5, 0x90});
    doc.maximumNetPower = smartcard::berFindString(merged, {0x71, 0xA5, 0x91});
    doc.typeOfFuel = smartcard::berFindString(merged, {0x71, 0xA5, 0x92});

    // Mass
    doc.vehicleMass = smartcard::berFindString(merged, {0x71, 0x8C});
    doc.maximumPermissibleLadenMass = smartcard::berFindString(merged, {0x71, 0xA4, 0x8B});
    doc.vehicleLoad = smartcard::berFindString(merged, {0x72, 0xC4});
    doc.powerWeightRatio = smartcard::berFindString(merged, {0x71, 0x93});
    doc.numberOfAxles = smartcard::berFindString(merged, {0x72, 0x99});

    // Capacity
    doc.numberOfSeats = smartcard::berFindString(merged, {0x71, 0xA6, 0x94});
    doc.numberOfStandingPlaces = smartcard::berFindString(merged, {0x71, 0xA6, 0x95});

    // Document
    doc.expiryDate = formatDate(smartcard::berFindString(merged, {0x71, 0x8D}));
    doc.issuingDate = formatDate(smartcard::berFindString(merged, {0x71, 0x8E}));
    doc.typeApprovalNumber = smartcard::berFindString(merged, {0x71, 0x8F});
    doc.stateIssuing = smartcard::berFindString(merged, {0x71, 0x9F33});
    doc.competentAuthority = smartcard::berFindString(merged, {0x71, 0x9F35});
    doc.authorityIssuing = smartcard::berFindString(merged, {0x71, 0x9F36});
    doc.unambiguousNumber = smartcard::berFindString(merged, {0x71, 0x9F38});
    doc.serialNumber = smartcard::berFindString(merged, {0x72, 0xC9});

    // Owner
    doc.ownersSurnameOrBusinessName = smartcard::berFindString(merged, {0x71, 0xA1, 0xA2, 0x83});
    doc.ownerName = smartcard::berFindString(merged, {0x71, 0xA1, 0xA2, 0x84});
    doc.ownerAddress = smartcard::berFindString(merged, {0x71, 0xA1, 0xA2, 0x85});
    doc.ownersPersonalNo = smartcard::berFindString(merged, {0x72, 0xC2});

    // User (try 0x71 first, fallback to 0x72)
    doc.usersSurnameOrBusinessName = smartcard::berFindString(merged, {0x71, 0xA1, 0xA9, 0x83});
    doc.usersName = smartcard::berFindString(merged, {0x71, 0xA1, 0xA9, 0x84});
    doc.usersAddress = smartcard::berFindString(merged, {0x71, 0xA1, 0xA9, 0x85});
    if (doc.usersSurnameOrBusinessName.empty() && doc.usersName.empty() && doc.usersAddress.empty()) {
        doc.usersSurnameOrBusinessName = smartcard::berFindString(merged, {0x72, 0xA1, 0xA9, 0x83});
        doc.usersName = smartcard::berFindString(merged, {0x72, 0xA1, 0xA9, 0x84});
        doc.usersAddress = smartcard::berFindString(merged, {0x72, 0xA1, 0xA9, 0x85});
    }
    doc.usersPersonalNo = smartcard::berFindString(merged, {0x72, 0xC3});

    return doc;
}

} // namespace vehiclecard
