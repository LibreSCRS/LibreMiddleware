// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "healthcard/healthcard.h"
#include "health_protocol.h"
#include "smartcard/apdu.h"
#include "smartcard/pcsc_connection.h"
#include "smartcard/tlv.h"
#include "cardedge/cardedge.h"
#include "cardedge/pki_applet_guard.h"
#include <algorithm>
#include <stdexcept>

namespace healthcard {

// Decode UTF-16 LE bytes → UTF-8 string (BMP only, covers all Serbian script)
static std::string decodeUtf16Le(const std::vector<uint8_t>& bytes)
{
    std::string out;
    out.reserve(bytes.size());
    for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
        uint16_t cp = static_cast<uint16_t>(bytes[i]) | (static_cast<uint16_t>(bytes[i + 1]) << 8);
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    return out;
}

// Format "DDMMYYYY" → "DD.MM.YYYY", pass through anything else unchanged
static std::string formatDate(const std::string& raw)
{
    if (raw.size() == 8 && std::all_of(raw.begin(), raw.end(), ::isdigit))
        return raw.substr(0, 2) + "." + raw.substr(2, 2) + "." + raw.substr(4, 4);
    return raw;
}

// Find a TLV field value and decode it as a UTF-16 LE string
static std::string findUtf16String(const std::vector<smartcard::TLVField>& fields, uint16_t tag)
{
    auto bytes = smartcard::findBytes(fields, tag);
    if (bytes.empty())
        return {};
    return decodeUtf16Le(bytes);
}

bool HealthCard::probe(const std::string& readerName)
{
    try {
        smartcard::PCSCConnection conn(readerName);
        return probe(conn);
    } catch (...) {
        return false;
    }
}

bool HealthCard::probe(smartcard::PCSCConnection& conn)
{
    try {
        auto resp = conn.transmit(smartcard::selectByAID(protocol::AID_SERVSZK));
        return resp.isSuccess();
    } catch (...) {
        return false;
    }
}

HealthCard::HealthCard(const std::string& readerName)
{
    ownedConnection = std::make_unique<smartcard::PCSCConnection>(readerName);
    conn = ownedConnection.get();
    initCard();
}

HealthCard::HealthCard(smartcard::PCSCConnection& externalConn) : conn(&externalConn)
{
    initCard();
}

HealthCard::~HealthCard() = default;

void HealthCard::initCard()
{
    auto resp = conn->transmit(smartcard::selectByAID(protocol::AID_SERVSZK));
    if (!resp.isSuccess())
        throw std::runtime_error("Health card: SERVSZK AID selection failed");
}

std::vector<uint8_t> HealthCard::readFile(const std::vector<uint8_t>& fileId)
{
    // SELECT FILE by ID (P1=0x00, P2=0x00) — required by health card SERVSZK applet
    auto selectResp = conn->transmit(smartcard::selectByFileId(fileId[0], fileId[1]));
    if (!selectResp.isSuccess())
        throw std::runtime_error("Health card: SELECT file failed for fileId " + std::to_string(fileId[0]) + "/" +
                                 std::to_string(fileId[1]) + " SW=" + std::to_string(selectResp.statusWord()));

    // Read 4-byte header: bytes [2:3] (LE) hold the content length
    auto headerResp = conn->transmit(smartcard::readBinary(0, protocol::FILE_HEADER_SIZE));
    if (!headerResp.isSuccess() || headerResp.data.size() < protocol::FILE_HEADER_SIZE)
        throw std::runtime_error("Health card: Cannot read file header");

    uint16_t contentLength =
        static_cast<uint16_t>(headerResp.data[2]) | (static_cast<uint16_t>(headerResp.data[3]) << 8);

    if (contentLength == 0)
        return {};

    // Read content in 255-byte chunks starting right after the 4-byte header
    std::vector<uint8_t> fileData;
    fileData.reserve(contentLength);
    uint16_t offset = protocol::FILE_HEADER_SIZE;

    while (fileData.size() < contentLength) {
        uint8_t chunkSize = static_cast<uint8_t>(
            std::min(static_cast<size_t>(protocol::READ_CHUNK_SIZE), contentLength - fileData.size()));
        auto readResp = conn->transmit(smartcard::readBinary(offset, chunkSize));
        if (!readResp.isSuccess())
            throw std::runtime_error("Health card: READ BINARY failed");
        if (readResp.data.empty())
            break;
        fileData.insert(fileData.end(), readResp.data.begin(), readResp.data.end());
        offset += static_cast<uint16_t>(readResp.data.size());
    }

    return fileData;
}

HealthDocumentData HealthCard::readDocumentData()
{
    auto docRaw = readFile(protocol::FILE_DOCUMENT);
    auto fixedRaw = readFile(protocol::FILE_FIXED_PERSONAL);
    auto varPersRaw = readFile(protocol::FILE_VARIABLE_PERSONAL);
    auto varAdminRaw = readFile(protocol::FILE_VARIABLE_ADMIN);

    auto docFields = smartcard::parseTLV(docRaw.data(), docRaw.size());
    auto fixedFields = smartcard::parseTLV(fixedRaw.data(), fixedRaw.size());
    auto varPersFields = smartcard::parseTLV(varPersRaw.data(), varPersRaw.size());
    auto varAdminFields = smartcard::parseTLV(varAdminRaw.data(), varAdminRaw.size());

    HealthDocumentData d;

    // Document file
    d.insurerName = findUtf16String(docFields, protocol::TAG_INSURER_NAME);
    d.insurerId = smartcard::findString(docFields, protocol::TAG_INSURER_ID);
    d.cardId = smartcard::findString(docFields, protocol::TAG_CARD_ID);
    d.dateOfIssue = formatDate(smartcard::findString(docFields, protocol::TAG_DATE_OF_ISSUE));
    d.dateOfExpiry = formatDate(smartcard::findString(docFields, protocol::TAG_DATE_OF_EXPIRY));
    d.printLanguage = smartcard::findString(docFields, protocol::TAG_PRINT_LANGUAGE);

    // Fixed personal file
    d.insurantNumber = smartcard::findString(fixedFields, protocol::TAG_INSURANT_NUMBER);
    d.familyName = findUtf16String(fixedFields, protocol::TAG_FAMILY_NAME);
    d.familyNameLatin = findUtf16String(fixedFields, protocol::TAG_FAMILY_NAME_LAT);
    d.givenName = findUtf16String(fixedFields, protocol::TAG_GIVEN_NAME);
    d.givenNameLatin = findUtf16String(fixedFields, protocol::TAG_GIVEN_NAME_LAT);
    d.dateOfBirth = formatDate(smartcard::findString(fixedFields, protocol::TAG_DATE_OF_BIRTH));

    // Variable personal file
    d.validUntil = formatDate(smartcard::findString(varPersFields, protocol::TAG_VALID_UNTIL));
    d.permanentlyValid = (smartcard::findString(varPersFields, protocol::TAG_PERMANENTLY_VALID) == "01");

    // Variable admin file
    d.parentName = findUtf16String(varAdminFields, protocol::TAG_PARENT_NAME);
    d.parentNameLatin = findUtf16String(varAdminFields, protocol::TAG_PARENT_NAME_LAT);

    auto genderRaw = smartcard::findString(varAdminFields, protocol::TAG_GENDER);
    d.gender = (genderRaw == "01") ? "\xD0\x9C\xD1\x83\xD1\x88\xD0\xBA\xD0\xBE"          // Мушко
                                   : "\xD0\x96\xD0\xB5\xD0\xBD\xD1\x81\xD0\xBA\xD0\xBE"; // Женско

    d.personalNumber = smartcard::findString(varAdminFields, protocol::TAG_PERSONAL_NUMBER);
    d.street = findUtf16String(varAdminFields, protocol::TAG_STREET);
    d.municipality = findUtf16String(varAdminFields, protocol::TAG_MUNICIPALITY);
    d.place = findUtf16String(varAdminFields, protocol::TAG_PLACE);
    d.addressNumber = findUtf16String(varAdminFields, protocol::TAG_ADDRESS_NUMBER);
    d.apartment = findUtf16String(varAdminFields, protocol::TAG_APARTMENT);
    d.insuranceBasisRzzo = smartcard::findString(varAdminFields, protocol::TAG_INSURANCE_BASIS);
    d.insuranceDescription = findUtf16String(varAdminFields, protocol::TAG_INSURANCE_DESC);
    d.carrierRelationship = findUtf16String(varAdminFields, protocol::TAG_CARRIER_RELATION);
    d.carrierFamilyMember = (smartcard::findString(varAdminFields, protocol::TAG_CARRIER_FAMILY_MEMBER) == "01");
    d.carrierIdNumber = smartcard::findString(varAdminFields, protocol::TAG_CARRIER_ID_NO);
    d.carrierInsurantNumber = smartcard::findString(varAdminFields, protocol::TAG_CARRIER_INSURANT_NO);
    d.carrierFamilyName = findUtf16String(varAdminFields, protocol::TAG_CARRIER_FAMILY_NAME);
    d.carrierFamilyNameLatin = findUtf16String(varAdminFields, protocol::TAG_CARRIER_FAMILY_NAME_LAT);
    d.carrierGivenName = findUtf16String(varAdminFields, protocol::TAG_CARRIER_GIVEN_NAME);
    d.carrierGivenNameLatin = findUtf16String(varAdminFields, protocol::TAG_CARRIER_GIVEN_NAME_LAT);
    d.insuranceStartDate = formatDate(smartcard::findString(varAdminFields, protocol::TAG_INSURANCE_START));
    d.country = findUtf16String(varAdminFields, protocol::TAG_COUNTRY);
    d.taxpayerName = findUtf16String(varAdminFields, protocol::TAG_TAXPAYER_NAME);
    d.taxpayerResidence = findUtf16String(varAdminFields, protocol::TAG_TAXPAYER_RES);

    // Use PIB 1632 if present, fall back to 1633
    auto taxId1 = smartcard::findString(varAdminFields, protocol::TAG_TAXPAYER_ID_1);
    auto taxId2 = smartcard::findString(varAdminFields, protocol::TAG_TAXPAYER_ID_2);
    d.taxpayerIdNumber = taxId1.empty() ? taxId2 : taxId1;

    d.taxpayerActivityCode = smartcard::findString(varAdminFields, protocol::TAG_TAXPAYER_ACTIV);

    return d;
}

cardedge::CertificateList HealthCard::readCertificates()
{
    cardedge::PkiAppletGuard guard(*conn);
    return cardedge::readCertificates(*conn);
}

cardedge::PINResult HealthCard::getPINTriesLeft()
{
    cardedge::PkiAppletGuard guard(*conn);
    return cardedge::getPINTriesLeft(*conn);
}

cardedge::PINResult HealthCard::changePIN(const std::string& oldPin, const std::string& newPin)
{
    cardedge::PkiAppletGuard guard(*conn);
    return cardedge::changePIN(*conn, oldPin, newPin);
}

} // namespace healthcard
