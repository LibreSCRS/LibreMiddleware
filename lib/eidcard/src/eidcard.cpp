// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "eidcard/eidcard.h"
#include "card_protocol.h"
#include "card_reader_base.h"
#include "card_reader_gemalto.h"
#include "card_reader_apollo.h"
#include "card_verifier.h"
#include "smartcard/pcsc_connection.h"
#include "smartcard/tlv.h"
#include "smartcard/apdu.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <zlib.h>

namespace eidcard {

// Format "DDMMYYYY" → "DD.MM.YYYY", pass through anything else unchanged
static std::string formatDate(const std::string& raw) {
    if (raw.size() == 8 && std::all_of(raw.begin(), raw.end(), ::isdigit))
        return raw.substr(0, 2) + "." + raw.substr(2, 2) + "." + raw.substr(4, 4);
    return raw;
}

bool EIdCard::probe(const std::string& readerName)
{
    try {
        smartcard::PCSCConnection conn(readerName);
        auto atr = conn.getATR();
        if (protocol::isGemaltoATR(atr) || protocol::isApolloATR(atr))
            return true;
        // Unknown ATR — try Gemalto AID selection as fallback
        return CardReaderGemalto::selectApplication(conn) != CardType::Unknown;
    } catch (...) {
        return false;
    }
}

EIdCard::EIdCard(const std::string& readerName)
{
    connection = std::make_unique<smartcard::PCSCConnection>(readerName);

    // Detect card type from ATR
    auto atr = connection->getATR();

    if (protocol::isGemaltoATR(atr)) {
        // Gemalto card: try AID selection to determine citizen/foreigner
        cardType = CardReaderGemalto::selectApplication(*connection);
        cardReader = std::make_unique<CardReaderGemalto>();
    } else if (protocol::isApolloATR(atr)) {
        cardType = CardType::Apollo2008;
        cardReader = std::make_unique<CardReaderApollo>();
    } else {
        // Unknown ATR - try Gemalto AID selection as fallback
        cardType = CardReaderGemalto::selectApplication(*connection);
        if (cardType != CardType::Unknown) {
            cardReader = std::make_unique<CardReaderGemalto>();
        } else {
            throw std::runtime_error("Unknown card type, ATR not recognized");
        }
    }
}

EIdCard::~EIdCard() = default;

CardType EIdCard::getCardType() const
{
    return cardType;
}

DocumentData EIdCard::readDocumentData()
{
    auto raw = cardReader->readFile(*connection,
                                     protocol::FILE_DOCUMENT_DATA_H,
                                     protocol::FILE_DOCUMENT_DATA_L);
    auto fields = smartcard::parseTLV(raw.data(), raw.size());

    DocumentData doc;
    doc.docRegNo            = smartcard::findString(fields, protocol::TAG_DOC_REG_NO);
    doc.documentType        = smartcard::findString(fields, protocol::TAG_DOCUMENT_TYPE);
    doc.documentSerialNumber = smartcard::findString(fields, protocol::TAG_DOCUMENT_SERIAL_NO);
    doc.issuingDate         = formatDate(smartcard::findString(fields, protocol::TAG_ISSUING_DATE));
    doc.expiryDate          = formatDate(smartcard::findString(fields, protocol::TAG_EXPIRY_DATE));
    doc.issuingAuthority    = smartcard::findString(fields, protocol::TAG_ISSUING_AUTHORITY);
    doc.chipSerialNumber    = smartcard::findString(fields, protocol::TAG_CHIP_SERIAL_NUMBER);
    return doc;
}

FixedPersonalData EIdCard::readFixedPersonalData()
{
    auto raw = cardReader->readFile(*connection,
                                     protocol::FILE_PERSONAL_DATA_H,
                                     protocol::FILE_PERSONAL_DATA_L);
    auto fields = smartcard::parseTLV(raw.data(), raw.size());

    FixedPersonalData fpd;
    fpd.personalNumber   = smartcard::findString(fields, protocol::TAG_PERSONAL_NUMBER);
    fpd.surname          = smartcard::findString(fields, protocol::TAG_SURNAME);
    fpd.givenName        = smartcard::findString(fields, protocol::TAG_GIVEN_NAME);
    fpd.parentGivenName  = smartcard::findString(fields, protocol::TAG_PARENT_GIVEN_NAME);
    fpd.sex              = smartcard::findString(fields, protocol::TAG_SEX);
    fpd.placeOfBirth     = smartcard::findString(fields, protocol::TAG_PLACE_OF_BIRTH);
    fpd.communityOfBirth = smartcard::findString(fields, protocol::TAG_COMMUNITY_OF_BIRTH);
    fpd.stateOfBirth     = smartcard::findString(fields, protocol::TAG_STATE_OF_BIRTH);
    fpd.dateOfBirth      = formatDate(smartcard::findString(fields, protocol::TAG_DATE_OF_BIRTH));
    fpd.nationalityFull  = smartcard::findString(fields, protocol::TAG_NATIONALITY_FULL);
    fpd.statusOfForeigner = smartcard::findString(fields, protocol::TAG_STATUS_OF_FOREIGNER);
    return fpd;
}

VariablePersonalData EIdCard::readVariablePersonalData()
{
    auto raw = cardReader->readFile(*connection,
                                     protocol::FILE_VARIABLE_DATA_H,
                                     protocol::FILE_VARIABLE_DATA_L);
    auto fields = smartcard::parseTLV(raw.data(), raw.size());

    VariablePersonalData vpd;
    vpd.state           = smartcard::findString(fields, protocol::TAG_STATE);
    vpd.community       = smartcard::findString(fields, protocol::TAG_COMMUNITY);
    vpd.place           = smartcard::findString(fields, protocol::TAG_PLACE);
    vpd.street          = smartcard::findString(fields, protocol::TAG_STREET);
    vpd.houseNumber     = smartcard::findString(fields, protocol::TAG_HOUSE_NUMBER);
    vpd.houseLetter     = smartcard::findString(fields, protocol::TAG_HOUSE_LETTER);
    vpd.entrance        = smartcard::findString(fields, protocol::TAG_ENTRANCE);
    vpd.floor           = smartcard::findString(fields, protocol::TAG_FLOOR);
    vpd.apartmentNumber = smartcard::findString(fields, protocol::TAG_APARTMENT_NUMBER);
    vpd.addressDate     = formatDate(smartcard::findString(fields, protocol::TAG_ADDRESS_DATE));
    vpd.addressLabel    = smartcard::findString(fields, protocol::TAG_ADDRESS_LABEL);
    return vpd;
}

PhotoData EIdCard::readPortrait()
{
    auto raw = cardReader->readFile(*connection,
                                     protocol::FILE_PORTRAIT_H,
                                     protocol::FILE_PORTRAIT_L);
    // Photo file data has a 4-byte TLV header (tag + length); trim it
    if (raw.size() > 4) {
        return PhotoData(raw.begin() + 4, raw.end());
    }
    return {};
}

// CardEdge FCI (File Control Information) response: 10 bytes, all big-endian
// [FID_H:1] [FID_L:1] [Size_H:1] [Size_L:1] [ACL: 6 bytes]
static uint16_t parseFciFileSize(const std::vector<uint8_t>& fci)
{
    if (fci.size() < 4) return 0;
    return static_cast<uint16_t>((fci[2] << 8) | fci[3]);
}

// CardEdge applet buffer size
constexpr uint8_t CE_BUFFER_LENGTH = 0x80;

// Read a file from the PKI (PKCS#15/CardEdge) applet using SELECT by file ID.
// Uses the FCI response to determine file size and reads in 128-byte chunks.
static std::vector<uint8_t> readPkiFile(smartcard::PCSCConnection& conn,
                                         uint16_t fileId)
{
    uint8_t fileH = static_cast<uint8_t>((fileId >> 8) & 0xFF);
    uint8_t fileL = static_cast<uint8_t>(fileId & 0xFF);

    auto selectResp = conn.transmit(smartcard::selectByFileId(fileH, fileL));
    if (!selectResp.isSuccess()) {
        std::cerr << "[EIdCard] readPkiFile: SELECT 0x"
                  << std::hex << std::setfill('0') << std::setw(4) << fileId
                  << " failed, SW=0x" << std::setw(4) << selectResp.statusWord()
                  << std::dec << std::endl;
        return {};
    }

    uint16_t fileSize = parseFciFileSize(selectResp.data);
    std::cerr << "[EIdCard] readPkiFile: SELECT 0x"
              << std::hex << std::setfill('0') << std::setw(4) << fileId
              << " OK, size=" << std::dec << fileSize << std::endl;

    if (fileSize == 0)
        return {};

    // Read file in chunks using READ BINARY
    std::vector<uint8_t> fileData;
    fileData.reserve(fileSize);

    for (uint16_t offset = 0; offset < fileSize; offset += CE_BUFFER_LENGTH) {
        uint8_t toRead = static_cast<uint8_t>(
            std::min(static_cast<uint16_t>(CE_BUFFER_LENGTH),
                     static_cast<uint16_t>(fileSize - offset)));

        auto readResp = conn.transmit(smartcard::readBinary(offset, toRead));
        if (readResp.data.empty())
            break;

        // Accept both 0x9000 (success) and 0x62XX (warnings like end-of-file)
        uint8_t sw1 = static_cast<uint8_t>((readResp.statusWord() >> 8) & 0xFF);
        if (sw1 != 0x90 && sw1 != 0x62) {
            std::cerr << "[EIdCard] readPkiFile: READ BINARY at offset " << offset
                      << " failed, SW=0x" << std::hex << std::setfill('0')
                      << std::setw(4) << readResp.statusWord() << std::dec << std::endl;
            break;
        }

        fileData.insert(fileData.end(), readResp.data.begin(), readResp.data.end());
    }

    return fileData;
}

// Decompress a zlib-compressed certificate from the PKI applet.
// Card format: [0x01, 0x00] [rawLen LE 2 bytes] [zlib compressed data]
static std::vector<uint8_t> decompressCertificate(const uint8_t* data, size_t dataLen)
{
    if (dataLen < 4)
        return {};

    // Skip 2-byte header (0x01, 0x00)
    uint16_t rawLen = static_cast<uint16_t>(data[2]) | (static_cast<uint16_t>(data[3]) << 8);
    const uint8_t* compressed = data + 4;
    size_t compressedLen = dataLen - 4;

    std::vector<uint8_t> result(rawLen);
    uLongf destLen = rawLen;
    int ret = uncompress(result.data(), &destLen, compressed, static_cast<uLong>(compressedLen));
    if (ret != Z_OK) {
        std::cerr << "[EIdCard] decompressCertificate: uncompress failed, ret=" << ret << std::endl;
        return {};
    }
    result.resize(destLen);
    return result;
}

// CardEdge directory file header (10 bytes):
//   [LeftFiles:1] [LeftDirs:1] [NextFileFID:2 LE] [NextDirFID:2 LE]
//   [EntriesCount:2 LE] [WriteACL:2 LE]
// Followed by DIR_ENTRY_RECORD entries (11 bytes each):
//   [Name:8 chars] [FID:2 LE] [IsDir:1]
struct DirEntry {
    std::string name;
    uint16_t fid;
    bool isDir;
};

static std::vector<DirEntry> parseDirFile(const std::vector<uint8_t>& data)
{
    std::vector<DirEntry> entries;
    if (data.size() < 10) return entries;

    uint16_t count = static_cast<uint16_t>(data[6]) | (static_cast<uint16_t>(data[7]) << 8);
    constexpr size_t headerSize = 10;
    // DIR_ENTRY_RECORD: char Name[8] + ushort FID + bool IsDir + padding = 12 bytes
    constexpr size_t entrySize = 12;

    for (uint16_t i = 0; i < count; i++) {
        size_t off = headerSize + i * entrySize;
        if (off + entrySize > data.size()) break;

        DirEntry e;
        // Name: 8 bytes, null-terminated
        e.name.assign(reinterpret_cast<const char*>(data.data() + off),
                       strnlen(reinterpret_cast<const char*>(data.data() + off), 8));
        e.fid = static_cast<uint16_t>(data[off + 8]) | (static_cast<uint16_t>(data[off + 9]) << 8);
        e.isDir = (data[off + 10] != 0);
        entries.push_back(std::move(e));
    }
    return entries;
}

CertificateList EIdCard::readCertificates()
{
    std::cerr << "[EIdCard] readCertificates: cardType=" << static_cast<int>(cardType) << std::endl;

    if (cardType != CardType::Gemalto2014 && cardType != CardType::ForeignerIF2020) {
        std::cerr << "[EIdCard] readCertificates: skipping, unsupported card type" << std::endl;
        return {};
    }

    // End-entity PKI certificates live in the CardEdge PKCS#15 applet.
    auto pkiResp = connection->transmit(smartcard::selectByAID(protocol::AID_PKCS15));
    if (!pkiResp.isSuccess()) {
        std::cerr << "[EIdCard] readCertificates: failed to select PKI applet, SW=0x"
                  << std::hex << std::setfill('0') << std::setw(4) << pkiResp.statusWord()
                  << std::dec << std::endl;
        CardReaderGemalto::selectApplication(*connection);
        return {};
    }
    std::cerr << "[EIdCard] readCertificates: PKI applet selected OK" << std::endl;

    // Step 1: Read root directory (FID 0x7000) to find the "mscp" subdirectory.
    constexpr uint16_t CE_ROOT_FILE_FID = 0x7000;
    auto rootDir = readPkiFile(*connection, CE_ROOT_FILE_FID);
    if (rootDir.empty()) {
        std::cerr << "[EIdCard] readCertificates: failed to read root directory" << std::endl;
        CardReaderGemalto::selectApplication(*connection);
        return {};
    }

    auto rootEntries = parseDirFile(rootDir);
    std::cerr << "[EIdCard] readCertificates: root dir has " << rootEntries.size() << " entries" << std::endl;

    uint16_t mscpFid = 0;
    for (const auto& e : rootEntries) {
        std::cerr << "[EIdCard] readCertificates: root entry: \"" << e.name
                  << "\" fid=0x" << std::hex << std::setfill('0') << std::setw(4) << e.fid
                  << std::dec << " isDir=" << e.isDir << std::endl;
        if (e.isDir && e.name == "mscp") {
            mscpFid = e.fid;
        }
    }

    if (mscpFid == 0) {
        std::cerr << "[EIdCard] readCertificates: 'mscp' directory not found" << std::endl;
        CardReaderGemalto::selectApplication(*connection);
        return {};
    }

    // Step 2: Read "mscp" directory to find certificate files (kxc*, ksc*).
    auto mscpDir = readPkiFile(*connection, mscpFid);
    if (mscpDir.empty()) {
        std::cerr << "[EIdCard] readCertificates: failed to read mscp directory" << std::endl;
        CardReaderGemalto::selectApplication(*connection);
        return {};
    }

    auto mscpEntries = parseDirFile(mscpDir);
    std::cerr << "[EIdCard] readCertificates: mscp dir has " << mscpEntries.size() << " entries" << std::endl;

    struct CertFileEntry {
        uint16_t fid;
        std::string label;
    };
    std::vector<CertFileEntry> certFiles;

    for (const auto& e : mscpEntries) {
        std::cerr << "[EIdCard] readCertificates: mscp entry: \"" << e.name
                  << "\" fid=0x" << std::hex << std::setfill('0') << std::setw(4) << e.fid
                  << std::dec << " isDir=" << e.isDir << std::endl;
        if (e.isDir) continue;

        if (e.name.substr(0, 3) == "kxc") {
            certFiles.push_back({ e.fid, "Key Exchange Certificate" });
        } else if (e.name.substr(0, 3) == "ksc") {
            certFiles.push_back({ e.fid, "Digital Signature Certificate" });
        }
    }

    std::cerr << "[EIdCard] readCertificates: found " << certFiles.size() << " certificate files" << std::endl;

    // Step 3: Read each certificate file, decompress, and collect.
    // Certificate file format (written by CardFS):
    //   [logicalLen: 2 bytes LE] — CardFS length prefix
    //   [0x01, 0x00]             — cert header
    //   [rawLen: 2 bytes LE]     — uncompressed DER length
    //   [zlib compressed DER]
    CertificateList certs;
    for (const auto& cf : certFiles) {
        try {
            auto raw = readPkiFile(*connection, cf.fid);
            std::cerr << "[EIdCard] readCertificates: cert file 0x" << std::hex << std::setfill('0')
                      << std::setw(4) << cf.fid << std::dec
                      << " raw size=" << raw.size() << std::endl;
            if (raw.size() < 6)
                continue;

            // Log first 8 bytes
            std::cerr << "[EIdCard] readCertificates: first bytes:";
            for (size_t i = 0; i < std::min(raw.size(), size_t(8)); i++)
                std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << (int)raw[i];
            std::cerr << std::dec << std::endl;

            // Skip 2-byte CardFS length prefix
            const uint8_t* certData = raw.data() + 2;
            size_t certDataLen = raw.size() - 2;

            std::vector<uint8_t> der;
            if (certDataLen >= 4 && certData[0] == 0x01 && certData[1] == 0x00) {
                // Compressed certificate
                der = decompressCertificate(certData, certDataLen);
            } else if (certData[0] == 0x30) {
                // Uncompressed DER (ASN.1 SEQUENCE)
                der.assign(certData, certData + certDataLen);
            } else {
                std::cerr << "[EIdCard] readCertificates: unknown cert format, skipping" << std::endl;
                continue;
            }

            if (!der.empty()) {
                std::cerr << "[EIdCard] readCertificates: \"" << cf.label
                          << "\" DER size=" << der.size() << std::endl;
                certs.push_back({ cf.label, std::move(der) });
            }
        } catch (const std::exception& e) {
            std::cerr << "[EIdCard] readCertificates: cert 0x" << std::hex << cf.fid
                      << std::dec << " exception: " << e.what() << std::endl;
        }
    }

    // Re-select the eID data applet so subsequent operations work
    CardReaderGemalto::selectApplication(*connection);

    std::cerr << "[EIdCard] readCertificates: returning " << certs.size()
              << " certificates" << std::endl;
    return certs;
}

// Parse ISO 7816-4 status word into PINResult
static PINResult parsePINStatusWord(uint16_t sw)
{
    PINResult r;
    if (sw == 0x9000) {
        r.success = true;
        return r;
    }
    if (sw == 0x6983) {
        r.blocked = true;
        r.retriesLeft = 0;
        return r;
    }
    if ((sw & 0xFFF0) == 0x63C0) {
        r.retriesLeft = sw & 0x0F;
        return r;
    }
    return r;
}

// Pad a PIN with 0x00 bytes to PIN_MAX_LENGTH (8 bytes).
static std::vector<uint8_t> padPIN(const std::string& pin)
{
    std::vector<uint8_t> padded(pin.begin(), pin.end());
    padded.resize(protocol::PIN_MAX_LENGTH, 0x00);
    return padded;
}

// RAII guard: selects the PKI (CardEdge/PKCS#15) applet on construction,
// re-selects the eID applet on destruction. PIN operations run on the PKI applet
// with P2=0x80 (CE_PIN_ID(RoleUser) = 0x80).
class PkiAppletGuard {
public:
    explicit PkiAppletGuard(smartcard::PCSCConnection& conn) : conn_(conn)
    {
        auto resp = conn_.transmit(smartcard::selectByAID(protocol::AID_PKCS15));
        if (!resp.isSuccess()) {
            throw std::runtime_error("Failed to select PKI applet for PIN operation");
        }
    }

    ~PkiAppletGuard()
    {
        try {
            CardReaderGemalto::selectApplication(conn_);
        } catch (...) {}
    }

    PkiAppletGuard(const PkiAppletGuard&) = delete;
    PkiAppletGuard& operator=(const PkiAppletGuard&) = delete;

private:
    smartcard::PCSCConnection& conn_;
};

PINResult EIdCard::getPINTriesLeft()
{
    if (cardType == CardType::Apollo2008)
        throw std::runtime_error("PIN operations not supported on Apollo2008 cards");

    PkiAppletGuard guard(*connection);

    // ISO 7816-4 VERIFY with empty data = status check (does not decrement retries)
    auto resp = connection->transmit(
        smartcard::verifyPINStatus(protocol::PKI_PIN_REFERENCE));
    return parsePINStatusWord(resp.statusWord());
}

PINResult EIdCard::verifyPIN(const std::string& pin)
{
    if (cardType == CardType::Apollo2008)
        throw std::runtime_error("PIN operations not supported on Apollo2008 cards");

    PkiAppletGuard guard(*connection);

    // ISO 7816-4 VERIFY with null-padded PIN (8 bytes)
    auto resp = connection->transmit(
        smartcard::verifyPIN(protocol::PKI_PIN_REFERENCE, padPIN(pin)));
    return parsePINStatusWord(resp.statusWord());
}

PINResult EIdCard::changePIN(const std::string& oldPin, const std::string& newPin)
{
    if (cardType == CardType::Apollo2008)
        throw std::runtime_error("PIN operations not supported on Apollo2008 cards");

    PkiAppletGuard guard(*connection);

    // ISO 7816-4 CHANGE REFERENCE DATA: data = padded oldPin (8) || padded newPin (8)
    auto resp = connection->transmit(
        smartcard::changeReferenceData(protocol::PKI_PIN_REFERENCE,
                                       padPIN(oldPin), padPIN(newPin)));
    return parsePINStatusWord(resp.statusWord());
}

void EIdCard::setCertificateFolderPath(const std::string& path)
{
    certFolderPath = path;
    verifier.reset();  // force re-creation with new path
}

void EIdCard::ensureVerifier()
{
    if (!verifier && !certFolderPath.empty()) {
        verifier = std::make_unique<CardVerifier>(certFolderPath);
    }
}

VerificationResult EIdCard::verifyCard()
{
    ensureVerifier();
    if (!verifier)
        return VerificationResult::Unknown;
    return verifier->verifyCard(*connection, *cardReader, cardType);
}

VerificationResult EIdCard::verifyFixedData()
{
    ensureVerifier();
    if (!verifier)
        return VerificationResult::Unknown;
    return verifier->verifyFixedData(*connection, *cardReader, cardType);
}

VerificationResult EIdCard::verifyVariableData()
{
    ensureVerifier();
    if (!verifier)
        return VerificationResult::Unknown;
    return verifier->verifyVariableData(*connection, *cardReader, cardType);
}

} // namespace eidcard
