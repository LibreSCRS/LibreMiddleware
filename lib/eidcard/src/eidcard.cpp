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
    smartcard::CardTransaction tx(*connection);
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
    smartcard::CardTransaction tx(*connection);
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
    smartcard::CardTransaction tx(*connection);
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
    smartcard::CardTransaction tx(*connection);
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

    for (uint16_t offset = 0; offset < fileSize; offset += protocol::PKI_READ_CHUNK) {
        uint8_t toRead = static_cast<uint8_t>(
            std::min(static_cast<uint16_t>(protocol::PKI_READ_CHUNK),
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
    if (data.size() < protocol::CE_DIR_HEADER_SIZE) return entries;

    uint16_t count = static_cast<uint16_t>(data[6]) | (static_cast<uint16_t>(data[7]) << 8);

    for (uint16_t i = 0; i < count; i++) {
        size_t off = protocol::CE_DIR_HEADER_SIZE + i * protocol::CE_DIR_ENTRY_SIZE;
        if (off + protocol::CE_DIR_ENTRY_SIZE > data.size()) break;

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

// RAII guard: acquires a PC/SC transaction, selects the PKI (CardEdge/PKCS#15)
// applet on construction, re-selects the eID applet and releases the transaction
// on destruction. Holds an exclusive transaction so no other process can
// interleave APDUs while PKI operations (cert reading, PIN ops, signing) are in progress.
class PkiAppletGuard {
public:
    explicit PkiAppletGuard(smartcard::PCSCConnection& conn)
        : conn(conn), tx(conn)   // tx begins transaction before body runs
    {
        auto resp = conn.transmit(smartcard::selectByAID(protocol::AID_PKCS15));
        if (!resp.isSuccess())
            throw std::runtime_error("Failed to select PKI applet");
    }

    ~PkiAppletGuard()
    {
        // Re-select eID applet so the card is in a consistent state when
        // the transaction (tx) is released during tx destruction below.
        try { CardReaderGemalto::selectApplication(conn); } catch (...) {}
        // tx destructor fires next, releasing the PC/SC transaction.
    }

    PkiAppletGuard(const PkiAppletGuard&) = delete;
    PkiAppletGuard& operator=(const PkiAppletGuard&) = delete;

private:
    smartcard::PCSCConnection& conn;
    smartcard::CardTransaction tx;  // destroyed after destructor body (reverse decl. order)
};

CertificateList EIdCard::readCertificates()
{
    std::cerr << "[EIdCard] readCertificates: cardType=" << static_cast<int>(cardType) << std::endl;

    if (cardType != CardType::Gemalto2014 && cardType != CardType::ForeignerIF2020) {
        std::cerr << "[EIdCard] readCertificates: skipping, unsupported card type" << std::endl;
        return {};
    }

    // PkiAppletGuard acquires a PC/SC transaction, selects the PKI applet, and
    // re-selects the eID applet on exit — same as PIN/sign operations.
    PkiAppletGuard guard(*connection);

    // Step 1: Read root directory to find the "mscp" subdirectory.
    auto rootDir = readPkiFile(*connection, protocol::PKI_ROOT_DIR_FID);
    if (rootDir.empty()) {
        std::cerr << "[EIdCard] readCertificates: failed to read root directory" << std::endl;
        return {};
    }

    auto rootEntries = parseDirFile(rootDir);
    std::cerr << "[EIdCard] readCertificates: root dir has " << rootEntries.size() << " entries" << std::endl;

    uint16_t mscpFid = 0;
    for (const auto& e : rootEntries) {
        std::cerr << "[EIdCard] readCertificates: root entry: \"" << e.name
                  << "\" fid=0x" << std::hex << std::setfill('0') << std::setw(4) << e.fid
                  << std::dec << " isDir=" << e.isDir << std::endl;
        if (e.isDir && e.name == "mscp")
            mscpFid = e.fid;
    }

    if (mscpFid == 0) {
        std::cerr << "[EIdCard] readCertificates: 'mscp' directory not found" << std::endl;
        return {};
    }

    // Step 2: Read "mscp" directory — collect cert files (kxc*, ksc*) and cmapfile FID.
    // Cert file names encode the container ID and key type: kxcNN = key exchange, kscNN = signature.
    // The cmapfile contains the CONTAINER_MAP_RECORD array used to derive private key FIDs.
    auto mscpDir = readPkiFile(*connection, mscpFid);
    if (mscpDir.empty()) {
        std::cerr << "[EIdCard] readCertificates: failed to read mscp directory" << std::endl;
        return {};
    }

    auto mscpEntries = parseDirFile(mscpDir);
    std::cerr << "[EIdCard] readCertificates: mscp dir has " << mscpEntries.size() << " entries" << std::endl;

    struct CertFileEntry {
        uint16_t fid;
        std::string label;
        uint8_t contId;
        uint16_t keyPairId;  // protocol::AT_KEYEXCHANGE or protocol::AT_SIGNATURE
    };
    std::vector<CertFileEntry> certFiles;
    uint16_t cmapFid = 0;

    for (const auto& e : mscpEntries) {
        std::cerr << "[EIdCard] readCertificates: mscp entry: \"" << e.name
                  << "\" fid=0x" << std::hex << std::setfill('0') << std::setw(4) << e.fid
                  << std::dec << " isDir=" << e.isDir << std::endl;
        if (e.isDir) continue;

        if (e.name == "cmapfile") {
            cmapFid = e.fid;
        } else if (e.name.size() == 5) {
            std::string prefix = e.name.substr(0, 3);
            if (prefix == "kxc" || prefix == "ksc") {
                uint8_t contId = static_cast<uint8_t>(std::stoul(e.name.substr(3, 2)));
                certFiles.push_back({
                    e.fid,
                    prefix == "kxc" ? "Key Exchange Certificate" : "Digital Signature Certificate",
                    contId,
                    prefix == "kxc" ? protocol::AT_KEYEXCHANGE : protocol::AT_SIGNATURE
                });
            }
        }
    }

    std::cerr << "[EIdCard] readCertificates: found " << certFiles.size() << " certificate files" << std::endl;

    // Step 3: Read cmapfile to derive each certificate's private key FID in one pass.
    // This avoids a separate discoverKeyReferences() traversal for PKCS#11 use.
    std::vector<uint8_t> cmapData;
    size_t cmapOffset = 0;
    size_t cmapRecordCount = 0;
    if (cmapFid != 0) {
        cmapData = readPkiFile(*connection, cmapFid);
        // Some cards prepend a 2-byte header before the record array.
        if (cmapData.size() >= 2 && (cmapData.size() - 2) % protocol::CMAP_RECORD_SIZE == 0)
            cmapOffset = 2;
        cmapRecordCount = (cmapData.size() - cmapOffset) / protocol::CMAP_RECORD_SIZE;
        std::cerr << "[EIdCard] readCertificates: cmapfile has " << cmapRecordCount
                  << " container records" << std::endl;
    } else {
        std::cerr << "[EIdCard] readCertificates: cmapfile not found, key FIDs unavailable" << std::endl;
    }

    // Step 4: Read each certificate file, decompress, and pair with its private key FID.
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

            if (der.empty())
                continue;

            // Derive private key FID from cmapfile container record.
            uint16_t keyFid = 0;
            if (!cmapData.empty() && cf.contId < cmapRecordCount) {
                size_t recOffset = cmapOffset + cf.contId * protocol::CMAP_RECORD_SIZE;
                uint8_t flags = cmapData[recOffset + protocol::CMAP_FLAGS_OFFSET];
                if (flags & protocol::CMAP_VALID_CONTAINER) {
                    size_t sizeOffset = (cf.keyPairId == protocol::AT_KEYEXCHANGE)
                        ? recOffset + protocol::CMAP_KX_SIZE_OFFSET
                        : recOffset + protocol::CMAP_SIG_SIZE_OFFSET;
                    uint16_t keySizeBits = static_cast<uint16_t>(
                        cmapData[sizeOffset] | (cmapData[sizeOffset + 1] << 8));
                    if (keySizeBits != 0)
                        keyFid = protocol::privateKeyFID(cf.contId, cf.keyPairId);
                }
            }

            std::cerr << "[EIdCard] readCertificates: \"" << cf.label
                      << "\" DER size=" << der.size()
                      << " keyFID=0x" << std::hex << std::setfill('0') << std::setw(4) << keyFid
                      << std::dec << std::endl;
            certs.push_back({ cf.label, std::move(der), keyFid });
        } catch (const std::exception& e) {
            std::cerr << "[EIdCard] readCertificates: cert 0x" << std::hex << cf.fid
                      << std::dec << " exception: " << e.what() << std::endl;
        }
    }

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
        if (r.retriesLeft == 0)
            r.blocked = true;
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

PINResult EIdCard::getPINTriesLeft()
{
    if (cardType == CardType::Apollo2008)
        throw std::runtime_error("PIN operations not supported on Apollo2008 cards");

    PkiAppletGuard guard(*connection);

    // ISO 7816-4 VERIFY with empty data = status check (does not decrement retries).
    // Returns 0x63CN (N = retries left) if not authenticated, or 0x9000 if the
    // security condition is already satisfied (e.g. another process verified the PIN).
    auto resp = connection->transmit(
        smartcard::verifyPINStatus(protocol::PKI_PIN_REFERENCE));
    auto result = parsePINStatusWord(resp.statusWord());

    // When the card reports the PIN is already authenticated (0x9000), the retry
    // counter has been reset to its maximum by the last successful verification.
    if (result.success && result.retriesLeft < 0)
        result.retriesLeft = protocol::PIN_MAX_RETRIES;

    return result;
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

std::vector<uint8_t> EIdCard::signData(uint16_t keyReference,
                                        const std::vector<uint8_t>& data)
{
    if (cardType != CardType::Gemalto2014 && cardType != CardType::ForeignerIF2020)
        throw std::runtime_error("signData not supported on this card type");

    PkiAppletGuard guard(*connection);

    // MSE SET: 00 22 41 B6 07 80 01 02 84 02 [keyFID_HI] [keyFID_LO]
    // P1=0x41 (SET), P2=0xB6 (digital signature template)
    // Tag 0x80: algorithm ID = 0x02 (RSA-2048)
    // Tag 0x84: key reference (2 bytes, big-endian)
    uint8_t keyH = static_cast<uint8_t>((keyReference >> 8) & 0xFF);
    uint8_t keyL = static_cast<uint8_t>(keyReference & 0xFF);
    smartcard::APDUCommand mseSet{
        .cla = 0x00,
        .ins = 0x22,  // MANAGE SECURITY ENVIRONMENT
        .p1 = 0x41,   // SET
        .p2 = 0xB6,   // Digital Signature template
        .data = {0x80, 0x01, 0x02, 0x84, 0x02, keyH, keyL},
        .le = 0,
        .hasLe = false
    };

    auto mseResp = connection->transmit(mseSet);
    if (!mseResp.isSuccess()) {
        std::cerr << "[EIdCard] signData: MSE SET failed, SW=0x"
                  << std::hex << std::setfill('0') << std::setw(4) << mseResp.statusWord()
                  << std::dec << std::endl;
        throw std::runtime_error("MSE SET failed");
    }

    // PSO COMPUTE DIGITAL SIGNATURE: 00 2A 9E 00 [Lc] [DigestInfo] 00
    smartcard::APDUCommand pso{
        .cla = 0x00,
        .ins = 0x2A,  // PERFORM SECURITY OPERATION
        .p1 = 0x9E,   // Compute digital signature
        .p2 = 0x00,
        .data = data,
        .le = 0x00,   // Expect max response (256 bytes for RSA-2048)
        .hasLe = true
    };

    auto psoResp = connection->transmit(pso);
    if (!psoResp.isSuccess()) {
        std::cerr << "[EIdCard] signData: PSO failed, SW=0x"
                  << std::hex << std::setfill('0') << std::setw(4) << psoResp.statusWord()
                  << std::dec << std::endl;
        throw std::runtime_error("PSO COMPUTE DIGITAL SIGNATURE failed");
    }

    std::cerr << "[EIdCard] signData: signature size=" << psoResp.data.size() << std::endl;
    return psoResp.data;
}


std::vector<std::pair<std::string, uint16_t>> EIdCard::discoverKeyReferences()
{
    if (cardType != CardType::Gemalto2014 && cardType != CardType::ForeignerIF2020)
        return {};

    PkiAppletGuard guard(*connection);

    // Step 1: Read root directory → find mscp subdirectory
    auto rootDir = readPkiFile(*connection, protocol::PKI_ROOT_DIR_FID);
    if (rootDir.empty()) return {};

    auto rootEntries = parseDirFile(rootDir);
    uint16_t mscpFid = 0;
    for (const auto& e : rootEntries) {
        if (e.isDir && e.name == "mscp") {
            mscpFid = e.fid;
            break;
        }
    }
    if (mscpFid == 0) return {};

    // Step 2: Read mscp directory → find cmapfile and cert file names
    auto mscpDir = readPkiFile(*connection, mscpFid);
    if (mscpDir.empty()) return {};

    auto mscpEntries = parseDirFile(mscpDir);

    uint16_t cmapFid = 0;
    struct CertFileInfo {
        std::string label;
        uint8_t contId;
        uint16_t keyPairId;  // protocol::AT_KEYEXCHANGE or protocol::AT_SIGNATURE
    };
    std::vector<CertFileInfo> certInfos;

    for (const auto& e : mscpEntries) {
        if (!e.isDir && e.name == "cmapfile") {
            cmapFid = e.fid;
        } else if (!e.isDir && e.name.size() == 5) {
            // Cert file names: kxcNN (key exchange) or kscNN (signature)
            // NN = container ID as 2-digit decimal (%02d)
            std::string prefix = e.name.substr(0, 3);
            if (prefix == "kxc" || prefix == "ksc") {
                uint8_t contId = static_cast<uint8_t>(
                    std::stoul(e.name.substr(3, 2)));
                certInfos.push_back({
                    prefix == "kxc" ? "Key Exchange Certificate"
                                    : "Digital Signature Certificate",
                    contId,
                    prefix == "kxc" ? protocol::AT_KEYEXCHANGE : protocol::AT_SIGNATURE
                });
            }
        }
    }

    if (cmapFid == 0 || certInfos.empty()) {
        std::cerr << "[EIdCard] discoverKeyReferences: cmapfile or cert files not found"
                  << std::endl;
        return {};
    }

    // Step 3: Read and parse cmapfile
    auto cmapData = readPkiFile(*connection, cmapFid);

    // Dump first bytes for layout verification
    std::cerr << "[EIdCard] discoverKeyReferences: cmapfile raw bytes (" << cmapData.size() << "):";
    for (size_t i = 0; i < std::min(cmapData.size(), size_t(20)); ++i)
        std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << (int)cmapData[i];
    std::cerr << std::dec << std::endl;

    // Some cards prepend a 2-byte header (count/version) before the record array.
    // Detect: if (size - 2) is a non-negative multiple of CMAP_RECORD_SIZE, skip 2 bytes.
    size_t cmapOffset = 0;
    if (cmapData.size() >= 2 && (cmapData.size() - 2) % protocol::CMAP_RECORD_SIZE == 0)
        cmapOffset = 2;

    size_t recCount = (cmapData.size() - cmapOffset) / protocol::CMAP_RECORD_SIZE;

    std::cerr << "[EIdCard] discoverKeyReferences: cmapfile has " << recCount
              << " container records (offset=" << cmapOffset
              << ", " << cmapData.size() << " bytes)" << std::endl;

    // Step 4: For each cert file, validate container and derive private key FID
    std::vector<std::pair<std::string, uint16_t>> result;
    for (const auto& ci : certInfos) {
        if (ci.contId >= recCount) {
            std::cerr << "[EIdCard] discoverKeyReferences: container " << (int)ci.contId
                      << " out of range (max " << recCount << ")" << std::endl;
            continue;
        }

        size_t recOffset = cmapOffset + ci.contId * protocol::CMAP_RECORD_SIZE;
        uint8_t flags = cmapData[recOffset + protocol::CMAP_FLAGS_OFFSET];

        if (!(flags & protocol::CMAP_VALID_CONTAINER)) {
            std::cerr << "[EIdCard] discoverKeyReferences: container " << (int)ci.contId
                      << " not valid (flags=0x" << std::hex << (int)flags << std::dec
                      << ")" << std::endl;
            continue;
        }

        // Verify key size is non-zero for this key type
        size_t sizeOffset = (ci.keyPairId == protocol::AT_KEYEXCHANGE)
            ? recOffset + protocol::CMAP_KX_SIZE_OFFSET
            : recOffset + protocol::CMAP_SIG_SIZE_OFFSET;
        uint16_t keySizeBits = static_cast<uint16_t>(
            cmapData[sizeOffset] | (cmapData[sizeOffset + 1] << 8));

        if (keySizeBits == 0) {
            std::cerr << "[EIdCard] discoverKeyReferences: container " << (int)ci.contId
                      << " has no " << (ci.keyPairId == protocol::AT_KEYEXCHANGE ? "KX" : "SIG")
                      << " key" << std::endl;
            continue;
        }

        uint16_t keyFid = protocol::privateKeyFID(ci.contId, ci.keyPairId);
        std::cerr << "[EIdCard] discoverKeyReferences: \"" << ci.label
                  << "\" container=" << (int)ci.contId
                  << " keySize=" << keySizeBits
                  << " FID=0x" << std::hex << std::setfill('0') << std::setw(4) << keyFid
                  << std::dec << std::endl;

        result.emplace_back(ci.label, keyFid);
    }

    std::cerr << "[EIdCard] discoverKeyReferences: found " << result.size()
              << " key references" << std::endl;
    return result;
}

void EIdCard::reconnectConnection()
{
    if (connection)
        connection->reconnect();
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
