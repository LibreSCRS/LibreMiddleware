// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "cardedge/cardedge.h"
#include "cardedge/pki_applet_guard.h"
#include "cardedge_protocol.h"
#include "smartcard/pcsc_connection.h"
#include "smartcard/apdu.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <zlib.h>

namespace cardedge {

// ---------------------------------------------------------------------------
// PkiAppletGuard
// ---------------------------------------------------------------------------

PkiAppletGuard::PkiAppletGuard(smartcard::PCSCConnection& conn, ReselHook on_exit)
    : conn(conn), tx(conn), on_exit(std::move(on_exit))
{
    auto resp = conn.transmit(smartcard::selectByAID(protocol::AID_PKCS15));
    if (!resp.isSuccess())
        throw std::runtime_error("Failed to select PKI applet");
}

PkiAppletGuard::~PkiAppletGuard() noexcept
{
    if (on_exit) {
        try { on_exit(conn); } catch (...) {}
    }
    // tx destructor fires next, releasing the PC/SC transaction.
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

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
        std::cerr << "[cardedge] readPkiFile: SELECT 0x"
                  << std::hex << std::setfill('0') << std::setw(4) << fileId
                  << " failed, SW=0x" << std::setw(4) << selectResp.statusWord()
                  << std::dec << std::endl;
        return {};
    }

    uint16_t fileSize = parseFciFileSize(selectResp.data);
    std::cerr << "[cardedge] readPkiFile: SELECT 0x"
              << std::hex << std::setfill('0') << std::setw(4) << fileId
              << " OK, size=" << std::dec << fileSize << std::endl;

    if (fileSize == 0)
        return {};

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
            std::cerr << "[cardedge] readPkiFile: READ BINARY at offset " << offset
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
        std::cerr << "[cardedge] decompressCertificate: uncompress failed, ret=" << ret << std::endl;
        return {};
    }
    result.resize(destLen);
    return result;
}

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
        e.name.assign(reinterpret_cast<const char*>(data.data() + off),
                       strnlen(reinterpret_cast<const char*>(data.data() + off), 8));
        e.fid = static_cast<uint16_t>(data[off + 8]) | (static_cast<uint16_t>(data[off + 9]) << 8);
        e.isDir = (data[off + 10] != 0);
        entries.push_back(std::move(e));
    }
    return entries;
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

// ---------------------------------------------------------------------------
// Public API — all assume PkiAppletGuard is held by caller
// ---------------------------------------------------------------------------

CertificateList readCertificates(smartcard::PCSCConnection& conn)
{
    // Step 1: Read root directory to find the "mscp" subdirectory.
    auto rootDir = readPkiFile(conn, protocol::PKI_ROOT_DIR_FID);
    if (rootDir.empty()) {
        std::cerr << "[cardedge] readCertificates: failed to read root directory" << std::endl;
        return {};
    }

    auto rootEntries = parseDirFile(rootDir);
    std::cerr << "[cardedge] readCertificates: root dir has " << rootEntries.size()
              << " entries" << std::endl;

    uint16_t mscpFid = 0;
    for (const auto& e : rootEntries) {
        std::cerr << "[cardedge] readCertificates: root entry: \"" << e.name
                  << "\" fid=0x" << std::hex << std::setfill('0') << std::setw(4) << e.fid
                  << std::dec << " isDir=" << e.isDir << std::endl;
        if (e.isDir && e.name == "mscp")
            mscpFid = e.fid;
    }

    if (mscpFid == 0) {
        std::cerr << "[cardedge] readCertificates: 'mscp' directory not found" << std::endl;
        return {};
    }

    // Step 2: Read "mscp" directory — collect cert files (kxc*, ksc*) and cmapfile FID.
    auto mscpDir = readPkiFile(conn, mscpFid);
    if (mscpDir.empty()) {
        std::cerr << "[cardedge] readCertificates: failed to read mscp directory" << std::endl;
        return {};
    }

    auto mscpEntries = parseDirFile(mscpDir);
    std::cerr << "[cardedge] readCertificates: mscp dir has " << mscpEntries.size()
              << " entries" << std::endl;

    struct CertFileEntry {
        uint16_t fid;
        std::string label;
        uint8_t contId;
        uint16_t keyPairId;  // protocol::AT_KEYEXCHANGE or protocol::AT_SIGNATURE
    };
    std::vector<CertFileEntry> certFiles;
    uint16_t cmapFid = 0;

    for (const auto& e : mscpEntries) {
        std::cerr << "[cardedge] readCertificates: mscp entry: \"" << e.name
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

    std::cerr << "[cardedge] readCertificates: found " << certFiles.size()
              << " certificate files" << std::endl;

    // Step 3: Read cmapfile to derive each certificate's private key FID.
    std::vector<uint8_t> cmapData;
    size_t cmapOffset = 0;
    size_t cmapRecordCount = 0;
    if (cmapFid != 0) {
        cmapData = readPkiFile(conn, cmapFid);
        if (cmapData.size() >= 2 && (cmapData.size() - 2) % protocol::CMAP_RECORD_SIZE == 0)
            cmapOffset = 2;
        cmapRecordCount = (cmapData.size() - cmapOffset) / protocol::CMAP_RECORD_SIZE;
        std::cerr << "[cardedge] readCertificates: cmapfile has " << cmapRecordCount
                  << " container records" << std::endl;
    } else {
        std::cerr << "[cardedge] readCertificates: cmapfile not found, key FIDs unavailable"
                  << std::endl;
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
            auto raw = readPkiFile(conn, cf.fid);
            std::cerr << "[cardedge] readCertificates: cert file 0x"
                      << std::hex << std::setfill('0') << std::setw(4) << cf.fid
                      << std::dec << " raw size=" << raw.size() << std::endl;
            if (raw.size() < 6)
                continue;

            // Skip 2-byte CardFS length prefix
            const uint8_t* certData = raw.data() + 2;
            size_t certDataLen = raw.size() - 2;

            std::vector<uint8_t> der;
            if (certDataLen >= 4 && certData[0] == 0x01 && certData[1] == 0x00) {
                der = decompressCertificate(certData, certDataLen);
            } else if (certData[0] == 0x30) {
                // Uncompressed DER (ASN.1 SEQUENCE)
                der.assign(certData, certData + certDataLen);
            } else {
                std::cerr << "[cardedge] readCertificates: unknown cert format, skipping"
                          << std::endl;
                continue;
            }

            if (der.empty())
                continue;

            uint16_t keyFid = 0;
            uint16_t keySizeBits = 0;
            if (!cmapData.empty() && cf.contId < cmapRecordCount) {
                size_t recOffset = cmapOffset + cf.contId * protocol::CMAP_RECORD_SIZE;
                uint8_t flags = cmapData[recOffset + protocol::CMAP_FLAGS_OFFSET];
                if (flags & protocol::CMAP_VALID_CONTAINER) {
                    size_t sizeOffset = (cf.keyPairId == protocol::AT_KEYEXCHANGE)
                        ? recOffset + protocol::CMAP_KX_SIZE_OFFSET
                        : recOffset + protocol::CMAP_SIG_SIZE_OFFSET;
                    keySizeBits = static_cast<uint16_t>(
                        cmapData[sizeOffset] | (cmapData[sizeOffset + 1] << 8));
                    if (keySizeBits != 0)
                        keyFid = protocol::privateKeyFID(cf.contId, cf.keyPairId);
                }
            }

            std::cerr << "[cardedge] readCertificates: \"" << cf.label
                      << "\" DER size=" << der.size()
                      << " keyFID=0x" << std::hex << std::setfill('0') << std::setw(4) << keyFid
                      << " keySizeBits=" << std::dec << keySizeBits << std::endl;
            certs.push_back({ cf.label, std::move(der), keyFid, keySizeBits });
        } catch (const std::exception& e) {
            std::cerr << "[cardedge] readCertificates: cert 0x" << std::hex << cf.fid
                      << std::dec << " exception: " << e.what() << std::endl;
        }
    }

    std::cerr << "[cardedge] readCertificates: returning " << certs.size()
              << " certificates" << std::endl;
    return certs;
}

PINResult getPINTriesLeft(smartcard::PCSCConnection& conn)
{
    // ISO 7816-4 VERIFY with empty data = status check (does not decrement retries).
    auto resp = conn.transmit(smartcard::verifyPINStatus(protocol::PKI_PIN_REFERENCE));
    auto result = parsePINStatusWord(resp.statusWord());

    if (result.success && result.retriesLeft < 0)
        result.retriesLeft = protocol::PIN_MAX_RETRIES;

    return result;
}

PINResult verifyPIN(smartcard::PCSCConnection& conn, const std::string& pin)
{
    auto resp = conn.transmit(
        smartcard::verifyPIN(protocol::PKI_PIN_REFERENCE, padPIN(pin)));
    return parsePINStatusWord(resp.statusWord());
}

PINResult changePIN(smartcard::PCSCConnection& conn,
                    const std::string& oldPin,
                    const std::string& newPin)
{
    auto resp = conn.transmit(
        smartcard::changeReferenceData(protocol::PKI_PIN_REFERENCE,
                                       padPIN(oldPin), padPIN(newPin)));
    return parsePINStatusWord(resp.statusWord());
}

std::vector<uint8_t> signData(smartcard::PCSCConnection& conn,
                               uint16_t keyReference,
                               const std::vector<uint8_t>& data)
{
    // MSE SET: 00 22 41 B6 07 80 01 02 84 02 [keyFID_HI] [keyFID_LO]
    // P1=0x41 (SET), P2=0xB6 (digital signature template)
    // Tag 0x80: algorithm ID = 0x02 (RSA-2048 PKCS#1 v1.5)
    // Tag 0x84: key reference (2 bytes, big-endian)
    uint8_t keyH = static_cast<uint8_t>((keyReference >> 8) & 0xFF);
    uint8_t keyL = static_cast<uint8_t>(keyReference & 0xFF);
    smartcard::APDUCommand mseSet{
        .cla = 0x00,
        .ins = 0x22,  // MANAGE SECURITY ENVIRONMENT
        .p1 = 0x41,   // SET
        .p2 = 0xB6,   // Digital Signature template
        .data = {0x80, 0x01, protocol::MSE_ALG_RSA2048, 0x84, 0x02, keyH, keyL},
        .le = 0,
        .hasLe = false
    };

    auto mseResp = conn.transmit(mseSet);
    if (!mseResp.isSuccess()) {
        std::cerr << "[cardedge] signData: MSE SET failed, SW=0x"
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
        .le = 0x00,
        .hasLe = true
    };

    auto psoResp = conn.transmit(pso);
    if (!psoResp.isSuccess()) {
        std::cerr << "[cardedge] signData: PSO failed, SW=0x"
                  << std::hex << std::setfill('0') << std::setw(4) << psoResp.statusWord()
                  << std::dec << std::endl;
        throw std::runtime_error("PSO COMPUTE DIGITAL SIGNATURE failed");
    }

    std::cerr << "[cardedge] signData: signature size=" << psoResp.data.size() << std::endl;
    return psoResp.data;
}

std::vector<std::pair<std::string, uint16_t>>
discoverKeyReferences(smartcard::PCSCConnection& conn)
{
    auto rootDir = readPkiFile(conn, protocol::PKI_ROOT_DIR_FID);
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

    auto mscpDir = readPkiFile(conn, mscpFid);
    if (mscpDir.empty()) return {};

    auto mscpEntries = parseDirFile(mscpDir);

    uint16_t cmapFid = 0;
    struct CertFileInfo {
        std::string label;
        uint8_t contId;
        uint16_t keyPairId;
    };
    std::vector<CertFileInfo> certInfos;

    for (const auto& e : mscpEntries) {
        if (!e.isDir && e.name == "cmapfile") {
            cmapFid = e.fid;
        } else if (!e.isDir && e.name.size() == 5) {
            std::string prefix = e.name.substr(0, 3);
            if (prefix == "kxc" || prefix == "ksc") {
                uint8_t contId = static_cast<uint8_t>(std::stoul(e.name.substr(3, 2)));
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
        std::cerr << "[cardedge] discoverKeyReferences: cmapfile or cert files not found"
                  << std::endl;
        return {};
    }

    auto cmapData = readPkiFile(conn, cmapFid);

    size_t cmapOffset = 0;
    if (cmapData.size() >= 2 && (cmapData.size() - 2) % protocol::CMAP_RECORD_SIZE == 0)
        cmapOffset = 2;

    size_t recCount = (cmapData.size() - cmapOffset) / protocol::CMAP_RECORD_SIZE;

    std::cerr << "[cardedge] discoverKeyReferences: cmapfile has " << recCount
              << " container records (offset=" << cmapOffset
              << ", " << cmapData.size() << " bytes)" << std::endl;

    std::vector<std::pair<std::string, uint16_t>> result;
    for (const auto& ci : certInfos) {
        if (ci.contId >= recCount) {
            std::cerr << "[cardedge] discoverKeyReferences: container " << (int)ci.contId
                      << " out of range" << std::endl;
            continue;
        }

        size_t recOffset = cmapOffset + ci.contId * protocol::CMAP_RECORD_SIZE;
        uint8_t flags = cmapData[recOffset + protocol::CMAP_FLAGS_OFFSET];

        if (!(flags & protocol::CMAP_VALID_CONTAINER)) {
            std::cerr << "[cardedge] discoverKeyReferences: container " << (int)ci.contId
                      << " not valid (flags=0x" << std::hex << (int)flags << std::dec
                      << ")" << std::endl;
            continue;
        }

        size_t sizeOffset = (ci.keyPairId == protocol::AT_KEYEXCHANGE)
            ? recOffset + protocol::CMAP_KX_SIZE_OFFSET
            : recOffset + protocol::CMAP_SIG_SIZE_OFFSET;
        uint16_t keySizeBits = static_cast<uint16_t>(
            cmapData[sizeOffset] | (cmapData[sizeOffset + 1] << 8));

        if (keySizeBits == 0) {
            std::cerr << "[cardedge] discoverKeyReferences: container " << (int)ci.contId
                      << " has no " << (ci.keyPairId == protocol::AT_KEYEXCHANGE ? "KX" : "SIG")
                      << " key" << std::endl;
            continue;
        }

        uint16_t keyFid = protocol::privateKeyFID(ci.contId, ci.keyPairId);
        std::cerr << "[cardedge] discoverKeyReferences: \"" << ci.label
                  << "\" container=" << (int)ci.contId
                  << " keySize=" << keySizeBits
                  << " FID=0x" << std::hex << std::setfill('0') << std::setw(4) << keyFid
                  << std::dec << std::endl;

        result.emplace_back(ci.label, keyFid);
    }

    std::cerr << "[cardedge] discoverKeyReferences: found " << result.size()
              << " key references" << std::endl;
    return result;
}

} // namespace cardedge
