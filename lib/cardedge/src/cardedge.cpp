// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "cardedge/cardedge.h"
#include "cardedge/pki_applet_guard.h"
#include "cardedge_protocol.h"
#include "smartcard/pcsc_connection.h"
#include "smartcard/apdu.h"
#include <algorithm>
#include <cstring>
#include <openssl/crypto.h>
#include <pkcs15/pkcs15_parser.h>
#include <zlib.h>

namespace cardedge {

// ---------------------------------------------------------------------------
// PkiAppletGuard
// ---------------------------------------------------------------------------

PkiAppletGuard::PkiAppletGuard(smartcard::PCSCConnection& conn) : conn(conn), tx(conn)
{
    // Use P2=0x0C (no FCI) — some cards (e.g. eMRTD with PKCS#15) reject P2=0x00
    auto resp = conn.transmit(smartcard::selectByAID(protocol::AID_PKCS15, 0x0C));
    if (!resp.isSuccess())
        throw std::runtime_error("Failed to select PKI applet");
}

PkiAppletGuard::~PkiAppletGuard() noexcept
{
    // tx destructor fires next, releasing the PC/SC transaction.
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// CardEdge FCI (File Control Information) response: 10 bytes, all big-endian
// [FID_H:1] [FID_L:1] [Size_H:1] [Size_L:1] [ACL: 6 bytes]
static uint16_t parseFciFileSize(const std::vector<uint8_t>& fci)
{
    if (fci.size() < 4)
        return 0;
    return static_cast<uint16_t>((fci[2] << 8) | fci[3]);
}

// Read a file from the PKI (PKCS#15/CardEdge) applet using SELECT by file ID.
// Uses the FCI response to determine file size and reads in 128-byte chunks.
static std::vector<uint8_t> readPkiFile(smartcard::PCSCConnection& conn, uint16_t fileId)
{
    uint8_t fileH = static_cast<uint8_t>((fileId >> 8) & 0xFF);
    uint8_t fileL = static_cast<uint8_t>(fileId & 0xFF);

    auto selectResp = conn.transmit(smartcard::selectByFileId(fileH, fileL));
    if (!selectResp.isSuccess())
        return {};

    uint16_t fileSize = parseFciFileSize(selectResp.data);
    if (fileSize == 0)
        return {};

    std::vector<uint8_t> fileData;
    fileData.reserve(fileSize);

    for (uint16_t offset = 0; offset < fileSize; offset += protocol::PKI_READ_CHUNK) {
        uint8_t toRead = static_cast<uint8_t>(
            std::min(static_cast<uint16_t>(protocol::PKI_READ_CHUNK), static_cast<uint16_t>(fileSize - offset)));

        auto readResp = conn.transmit(smartcard::readBinary(offset, toRead));
        if (readResp.data.empty())
            break;

        // Accept both 0x9000 (success) and 0x62XX (warnings like end-of-file)
        uint8_t sw1 = static_cast<uint8_t>((readResp.statusWord() >> 8) & 0xFF);
        if (sw1 != 0x90 && sw1 != 0x62)
            break;

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
    if (rawLen == 0 || rawLen > 16384)
        return {}; // reject unreasonable decompressed sizes
    const uint8_t* compressed = data + 4;
    size_t compressedLen = dataLen - 4;

    std::vector<uint8_t> result(rawLen);
    uLongf destLen = rawLen;
    int ret = uncompress(result.data(), &destLen, compressed, static_cast<uLong>(compressedLen));
    if (ret != Z_OK)
        return {};
    result.resize(destLen);
    return result;
}

struct DirEntry
{
    std::string name;
    uint16_t fid;
    bool isDir;
};

static std::vector<DirEntry> parseDirFile(const std::vector<uint8_t>& data)
{
    std::vector<DirEntry> entries;
    if (data.size() < protocol::CE_DIR_HEADER_SIZE)
        return entries;

    uint16_t count = static_cast<uint16_t>(data[6]) | (static_cast<uint16_t>(data[7]) << 8);

    for (uint16_t i = 0; i < count; i++) {
        size_t off = protocol::CE_DIR_HEADER_SIZE + i * protocol::CE_DIR_ENTRY_SIZE;
        if (off + protocol::CE_DIR_ENTRY_SIZE > data.size())
            break;

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
    if (rootDir.empty())
        return {};

    auto rootEntries = parseDirFile(rootDir);

    uint16_t mscpFid = 0;
    for (const auto& e : rootEntries) {
        if (e.isDir && e.name == "mscp")
            mscpFid = e.fid;
    }

    if (mscpFid == 0)
        return {};

    // Step 2: Read "mscp" directory — collect cert files (kxc*, ksc*) and cmapfile FID.
    auto mscpDir = readPkiFile(conn, mscpFid);
    if (mscpDir.empty())
        return {};

    auto mscpEntries = parseDirFile(mscpDir);

    struct CertFileEntry
    {
        uint16_t fid;
        std::string label;
        uint8_t contId;
        uint16_t keyPairId; // protocol::AT_KEYEXCHANGE or protocol::AT_SIGNATURE
    };
    std::vector<CertFileEntry> certFiles;
    uint16_t cmapFid = 0;

    for (const auto& e : mscpEntries) {
        if (e.isDir)
            continue;

        if (e.name == "cmapfile") {
            cmapFid = e.fid;
        } else if (e.name.size() == 5) {
            std::string prefix = e.name.substr(0, 3);
            if (prefix == "kxc" || prefix == "ksc") {
                try {
                    auto idx = std::stoul(e.name.substr(3, 2));
                    uint8_t contId = static_cast<uint8_t>(idx);
                    certFiles.push_back({e.fid,
                                         prefix == "kxc" ? "Key Exchange Certificate" : "Digital Signature Certificate",
                                         contId, prefix == "kxc" ? protocol::AT_KEYEXCHANGE : protocol::AT_SIGNATURE});
                } catch (const std::exception&) {
                    continue; // skip malformed entry
                }
            }
        }
    }

    // Step 3: Read cmapfile to derive each certificate's private key FID.
    std::vector<uint8_t> cmapData;
    size_t cmapOffset = 0;
    size_t cmapRecordCount = 0;
    if (cmapFid != 0) {
        cmapData = readPkiFile(conn, cmapFid);
        if (cmapData.size() >= 2 && (cmapData.size() - 2) % protocol::CMAP_RECORD_SIZE == 0)
            cmapOffset = 2;
        cmapRecordCount = (cmapData.size() - cmapOffset) / protocol::CMAP_RECORD_SIZE;
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
                    if (sizeOffset + 1 < cmapData.size())
                        keySizeBits = static_cast<uint16_t>(cmapData[sizeOffset] | (cmapData[sizeOffset + 1] << 8));
                    if (keySizeBits != 0)
                        keyFid = protocol::privateKeyFID(cf.contId, cf.keyPairId);
                }
            }

            certs.push_back({cf.label, std::move(der), keyFid, keySizeBits});
        } catch (const std::exception&) {
            // Skip certificates that fail to read or decompress
        }
    }

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
    auto paddedPin = padPIN(pin);
    auto resp = conn.transmit(smartcard::verifyPIN(protocol::PKI_PIN_REFERENCE, paddedPin));
    OPENSSL_cleanse(paddedPin.data(), paddedPin.size());
    return parsePINStatusWord(resp.statusWord());
}

PINResult changePIN(smartcard::PCSCConnection& conn, const std::string& oldPin, const std::string& newPin)
{
    auto paddedOld = padPIN(oldPin);
    auto paddedNew = padPIN(newPin);
    auto resp = conn.transmit(smartcard::changeReferenceData(protocol::PKI_PIN_REFERENCE, paddedOld, paddedNew));
    OPENSSL_cleanse(paddedOld.data(), paddedOld.size());
    OPENSSL_cleanse(paddedNew.data(), paddedNew.size());
    return parsePINStatusWord(resp.statusWord());
}

std::vector<uint8_t> signData(smartcard::PCSCConnection& conn, uint16_t keyReference, const std::vector<uint8_t>& data)
{
    // MSE SET: 00 22 41 B6 07 80 01 02 84 02 [keyFID_HI] [keyFID_LO]
    // P1=0x41 (SET), P2=0xB6 (digital signature template)
    // Tag 0x80: algorithm ID = 0x02 (RSA-2048 PKCS#1 v1.5)
    // Tag 0x84: key reference (2 bytes, big-endian)
    uint8_t keyH = static_cast<uint8_t>((keyReference >> 8) & 0xFF);
    uint8_t keyL = static_cast<uint8_t>(keyReference & 0xFF);
    smartcard::APDUCommand mseSet{.cla = 0x00,
                                  .ins = 0x22, // MANAGE SECURITY ENVIRONMENT
                                  .p1 = 0x41,  // SET
                                  .p2 = 0xB6,  // Digital Signature template
                                  .data = {0x80, 0x01, protocol::MSE_ALG_RSA2048, 0x84, 0x02, keyH, keyL},
                                  .le = 0,
                                  .hasLe = false};

    auto mseResp = conn.transmit(mseSet);
    if (!mseResp.isSuccess())
        throw std::runtime_error("MSE SET failed");

    // PSO COMPUTE DIGITAL SIGNATURE: 00 2A 9E 00 [Lc] [DigestInfo] 00
    smartcard::APDUCommand pso{.cla = 0x00,
                               .ins = 0x2A, // PERFORM SECURITY OPERATION
                               .p1 = 0x9E,  // Compute digital signature
                               .p2 = 0x00,
                               .data = data,
                               .le = 0x00,
                               .hasLe = true};

    auto psoResp = conn.transmit(pso);
    if (!psoResp.isSuccess())
        throw std::runtime_error("PSO COMPUTE DIGITAL SIGNATURE failed");

    return psoResp.data;
}

std::vector<std::pair<std::string, uint16_t>> discoverKeyReferences(smartcard::PCSCConnection& conn)
{
    auto rootDir = readPkiFile(conn, protocol::PKI_ROOT_DIR_FID);
    if (rootDir.empty())
        return {};

    auto rootEntries = parseDirFile(rootDir);
    uint16_t mscpFid = 0;
    for (const auto& e : rootEntries) {
        if (e.isDir && e.name == "mscp") {
            mscpFid = e.fid;
            break;
        }
    }
    if (mscpFid == 0)
        return {};

    auto mscpDir = readPkiFile(conn, mscpFid);
    if (mscpDir.empty())
        return {};

    auto mscpEntries = parseDirFile(mscpDir);

    uint16_t cmapFid = 0;
    struct CertFileInfo
    {
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
                try {
                    auto idx = std::stoul(e.name.substr(3, 2));
                    uint8_t contId = static_cast<uint8_t>(idx);
                    certInfos.push_back({prefix == "kxc" ? "Key Exchange Certificate" : "Digital Signature Certificate",
                                         contId, prefix == "kxc" ? protocol::AT_KEYEXCHANGE : protocol::AT_SIGNATURE});
                } catch (const std::exception&) {
                    continue; // skip malformed entry
                }
            }
        }
    }

    if (cmapFid == 0 || certInfos.empty())
        return {};

    auto cmapData = readPkiFile(conn, cmapFid);

    size_t cmapOffset = 0;
    if (cmapData.size() >= 2 && (cmapData.size() - 2) % protocol::CMAP_RECORD_SIZE == 0)
        cmapOffset = 2;

    size_t recCount = (cmapData.size() - cmapOffset) / protocol::CMAP_RECORD_SIZE;

    std::vector<std::pair<std::string, uint16_t>> result;
    for (const auto& ci : certInfos) {
        if (ci.contId >= recCount)
            continue;

        size_t recOffset = cmapOffset + ci.contId * protocol::CMAP_RECORD_SIZE;
        uint8_t flags = cmapData[recOffset + protocol::CMAP_FLAGS_OFFSET];

        if (!(flags & protocol::CMAP_VALID_CONTAINER))
            continue;

        size_t sizeOffset = (ci.keyPairId == protocol::AT_KEYEXCHANGE) ? recOffset + protocol::CMAP_KX_SIZE_OFFSET
                                                                       : recOffset + protocol::CMAP_SIG_SIZE_OFFSET;
        if (sizeOffset + 1 >= cmapData.size())
            continue;
        uint16_t keySizeBits = static_cast<uint16_t>(cmapData[sizeOffset] | (cmapData[sizeOffset + 1] << 8));

        if (keySizeBits == 0)
            continue;

        uint16_t keyFid = protocol::privateKeyFID(ci.contId, ci.keyPairId);
        result.emplace_back(ci.label, keyFid);
    }

    return result;
}

pkcs15::TokenInfo readTokenInfo(smartcard::PCSCConnection& conn)
{
    auto data = readPkiFile(conn, protocol::PKI_TOKEN_INFO_FID);
    if (data.empty())
        return {};
    return pkcs15::parseTokenInfo(data);
}

} // namespace cardedge
