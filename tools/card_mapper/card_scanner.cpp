// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_scanner.h"
#include "apdu_logger.h"

#include <card_protocol.h>
#include <cardedge_protocol.h>
#include <health_protocol.h>
#include <eu_vrc_protocol.h>
#include <emrtd/emrtd_types.h>

#include <pkcs15/pkcs15_card.h>

#include <smartcard/apdu.h>
#include <smartcard/ber.h>
#include <smartcard/tlv.h>

#include <algorithm>
#include <format>
#include <iostream>
#include <optional>
#include <unordered_map>

namespace card_mapper {

std::vector<std::pair<uint16_t, uint16_t>> getProbeRanges()
{
    return {
        {0x0F00, 0x0FFF}, // Serbian eID file range
        {0x0D00, 0x0DFF}, // Serbian health card file range
        {0xC000, 0xC0FF}, // EU VRC certificate files (C001, C011)
        {0xD000, 0xD0FF}, // EU VRC / Serbian vehicle data files (D001, D011, D021, D031)
        {0xE000, 0xE0FF}, // EU VRC signature files (E001, E011)
        {0x4400, 0x440F}, // PKCS#15 object files (CDF, PrKDF, AODF, certs)
        {0x5030, 0x5035}, // PKCS#15 control files (EF.ODF, EF.TokenInfo)
    };
}

std::vector<AidProbe> getAllKnownProbes()
{
    using namespace euvrc::protocol;

    auto emrtdAid = std::vector<uint8_t>(emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN);

    return {
        // Simple single-SELECT AIDs
        {"SERID", eidcard::protocol::AID_SERID, {eidcard::protocol::AID_SERID}},
        {"SERIF", eidcard::protocol::AID_SERIF, {eidcard::protocol::AID_SERIF}},
        {"SERRP", eidcard::protocol::AID_SERRP, {eidcard::protocol::AID_SERRP}},
        {"PKCS15", cardedge::protocol::AID_PKCS15, {cardedge::protocol::AID_PKCS15}},
        {"SERVSZK", healthcard::protocol::AID_SERVSZK, {healthcard::protocol::AID_SERVSZK}},
        {"eMRTD", emrtdAid, {emrtdAid}},
        {"PIV", {0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10}, {{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10}}},

        // EU VRC: EU standard AID (single SELECT)
        {"EU-EVR-01", EU_VRC_AID, {EU_VRC_AID}},

        // EU VRC: Serbian 3-command selection sequences — all must succeed
        {"EU-VRC-RS-SEQ1", SEQ1_CMD1, {SEQ1_CMD1, SEQ1_CMD2, SEQ1_CMD3}, 0x0C},
        {"EU-VRC-RS-SEQ2", SEQ2_CMD1, {SEQ2_CMD1, SEQ2_CMD2, SEQ1_CMD3}, 0x0C},
        {"EU-VRC-RS-SEQ3", SEQ3_CMD1, {SEQ3_CMD1, SEQ3_CMD2, SEQ3_CMD3}, 0x0C},
    };
}

namespace {

bool aidContained(const std::vector<std::vector<uint8_t>>& detected, const std::vector<uint8_t>& aid)
{
    return std::find(detected.begin(), detected.end(), aid) != detected.end();
}

// Try an AID probe: execute all SELECT commands in sequence.
// Returns the P2 that worked for the last SELECT, or nullopt if probe failed.
// When a SELECT returns a retryable error, tries alternative P2 values.
std::optional<uint8_t> tryProbe(smartcard::PCSCConnection& conn, const AidProbe& probe)
{
    constexpr uint8_t AID_P2_ALTS[] = {0x0C, 0x04, 0x00};

    uint8_t workingP2 = probe.lastP2;

    for (size_t i = 0; i < probe.selectSequence.size(); ++i) {
        bool isLast = (i == probe.selectSequence.size() - 1);
        uint8_t preferredP2 = isLast ? probe.lastP2 : 0x00;

        auto resp = conn.transmit(smartcard::selectByAID(probe.selectSequence[i], preferredP2));
        if (resp.isSuccess() || resp.sw1 == 0x62 || resp.sw1 == 0x61) {
            if (isLast)
                workingP2 = preferredP2;
            continue;
        }

        // Try alternative P2 values on retryable errors
        if (!smartcard::isSelectRetryable(resp.statusWord()))
            return std::nullopt;

        bool found = false;
        for (uint8_t altP2 : AID_P2_ALTS) {
            if (altP2 == preferredP2)
                continue;
            resp = conn.transmit(smartcard::selectByAID(probe.selectSequence[i], altP2));
            if (resp.isSuccess() || resp.sw1 == 0x62 || resp.sw1 == 0x61) {
                if (isLast)
                    workingP2 = altP2;
                found = true;
                break;
            }
        }
        if (!found)
            return std::nullopt;
    }
    return workingP2;
}

// SELECT variant for file selection — each combination of P1/P2/Le that cards may require.
smartcard::APDUResponse trySelectVariant(smartcard::PCSCConnection& conn, uint8_t hi, uint8_t lo, int variant)
{
    switch (variant) {
    case 0: // P1=0x08, P2=0x00, Le=4 — SELECT by path from MF (eID, health)
        return conn.transmit(smartcard::selectByPath(hi, lo));
    case 1: // P1=0x02, P2=0x04, no Le — SELECT child EF, return FCP (vehicle)
        return conn.transmit(smartcard::APDUCommand{
            .cla = 0x00, .ins = 0xA4, .p1 = 0x02, .p2 = 0x04, .data = {hi, lo}, .le = 0, .hasLe = false});
    case 2: // P1=0x00, P2=0x00, Le=0 — SELECT by FID, return FCI (generic)
        return conn.transmit(smartcard::selectByFileId(hi, lo));
    case 3: // P1=0x02, P2=0x0C, no Le — SELECT child EF, no response data (strict cards)
        return conn.transmit(smartcard::APDUCommand{
            .cla = 0x00, .ins = 0xA4, .p1 = 0x02, .p2 = 0x0C, .data = {hi, lo}, .le = 0, .hasLe = false});
    case 4: // P1=0x00, P2=0x0C, no Le — SELECT by FID, no response data (strict cards)
        return conn.transmit(smartcard::selectByFileId(hi, lo, 0x0C));
    default:
        return smartcard::APDUResponse{.data = {}, .sw1 = 0x6A, .sw2 = 0x82};
    }
}

constexpr int FID_SELECT_VARIANT_COUNT = 5;

// Try to SELECT a file, using cached variant first if available.
// Permanently skips variants the card rejects (6700/6982/6A86 = format mismatch).
// Still tries all accepted variants per FID since different P1 values search
// different scopes (P1=0x00 searches MF, P1=0x02 searches current DF).
smartcard::APDUResponse selectFile(smartcard::PCSCConnection& conn, uint8_t hi, uint8_t lo, int& cachedVariant,
                                   uint32_t& rejectedMask)
{
    // Fast path: try cached variant first (last variant that returned success)
    if (cachedVariant >= 0) {
        auto resp = trySelectVariant(conn, hi, lo, cachedVariant);
        if (resp.isSuccess() || resp.sw1 == 0x62 || resp.sw1 == 0x61)
            return resp;
    }

    // Try all non-rejected variants
    for (int v = 0; v < FID_SELECT_VARIANT_COUNT; ++v) {
        if (v == cachedVariant)
            continue;
        if (rejectedMask & (1u << v))
            continue;

        auto resp = trySelectVariant(conn, hi, lo, v);
        if (resp.isSuccess() || resp.sw1 == 0x62 || resp.sw1 == 0x61) {
            cachedVariant = v;
            return resp;
        }
        // Permanently skip formats the card rejects (format mismatch)
        if (smartcard::isSelectRetryable(resp.statusWord()))
            rejectedMask |= (1u << v);
    }

    return smartcard::APDUResponse{.data = {}, .sw1 = 0x6A, .sw2 = 0x82};
}

// Read file content with resilience: Le correction, chunk fallback, multi-chunk loop.
std::vector<uint8_t> readFileContent(smartcard::PCSCConnection& conn)
{
    constexpr size_t MAX_READ_SIZE = 65536;
    constexpr uint8_t CHUNK_SIZES[] = {0xFF, 0x80, 0x40, 0x20};

    // Determine working chunk size from first read
    uint8_t chunkSize = 0;
    smartcard::APDUResponse firstResp{};

    for (uint8_t cs : CHUNK_SIZES) {
        firstResp = conn.transmit(smartcard::readBinary(0, cs));

        // SW=6C XX: card tells us correct Le — use it
        if (firstResp.sw1 == 0x6C) {
            chunkSize = firstResp.sw2;
            firstResp = conn.transmit(smartcard::readBinary(0, chunkSize));
            break;
        }

        if (firstResp.isSuccess() || firstResp.statusWord() == 0x6282) {
            chunkSize = cs;
            break;
        }
    }

    if (chunkSize == 0 || (firstResp.data.empty() && !firstResp.isSuccess() && firstResp.statusWord() != 0x6282))
        return {};

    std::vector<uint8_t> result(firstResp.data.begin(), firstResp.data.end());

    // End of file on first read
    if (firstResp.statusWord() == 0x6282 || firstResp.data.size() < chunkSize)
        return result;

    // Multi-chunk read loop
    size_t offset = result.size();
    while (offset < MAX_READ_SIZE) {
        auto resp = conn.transmit(smartcard::readBinary(static_cast<uint16_t>(offset), chunkSize));
        if (resp.data.empty() || (!resp.isSuccess() && resp.statusWord() != 0x6282))
            break;
        result.insert(result.end(), resp.data.begin(), resp.data.end());
        offset += resp.data.size();
        if (resp.statusWord() == 0x6282)
            break;
        if (resp.data.size() < chunkSize)
            break;
    }

    return result;
}

// Known BER-TLV tag names from EU VRC (Directive 2003/127/EC) and ICAO 9303
std::string lookupBERTagName(uint32_t tag)
{
    // EU VRC mandatory (tag 71) and optional (tag 72) fields
    static const std::unordered_map<uint32_t, std::string> names = {
        // Container tags
        {0x78, "Tag allocation authority"},
        {0x4F, "Application identifier"},
        {0x71, "Mandatory data (EU)"},
        {0x72, "Optional data (EU)"},
        // EU VRC mandatory
        {0x80, "Version"},
        {0x81, "A: Registration number"},
        {0x82, "B: Date of first registration"},
        {0x83, "C.1.1: Holder surname/business name"},
        {0x84, "C.1.2: Holder other names"},
        {0x85, "C.1.3: Holder address"},
        {0x86, "C.4: Ownership status"},
        {0x87, "D.1: Vehicle make"},
        {0x88, "D.2: Vehicle type"},
        {0x89, "D.3: Commercial description"},
        {0x8A, "E: VIN"},
        {0x8B, "F.1: Max permissible laden mass"},
        {0x8C, "G: Vehicle in-service mass"},
        {0x8D, "H: Validity period / expiry"},
        {0x8E, "I: Registration date"},
        {0x8F, "K: Type-approval number"},
        {0x90, "P.1: Engine capacity (cm3)"},
        {0x91, "P.2: Max net power (kW)"},
        {0x92, "P.3: Fuel type"},
        {0x93, "Q: Power-to-weight ratio"},
        {0x94, "S.1: Number of seats"},
        {0x95, "S.2: Standing places"},
        // EU VRC optional
        {0x96, "F.2: Max laden mass in service"},
        {0x97, "F.3: Max laden mass whole vehicle"},
        {0x98, "J: Vehicle category"},
        {0x99, "L: Number of axles"},
        {0x9A, "M: Wheelbase"},
        {0x9B, "O.1: Braked trailer mass"},
        {0x9C, "O.2: Unbraked trailer mass"},
        {0x9D, "P.4: Rated engine speed"},
        {0x9E, "P.5: Engine ID number"},
        {0x9F24, "R: Colour"},
        {0x9F25, "T: Maximum speed"},
        {0x9F33, "Member State name"},
        {0x9F35, "Competent authority"},
        {0x9F36, "Issuing authority"},
        {0x9F38, "Document number"},
        // Container tags
        {0xA1, "C: Personal data"},
        {0xA2, "C.1: Registration holder"},
        {0xA3, "D: Vehicle data"},
        {0xA4, "F: Mass data"},
        {0xA5, "P: Engine data"},
        {0xA6, "S: Seating capacity"},
        {0xA7, "C.2: Vehicle owner"},
        {0xA8, "C.2: Second owner"},
        {0xA9, "C.3: User"},
    };

    auto it = names.find(tag);
    return (it != names.end()) ? it->second : std::format("Tag 0x{:02X}", tag);
}

// Recursively collect leaf tags from a BER tree into TagInfo entries
void collectBERTags(const smartcard::BERField& node, DataFile& dataFile, const std::string& prefix)
{
    for (const auto& child : node.children) {
        if (child.constructed && !child.children.empty()) {
            collectBERTags(child, dataFile, std::format("{}_{:02X}", prefix, child.tag));
        } else if (!child.value.empty()) {
            TagInfo tag;
            tag.tag = static_cast<uint16_t>(child.tag);
            tag.fieldKey = std::format("kTag{:s}_{:02X}", prefix, child.tag);
            tag.name = lookupBERTagName(child.tag);
            tag.type = "unknown";
            tag.example = child.asString();
            dataFile.tags.push_back(tag);
        }
    }
}

// Parse file data into an EF node: try TLV, then BER-TLV, else mark binary
void parseFileData(const std::vector<uint8_t>& fileData, FileNode& efNode, DataFile& dataFile)
{
    auto fields = smartcard::parseTLV(fileData.data(), fileData.size());
    if (!fields.empty()) {
        efNode.format = "TLV (LE 16-bit)";
        for (const auto& field : fields) {
            TagInfo tag;
            tag.tag = field.tag;
            tag.fieldKey = std::format("kTag_{:04X}", field.tag);
            tag.name = std::format("Tag {}", field.tag);
            tag.type = "unknown";
            tag.example = field.asString();
            dataFile.tags.push_back(tag);
        }
    } else {
        try {
            auto berRoot = smartcard::parseBER(fileData.data(), fileData.size());
            if (!berRoot.children.empty()) {
                efNode.format = "BER-TLV";
                collectBERTags(berRoot, dataFile, "");
            } else {
                efNode.format = "binary";
            }
        } catch (const std::exception&) {
            efNode.format = "binary";
        }
    }
}

std::string probeCertPath(smartcard::PCSCConnection& conn, const std::vector<uint8_t>& path)
{
    if (path.empty() || path.size() % 2 != 0)
        return "[invalid path]";

    size_t startIdx = 0;
    if (path.size() >= 2 && path[0] == 0x3F && path[1] == 0xFF) {
        startIdx = 2;
    }

    std::string lastDf = "applet";
    for (size_t i = startIdx; i + 1 < path.size(); i += 2) {
        uint8_t hi = path[i];
        uint8_t lo = path[i + 1];
        std::string fid = formatFid(hi, lo);

        auto resp = conn.transmit(smartcard::selectByFileId(hi, lo, 0x0C));
        if (!resp.isSuccess()) {
            resp = conn.transmit(smartcard::selectByFileId(hi, lo, 0x00));
        }
        if (!resp.isSuccess()) {
            return std::format("[SELECT {} failed: {:04X} under {}]", fid, resp.statusWord(), lastDf);
        }

        if (i + 2 >= path.size()) {
            auto readResp = conn.transmit(smartcard::readBinary(0, 4));
            if (readResp.isSuccess() || readResp.statusWord() == 0x6282) {
                return "[readable]";
            } else if (readResp.statusWord() == 0x6982) {
                return "[PIN required]";
            } else if (readResp.statusWord() == 0x6986) {
                return std::format("[SELECT OK but read failed: {:04X} — may be DF not EF]", readResp.statusWord());
            } else {
                return std::format("[read error: {:04X}]", readResp.statusWord());
            }
        }
        lastDf = fid;
    }
    return "[path exhausted]";
}

// PKCS#15 smart probe: use the PKCS#15 parser to navigate ODF→CDF/PrKDF/AODF
// instead of brute-forcing FID ranges. Returns true if PKCS#15 structure was read.
bool probePKCS15(smartcard::PCSCConnection& conn, FileNode& df, AppletInfo& applet)
{
    try {
        pkcs15::PKCS15Card card(conn);
        if (!card.probe())
            return false;

        auto profile = card.readProfile();

        applet.description = std::format("PKCS#15: {} ({})", profile.tokenInfo.label, profile.tokenInfo.manufacturer);

        auto addEF = [&](const char* name, uint8_t fidH, uint8_t fidL, const std::string& size) {
            FileNode ef;
            ef.name = std::format("{} ({})", name, formatFid(fidH, fidL));
            ef.fidHi = fidH;
            ef.fidLo = fidL;
            ef.format = "BER-TLV";
            ef.sizeEstimate = size;
            df.children.push_back(ef);
        };

        // EF.ODF + EF.TokenInfo
        addEF("EF.ODF", 0x50, 0x31, "");
        addEF("EF.TokenInfo", 0x50, 0x32,
              std::format("label={}, serial={}", profile.tokenInfo.label, profile.tokenInfo.serialNumber));

        // CDF entries (certificates)
        if (!profile.odf.certificatesPath.empty()) {
            auto& cp = profile.odf.certificatesPath;
            addEF("EF.CDF", cp[cp.size() - 2], cp[cp.size() - 1], std::format("{} certs", profile.certificates.size()));
        }

        for (const auto& cert : profile.certificates) {
            if (cert.path.size() >= 2) {
                auto h = cert.path[cert.path.size() - 2];
                auto l = cert.path[cert.path.size() - 1];
                FileNode ef;
                ef.name = std::format("Cert: {} ({})", cert.label, formatFid(h, l));
                ef.fidHi = h;
                ef.fidLo = l;
                ef.format = cert.authority ? "X.509 CA" : "X.509 end-entity";
                df.children.push_back(ef);

                // Try reading certificate size
                try {
                    auto certData = card.readCertificate(cert);
                    if (!certData.empty()) {
                        df.children.back().sizeEstimate = std::format("~{}B", certData.size());
                    } else {
                        card.selectApplet();
                        std::string diag = probeCertPath(conn, cert.path);
                        df.children.back().sizeEstimate = diag;
                    }
                } catch (const std::exception& e) {
                    df.children.back().sizeEstimate = std::format("[error: {}]", e.what());
                }

                DataFile dataFile;
                dataFile.name = cert.label;
                dataFile.fidHi = h;
                dataFile.fidLo = l;
                TagInfo tag;
                tag.tag = 0;
                tag.name = cert.label;
                tag.type = cert.authority ? "CA certificate" : "end-entity certificate";
                tag.fieldKey = "cert";
                tag.example = std::format("ID={}", formatHex(cert.id));
                dataFile.tags.push_back(tag);
                applet.dataFiles.push_back(dataFile);
            }
        }

        // PrKDF entries (private keys)
        if (!profile.odf.privateKeysPath.empty()) {
            auto& kp = profile.odf.privateKeysPath;
            addEF("EF.PrKDF", kp[kp.size() - 2], kp[kp.size() - 1], std::format("{} keys", profile.privateKeys.size()));
        }

        for (const auto& key : profile.privateKeys) {
            if (key.path.size() >= 2) {
                FileNode ef;
                ef.name = std::format("Key: {} ({}, {}b)", key.label,
                                      formatFid(key.path[key.path.size() - 2], key.path[key.path.size() - 1]),
                                      key.keySizeBits);
                ef.fidHi = key.path[key.path.size() - 2];
                ef.fidLo = key.path[key.path.size() - 1];
                ef.format = std::format("RSA-{}", key.keySizeBits);
                df.children.push_back(ef);
            }
        }

        // AODF entries (PINs)
        if (!profile.odf.authObjectsPath.empty()) {
            auto& ap = profile.odf.authObjectsPath;
            addEF("EF.AODF", ap[ap.size() - 2], ap[ap.size() - 1], std::format("{} PINs", profile.pins.size()));
        }

        for (const auto& pin : profile.pins) {
            DataFile dataFile;
            dataFile.name = std::format("PIN: {}", pin.label);
            TagInfo tag;
            tag.tag = pin.pinReference;
            tag.name = pin.label;
            tag.type = pin.initialized ? "initialized" : "transport";
            tag.fieldKey = "pin";
            tag.example = std::format("ref=0x{:02X}, local={}, tries={}", pin.pinReference, pin.local, pin.maxRetries);
            dataFile.tags.push_back(tag);
            applet.dataFiles.push_back(dataFile);
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "PKCS#15 smart probe failed: " << e.what() << " — falling back to FID scan\n";
        return false;
    }
}

// PIV GET DATA probe: read known PIV data objects via INS=CB
bool probePIV(smartcard::PCSCConnection& conn, FileNode& df, AppletInfo& applet)
{
    struct PIVObject
    {
        const char* name;
        std::vector<uint8_t> tag;
        const char* description;
    };

    std::vector<PIVObject> objects = {
        {"CCC", {0x5F, 0xC1, 0x07}, "Card Capability Container"},
        {"CHUID", {0x5F, 0xC1, 0x02}, "Cardholder Unique Identifier"},
        {"Discovery", {0x7E}, "Discovery Object"},
        {"Printed Info", {0x5F, 0xC1, 0x09}, "Printed Information"},
        {"Key History", {0x5F, 0xC1, 0x0C}, "Key History Object"},
        {"PIV Auth Cert", {0x5F, 0xC1, 0x05}, "X.509 Certificate for PIV Authentication"},
        {"Digital Sig Cert", {0x5F, 0xC1, 0x0A}, "X.509 Certificate for Digital Signature"},
        {"Key Mgmt Cert", {0x5F, 0xC1, 0x0B}, "X.509 Certificate for Key Management"},
        {"Card Auth Cert", {0x5F, 0xC1, 0x01}, "X.509 Certificate for Card Authentication"},
    };

    // Add retired certificate containers (5FC10D - 5FC120)
    for (uint8_t i = 0; i < 20; ++i) {
        objects.push_back({nullptr, {0x5F, 0xC1, static_cast<uint8_t>(0x0D + i)}, "Retired X.509 Certificate"});
    }

    applet.description = "PIV (NIST SP 800-73)";
    bool foundAny = false;

    for (size_t idx = 0; idx < objects.size(); ++idx) {
        auto& obj = objects[idx];

        std::string name;
        if (obj.name) {
            name = obj.name;
        } else {
            name = std::format("Retired Cert {}", idx - 8);
        }

        // Build GET DATA APDU: 00 CB 3F FF Lc [5C len tag...] 00
        std::vector<uint8_t> data = {0x5C, static_cast<uint8_t>(obj.tag.size())};
        data.insert(data.end(), obj.tag.begin(), obj.tag.end());

        smartcard::APDUCommand cmd{
            .cla = 0x00, .ins = 0xCB, .p1 = 0x3F, .p2 = 0xFF, .data = data, .le = 0, .hasLe = true};
        auto resp = conn.transmit(cmd);

        FileNode efNode;
        efNode.name = std::format("{} ({})", name, formatHex(obj.tag));

        if (resp.isSuccess() || resp.sw1 == 0x62 || resp.sw1 == 0x61) {
            foundAny = true;
            efNode.sizeEstimate = std::format("~{}B", resp.data.size());

            DataFile dataFile;
            dataFile.name = name;

            if (!resp.data.empty()) {
                try {
                    auto root = smartcard::parseBER(resp.data.data(), resp.data.size());
                    efNode.format = "BER-TLV";
                    collectBERTags(root, dataFile, "");
                } catch (const std::exception&) {
                    efNode.format = "binary";
                }
            }

            if (!dataFile.tags.empty()) {
                applet.dataFiles.push_back(dataFile);
            }

            df.children.push_back(efNode);
        } else if (resp.statusWord() == 0x6982) {
            efNode.format = "[AUTH REQUIRED]";
            df.children.push_back(efNode);
            foundAny = true;
        }
    }

    return foundAny;
}

// Walk FID ranges for an applet: SELECT + READ each file, build file tree
void walkFidRanges(smartcard::PCSCConnection& conn, FileNode& df, AppletInfo& applet)
{
    int cachedFidVariant = -1;
    uint32_t rejectedFidMask = 0;
    auto ranges = getProbeRanges();

    for (const auto& [rangeStart, rangeEnd] : ranges) {
        for (uint16_t fid = rangeStart; fid <= rangeEnd; ++fid) {
            auto hi = static_cast<uint8_t>(fid >> 8);
            auto lo = static_cast<uint8_t>(fid & 0xFF);

            auto fileResp = selectFile(conn, hi, lo, cachedFidVariant, rejectedFidMask);

            if (fileResp.isSuccess() || fileResp.sw1 == 0x62) {
                FileNode efNode;
                efNode.name = std::format("EF ({})", formatFid(hi, lo));
                efNode.fidHi = hi;
                efNode.fidLo = lo;

                auto fileData = readFileContent(conn);
                if (!fileData.empty()) {
                    DataFile dataFile;
                    dataFile.name = efNode.name;
                    dataFile.fidHi = hi;
                    dataFile.fidLo = lo;

                    parseFileData(fileData, efNode, dataFile);

                    if (!dataFile.tags.empty()) {
                        applet.dataFiles.push_back(dataFile);
                    }
                    efNode.sizeEstimate = std::format("~{}B", fileData.size());
                } else if (fileResp.statusWord() == 0x6982) {
                    efNode.format = "[AUTH REQUIRED]";
                }

                df.children.push_back(efNode);
            }
        }
    }
}

} // anonymous namespace

std::string matchProfile(const std::vector<std::vector<uint8_t>>& detectedAIDs)
{
    bool hasEid = aidContained(detectedAIDs, eidcard::protocol::AID_SERID) ||
                  aidContained(detectedAIDs, eidcard::protocol::AID_SERIF) ||
                  aidContained(detectedAIDs, eidcard::protocol::AID_SERRP);
    bool hasCardEdge = aidContained(detectedAIDs, cardedge::protocol::AID_PKCS15);
    bool hasHealth = aidContained(detectedAIDs, healthcard::protocol::AID_SERVSZK);
    bool hasVehicle = aidContained(detectedAIDs, euvrc::protocol::EU_VRC_AID) ||
                      aidContained(detectedAIDs, euvrc::protocol::SEQ1_CMD1) ||
                      aidContained(detectedAIDs, euvrc::protocol::SEQ2_CMD1) ||
                      aidContained(detectedAIDs, euvrc::protocol::SEQ3_CMD1);
    bool hasEmrtd =
        aidContained(detectedAIDs, std::vector<uint8_t>(emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN));
    const std::vector<uint8_t> pivAid = {0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10};
    bool hasPIV = aidContained(detectedAIDs, pivAid);

    if (hasEid && hasCardEdge)
        return "rs-eid-profile";
    if (hasEid)
        return "rs-eid-profile";
    if (hasHealth && hasCardEdge)
        return "rs-health-profile";
    if (hasHealth)
        return "rs-health-profile";
    if (hasVehicle)
        return "rs-vehicle-profile";
    if (hasEmrtd && hasCardEdge)
        return "emrtd-pkcs15-profile";
    if (hasEmrtd)
        return "passport-icao-profile";
    if (hasPIV)
        return "piv-profile";
    if (hasCardEdge)
        return "cardedge-only-profile";

    return "";
}

ScanResult discoverCard(smartcard::PCSCConnection& conn, bool verbose)
{
    ScanResult result;
    result.atr = conn.getATR();

    ApduLogger logger;

    if (verbose) {
        conn.setTransmitFilter([&logger, &conn](const smartcard::APDUCommand& cmd) -> smartcard::APDUResponse {
            auto resp = conn.transmitRaw(cmd);
            logger.log(cmd, resp);
            return resp;
        });
    }

    std::vector<std::vector<uint8_t>> detectedAIDs;
    std::vector<std::vector<uint8_t>> efDirAIDs; // AIDs discovered from EF.DIR

    // Try reading EF.DIR (2F00) at MF level — ISO 7816-4 application directory
    // This lists all applications on the card regardless of country/vendor
    {
        auto selectMF = smartcard::selectByFileId(0x3F, 0x00);
        conn.transmit(selectMF);

        // Try SELECT EF.DIR by FID — multiple methods for strict cards
        int dirVariant = -1;
        uint32_t dirRejected = 0;
        auto dirResp = selectFile(conn, 0x2F, 0x00, dirVariant, dirRejected);

        if (dirResp.isSuccess() || dirResp.sw1 == 0x62) {
            auto dirData = readFileContent(conn);
            if (!dirData.empty()) {
                // Parse BER-TLV — EF.DIR contains application templates (tag 61)
                // with AID (tag 4F) and optional label (tag 50)
                try {
                    auto dirTree = smartcard::parseBER(dirData.data(), dirData.size());
                    for (const auto& tmpl : dirTree.children) {
                        if (tmpl.tag == 0x61) // Application template
                        {
                            for (const auto& field : tmpl.children) {
                                if (field.tag == 0x4F && !field.value.empty()) {
                                    efDirAIDs.push_back(field.value);
                                }
                            }
                        }
                    }
                } catch (const std::exception&) {
                    // EF.DIR content is not valid BER-TLV — skip
                }
            }
        }
    }

    // Probe AIDs discovered from EF.DIR (unknown applications)
    for (const auto& aid : efDirAIDs) {
        if (aidContained(detectedAIDs, aid)) {
            continue;
        }

        AidProbe dirProbe;
        dirProbe.name = "EF.DIR:" + formatHex(aid);
        dirProbe.canonicalAid = aid;
        dirProbe.selectSequence = {aid};

        if (tryProbe(conn, dirProbe).has_value()) {
            detectedAIDs.push_back(aid);

            AppletInfo applet;
            applet.name = std::format("Applet ({})", formatHex(aid));
            applet.description = "Discovered via EF.DIR";
            applet.aids = {aid};
            applet.authentication = "Unknown";
            applet.pluginName = "efdir-" + formatHex(aid);

            FileNode mf;
            mf.name = "MF";
            mf.fidHi = 0x3F;
            mf.fidLo = 0x00;
            mf.isDir = true;

            FileNode df;
            df.name = std::format("DF ({})", formatHex(aid));
            df.isDir = true;

            const std::vector<uint8_t> pivAid = {0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10};

            // Smart path for PKCS#15: parse ODF→CDF/PrKDF/AODF structure
            if (aid == cardedge::protocol::AID_PKCS15) {
                if (!probePKCS15(conn, df, applet))
                    walkFidRanges(conn, df, applet);
            } else if (aid == pivAid) {
                if (!probePIV(conn, df, applet))
                    walkFidRanges(conn, df, applet);
            } else {
                walkFidRanges(conn, df, applet);
            }

            mf.children.push_back(df);
            applet.rootNode = mf;
            result.detectedApplets.push_back(applet);
        }
    }

    // Probe all known AID sequences
    auto allProbes = getAllKnownProbes();
    for (const auto& probe : allProbes) {
        if (auto probeP2 = tryProbe(conn, probe)) {
            // Avoid duplicate canonical AIDs (e.g. multiple vehicle sequences)
            if (aidContained(detectedAIDs, probe.canonicalAid)) {
                continue;
            }
            detectedAIDs.push_back(probe.canonicalAid);

            // Build applet info for this detection
            AppletInfo applet;
            applet.name = std::format("Unknown Applet ({})", probe.name);
            applet.description = "Auto-detected applet: " + probe.name;
            applet.aids = {probe.canonicalAid};
            applet.authentication = "Unknown";
            applet.pluginName = probe.name;

            FileNode mf;
            mf.name = "MF";
            mf.fidHi = 0x3F;
            mf.fidLo = 0x00;
            mf.isDir = true;

            FileNode df;
            df.name = std::format("DF ({})", probe.name);
            df.isDir = true;

            const std::vector<uint8_t> pivAid = {0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10};

            // Smart path for PKCS#15: parse ODF→CDF/PrKDF/AODF structure
            if (probe.canonicalAid == cardedge::protocol::AID_PKCS15) {
                if (!probePKCS15(conn, df, applet)) {
                    tryProbe(conn, probe);
                    walkFidRanges(conn, df, applet);
                }
            } else if (probe.canonicalAid == pivAid) {
                if (!probePIV(conn, df, applet)) {
                    tryProbe(conn, probe);
                    walkFidRanges(conn, df, applet);
                }
            } else {
                tryProbe(conn, probe);
                walkFidRanges(conn, df, applet);
            }

            mf.children.push_back(df);
            applet.rootNode = mf;
            result.detectedApplets.push_back(applet);
        }
    }

    // Match profile
    auto profileName = matchProfile(detectedAIDs);
    result.profile.name = profileName.empty() ? "Unknown Card" : profileName;
    result.profile.description = profileName.empty() ? "Unrecognized card" : "Auto-detected card profile";
    result.profile.knownATRs = {formatHex(result.atr)};

    for (const auto& applet : result.detectedApplets) {
        ProfileInfo::AppletRef ref;
        ref.name = applet.name;
        ref.aid = applet.aids.empty() ? std::vector<uint8_t>{} : applet.aids[0];
        ref.docPath = "../applets/";
        result.profile.applets.push_back(ref);
    }

    if (verbose) {
        conn.clearTransmitFilter();
        auto trace = logger.formatTrace();
        // Attach the full trace to each detected applet
        for (auto& applet : result.detectedApplets) {
            applet.apduTrace = trace;
        }
    }

    return result;
}

} // namespace card_mapper
