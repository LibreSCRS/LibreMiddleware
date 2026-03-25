// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_scanner.h"
#include "apdu_logger.h"

#include <card_protocol.h>
#include <cardedge_protocol.h>
#include <health_protocol.h>
#include <eu_vrc_protocol.h>
#include <emrtd/emrtd_types.h>

#include <smartcard/apdu.h>
#include <smartcard/ber.h>
#include <smartcard/tlv.h>

#include <algorithm>
#include <format>
#include <iostream>
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
    };
}

std::vector<AidProbe> getAllKnownProbes()
{
    using namespace euvrc::protocol;

    auto emrtdAid = std::vector<uint8_t>(emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN);

    return {
        // Simple single-SELECT AIDs
        {"SERID",   eidcard::protocol::AID_SERID,       {eidcard::protocol::AID_SERID}},
        {"SERIF",   eidcard::protocol::AID_SERIF,       {eidcard::protocol::AID_SERIF}},
        {"SERRP",   eidcard::protocol::AID_SERRP,       {eidcard::protocol::AID_SERRP}},
        {"PKCS15",  cardedge::protocol::AID_PKCS15,     {cardedge::protocol::AID_PKCS15}},
        {"SERVSZK", healthcard::protocol::AID_SERVSZK,  {healthcard::protocol::AID_SERVSZK}},
        {"eMRTD",   emrtdAid,                           {emrtdAid}},

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
// Returns true only if ALL succeed.
bool tryProbe(smartcard::PCSCConnection& conn, const AidProbe& probe)
{
    for (size_t i = 0; i < probe.selectSequence.size(); ++i)
    {
        bool isLast = (i == probe.selectSequence.size() - 1);
        uint8_t p2 = isLast ? probe.lastP2 : 0x00;

        auto cmd = smartcard::selectByAID(probe.selectSequence[i], p2);
        auto resp = conn.transmit(cmd);
        if (!resp.isSuccess() && resp.sw1 != 0x62)
        {
            return false;
        }
    }
    return true;
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
    for (const auto& child : node.children)
    {
        if (child.constructed && !child.children.empty())
        {
            collectBERTags(child, dataFile, std::format("{}_{:02X}", prefix, child.tag));
        }
        else if (!child.value.empty())
        {
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
    bool hasEmrtd = aidContained(detectedAIDs,
        std::vector<uint8_t>(emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN));

    if (hasEid && hasCardEdge) return "rs-eid-profile";
    if (hasEid) return "rs-eid-profile";
    if (hasHealth && hasCardEdge) return "rs-health-profile";
    if (hasHealth) return "rs-health-profile";
    if (hasVehicle) return "rs-vehicle-profile";
    if (hasEmrtd && hasCardEdge) return "emrtd-pkcs15-profile";
    if (hasEmrtd) return "passport-icao-profile";
    if (hasCardEdge) return "cardedge-only-profile";

    return "";
}

ScanResult discoverCard(smartcard::PCSCConnection& conn, bool verbose)
{
    ScanResult result;
    result.atr = conn.getATR();

    ApduLogger logger;

    if (verbose)
    {
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

        // Try SELECT EF.DIR by FID
        smartcard::APDUCommand selectDir{
            .cla = 0x00, .ins = 0xA4, .p1 = 0x02, .p2 = 0x04,
            .data = {0x2F, 0x00}, .le = 0, .hasLe = false};
        auto dirResp = conn.transmit(selectDir);

        if (!dirResp.isSuccess())
        {
            // Fallback: try SELECT by path
            dirResp = conn.transmit(smartcard::selectByPath(0x2F, 0x00));
        }

        if (dirResp.isSuccess())
        {
            // Read EF.DIR content
            auto readResp = conn.transmit(smartcard::readBinary(0, 0xFF));
            if (readResp.isSuccess() && !readResp.data.empty())
            {
                // Parse BER-TLV — EF.DIR contains application templates (tag 61)
                // with AID (tag 4F) and optional label (tag 50)
                try
                {
                    auto dirTree = smartcard::parseBER(readResp.data.data(), readResp.data.size());
                    for (const auto& tmpl : dirTree.children)
                    {
                        if (tmpl.tag == 0x61) // Application template
                        {
                            for (const auto& field : tmpl.children)
                            {
                                if (field.tag == 0x4F && !field.value.empty())
                                {
                                    efDirAIDs.push_back(field.value);
                                }
                            }
                        }
                    }
                }
                catch (const std::exception&)
                {
                    // EF.DIR content is not valid BER-TLV — skip
                }
            }
        }
    }

    // Probe AIDs discovered from EF.DIR (unknown applications)
    for (const auto& aid : efDirAIDs)
    {
        if (aidContained(detectedAIDs, aid))
        {
            continue;
        }

        AidProbe dirProbe;
        dirProbe.name = "EF.DIR:" + formatHex(aid);
        dirProbe.canonicalAid = aid;
        dirProbe.selectSequence = {aid};

        if (tryProbe(conn, dirProbe))
        {
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

            // Walk FID ranges
            auto ranges = getProbeRanges();
            for (const auto& [rangeStart, rangeEnd] : ranges)
            {
                for (uint16_t fid = rangeStart; fid <= rangeEnd; ++fid)
                {
                    auto hi = static_cast<uint8_t>(fid >> 8);
                    auto lo = static_cast<uint8_t>(fid & 0xFF);

                    auto fileResp = conn.transmit(smartcard::selectByPath(hi, lo));
                    if (!fileResp.isSuccess())
                    {
                        smartcard::APDUCommand selectChild{
                            .cla = 0x00, .ins = 0xA4, .p1 = 0x02, .p2 = 0x04,
                            .data = {hi, lo}, .le = 0, .hasLe = false};
                        fileResp = conn.transmit(selectChild);
                    }
                    if (!fileResp.isSuccess())
                    {
                        fileResp = conn.transmit(smartcard::selectByFileId(hi, lo));
                    }

                    if (fileResp.isSuccess())
                    {
                        FileNode efNode;
                        efNode.name = std::format("EF ({})", formatFid(hi, lo));
                        efNode.fidHi = hi;
                        efNode.fidLo = lo;

                        auto readCmd = smartcard::readBinary(0, 0xFF);
                        auto readResp = conn.transmit(readCmd);
                        if (readResp.isSuccess() && !readResp.data.empty())
                        {
                            DataFile dataFile;
                            dataFile.name = efNode.name;
                            dataFile.fidHi = hi;
                            dataFile.fidLo = lo;

                            auto fields = smartcard::parseTLV(readResp.data.data(), readResp.data.size());
                            if (!fields.empty())
                            {
                                efNode.format = "TLV (LE 16-bit)";
                                for (const auto& field : fields)
                                {
                                    TagInfo tag;
                                    tag.tag = field.tag;
                                    tag.fieldKey = std::format("kTag_{:04X}", field.tag);
                                    tag.name = std::format("Tag {}", field.tag);
                                    tag.type = "unknown";
                                    tag.example = field.asString();
                                    dataFile.tags.push_back(tag);
                                }
                            }
                            else
                            {
                                try
                                {
                                    auto berRoot = smartcard::parseBER(readResp.data.data(), readResp.data.size());
                                    if (!berRoot.children.empty())
                                    {
                                        efNode.format = "BER-TLV";
                                        collectBERTags(berRoot, dataFile, "");
                                    }
                                    else
                                    {
                                        efNode.format = "binary";
                                    }
                                }
                                catch (const std::exception&)
                                {
                                    efNode.format = "binary";
                                }
                            }

                            if (!dataFile.tags.empty())
                            {
                                applet.dataFiles.push_back(dataFile);
                            }
                            efNode.sizeEstimate = std::format("~{}B", readResp.data.size());
                        }
                        else if (fileResp.statusWord() == 0x6982)
                        {
                            efNode.format = "[AUTH REQUIRED]";
                        }

                        df.children.push_back(efNode);
                    }
                }
            }

            mf.children.push_back(df);
            applet.rootNode = mf;
            result.detectedApplets.push_back(applet);
        }
    }

    // Probe all known AID sequences
    auto allProbes = getAllKnownProbes();
    for (const auto& probe : allProbes)
    {
        if (tryProbe(conn, probe))
        {
            // Avoid duplicate canonical AIDs (e.g. multiple vehicle sequences)
            if (aidContained(detectedAIDs, probe.canonicalAid))
            {
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

            // Re-select so we're inside this applet for FID walking
            tryProbe(conn, probe);

            // Walk FID ranges for this applet
            // Try both SELECT by path (P1=08) and SELECT by FID (P1=02)
            // because different cards use different selection methods.
            auto ranges = getProbeRanges();
            for (const auto& [rangeStart, rangeEnd] : ranges)
            {
                for (uint16_t fid = rangeStart; fid <= rangeEnd; ++fid)
                {
                    auto hi = static_cast<uint8_t>(fid >> 8);
                    auto lo = static_cast<uint8_t>(fid & 0xFF);

                    // Try multiple SELECT variants — different cards use different methods:
                    //   P1=08 P2=04     SELECT by path from MF (eID, health)
                    //   P1=02 P2=04     SELECT child EF, no Le (vehicle)
                    //   P1=00 P2=00     SELECT by FID, return FCI (generic)
                    auto fileResp = conn.transmit(smartcard::selectByPath(hi, lo));
                    if (!fileResp.isSuccess())
                    {
                        // P1=02 P2=04 without Le — as used by vehicle cards
                        smartcard::APDUCommand selectChild{
                            .cla = 0x00, .ins = 0xA4, .p1 = 0x02, .p2 = 0x04,
                            .data = {hi, lo}, .le = 0, .hasLe = false};
                        fileResp = conn.transmit(selectChild);
                    }
                    if (!fileResp.isSuccess())
                    {
                        fileResp = conn.transmit(smartcard::selectByFileId(hi, lo));
                    }

                    if (fileResp.isSuccess())
                    {
                        FileNode efNode;
                        efNode.name = std::format("EF ({})", formatFid(hi, lo));
                        efNode.fidHi = hi;
                        efNode.fidLo = lo;

                        // Try reading to determine format
                        auto readCmd = smartcard::readBinary(0, 0xFF);
                        auto readResp = conn.transmit(readCmd);
                        if (readResp.isSuccess() && !readResp.data.empty())
                        {
                            DataFile dataFile;
                            dataFile.name = efNode.name;
                            dataFile.fidHi = hi;
                            dataFile.fidLo = lo;

                            // Try LE 16-bit TLV first (Serbian eID, health)
                            auto fields = smartcard::parseTLV(readResp.data.data(), readResp.data.size());
                            if (!fields.empty())
                            {
                                efNode.format = "TLV (LE 16-bit)";
                                for (const auto& field : fields)
                                {
                                    TagInfo tag;
                                    tag.tag = field.tag;
                                    tag.fieldKey = std::format("kTag_{:04X}", field.tag);
                                    tag.name = std::format("Tag {}", field.tag);
                                    tag.type = "unknown";
                                    tag.example = field.asString();
                                    dataFile.tags.push_back(tag);
                                }
                            }
                            else
                            {
                                // Try BER-TLV (ISO 7816-4, vehicle cards)
                                try
                                {
                                    auto berRoot = smartcard::parseBER(readResp.data.data(), readResp.data.size());
                                    if (!berRoot.children.empty())
                                    {
                                        efNode.format = "BER-TLV";
                                        collectBERTags(berRoot, dataFile, "");
                                    }
                                    else
                                    {
                                        efNode.format = "binary";
                                    }
                                }
                                catch (const std::exception&)
                                {
                                    efNode.format = "binary";
                                }
                            }

                            if (!dataFile.tags.empty())
                            {
                                applet.dataFiles.push_back(dataFile);
                            }
                            efNode.sizeEstimate = std::format("~{}B", readResp.data.size());
                        }
                        else if (fileResp.statusWord() == 0x6982)
                        {
                            efNode.format = "[AUTH REQUIRED]";
                        }

                        df.children.push_back(efNode);
                    }
                }
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

    for (const auto& applet : result.detectedApplets)
    {
        ProfileInfo::AppletRef ref;
        ref.name = applet.name;
        ref.aid = applet.aids.empty() ? std::vector<uint8_t>{} : applet.aids[0];
        ref.docPath = "../applets/";
        result.profile.applets.push_back(ref);
    }

    if (verbose)
    {
        conn.clearTransmitFilter();
        auto trace = logger.formatTrace();
        // Attach the full trace to each detected applet
        for (auto& applet : result.detectedApplets)
        {
            applet.apduTrace = trace;
        }
    }

    return result;
}

} // namespace card_mapper
