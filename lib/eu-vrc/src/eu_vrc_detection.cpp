// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "eu_vrc_detection.h"
#include "eu_vrc_protocol.h"

#include <smartcard/apdu.h>
#include <smartcard/ber.h>
#include <smartcard/pcsc_connection.h>

namespace euvrc {

std::vector<AidSequence> getAllKnownAidSequences()
{
    using namespace protocol;

    return {
        // EU standard AID (single SELECT)
        {"EU-EVR-01", {EU_VRC_AID}, 0x00},

        // Serbian sequences (3-command each)
        {"RS-SEQ1", {SEQ1_CMD1, SEQ1_CMD2, SEQ1_CMD3}, 0x0C},
        {"RS-SEQ2", {SEQ2_CMD1, SEQ2_CMD2, SEQ1_CMD3}, 0x0C},
        {"RS-SEQ3", {SEQ3_CMD1, SEQ3_CMD2, SEQ3_CMD3}, 0x0C},
    };
}

std::vector<FileFid> getStandardFileFids()
{
    std::vector<FileFid> fids;
    for (const auto& f : protocol::STANDARD_FILES)
    {
        fids.push_back({f.fidHi, f.fidLo, f.name, f.isBerTlv});
    }
    return fids;
}

std::vector<FileFid> getNationalExtensionFids()
{
    std::vector<FileFid> fids;
    for (const auto& f : protocol::NATIONAL_EXTENSION_FILES)
    {
        fids.push_back({f.fidHi, f.fidLo, f.name, f.isBerTlv});
    }
    return fids;
}

namespace {

// Try to discover AID from EF.DIR
bool tryEfDir(smartcard::PCSCConnection& conn)
{
    // SELECT MF
    auto mfResp = conn.transmit(smartcard::selectByFileId(0x3F, 0x00));
    if (!mfResp.isSuccess())
        return false;

    // SELECT EF.DIR (2F00) by FID with P1=02 P2=04, no Le
    smartcard::APDUCommand selectDir{
        .cla = 0x00, .ins = 0xA4, .p1 = 0x02, .p2 = 0x04,
        .data = {0x2F, 0x00}, .le = 0, .hasLe = false};
    auto dirResp = conn.transmit(selectDir);

    if (!dirResp.isSuccess())
    {
        // Fallback: SELECT by path (P1=08)
        dirResp = conn.transmit(smartcard::selectByPath(0x2F, 0x00));
    }

    if (!dirResp.isSuccess())
        return false;

    // READ BINARY
    auto readResp = conn.transmit(smartcard::readBinary(0, 0xFF));
    if (!readResp.isSuccess() || readResp.data.empty())
        return false;

    // Parse BER-TLV — look for application template (tag 61) with AID (tag 4F)
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
                        // Try to SELECT discovered AID
                        auto selectAid = smartcard::selectByAID(field.value);
                        auto aidResp = conn.transmit(selectAid);
                        if (aidResp.isSuccess())
                            return true;
                    }
                }
            }
        }
    }
    catch (...)
    {
        // EF.DIR content is not valid BER-TLV — skip
    }

    return false;
}

// Try a single EU standard AID
bool tryEuStandardAid(smartcard::PCSCConnection& conn)
{
    auto resp = conn.transmit(smartcard::selectByAID(protocol::EU_VRC_AID));
    return resp.isSuccess();
}

// Try a multi-command AID sequence (all commands must succeed)
bool tryAidSequence(smartcard::PCSCConnection& conn, const AidSequence& seq)
{
    for (size_t i = 0; i < seq.selectCommands.size(); ++i)
    {
        bool isLast = (i == seq.selectCommands.size() - 1);
        uint8_t p2 = isLast ? seq.lastP2 : 0x00;

        if (isLast && p2 == 0x0C)
        {
            // Use raw APDU for P2=0x0C
            smartcard::APDUCommand cmd{
                .cla = 0x00, .ins = 0xA4, .p1 = 0x04, .p2 = 0x0C,
                .data = seq.selectCommands[i], .le = 0, .hasLe = false};
            auto resp = conn.transmit(cmd);
            // Don't check last response — some cards return warnings
        }
        else
        {
            auto resp = conn.transmit(smartcard::selectByAID(seq.selectCommands[i], p2));
            if (!resp.isSuccess())
                return false;
        }
    }
    return true;
}

} // anonymous namespace

bool detect(smartcard::PCSCConnection& conn)
{
    // Level 1: EF.DIR
    if (tryEfDir(conn))
        return true;

    // Level 2: EU standard AID
    if (tryEuStandardAid(conn))
        return true;

    // Level 3: Known national AID sequences
    auto sequences = getAllKnownAidSequences();
    // Skip first (EU standard, already tried)
    for (size_t i = 1; i < sequences.size(); ++i)
    {
        if (tryAidSequence(conn, sequences[i]))
            return true;
    }

    return false;
}

bool probe(smartcard::PCSCConnection& conn)
{
    return detect(conn);
}

} // namespace euvrc
