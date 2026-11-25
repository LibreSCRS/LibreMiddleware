// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "plugin_mapper.h"
#include "apdu_logger.h"

#include <rs_document_profile.h>
#include "cardedge_protocol_constants.h"
#include <health_protocol.h>
#include <eu_vrc_protocol.h>
#include <emrtd_types.h>

#include <apdu.h>
#include <smartcard/or_throw.h>
#include <tlv.h>

#include <algorithm>
#include <cstdlib>
#include <map>
#include <string_view>
#include <format>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace card_mapper {

namespace {

// Names of the files as documentation calls them. The profile knows ids, modes and
// fields; these are only the headings of the generated pages.
const char* efName(std::string_view code, std::uint16_t fid)
{
    if (code == "EL") {
        switch (fid) {
        case 0x0D00:
            return "EF.Manifest";
        case 0x0D01:
            return "EF.DocumentData";
        case 0x0D02:
            return "EF.PersonalData";
        case 0x0D03:
            return "EF.ServiceData";
        case 0x0D04:
            return "EF.SealedData";
        case 0x0D05:
            return "EF.Portrait";
        case 0x0D07:
            return "EF.Digest";
        case 0x0D08:
            return "EF.SOD_FX";
        case 0x0D09:
            return "EF.SOD_SERVICE";
        case 0x0D0A:
            return "EF.SOD_SEALED";
        case 0x0D10:
            return "EF.PublicKey";
        default:
            return "EF";
        }
    }
    switch (fid) {
    case 0x0F1B:
        return "EF.Manifest";
    case 0x0F02:
        return "EF.DocumentData";
    case 0x0F03:
        return "EF.PersonalData";
    case 0x0F04:
        return "EF.VariableData";
    case 0x0F06:
        return "EF.Portrait";
    case 0x0FA1:
        return "EF.IdHash";
    case 0x0FA2:
        return "EF.IssuerHash";
    case 0x0F12:
        return "EF.CertDigests";
    case 0x0D10:
        return "EF.PublicKey";
    case 0x0F1C:
        return "EF.SOD_FX";
    case 0x0F1D:
        return "EF.SOD_VX";
    default:
        return "EF";
    }
}

std::string aidName(const LibreSCRS::RsEId::Core::DocumentProfile& p)
{
    // The application name is in the AID itself: F3 81 00 00 02 'S' 'E' 'R' x y 01.
    std::string name(p.aid.begin() + 5, p.aid.begin() + 10);
    const char* what = p.code == "ID"   ? "identity card"
                       : p.code == "IF" ? "identity card for foreigners"
                       : p.code == "RP" ? "residence permit"
                       : p.code == "EL" ? "official service ID"
                                        : nullptr;
    // A profile added without a name here is listed by its code, not mislabelled.
    return name + " \xe2\x80\x94 " + (what ? std::string(what) : std::string(p.code));
}

std::string fileFormat(const LibreSCRS::RsEId::Core::DocumentProfile& p, const LibreSCRS::RsEId::Core::FileSpec& f)
{
    if (f.fid == p.photoFid)
        return "TLV, JPEG inside";
    for (const auto& sod : p.sods) {
        if (sod.fid == f.fid)
            return "PKCS#7 SignedData";
    }
    return f.mode == LibreSCRS::RsEId::Core::ReadMode::Allocation ? "binary (whole allocation)" : "TLV";
}

AppletInfo buildEidInfo()
{
    namespace Core = LibreSCRS::RsEId::Core;

    AppletInfo info;
    info.name = "Serbian eID";
    info.description =
        "Serbian electronic identity documents (identity card, identity card for foreigners, residence permit, "
        "official service ID)";
    info.authentication = "None required for read";
    info.pluginName = "eid";

    FileNode mf;
    mf.name = "MF";
    mf.fidHi = 0x3F;
    mf.fidLo = 0x00;
    mf.isDir = true;

    // ID, IF and RP share one layout, so they share one directory and one set
    // of data files; every other profile has its own.
    const Core::DocumentProfile* shown = nullptr;
    for (const auto& p : Core::documentProfiles()) {
        info.aids.emplace_back(p.aid.begin(), p.aid.end());
        info.aidNames.push_back(aidName(p));
        if (shown && shown->files.data() == p.files.data())
            continue;
        shown = &p;

        FileNode df;
        df.name = "DF." + std::string(p.aid.begin() + 5, p.aid.begin() + 10);
        df.isDir = true;
        for (const auto& f : p.files) {
            df.children.push_back({efName(p.code, f.fid),
                                   static_cast<uint8_t>(f.fid >> 8),
                                   static_cast<uint8_t>(f.fid & 0xFF),
                                   fileFormat(p, f),
                                   "",
                                   "",
                                   false,
                                   {}});
        }
        mf.children.push_back(std::move(df));

        // Data files: those that carry CardEdge fields, rows in profile order.
        std::map<std::uint16_t, DataFile> byFid;
        for (const auto& f : p.fields) {
            if ((f.surfaces & static_cast<std::uint8_t>(Core::Surface::CardEdge)) == 0)
                continue;
            auto& file = byFid[f.fid];
            file.name = efName(p.code, f.fid);
            file.fidHi = static_cast<uint8_t>(f.fid >> 8);
            file.fidLo = static_cast<uint8_t>(f.fid & 0xFF);
            file.tags.push_back({f.tag, std::string(f.key), std::string(f.label),
                                 f.format == Core::FieldFormat::Date ? "string (DD.MM.YYYY)" : "string", ""});
        }
        for (auto& [fid, file] : byFid)
            info.dataFiles.push_back(std::move(file));
    }
    info.rootNode = mf;

    info.readProcedure = {
        "SELECT by AID, in order SERID, SERIF, SERRP, SEREL: `00 A4 04 00 0B F3 81 00 00 02 53 45 52 <x> <y> 01`",
        "SELECT EF by path: `00 A4 08 00 02 <FID_H> <FID_L> 04`",
        "READ BINARY in 255-byte chunks: `00 B0 <offsetHi> <offsetLo> FF`",
        "Parse response as LE 16-bit TLV",
    };

    return info;
}

AppletInfo buildCardEdgeInfo()
{
    using namespace cardedge::protocol;

    AppletInfo info;
    info.name = "CardEdge PKI";
    info.description = "CardEdge PKCS#15 applet (Gemalto IDPrime-based)";
    info.aids = {AID_PKCS15};
    info.aidNames = {"PKCS#15"};
    info.authentication = "PIN required for crypto operations; directory/cert reading unauthenticated";
    info.pluginName = "cardedge";

    FileNode mf;
    mf.name = "MF";
    mf.fidHi = 0x3F;
    mf.fidLo = 0x00;
    mf.isDir = true;

    FileNode df;
    df.name = "DF.PKCS15";
    df.isDir = true;

    FileNode rootDir;
    rootDir.name = "Root Dir";
    rootDir.fidHi = static_cast<uint8_t>(PKI_ROOT_DIR_FID >> 8);
    rootDir.fidLo = static_cast<uint8_t>(PKI_ROOT_DIR_FID & 0xFF);
    rootDir.isDir = true;
    rootDir.format = "directory";
    rootDir.note = "10-byte header + 12-byte entries";

    rootDir.children.push_back({"cmapfile", 0, 0, "CMAP records", "86B/entry", "", false, {}});
    rootDir.children.push_back({"Certificate files", 0, 0, "X.509 DER", "", "", false, {}});
    rootDir.children.push_back({"Private key files", 0, 0, "RSA key", "", "[PIN required]", false, {}});

    df.children.push_back(rootDir);
    mf.children.push_back(df);
    info.rootNode = mf;

    // Directory entry format as data file
    DataFile dirEntry;
    dirEntry.name = "Directory Entry";
    dirEntry.tags = {
        {0, "name", "Entry name", "8 bytes ASCII, null-padded", ""},
        {0, "fid", "File ID", "2 bytes LE", ""},
        {0, "is_dir", "Is directory flag", "1 byte (0/1)", ""},
    };
    info.dataFiles.push_back(dirEntry);

    DataFile cmapRecord;
    cmapRecord.name = "CMAP Record";
    cmapRecord.tags = {
        {0, "guid", "Container GUID", "80 bytes UTF-16LE", ""},
        {0, "flags", "Container flags", "1 byte (bit0=valid, bit1=default)", ""},
        {0, "sig_key_size", "Signature key size (bits)", "2 bytes LE", ""},
        {0, "kx_key_size", "Key exchange key size (bits)", "2 bytes LE", ""},
    };
    info.dataFiles.push_back(cmapRecord);

    info.readProcedure = {
        "SELECT by AID: `00 A4 04 00 0C A0 00 00 00 63 50 4B 43 53 2D 31 35`",
        "Read root directory (FID 7000): `00 A4 00 00 02 70 00`",
        "READ BINARY in 128-byte chunks: `00 B0 <offsetHi> <offsetLo> 80`",
        "Parse 10-byte directory header, then 12-byte entries",
        "SELECT and READ each file/subdirectory by FID",
    };

    return info;
}

AppletInfo buildHealthInfo()
{
    using namespace healthcard::protocol;

    AppletInfo info;
    info.name = "Serbian Health Insurance";
    info.description = "Serbian health insurance card (RFZO)";
    info.aids = {AID_SERVSZK};
    info.aidNames = {"SERVSZK"};
    info.authentication = "None required for read";
    info.pluginName = "health";

    FileNode mf;
    mf.name = "MF";
    mf.fidHi = 0x3F;
    mf.fidLo = 0x00;
    mf.isDir = true;

    FileNode df;
    df.name = "DF.SERVSZK";
    df.isDir = true;

    df.children.push_back({"EF.Document", FILE_DOCUMENT[0], FILE_DOCUMENT[1], "TLV", "", "", false, {}});
    df.children.push_back(
        {"EF.FixedPersonal", FILE_FIXED_PERSONAL[0], FILE_FIXED_PERSONAL[1], "TLV", "", "", false, {}});
    df.children.push_back(
        {"EF.VariablePersonal", FILE_VARIABLE_PERSONAL[0], FILE_VARIABLE_PERSONAL[1], "TLV", "", "", false, {}});
    df.children.push_back(
        {"EF.VariableAdmin", FILE_VARIABLE_ADMIN[0], FILE_VARIABLE_ADMIN[1], "TLV", "", "", false, {}});

    mf.children.push_back(df);
    info.rootNode = mf;

    // Data files
    DataFile docFile;
    docFile.name = "EF.Document";
    docFile.fidHi = FILE_DOCUMENT[0];
    docFile.fidLo = FILE_DOCUMENT[1];
    docFile.tags = {
        {TAG_INSURER_NAME, "insurer_name", "Insurer name", "string", ""},
        {TAG_INSURER_ID, "insurer_id", "Insurer ID", "string", ""},
        {TAG_CARD_ID, "card_id", "Card ID", "string", ""},
        {TAG_DATE_OF_ISSUE, "date_of_issue", "Date of issue", "string", ""},
        {TAG_DATE_OF_EXPIRY, "date_of_expiry", "Date of expiry", "string", ""},
        {TAG_PRINT_LANGUAGE, "print_language", "Print language", "string", ""},
    };
    info.dataFiles.push_back(docFile);

    DataFile personalFile;
    personalFile.name = "EF.FixedPersonal";
    personalFile.fidHi = FILE_FIXED_PERSONAL[0];
    personalFile.fidLo = FILE_FIXED_PERSONAL[1];
    personalFile.tags = {
        {TAG_INSURANT_NUMBER, "insurant_number", "Insurant number", "string", ""},
        {TAG_FAMILY_NAME, "family_name", "Family name", "string (Cyrillic)", ""},
        {TAG_FAMILY_NAME_LAT, "family_name_lat", "Family name (Latin)", "string", ""},
        {TAG_GIVEN_NAME, "given_name", "Given name", "string (Cyrillic)", ""},
        {TAG_GIVEN_NAME_LAT, "given_name_lat", "Given name (Latin)", "string", ""},
        {TAG_DATE_OF_BIRTH, "date_of_birth", "Date of birth", "string", ""},
    };
    info.dataFiles.push_back(personalFile);

    DataFile varPersonalFile;
    varPersonalFile.name = "EF.VariablePersonal";
    varPersonalFile.fidHi = FILE_VARIABLE_PERSONAL[0];
    varPersonalFile.fidLo = FILE_VARIABLE_PERSONAL[1];
    varPersonalFile.tags = {
        {TAG_VALID_UNTIL, "valid_until", "Valid until", "string", ""},
        {TAG_PERMANENTLY_VALID, "permanently_valid", "Permanently valid", "string", ""},
    };
    info.dataFiles.push_back(varPersonalFile);

    DataFile varAdminFile;
    varAdminFile.name = "EF.VariableAdmin";
    varAdminFile.fidHi = FILE_VARIABLE_ADMIN[0];
    varAdminFile.fidLo = FILE_VARIABLE_ADMIN[1];
    varAdminFile.tags = {
        {TAG_PARENT_NAME, "parent_name", "Parent name", "string", ""},
        {TAG_PARENT_NAME_LAT, "parent_name_lat", "Parent name (Latin)", "string", ""},
        {TAG_GENDER, "gender", "Gender", "string", ""},
        {TAG_PERSONAL_NUMBER, "personal_number", "Personal number (JMBG)", "string", ""},
        {TAG_STREET, "street", "Street", "string", ""},
        {TAG_MUNICIPALITY, "municipality", "Municipality", "string", ""},
        {TAG_PLACE, "place", "Place", "string", ""},
        {TAG_ADDRESS_NUMBER, "address_number", "Address number", "string", ""},
        {TAG_APARTMENT, "apartment", "Apartment", "string", ""},
        {TAG_INSURANCE_BASIS, "insurance_basis", "Insurance basis", "string", ""},
        {TAG_INSURANCE_DESC, "insurance_desc", "Insurance description", "string", ""},
        {TAG_CARRIER_RELATION, "carrier_relation", "Carrier relation", "string", ""},
        {TAG_CARRIER_FAMILY_MEMBER, "carrier_family_member", "Carrier family member", "string", ""},
        {TAG_CARRIER_ID_NO, "carrier_id_no", "Carrier ID number", "string", ""},
        {TAG_CARRIER_INSURANT_NO, "carrier_insurant_no", "Carrier insurant number", "string", ""},
        {TAG_CARRIER_FAMILY_NAME, "carrier_family_name", "Carrier family name", "string", ""},
        {TAG_CARRIER_FAMILY_NAME_LAT, "carrier_family_name_lat", "Carrier family name (Latin)", "string", ""},
        {TAG_CARRIER_GIVEN_NAME, "carrier_given_name", "Carrier given name", "string", ""},
        {TAG_CARRIER_GIVEN_NAME_LAT, "carrier_given_name_lat", "Carrier given name (Latin)", "string", ""},
        {TAG_INSURANCE_START, "insurance_start", "Insurance start date", "string", ""},
        {TAG_COUNTRY, "country", "Country", "string", ""},
        {TAG_TAXPAYER_NAME, "taxpayer_name", "Taxpayer name", "string", ""},
        {TAG_TAXPAYER_RES, "taxpayer_res", "Taxpayer residence", "string", ""},
        {TAG_TAXPAYER_ID_1, "taxpayer_id_1", "Taxpayer ID 1", "string", ""},
        {TAG_TAXPAYER_ID_2, "taxpayer_id_2", "Taxpayer ID 2", "string", ""},
        {TAG_TAXPAYER_ACTIV, "taxpayer_activ", "Taxpayer activity", "string", ""},
    };
    info.dataFiles.push_back(varAdminFile);

    info.readProcedure = {
        "SELECT by AID: `00 A4 04 00 0D F3 81 00 00 02 53 45 52 56 53 5A 4B 01`",
        "SELECT EF by ID: `00 A4 02 00 02 <FID_H> <FID_L>`",
        "Read 4-byte file header, extract content length from bytes [2:3] LE",
        "READ BINARY in 255-byte chunks: `00 B0 <offsetHi> <offsetLo> FF`",
        "Parse response as LE 16-bit TLV",
    };

    return info;
}

AppletInfo buildEuVrcInfo()
{
    using namespace euvrc::protocol;

    AppletInfo info;
    info.name = "EU Vehicle Registration Certificate";
    info.description = "EU VRC smart card (Directive 2003/127/EC) — supports all EU/EEA countries";
    info.aids = {EU_VRC_AID, SEQ1_CMD1, SEQ2_CMD1, SEQ3_CMD1};
    info.aidNames = {"EU EVR-01", "Serbian SEQ1", "Serbian SEQ2", "Serbian SEQ3"};
    info.authentication = "None required for read";
    info.pluginName = "eu-vrc";

    FileNode mf;
    mf.name = "MF";
    mf.fidHi = 0x3F;
    mf.fidLo = 0x00;
    mf.isDir = true;

    FileNode df;
    df.name = "DF.EuVrc";
    df.isDir = true;

    for (const auto& f : STANDARD_FILES) {
        df.children.push_back({f.name, f.fidHi, f.fidLo, f.isBerTlv ? "BER-TLV" : "binary", "", "", false, {}});
    }
    for (const auto& f : NATIONAL_EXTENSION_FILES) {
        df.children.push_back(
            {f.name, f.fidHi, f.fidLo, f.isBerTlv ? "BER-TLV" : "binary", "", "[national ext]", false, {}});
    }

    mf.children.push_back(df);
    info.rootNode = mf;

    info.readProcedure = {
        "Detect via EF.DIR (2F00), fallback to EU AID, then national AID sequences",
        "SELECT EF by FID: `00 A4 02 04 02 <FID_H> <FID_L>` (no Le)",
        "READ BINARY: start with 255-byte chunks, fall back to 100 on error",
        "Parse data files as BER-TLV (header-skip fallback for NXP eVL)",
        "Extract EU-harmonized fields from tag 71/72 trees",
    };

    return info;
}

AppletInfo buildEmrtdInfo()
{
    AppletInfo info;
    info.name = "eMRTD";
    info.description = "Electronic Machine Readable Travel Document (ICAO 9303)";
    info.aids = {std::vector<uint8_t>(emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN)};
    info.aidNames = {"eMRTD"};
    info.authentication = "PACE required for data group access";
    info.pluginName = "emrtd";

    FileNode mf;
    mf.name = "MF";
    mf.fidHi = 0x3F;
    mf.fidLo = 0x00;
    mf.isDir = true;

    // EF.CardAccess lives at MF level, accessed via SFI 0x1C before applet SELECT
    mf.children.push_back({"EF.CardAccess", 0, 0, "ASN.1", "", "SFI 0x1C, read before applet SELECT", false, {}});

    FileNode df;
    df.name = "DF.eMRTD";
    df.isDir = true;

    // EF.COM
    df.children.push_back({"EF.COM",
                           static_cast<uint8_t>(emrtd::FID_COM >> 8),
                           static_cast<uint8_t>(emrtd::FID_COM & 0xFF),
                           "ASN.1",
                           "",
                           "",
                           false,
                           {}});

    // Data Groups 1-16
    for (int dg = 1; dg <= 16; ++dg) {
        uint16_t fid = emrtd::dgToFID(dg);
        std::string name = std::format("DG{}", dg);
        std::string format;
        std::string note;

        switch (dg) {
        case 1:
            format = "MRZ data";
            break;
        case 2:
            format = "facial image";
            break;
        case 3:
            format = "fingerprints";
            note = "[EAC required]";
            break;
        case 4:
            format = "iris";
            note = "[EAC required]";
            break;
        case 7:
            format = "signature image";
            break;
        case 11:
            format = "additional personal details";
            break;
        case 12:
            format = "issuing information";
            break;
        default:
            format = "data group";
            note = "[optional]";
            break;
        }

        df.children.push_back(
            {name, static_cast<uint8_t>(fid >> 8), static_cast<uint8_t>(fid & 0xFF), format, "", note, false, {}});
    }

    mf.children.push_back(df);
    info.rootNode = mf;

    info.readProcedure = {
        "Read EF.CardAccess from MF via SFI: `00 B0 9C 00 FF` (P1 = 0x80 | 0x1C)",
        "Perform PACE authentication (MRZ or CAN)",
        "SELECT eMRTD application: `00 A4 04 0C 07 A0 00 00 02 47 10 01`",
        "Read EF.COM (FID 011E) to discover present Data Groups",
        "SELECT each DG by FID: `00 A4 02 0C 02 01 <DG>`",
        "READ BINARY in chunks: `00 B0 <offsetHi> <offsetLo> 00`",
        "Parse DG1 as ASN.1 for MRZ, DG2/DG7 as JPEG2000 images",
    };

    return info;
}

} // anonymous namespace

AppletInfo getPluginInfo(const std::string& pluginName)
{
    if (pluginName == "eid")
        return buildEidInfo();
    if (pluginName == "cardedge")
        return buildCardEdgeInfo();
    if (pluginName == "health")
        return buildHealthInfo();
    if (pluginName == "eu-vrc")
        return buildEuVrcInfo();
    if (pluginName == "emrtd")
        return buildEmrtdInfo();

    throw std::runtime_error("unknown plugin: " + pluginName + " (known: eid, cardedge, health, eu-vrc, emrtd)");
}

namespace {

AppletInfo mapEmrtdPlugin(LibreSCRS::SmartCard::Internal::PCSCConnection& conn, bool verbose)
{
    auto info = buildEmrtdInfo();

    ApduLogger logger;
    if (verbose) {
        conn.setTransmitFilter(
            [&logger, &conn](const LibreSCRS::SmartCard::Internal::APDUCommand& cmd)
                -> std::expected<LibreSCRS::SmartCard::Internal::APDUResponse, LibreSCRS::SmartCard::TransportError> {
                auto resp = conn.transmitRaw(cmd);
                if (resp)
                    logger.log(cmd, *resp);
                return resp;
            });
    }

    // 4.2 SecureChannel migration: EMRTDCard no longer performs PACE/BAC
    // internally; that responsibility moved to CardSession.activateChannelWithSm.
    // This developer tool has not yet been ported to construct a CardSession,
    // so the PACE-authenticated DG scan is stubbed out. Use LibreCelik when an
    // authenticated scan is needed.
    std::cerr << "eMRTD: card_mapper PACE-authenticated scan is not yet ported to the 4.2 SecureChannel; "
              << "returning static plugin info only.\n";

    if (verbose) {
        conn.clearTransmitFilter();
        info.apduTrace = logger.formatTrace();
    }

    return info;
}

} // namespace

AppletInfo mapPlugin(const std::string& pluginName, LibreSCRS::SmartCard::Internal::PCSCConnection& conn, bool verbose)
{
    // eMRTD gets its own path — requires PACE/BAC authentication
    if (pluginName == "emrtd") {
        return mapEmrtdPlugin(conn, verbose);
    }

    auto info = getPluginInfo(pluginName);

    ApduLogger logger;

    if (verbose) {
        conn.setTransmitFilter(
            [&logger, &conn](const LibreSCRS::SmartCard::Internal::APDUCommand& cmd)
                -> std::expected<LibreSCRS::SmartCard::Internal::APDUResponse, LibreSCRS::SmartCard::TransportError> {
                auto resp = conn.transmitRaw(cmd);
                if (resp)
                    logger.log(cmd, *resp);
                return resp;
            });
    }

    // Select the application
    if (pluginName == "eu-vrc") {
        // EU VRC: try EU standard AID first, then Serbian multi-command sequences
        using namespace euvrc::protocol;

        bool selected = false;

        // Try EU standard AID first
        auto euResp = LibreSCRS::SmartCard::Internal::orThrow(
            conn.transmit(LibreSCRS::SmartCard::Internal::selectByAID(EU_VRC_AID)));
        if (euResp.isSuccess()) {
            selected = true;
        }

        // Fall back to Serbian sequences
        if (!selected) {
            struct AidSeq
            {
                std::vector<uint8_t> cmd1, cmd2, cmd3;
                uint8_t cmd3P2;
            };
            std::vector<AidSeq> sequences = {
                {SEQ1_CMD1, SEQ1_CMD2, SEQ1_CMD3, 0x0C},
                {SEQ2_CMD1, SEQ2_CMD2, SEQ1_CMD3, 0x0C},
                {SEQ3_CMD1, SEQ3_CMD2, SEQ3_CMD3, 0x0C},
            };

            for (const auto& seq : sequences) {
                auto r1 = LibreSCRS::SmartCard::Internal::orThrow(
                    conn.transmit(LibreSCRS::SmartCard::Internal::selectByAID(seq.cmd1)));
                if (!r1.isSuccess())
                    continue;
                auto r2 = LibreSCRS::SmartCard::Internal::orThrow(
                    conn.transmit(LibreSCRS::SmartCard::Internal::selectByAID(seq.cmd2)));
                if (!r2.isSuccess())
                    continue;
                auto r3 = LibreSCRS::SmartCard::Internal::orThrow(
                    conn.transmit(LibreSCRS::SmartCard::Internal::selectByAID(seq.cmd3, seq.cmd3P2)));
                if (r3.isSuccess()) {
                    selected = true;
                    break;
                }
            }
        }

        if (!selected) {
            std::cerr << "Warning: all EU VRC AID sequences failed\n";
        }
    } else if (pluginName == "eid") {
        // The card hosts one of the document types: select the first it accepts
        // and read only that type's files.
        namespace Core = LibreSCRS::RsEId::Core;
        const Core::DocumentProfile* selected = nullptr;
        for (const auto& p : Core::documentProfiles()) {
            if (LibreSCRS::SmartCard::Internal::orThrow(
                    conn.transmit(LibreSCRS::SmartCard::Internal::selectByAID({p.aid.begin(), p.aid.end()})))
                    .isSuccess()) {
                selected = &p;
                break;
            }
        }
        if (!selected) {
            std::cerr << "Warning: no Serbian eID application could be selected\n";
        } else {
            std::erase_if(info.dataFiles, [&](const DataFile& df) {
                const auto fid = static_cast<std::uint16_t>((df.fidHi << 8) | df.fidLo);
                return std::ranges::none_of(selected->files, [&](const Core::FileSpec& f) { return f.fid == fid; });
            });
        }
    } else if (!info.aids.empty()) {
        auto selectCmd = LibreSCRS::SmartCard::Internal::selectByAID(info.aids[0]);
        auto selectResp = LibreSCRS::SmartCard::Internal::orThrow(conn.transmit(selectCmd));
        if (!selectResp.isSuccess()) {
            std::cerr << "Warning: SELECT AID failed with SW " << std::format("{:04X}", selectResp.statusWord())
                      << "\n";
        }
    }

    // Determine plugin-specific read chunk size
    uint8_t chunkSize = 0xFF; // default 255
    if (pluginName == "cardedge")
        chunkSize = cardedge::protocol::PKI_READ_CHUNK;
    else if (pluginName == "eu-vrc")
        chunkSize = euvrc::protocol::READ_CHUNK_SMALL;

    // Read each data file and populate example values
    for (auto& df : info.dataFiles) {
        if (df.fidHi == 0 && df.fidLo == 0) {
            continue; // No FID (e.g. CardEdge structural info)
        }

        auto selectFile = LibreSCRS::SmartCard::Internal::selectByPath(df.fidHi, df.fidLo);
        auto selectResp = LibreSCRS::SmartCard::Internal::orThrow(conn.transmit(selectFile));
        if (!selectResp.isSuccess()) {
            if (selectResp.statusWord() == 0x6982) {
                // Auth required — mark tags
                for (auto& tag : df.tags) {
                    tag.example = "[AUTH REQUIRED]";
                }
            }
            continue;
        }

        // Read binary data
        std::vector<uint8_t> fileData;
        uint16_t offset = 0;
        bool reading = true;
        while (reading) {
            auto readCmd = LibreSCRS::SmartCard::Internal::readBinary(offset, chunkSize);
            auto readResp = LibreSCRS::SmartCard::Internal::orThrow(conn.transmit(readCmd));
            if (readResp.isSuccess() && !readResp.data.empty()) {
                fileData.insert(fileData.end(), readResp.data.begin(), readResp.data.end());
                offset += static_cast<uint16_t>(readResp.data.size());
                if (readResp.data.size() < chunkSize) {
                    reading = false;
                }
            } else {
                reading = false;
            }
        }

        // Try TLV parsing
        if (!fileData.empty()) {
            auto fields = LibreSCRS::SmartCard::Internal::parseTLV(fileData.data(), fileData.size());
            for (auto& tag : df.tags) {
                auto value = LibreSCRS::SmartCard::Internal::findString(fields, tag.tag);
                if (!value.empty()) {
                    tag.example = value;
                }
            }
        }
    }

    if (verbose) {
        conn.clearTransmitFilter();
        info.apduTrace = logger.formatTrace();
    }

    return info;
}

} // namespace card_mapper
