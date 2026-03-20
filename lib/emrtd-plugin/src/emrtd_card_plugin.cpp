// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <emrtd/crypto/pace.h>
#include <emrtd/data_group.h>
#include <emrtd/emrtd_card.h>
#include <emrtd/emrtd_types.h>
#include <plugin/card_plugin.h>
#include <smartcard/apdu.h>
#include <smartcard/pcsc_connection.h>

#include <ctime>
#include <optional>
#include <string>
#include <variant>

namespace {

// Format MRZ date YYMMDD → DD.MM.YYYY.
// For DOB: 2-digit year mapped to past (20xx if ≤ current year, else 19xx).
// For DOE: 2-digit year mapped to future (19xx only if > current year + 20).
std::string formatMRZDate(const std::string& yymmdd, bool isExpiry = false)
{
    if (yymmdd.size() != 6)
        return yymmdd;
    std::string yy = yymmdd.substr(0, 2);
    std::string mm = yymmdd.substr(2, 2);
    std::string dd = yymmdd.substr(4, 2);
    int y = std::stoi(yy);
    int fullYear;
    if (isExpiry) {
        // Expiry dates are in the near future — use 20xx unless obviously wrong
        fullYear = (y + 2000 > 2080) ? 1900 + y : 2000 + y;
    } else {
        // Birth dates are in the past — use 19xx if 20xx would be in the future
        auto now = std::time(nullptr);
        auto* tm = std::localtime(&now);
        int currentYY = (tm->tm_year + 1900) % 100;
        fullYear = (y > currentYY) ? 1900 + y : 2000 + y;
    }
    return dd + "." + mm + "." + std::to_string(fullYear);
}

class EMRTDCardPlugin : public plugin::CardPlugin
{
public:
    std::string pluginId() const override
    {
        return "emrtd";
    }
    std::string displayName() const override
    {
        return "Electronic Passport (eMRTD)";
    }
    int probePriority() const override
    {
        return 800;
    }

    bool canHandle(const std::vector<uint8_t>& /*atr*/) const override
    {
        return false;
    }

    bool canHandleConnection(smartcard::PCSCConnection& conn) const override
    {
        // Clear credentials from previous session (new card insert = new session)
        credentials.reset();
        pendingDocNum.clear();
        pendingDob.clear();
        pendingExpiry.clear();

        // SELECT eMRTD applet by AID
        smartcard::APDUCommand selectCmd{
            0x00, 0xA4, 0x04, 0x0C, {emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN}, 0, false};
        auto response = conn.transmit(selectCmd);
        return response.isSuccess();
    }

    plugin::CardData readCard(smartcard::PCSCConnection& conn) const override
    {
        plugin::CardData data;
        data.cardType = "emrtd";

        if (!credentials) {
            // Phase 1: no credentials — return auth_required
            plugin::CardFieldGroup authGroup;
            authGroup.groupKey = "auth_required";
            authGroup.groupLabel = "Authentication Required";

            auto addText = [&](const std::string& key, const std::string& label, const std::string& val) {
                authGroup.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
            };

            addText("status", "Status", "MRZ or CAN required");

            // Try to read EF.CardAccess to report PACE support
            bool paceSupported = false;
            try {
                // Re-select applet
                smartcard::APDUCommand selectCmd{
                    0x00, 0xA4, 0x04, 0x0C, {emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN}, 0, false};
                conn.transmit(selectCmd);

                // READ BINARY EF.CardAccess (short FID)
                smartcard::APDUCommand readCA{
                    0x00, 0xB0, static_cast<uint8_t>(0x80 | emrtd::SFID_CARD_ACCESS), 0x00, {}, 0x00, true};
                auto caResp = conn.transmit(readCA);
                if (caResp.isSuccess() && !caResp.data.empty()) {
                    supportedPACEOids = emrtd::crypto::parseCardAccess(caResp.data);
                    paceSupported = !supportedPACEOids.empty();
                }
            } catch (...) {
                // Non-fatal
            }

            addText("pace_supported", "PACE Supported", paceSupported ? "true" : "false");
            if (!supportedPACEOids.empty()) {
                std::string oids;
                for (const auto& oid : supportedPACEOids) {
                    if (!oids.empty())
                        oids += ", ";
                    oids += oid;
                }
                addText("pace_oids", "PACE Algorithms", oids);
            }

            data.groups.push_back(std::move(authGroup));
            return data;
        }

        // Phase 2: credentials set — authenticate and read
        std::unique_ptr<emrtd::EMRTDCard> card;
        if (auto* mrz = std::get_if<emrtd::MRZData>(&*credentials)) {
            card = std::make_unique<emrtd::EMRTDCard>(conn, *mrz);
        } else if (auto* can = std::get_if<std::string>(&*credentials)) {
            card = std::make_unique<emrtd::EMRTDCard>(conn, *can);
        }

        auto authResult = card->authenticate();
        if (!authResult.success) {
            plugin::CardFieldGroup errorGroup;
            errorGroup.groupKey = "error";
            errorGroup.groupLabel = "Authentication Failed";
            std::string err = authResult.error;
            errorGroup.fields.push_back({"error", "Error", plugin::FieldType::Text, {err.begin(), err.end()}});
            data.groups.push_back(std::move(errorGroup));
            return data;
        }

        // Read all DGs
        auto rawDGs = card->readAllDataGroups();
        auto parsed = emrtd::parseDataGroups(rawDGs);

        // Build CardData from parsed DGs
        if (parsed.dg1) {
            plugin::CardFieldGroup personalGroup;
            personalGroup.groupKey = "personal";
            personalGroup.groupLabel = "Personal Data (DG1)";

            auto addField = [&](const std::string& key, const std::string& label, const std::string& val) {
                if (!val.empty()) {
                    personalGroup.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
                }
            };

            addField("surname", "Surname", parsed.dg1->surname);
            addField("given_names", "Given Names", parsed.dg1->givenNames);
            addField("nationality", "Nationality", parsed.dg1->nationality);
            addField("date_of_birth", "Date of Birth", formatMRZDate(parsed.dg1->dateOfBirth));
            addField("sex", "Sex", parsed.dg1->sex);
            data.groups.push_back(std::move(personalGroup));

            plugin::CardFieldGroup docGroup;
            docGroup.groupKey = "document";
            docGroup.groupLabel = "Document Data (DG1)";

            auto addDocField = [&](const std::string& key, const std::string& label, const std::string& val) {
                if (!val.empty()) {
                    docGroup.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
                }
            };

            addDocField("document_number", "Document Number", parsed.dg1->documentNumber);
            addDocField("document_code", "Document Code", parsed.dg1->documentCode);
            addDocField("issuing_state", "Issuing State", parsed.dg1->issuingState);
            addDocField("date_of_expiry", "Date of Expiry", formatMRZDate(parsed.dg1->dateOfExpiry, true));
            addDocField("personal_number", "Personal Number", parsed.dg1->optionalData);
            data.groups.push_back(std::move(docGroup));
        }

        if (parsed.dg2) {
            plugin::CardFieldGroup photoGroup;
            photoGroup.groupKey = "photo";
            photoGroup.groupLabel = "Photo";
            photoGroup.fields.push_back({"photo", "Photo", plugin::FieldType::Photo, parsed.dg2->imageData});
            data.groups.push_back(std::move(photoGroup));
        }

        if (parsed.dg7) {
            plugin::CardFieldGroup sigGroup;
            sigGroup.groupKey = "signature";
            sigGroup.groupLabel = "Signature / Mark (DG7)";
            sigGroup.fields.push_back({"signature", "Signature", plugin::FieldType::Photo, parsed.dg7->imageData});
            data.groups.push_back(std::move(sigGroup));
        }

        if (parsed.dg11) {
            plugin::CardFieldGroup additionalGroup;
            additionalGroup.groupKey = "additional";
            additionalGroup.groupLabel = "Additional Personal Data (DG11)";

            auto addAdditional = [&](const std::string& key, const std::string& label, const std::string& val) {
                if (!val.empty()) {
                    additionalGroup.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
                }
            };

            addAdditional("full_name", "Full Name", parsed.dg11->fullName);
            addAdditional("other_names", "Other Names", parsed.dg11->otherNames);
            addAdditional("personal_number", "Personal Number", parsed.dg11->personalNumber);
            addAdditional("place_of_birth", "Place of Birth", parsed.dg11->placeOfBirth);
            addAdditional("address", "Address", parsed.dg11->address);
            addAdditional("telephone", "Telephone", parsed.dg11->telephone);
            addAdditional("profession", "Profession", parsed.dg11->profession);
            addAdditional("title", "Title", parsed.dg11->title);
            addAdditional("custody_info", "Custody Information", parsed.dg11->custodyInfo);
            if (!additionalGroup.fields.empty())
                data.groups.push_back(std::move(additionalGroup));
        }

        if (parsed.dg12) {
            plugin::CardFieldGroup docExtra;
            docExtra.groupKey = "document_extra";
            docExtra.groupLabel = "Issuing Information (DG12)";

            auto addDocExtra = [&](const std::string& key, const std::string& label, const std::string& val) {
                if (!val.empty()) {
                    docExtra.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
                }
            };

            addDocExtra("issuing_authority", "Issuing Authority", parsed.dg12->issuingAuthority);
            // DG12 dates are CCYYMMDD (8 chars) per ICAO 9303 Part 10
            std::string doi = parsed.dg12->dateOfIssue;
            if (doi.size() == 8)
                doi = doi.substr(6, 2) + "." + doi.substr(4, 2) + "." + doi.substr(0, 4);
            else if (doi.size() == 6)
                doi = formatMRZDate(doi, true);
            addDocExtra("date_of_issue", "Date of Issue", doi);
            addDocExtra("endorsements", "Endorsements", parsed.dg12->endorsements);
            addDocExtra("tax_exit", "Tax/Exit Requirements", parsed.dg12->taxExitRequirements);
            if (!docExtra.fields.empty())
                data.groups.push_back(std::move(docExtra));
        }

        return data;
    }

    void setCredentials(const std::string& key, const std::string& value) const override
    {
        if (key == "can") {
            credentials = std::string(value);
            pendingDocNum.clear();
            pendingDob.clear();
            pendingExpiry.clear();
        } else if (key == "mrz_doc_number") {
            pendingDocNum = value;
            trySetMRZ();
        } else if (key == "mrz_dob") {
            pendingDob = value;
            trySetMRZ();
        } else if (key == "mrz_expiry") {
            pendingExpiry = value;
            trySetMRZ();
        }
    }

private:
    void trySetMRZ() const
    {
        if (!pendingDocNum.empty() && !pendingDob.empty() && !pendingExpiry.empty()) {
            credentials = emrtd::MRZData{pendingDocNum, pendingDob, pendingExpiry};
        }
    }

    mutable std::optional<std::variant<emrtd::MRZData, std::string>> credentials;
    mutable std::vector<std::string> supportedPACEOids;
    mutable std::string pendingDocNum;
    mutable std::string pendingDob;
    mutable std::string pendingExpiry;
};

} // namespace

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<EMRTDCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
