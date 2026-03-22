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
#include <mutex>
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
        struct tm tmBuf{};
        localtime_r(&now, &tmBuf);
        int currentYY = (tmBuf.tm_year + 1900) % 100;
        fullYear = (y > currentYY) ? 1900 + y : 2000 + y; // NOLINT(readability-magic-numbers)
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
        std::lock_guard lock(mtx);
        credentials.reset();
        pendingDocNum.clear();
        pendingDob.clear();
        pendingExpiry.clear();
        emrTDCard.reset();
        conn.clearTransmitFilter();

        // SELECT eMRTD applet by AID (P2=0x0C: no FCI response)
        auto response =
            conn.transmit(smartcard::selectByAID({emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN}, 0x0C));
        return response.isSuccess();
    }

    plugin::CardData readCard(smartcard::PCSCConnection& conn) const override
    {
        return readCardStreaming(conn, nullptr);
    }

    plugin::CardData readCardStreaming(smartcard::PCSCConnection& conn, GroupCallback onGroup) const override
    {
        plugin::CardData data;
        data.cardType = "emrtd";

        auto emitGroup = [&](plugin::CardFieldGroup&& group) {
            if (onGroup)
                onGroup(data.cardType, group);
            data.groups.push_back(std::move(group));
        };

        std::unique_lock lock(mtx);
        if (!credentials) {
            // Phase 1: no credentials — return auth_required (no streaming needed)
            plugin::CardFieldGroup authGroup;
            authGroup.groupKey = "auth_required";
            authGroup.groupLabel = "Authentication Required";

            auto addText = [&](const std::string& key, const std::string& label, const std::string& val) {
                authGroup.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
            };

            addText("status", "Status", "MRZ or CAN required");

            bool paceSupported = false;
            std::vector<std::string> paceOids;
            try {
                smartcard::APDUCommand selectCmd{
                    0x00, 0xA4, 0x04, 0x0C, {emrtd::EMRTD_AID, emrtd::EMRTD_AID + emrtd::EMRTD_AID_LEN}, 0, false};
                conn.transmit(selectCmd);

                smartcard::APDUCommand readCA{
                    0x00, 0xB0, static_cast<uint8_t>(0x80 | emrtd::SFID_CARD_ACCESS), 0x00, {}, 0x00, true};
                auto caResp = conn.transmit(readCA);
                if (caResp.isSuccess() && !caResp.data.empty()) {
                    paceOids = emrtd::crypto::parseCardAccess(caResp.data);
                    paceSupported = !paceOids.empty();
                }
            } catch (...) {
            }

            addText("pace_supported", "PACE Supported", paceSupported ? "true" : "false");
            if (!paceOids.empty()) {
                std::string oids;
                for (const auto& oid : paceOids) {
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
        auto creds = *credentials;
        lock.unlock();

        if (auto* mrz = std::get_if<emrtd::MRZData>(&creds)) {
            emrTDCard = std::make_unique<emrtd::EMRTDCard>(conn, *mrz);
        } else if (auto* can = std::get_if<std::string>(&creds)) {
            emrTDCard = std::make_unique<emrtd::EMRTDCard>(conn, *can);
        }

        auto authResult = emrTDCard->authenticate();
        if (!authResult.success) {
            plugin::CardFieldGroup errorGroup;
            errorGroup.groupKey = "error";
            errorGroup.groupLabel = "Authentication Failed";
            std::string err = authResult.error;
            errorGroup.fields.push_back({"error", "Error", plugin::FieldType::Text, {err.begin(), err.end()}});
            data.groups.push_back(std::move(errorGroup));
            return data;
        }

        // Read DGs one by one and emit groups progressively
        auto dgList = emrTDCard->readCOM();

        auto addTextField = [](plugin::CardFieldGroup& g, const std::string& key, const std::string& label,
                               const std::string& val) {
            if (!val.empty())
                g.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
        };

        for (int dg : dgList) {
            auto raw = emrTDCard->readDataGroup(dg);
            if (!raw)
                continue;

            std::map<int, std::vector<uint8_t>> singleDG;
            singleDG[dg] = std::move(*raw);
            auto parsed = emrtd::parseDataGroups(singleDG);

            switch (dg) {
            case 1:
                if (parsed.dg1) {
                    {
                        plugin::CardFieldGroup g;
                        g.groupKey = "personal";
                        g.groupLabel = "Personal Data (DG1)";
                        addTextField(g, "surname", "Surname", parsed.dg1->surname);
                        addTextField(g, "given_names", "Given Names", parsed.dg1->givenNames);
                        addTextField(g, "nationality", "Nationality", parsed.dg1->nationality);
                        addTextField(g, "date_of_birth", "Date of Birth", formatMRZDate(parsed.dg1->dateOfBirth));
                        addTextField(g, "sex", "Sex", parsed.dg1->sex);
                        emitGroup(std::move(g));
                    }
                    {
                        plugin::CardFieldGroup g;
                        g.groupKey = "document";
                        g.groupLabel = "Document Data (DG1)";
                        addTextField(g, "document_number", "Document Number", parsed.dg1->documentNumber);
                        addTextField(g, "document_code", "Document Code", parsed.dg1->documentCode);
                        addTextField(g, "issuing_state", "Issuing State", parsed.dg1->issuingState);
                        addTextField(g, "date_of_expiry", "Date of Expiry",
                                     formatMRZDate(parsed.dg1->dateOfExpiry, true));
                        addTextField(g, "personal_number", "Personal Number", parsed.dg1->optionalData);
                        emitGroup(std::move(g));
                    }
                }
                break;
            case 2:
                if (parsed.dg2) {
                    plugin::CardFieldGroup g;
                    g.groupKey = "photo";
                    g.groupLabel = "Photo";
                    g.fields.push_back({"photo", "Photo", plugin::FieldType::Photo, parsed.dg2->imageData});
                    emitGroup(std::move(g));
                }
                break;
            case 7:
                if (parsed.dg7) {
                    plugin::CardFieldGroup g;
                    g.groupKey = "signature";
                    g.groupLabel = "Signature / Mark (DG7)";
                    g.fields.push_back({"signature", "Signature", plugin::FieldType::Photo, parsed.dg7->imageData});
                    emitGroup(std::move(g));
                }
                break;
            case 11:
                if (parsed.dg11) {
                    plugin::CardFieldGroup g;
                    g.groupKey = "additional";
                    g.groupLabel = "Additional Personal Data (DG11)";
                    addTextField(g, "full_name", "Full Name", parsed.dg11->fullName);
                    addTextField(g, "other_names", "Other Names", parsed.dg11->otherNames);
                    addTextField(g, "personal_number", "Personal Number", parsed.dg11->personalNumber);
                    addTextField(g, "place_of_birth", "Place of Birth", parsed.dg11->placeOfBirth);
                    addTextField(g, "address", "Address", parsed.dg11->address);
                    addTextField(g, "telephone", "Telephone", parsed.dg11->telephone);
                    addTextField(g, "profession", "Profession", parsed.dg11->profession);
                    addTextField(g, "title", "Title", parsed.dg11->title);
                    addTextField(g, "custody_info", "Custody Information", parsed.dg11->custodyInfo);
                    if (!g.fields.empty())
                        emitGroup(std::move(g));
                }
                break;
            case 12:
                if (parsed.dg12) {
                    plugin::CardFieldGroup g;
                    g.groupKey = "document_extra";
                    g.groupLabel = "Issuing Information (DG12)";
                    addTextField(g, "issuing_authority", "Issuing Authority", parsed.dg12->issuingAuthority);
                    std::string doi = parsed.dg12->dateOfIssue;
                    if (doi.size() == 8)
                        doi = doi.substr(6, 2) + "." + doi.substr(4, 2) + "." + doi.substr(0, 4);
                    else if (doi.size() == 6)
                        doi = formatMRZDate(doi, true);
                    addTextField(g, "date_of_issue", "Date of Issue", doi);
                    addTextField(g, "endorsements", "Endorsements", parsed.dg12->endorsements);
                    addTextField(g, "tax_exit", "Tax/Exit Requirements", parsed.dg12->taxExitRequirements);
                    if (!g.fields.empty())
                        emitGroup(std::move(g));
                }
                break;
            default:
                break;
            }
        }

        // Install SM filter so PKI fallback plugins get SM wrapping transparently
        conn.setTransmitFilter([this](const smartcard::APDUCommand& cmd) {
            std::lock_guard lock(mtx);
            if (!emrTDCard)
                return smartcard::APDUResponse{{}, 0x69, 0x82};
            return emrTDCard->transmitSecureAPDU(cmd);
        });

        return data;
    }

    void setCredentials(const std::string& key, const std::string& value) const override
    {
        std::lock_guard lock(mtx);
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

    mutable std::mutex mtx;
    mutable std::optional<std::variant<emrtd::MRZData, std::string>> credentials;
    mutable std::string pendingDocNum;
    mutable std::string pendingDob;
    mutable std::string pendingExpiry;
    mutable std::unique_ptr<emrtd::EMRTDCard> emrTDCard;
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
