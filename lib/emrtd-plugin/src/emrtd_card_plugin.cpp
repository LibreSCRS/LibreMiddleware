// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <emrtd/crypto/active_auth.h>
#include <emrtd/crypto/chip_auth.h>
#include <emrtd/crypto/pace.h>
#include <emrtd/crypto/passive_auth.h>
#include <emrtd/data_group.h>
#include <emrtd/emrtd_card.h>
#include <emrtd/emrtd_types.h>
#include <plugin/card_plugin.h>
#include <plugin/security_check.h>
#include <smartcard/apdu.h>
#include <smartcard/pcsc_connection.h>

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <map>
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

struct SessionContext {
    std::optional<std::variant<emrtd::MRZData, std::string>> credentials;
    std::string pendingDocNum, pendingDob, pendingExpiry;
    std::unique_ptr<emrtd::EMRTDCard> emrTDCard;
};

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
        // Reset session for this connection (new card insert = new session)
        std::lock_guard lock(mtx);
        sessions.erase(&conn);
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

        // Check for pending credentials (set via setCredentials() which has no conn param)
        auto& session = sessions[&conn];
        if (pendingCredentials) {
            session.credentials = *pendingCredentials;
            pendingCredentials.reset();
        }
        if (!session.pendingDocNum.empty() && session.pendingDocNum != pendingDocNum) {
            // sync pending MRZ fields
        }
        // Copy global pending MRZ into session if not yet set
        if (!session.credentials) {
            if (!pendingDocNum.empty() && !pendingDob.empty() && !pendingExpiry.empty()) {
                session.credentials = emrtd::MRZData{pendingDocNum, pendingDob, pendingExpiry};
            }
        }

        if (!session.credentials) {
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
        auto creds = *session.credentials;
        lock.unlock();

        std::unique_ptr<emrtd::EMRTDCard> localCard;
        if (auto* mrz = std::get_if<emrtd::MRZData>(&creds)) {
            localCard = std::make_unique<emrtd::EMRTDCard>(conn, *mrz);
        } else if (auto* can = std::get_if<std::string>(&creds)) {
            localCard = std::make_unique<emrtd::EMRTDCard>(conn, *can);
        }
        {
            std::lock_guard lk(mtx);
            sessions[&conn].emrTDCard = std::move(localCard);
        }
        emrtd::EMRTDCard* card = sessions[&conn].emrTDCard.get();

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

        // --- ICAO-compliant reading flow ---

        auto addTextField = [](plugin::CardFieldGroup& g, const std::string& key, const std::string& label,
                               const std::string& val) {
            if (!val.empty())
                g.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
        };

        // 1. Read COM → emit presence group
        auto dgList = card->readCOM();
        {
            plugin::CardFieldGroup g;
            g.groupKey = "presence";
            g.groupLabel = "Data Groups Present";
            std::string dgListStr;
            for (int dg : dgList) {
                if (!dgListStr.empty())
                    dgListStr += ", ";
                dgListStr += "DG" + std::to_string(dg);
            }
            addTextField(g, "data_groups", "Data Groups", dgListStr);
            addTextField(g, "auth_method", "Authentication Method",
                         authResult.method == emrtd::AuthMethod::BAC        ? "BAC"
                         : authResult.method == emrtd::AuthMethod::PACE_MRZ ? "PACE (MRZ)"
                                                                            : "PACE (CAN)");
            emitGroup(std::move(g));
        }

        // 2. Read SOD → store raw bytes
        auto sodRaw = card->readSOD();

        // 3. Parse SOD → get authoritative DG list from hash entries
        std::vector<int> authoritativeDGs;
        std::optional<emrtd::crypto::SODContent> sodContent;
        if (sodRaw) {
            sodContent = emrtd::crypto::parseSOD(*sodRaw);
            if (sodContent) {
                for (const auto& [dgNum, hash] : sodContent->dgHashes)
                    authoritativeDGs.push_back(dgNum);
                std::sort(authoritativeDGs.begin(), authoritativeDGs.end());
            }
        }
        // Fall back to COM list if SOD parsing failed
        if (authoritativeDGs.empty())
            authoritativeDGs = dgList;

        bool hasDG14 = std::find(authoritativeDGs.begin(), authoritativeDGs.end(), 14) != authoritativeDGs.end();
        bool hasDG15 = std::find(authoritativeDGs.begin(), authoritativeDGs.end(), 15) != authoritativeDGs.end();

        // Storage for raw DG bytes (for passive auth)
        std::map<int, std::vector<uint8_t>> dgRawData;

        // 4. If DG14 present → Chip Authentication → upgrade SM
        emrtd::crypto::ChipAuthResult caResult;
        caResult.chipAuthentication = emrtd::crypto::ChipAuthResult::NOT_PERFORMED;
        caResult.activeAuthentication = emrtd::crypto::ChipAuthResult::NOT_PERFORMED;

        if (hasDG14) {
            auto dg14Result = card->readDataGroupSafe(14);
            if (dg14Result.status == emrtd::DGReadStatus::OK && !dg14Result.data.empty()) {
                dgRawData[14] = dg14Result.data;
                if (card->hasSecureMessaging()) {
                    caResult =
                        emrtd::crypto::performChipAuth(card->connection(), dg14Result.data, card->secureMessaging());
                    if (caResult.newSessionKeys) {
                        card->replaceSM(*caResult.newSessionKeys, caResult.newAlgorithm);
                    }
                }
            }
        }

        // 5. If no DG14 but DG15 present → Active Authentication
        if (caResult.chipAuthentication != emrtd::crypto::ChipAuthResult::PASSED && hasDG15) {
            auto dg15Result = card->readDataGroupSafe(15);
            if (dg15Result.status == emrtd::DGReadStatus::OK && !dg15Result.data.empty()) {
                dgRawData[15] = dg15Result.data;
                if (card->hasSecureMessaging()) {
                    auto aaResult =
                        emrtd::crypto::performActiveAuth(card->connection(), dg15Result.data, card->secureMessaging());
                    caResult.activeAuthentication = aaResult.activeAuthentication;
                    if (aaResult.errorDetail.size() > caResult.errorDetail.size())
                        caResult.errorDetail = aaResult.errorDetail;
                }
            }
        }

        // 6. Read remaining DGs and emit groups
        for (int dg : authoritativeDGs) {
            // Skip DG14/DG15 — already read above
            if (dg == 14 || dg == 15)
                continue;

            auto dgResult = card->readDataGroupSafe(dg);
            if (dgResult.status == emrtd::DGReadStatus::OK && !dgResult.data.empty()) {
                dgRawData[dg] = dgResult.data;
            }

            // Parse and emit based on DG number
            switch (dg) {
            case 1: {
                if (dgResult.status != emrtd::DGReadStatus::OK || dgResult.data.empty())
                    break;
                std::map<int, std::vector<uint8_t>> singleDG;
                singleDG[1] = dgResult.data;
                auto parsed = emrtd::parseDataGroups(singleDG);
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
            }
            case 2: {
                if (dgResult.status != emrtd::DGReadStatus::OK || dgResult.data.empty())
                    break;
                std::map<int, std::vector<uint8_t>> singleDG;
                singleDG[2] = dgResult.data;
                auto parsed = emrtd::parseDataGroups(singleDG);
                if (parsed.dg2) {
                    plugin::CardFieldGroup g;
                    g.groupKey = "photo";
                    g.groupLabel = "Photo";
                    g.fields.push_back({"photo", "Photo", plugin::FieldType::Photo, parsed.dg2->imageData});
                    emitGroup(std::move(g));
                }
                break;
            }
            case 3: {
                plugin::CardFieldGroup g;
                g.groupKey = "biometric_fingerprint";
                g.groupLabel = "Fingerprint (DG3)";
                if (dgResult.status == emrtd::DGReadStatus::ACCESS_DENIED) {
                    addTextField(g, "access", "Access", "EAC required");
                } else if (dgResult.status == emrtd::DGReadStatus::OK && !dgResult.data.empty()) {
                    g.fields.push_back({"fingerprint", "Fingerprint", plugin::FieldType::Binary, dgResult.data});
                } else {
                    break; // NOT_PRESENT or ERROR — skip
                }
                emitGroup(std::move(g));
                break;
            }
            case 4: {
                plugin::CardFieldGroup g;
                g.groupKey = "biometric_iris";
                g.groupLabel = "Iris (DG4)";
                if (dgResult.status == emrtd::DGReadStatus::ACCESS_DENIED) {
                    addTextField(g, "access", "Access", "EAC required");
                } else if (dgResult.status == emrtd::DGReadStatus::OK && !dgResult.data.empty()) {
                    g.fields.push_back({"iris", "Iris", plugin::FieldType::Binary, dgResult.data});
                } else {
                    break; // NOT_PRESENT or ERROR — skip
                }
                emitGroup(std::move(g));
                break;
            }
            case 5: {
                if (dgResult.status != emrtd::DGReadStatus::OK || dgResult.data.empty())
                    break;
                // DG5 contains a portrait image — emit raw as photo
                plugin::CardFieldGroup g;
                g.groupKey = "portrait";
                g.groupLabel = "Portrait (DG5)";
                g.fields.push_back({"portrait", "Portrait", plugin::FieldType::Photo, dgResult.data});
                emitGroup(std::move(g));
                break;
            }
            case 7: {
                if (dgResult.status != emrtd::DGReadStatus::OK || dgResult.data.empty())
                    break;
                std::map<int, std::vector<uint8_t>> singleDG;
                singleDG[7] = dgResult.data;
                auto parsed = emrtd::parseDataGroups(singleDG);
                if (parsed.dg7) {
                    plugin::CardFieldGroup g;
                    g.groupKey = "signature";
                    g.groupLabel = "Signature / Mark (DG7)";
                    g.fields.push_back({"signature", "Signature", plugin::FieldType::Photo, parsed.dg7->imageData});
                    emitGroup(std::move(g));
                }
                break;
            }
            case 11: {
                if (dgResult.status != emrtd::DGReadStatus::OK || dgResult.data.empty())
                    break;
                std::map<int, std::vector<uint8_t>> singleDG;
                singleDG[11] = dgResult.data;
                auto parsed = emrtd::parseDataGroups(singleDG);
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
            }
            case 12: {
                if (dgResult.status != emrtd::DGReadStatus::OK || dgResult.data.empty())
                    break;
                std::map<int, std::vector<uint8_t>> singleDG;
                singleDG[12] = dgResult.data;
                auto parsed = emrtd::parseDataGroups(singleDG);
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
            }
            case 13: {
                if (dgResult.status != emrtd::DGReadStatus::OK || dgResult.data.empty())
                    break;
                plugin::CardFieldGroup g;
                g.groupKey = "national";
                g.groupLabel = "National Data (DG13)";
                g.fields.push_back({"national_data", "National Data", plugin::FieldType::Binary, dgResult.data});
                emitGroup(std::move(g));
                break;
            }
            case 16: {
                if (dgResult.status != emrtd::DGReadStatus::OK || dgResult.data.empty())
                    break;
                auto contacts = emrtd::EMRTDCard::parseDG16(dgResult.data);
                if (!contacts.empty()) {
                    plugin::CardFieldGroup g;
                    g.groupKey = "contacts";
                    g.groupLabel = "Persons to Notify (DG16)";
                    int idx = 0;
                    for (const auto& contact : contacts) {
                        std::string prefix = (contacts.size() > 1) ? "contact_" + std::to_string(idx) + "_" : "";
                        addTextField(g, prefix + "name", "Name", contact.name);
                        addTextField(g, prefix + "telephone", "Telephone", contact.telephone);
                        addTextField(g, prefix + "address", "Address", contact.address);
                        ++idx;
                    }
                    emitGroup(std::move(g));
                }
                break;
            }
            default:
                break;
            }
        }

        // 7. Passive Authentication
        plugin::SecurityStatus secStatus;

        if (sodRaw && !dgRawData.empty()) {
            // CSCA trust store path from env var
            std::string trustStorePath;
            if (const char* envPath = std::getenv("LIBRESCRS_CSCA_STORE"))
                trustStorePath = envPath;

            auto paResult = emrtd::crypto::performPassiveAuth(*sodRaw, dgRawData, trustStorePath);

            // SOD signature check
            {
                plugin::SecurityCheck check;
                check.checkId = "pa_sod_signature";
                check.category = "data_authenticity";
                check.label = "SOD Digital Signature";
                check.status = (paResult.sodSignature == emrtd::crypto::PAResult::PASSED)
                                   ? plugin::SecurityCheck::PASSED
                               : (paResult.sodSignature == emrtd::crypto::PAResult::FAILED)
                                   ? plugin::SecurityCheck::FAILED
                                   : plugin::SecurityCheck::NOT_PERFORMED;
                if (!paResult.dscSubject.empty())
                    check.detail = "DSC: " + paResult.dscSubject;
                secStatus.checks.push_back(std::move(check));
            }

            // CSCA chain check
            {
                plugin::SecurityCheck check;
                check.checkId = "pa_csca_chain";
                check.category = "data_authenticity";
                check.label = "CSCA Certificate Chain";
                check.status = (paResult.cscaChain == emrtd::crypto::PAResult::PASSED)
                                   ? plugin::SecurityCheck::PASSED
                               : (paResult.cscaChain == emrtd::crypto::PAResult::FAILED)
                                   ? plugin::SecurityCheck::FAILED
                                   : plugin::SecurityCheck::NOT_PERFORMED;
                if (trustStorePath.empty())
                    check.detail = "No CSCA trust store configured";
                secStatus.checks.push_back(std::move(check));
            }

            // Per-DG hash checks
            for (const auto& [dgNum, status] : paResult.dgHashes) {
                plugin::SecurityCheck check;
                check.checkId = "pa_dg" + std::to_string(dgNum) + "_hash";
                check.category = "data_integrity";
                check.label = "DG" + std::to_string(dgNum) + " Hash (" + paResult.hashAlgorithm + ")";
                check.status = (status == emrtd::crypto::PAResult::PASSED)    ? plugin::SecurityCheck::PASSED
                               : (status == emrtd::crypto::PAResult::FAILED)  ? plugin::SecurityCheck::FAILED
                                                                              : plugin::SecurityCheck::NOT_PERFORMED;
                secStatus.checks.push_back(std::move(check));
            }

            if (!paResult.errorDetail.empty()) {
                plugin::SecurityCheck check;
                check.checkId = "pa_error";
                check.category = "data_authenticity";
                check.label = "Passive Authentication";
                check.status = plugin::SecurityCheck::FAILED;
                check.errorDetail = paResult.errorDetail;
                secStatus.checks.push_back(std::move(check));
            }
        }

        // Chip Authentication check
        {
            plugin::SecurityCheck check;
            check.checkId = "chip_auth";
            check.category = "chip_genuineness";
            check.label = "Chip Authentication";
            check.status = (caResult.chipAuthentication == emrtd::crypto::ChipAuthResult::PASSED)
                               ? plugin::SecurityCheck::PASSED
                           : (caResult.chipAuthentication == emrtd::crypto::ChipAuthResult::FAILED)
                               ? plugin::SecurityCheck::FAILED
                           : (caResult.chipAuthentication == emrtd::crypto::ChipAuthResult::NOT_SUPPORTED)
                               ? plugin::SecurityCheck::NOT_SUPPORTED
                               : plugin::SecurityCheck::NOT_PERFORMED;
            if (!caResult.protocol.empty())
                check.detail = caResult.protocol;
            secStatus.checks.push_back(std::move(check));
        }

        // Active Authentication check
        {
            plugin::SecurityCheck check;
            check.checkId = "active_auth";
            check.category = "chip_genuineness";
            check.label = "Active Authentication";
            check.status = (caResult.activeAuthentication == emrtd::crypto::ChipAuthResult::PASSED)
                               ? plugin::SecurityCheck::PASSED
                           : (caResult.activeAuthentication == emrtd::crypto::ChipAuthResult::FAILED)
                               ? plugin::SecurityCheck::FAILED
                           : (caResult.activeAuthentication == emrtd::crypto::ChipAuthResult::NOT_SUPPORTED)
                               ? plugin::SecurityCheck::NOT_SUPPORTED
                               : plugin::SecurityCheck::NOT_PERFORMED;
            if (!caResult.errorDetail.empty())
                check.errorDetail = caResult.errorDetail;
            secStatus.checks.push_back(std::move(check));
        }

        secStatus.computeOverall();

        // 8. Emit security_status group
        {
            plugin::CardFieldGroup g;
            g.groupKey = "security_status";
            g.groupLabel = "Security Verification";

            addTextField(g, "overall_integrity", "Data Integrity", plugin::statusToString(secStatus.overallIntegrity));
            addTextField(g, "overall_authenticity", "Data Authenticity",
                         plugin::statusToString(secStatus.overallAuthenticity));
            addTextField(g, "overall_genuineness", "Chip Genuineness",
                         plugin::statusToString(secStatus.overallGenuineness));

            for (const auto& check : secStatus.checks) {
                std::string val = plugin::statusToString(check.status);
                if (!check.detail.empty())
                    val += " (" + check.detail + ")";
                if (!check.errorDetail.empty())
                    val += " [" + check.errorDetail + "]";
                addTextField(g, check.checkId, check.label, val);
            }

            emitGroup(std::move(g));
        }

        // Install SM filter so PKI fallback plugins get SM wrapping transparently
        conn.setTransmitFilter([this, connPtr = &conn](const smartcard::APDUCommand& cmd) {
            std::lock_guard lock(mtx);
            auto it = sessions.find(connPtr);
            if (it == sessions.end() || !it->second.emrTDCard)
                return smartcard::APDUResponse{{}, 0x69, 0x82};
            return it->second.emrTDCard->transmitSecureAPDU(cmd);
        });

        return data;
    }

    void setCredentials(const std::string& key, const std::string& value) const override
    {
        std::lock_guard lock(mtx);
        if (key == "can") {
            pendingCredentials = std::string(value);
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
            pendingCredentials = emrtd::MRZData{pendingDocNum, pendingDob, pendingExpiry};
        }
    }

    mutable std::mutex mtx;
    mutable std::map<smartcard::PCSCConnection*, SessionContext> sessions;
    // Keep pendingCredentials global since setCredentials() has no conn param
    mutable std::optional<std::variant<emrtd::MRZData, std::string>> pendingCredentials;
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
