// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <eidcard/eidcard.h>
#include <eidcard/eidtypes.h>
#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>

#include <filesystem>
#include <fstream>

namespace {

void addText(plugin::CardFieldGroup& group, const std::string& key, const std::string& label, const std::string& val)
{
    if (!val.empty()) {
        group.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
    }
}

plugin::CardFieldGroup personalGroup(const eidcard::FixedPersonalData& fp)
{
    plugin::CardFieldGroup group;
    group.groupKey = "personal";
    group.groupLabel = "Personal Data";

    addText(group, "personal_number", "Personal Number", fp.personalNumber);
    addText(group, "surname", "Surname", fp.surname);
    addText(group, "given_name", "Given Name", fp.givenName);
    addText(group, "parent_given_name", "Parent Given Name", fp.parentGivenName);
    addText(group, "sex", "Sex", fp.sex);
    addText(group, "place_of_birth", "Place of Birth", fp.placeOfBirth);
    addText(group, "community_of_birth", "Community of Birth", fp.communityOfBirth);
    addText(group, "state_of_birth", "State of Birth", fp.stateOfBirth);
    addText(group, "date_of_birth", "Date of Birth", fp.dateOfBirth);
    addText(group, "nationality", "Nationality", fp.nationalityFull);
    addText(group, "status_of_foreigner", "Status of Foreigner", fp.statusOfForeigner);

    return group;
}

plugin::CardFieldGroup addressGroup(const eidcard::VariablePersonalData& vp)
{
    plugin::CardFieldGroup group;
    group.groupKey = "address";
    group.groupLabel = "Address";

    addText(group, "state", "State", vp.state);
    addText(group, "community", "Community", vp.community);
    addText(group, "place", "Place", vp.place);
    addText(group, "street", "Street", vp.street);
    addText(group, "house_number", "House Number", vp.houseNumber);
    addText(group, "house_letter", "House Letter", vp.houseLetter);
    addText(group, "entrance", "Entrance", vp.entrance);
    addText(group, "floor", "Floor", vp.floor);
    addText(group, "apartment_number", "Apartment Number", vp.apartmentNumber);

    return group;
}

plugin::CardFieldGroup documentGroup(const eidcard::DocumentData& doc)
{
    plugin::CardFieldGroup group;
    group.groupKey = "document";
    group.groupLabel = "Document Data";

    addText(group, "doc_reg_no", "Registration Number", doc.docRegNo);
    addText(group, "document_type", "Document Type", doc.documentType);
    addText(group, "document_serial_number", "Serial Number", doc.documentSerialNumber);
    addText(group, "issuing_date", "Issuing Date", doc.issuingDate);
    addText(group, "expiry_date", "Expiry Date", doc.expiryDate);
    addText(group, "issuing_authority", "Issuing Authority", doc.issuingAuthority);

    return group;
}

class EidCardPlugin : public plugin::CardPlugin
{
public:
    std::string pluginId() const override
    {
        return "rs-eid";
    }
    std::string displayName() const override
    {
        return "Serbian eID";
    }
    int probePriority() const override
    {
        return 100;
    }

    bool canHandle(const std::vector<uint8_t>& atr) const override
    {
        if (atr.size() < 3)
            return false;
        // Apollo 2008 (contact)
        if (atr[0] == 0x3B && atr[1] == 0xB9 && atr[2] == 0x18)
            return true;
        // Gemalto 2014+ (contact)
        if (atr[0] == 0x3B && atr[1] == 0xFF && atr[2] == 0x94)
            return true;
        return false;
    }

    bool canHandleConnection(smartcard::PCSCConnection& conn) const override
    {
        try {
            // Try to detect card type by selecting eID applet AIDs
            eidcard::EIdCard card(conn);
            return card.getCardType() != eidcard::CardType::Unknown;
        } catch (...) {
            return false;
        }
    }

    plugin::CardData readCard(smartcard::PCSCConnection& conn) const override
    {
        return readCardStreaming(conn, nullptr);
    }

    plugin::CardData readCardStreaming(smartcard::PCSCConnection& conn, GroupCallback onGroup) const override
    {
        eidcard::EIdCard card(conn);

        plugin::CardData data;
        data.cardType = "rs-eid";

        auto emitGroup = [&](plugin::CardFieldGroup&& group) {
            if (onGroup)
                onGroup(data.cardType, group);
            data.groups.push_back(std::move(group));
        };

        // 1. Meta (card type detection — fast, single SELECT)
        auto cardType = card.getCardType();
        {
            plugin::CardFieldGroup meta;
            meta.groupKey = "meta";
            meta.groupLabel = "Card Metadata";
            std::string ct;
            switch (cardType) {
            case eidcard::CardType::Apollo2008:
                ct = "Apollo2008";
                break;
            case eidcard::CardType::Gemalto2014:
                ct = "Gemalto2014";
                break;
            case eidcard::CardType::ForeignerIF2020:
                ct = "ForeignerIF2020";
                break;
            default:
                ct = "Unknown";
                break;
            }
            meta.fields.push_back({"card_type", "Card Type", plugin::FieldType::Text, {ct.begin(), ct.end()}});
            emitGroup(std::move(meta));
        }

        // 2. Personal data (card I/O: readFixedPersonalData)
        auto fixedPersonal = card.readFixedPersonalData();
        emitGroup(personalGroup(fixedPersonal));

        // 3. Address (card I/O: readVariablePersonalData)
        auto variablePersonal = card.readVariablePersonalData();
        {
            auto addrGrp = addressGroup(variablePersonal);
            if (!variablePersonal.addressDate.empty()) {
                addrGrp.fields.push_back({"address_date",
                                          "Address Date",
                                          plugin::FieldType::Text,
                                          {variablePersonal.addressDate.begin(), variablePersonal.addressDate.end()}});
            }
            emitGroup(std::move(addrGrp));
        }

        // 4. Document (card I/O: readDocumentData)
        auto documentData = card.readDocumentData();
        emitGroup(documentGroup(documentData));

        // 5. Photo (card I/O: readPortrait — slowest)
        auto photo = card.readPortrait();
        if (!photo.empty()) {
            plugin::CardFieldGroup photoGroup;
            photoGroup.groupKey = "photo";
            photoGroup.groupLabel = "Photo";
            photoGroup.fields.push_back({"photo", "Photo", plugin::FieldType::Photo, photo});
            emitGroup(std::move(photoGroup));
        }

        // 6. Verification — CA cert loading + verify, results added to meta group
#ifdef LIBREMIDDLEWARE_CERT_DIR
        {
            namespace fs = std::filesystem;
            std::error_code ec;
            for (const auto& entry : fs::directory_iterator(LIBREMIDDLEWARE_CERT_DIR, ec)) {
                if (!entry.is_regular_file())
                    continue;
                auto ext = entry.path().extension().string();
                if (ext != ".cer" && ext != ".crt")
                    continue;
                std::ifstream f(entry.path(), std::ios::binary);
                if (!f)
                    continue;
                std::vector<uint8_t> der((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                card.addTrustedCertificate(der);
            }
        }
#endif

        auto toStr = [](eidcard::VerificationResult r) -> std::string {
            switch (r) {
            case eidcard::VerificationResult::Valid:
                return "valid";
            case eidcard::VerificationResult::Invalid:
                return "invalid";
            default:
                return "unknown";
            }
        };

        auto cardVerification = card.verifyCard();
        auto fixedVerification = card.verifyFixedData();
        auto variableVerification = card.verifyVariableData();

        auto* metaGroup = data.findGroup("meta");
        if (metaGroup) {
            auto addVerField = [&](const std::string& key, const std::string& val) {
                metaGroup->fields.push_back({key, key, plugin::FieldType::Text, {val.begin(), val.end()}});
            };
            addVerField("card_verification", toStr(cardVerification));
            addVerField("fixed_verification", toStr(fixedVerification));
            addVerField("variable_verification", toStr(variableVerification));
        }

        // Emit verification as a separate group for the streaming path
        plugin::CardFieldGroup verGroup;
        verGroup.groupKey = "verification";
        verGroup.groupLabel = "Verification";
        auto addVerField = [&](const std::string& key, const std::string& val) {
            verGroup.fields.push_back({key, key, plugin::FieldType::Text, {val.begin(), val.end()}});
        };
        addVerField("card_verification", toStr(cardVerification));
        addVerField("fixed_verification", toStr(fixedVerification));
        addVerField("variable_verification", toStr(variableVerification));
        emitGroup(std::move(verGroup));

        return data;
    }
};

} // namespace

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<EidCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
