// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <eidcard/eidcard.h>
#include <eidcard/eidtypes.h>
#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>

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

} // namespace

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
        // Apollo 2008
        if (atr[0] == 0x3B && atr[1] == 0xB9 && atr[2] == 0x18)
            return true;
        // Gemalto 2014+
        if (atr[0] == 0x3B && atr[1] == 0xFF && atr[2] == 0x94)
            return true;
        return false;
    }

    plugin::CardData readCard(smartcard::PCSCConnection& conn) const override
    {
        eidcard::EIdCard card(conn);

        plugin::CardData data;
        data.cardType = "rs-eid";

        data.groups.push_back(personalGroup(card.readFixedPersonalData()));
        data.groups.push_back(addressGroup(card.readVariablePersonalData()));
        data.groups.push_back(documentGroup(card.readDocumentData()));

        auto photo = card.readPortrait();
        if (!photo.empty()) {
            plugin::CardFieldGroup photoGroup;
            photoGroup.groupKey = "photo";
            photoGroup.groupLabel = "Photo";
            photoGroup.fields.push_back({"photo", "Photo", plugin::FieldType::Photo, photo});
            data.groups.push_back(std::move(photoGroup));
        }

        return data;
    }

    bool supportsPKI() const override
    {
        return true;
    }

    std::vector<plugin::CertificateData> readCertificates(smartcard::PCSCConnection& conn) const override
    {
        eidcard::EIdCard card(conn);
        auto certs = card.readCertificates();

        std::vector<plugin::CertificateData> result;
        for (const auto& cert : certs) {
            result.push_back({cert.label, cert.derBytes, cert.keyFID, cert.keySizeBits});
        }
        return result;
    }

    plugin::PINResult verifyPIN(smartcard::PCSCConnection& conn, const std::string& pin) const override
    {
        eidcard::EIdCard card(conn);
        auto r = card.verifyPIN(pin);
        return {r.success, r.retriesLeft, r.blocked};
    }

    plugin::PINResult changePIN(smartcard::PCSCConnection& conn, const std::string& oldPin,
                                const std::string& newPin) const override
    {
        eidcard::EIdCard card(conn);
        auto r = card.changePIN(oldPin, newPin);
        return {r.success, r.retriesLeft, r.blocked};
    }

    int getPINTriesLeft(smartcard::PCSCConnection& conn) const override
    {
        eidcard::EIdCard card(conn);
        return card.getPINTriesLeft().retriesLeft;
    }

    plugin::SignResult sign(smartcard::PCSCConnection& conn, uint16_t keyReference, std::span<const uint8_t> data,
                            plugin::SignMechanism /*mechanism*/) const override
    {
        eidcard::EIdCard card(conn);
        auto sig = card.signData(keyReference, {data.begin(), data.end()});
        return {!sig.empty(), std::move(sig)};
    }

    std::vector<std::pair<std::string, uint16_t>> discoverKeyReferences(smartcard::PCSCConnection& conn) const override
    {
        eidcard::EIdCard card(conn);
        return card.discoverKeyReferences();
    }
};

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<EidCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
