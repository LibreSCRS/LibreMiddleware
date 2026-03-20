// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <healthcard/healthcard.h>
#include <healthcard/healthtypes.h>
#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>

namespace {

void addText(plugin::CardFieldGroup& group, const std::string& key, const std::string& label, const std::string& val)
{
    if (!val.empty()) {
        group.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
    }
}

} // namespace

class HealthCardPlugin : public plugin::CardPlugin
{
public:
    std::string pluginId() const override
    {
        return "rs-health";
    }
    std::string displayName() const override
    {
        return "Serbian Health Insurance";
    }
    int probePriority() const override
    {
        return 200;
    }

    bool canHandle(const std::vector<uint8_t>& /*atr*/) const override
    {
        return false;
    }

    bool canHandleConnection(smartcard::PCSCConnection& conn) const override
    {
        return healthcard::HealthCard::probe(conn);
    }

    plugin::CardData readCard(smartcard::PCSCConnection& conn) const override
    {
        healthcard::HealthCard card(conn);
        auto doc = card.readDocumentData();

        plugin::CardData data;
        data.cardType = "rs-health";

        plugin::CardFieldGroup personal;
        personal.groupKey = "personal";
        personal.groupLabel = "Personal Data";
        addText(personal, "given_name", "Given Name", doc.givenName);
        addText(personal, "given_name_latin", "Given Name (Latin)", doc.givenNameLatin);
        addText(personal, "family_name", "Family Name", doc.familyName);
        addText(personal, "family_name_latin", "Family Name (Latin)", doc.familyNameLatin);
        addText(personal, "parent_name", "Parent Name", doc.parentName);
        addText(personal, "date_of_birth", "Date of Birth", doc.dateOfBirth);
        addText(personal, "gender", "Gender", doc.gender);
        addText(personal, "personal_number", "JMBG", doc.personalNumber);
        addText(personal, "insurant_number", "LBO", doc.insurantNumber);
        data.groups.push_back(std::move(personal));

        plugin::CardFieldGroup document;
        document.groupKey = "document";
        document.groupLabel = "Document";
        addText(document, "insurer_name", "Insurer", doc.insurerName);
        addText(document, "card_id", "Card ID", doc.cardId);
        addText(document, "date_of_issue", "Date of Issue", doc.dateOfIssue);
        addText(document, "date_of_expiry", "Date of Expiry", doc.dateOfExpiry);
        addText(document, "valid_until", "Valid Until", doc.validUntil);
        data.groups.push_back(std::move(document));

        plugin::CardFieldGroup address;
        address.groupKey = "address";
        address.groupLabel = "Address";
        addText(address, "street", "Street", doc.street);
        addText(address, "address_number", "Number", doc.addressNumber);
        addText(address, "apartment", "Apartment", doc.apartment);
        addText(address, "place", "Place", doc.place);
        addText(address, "municipality", "Municipality", doc.municipality);
        addText(address, "country", "Country", doc.country);
        data.groups.push_back(std::move(address));

        plugin::CardFieldGroup insurance;
        insurance.groupKey = "insurance";
        insurance.groupLabel = "Insurance";
        addText(insurance, "insurance_basis", "Basis", doc.insuranceBasisRzzo);
        addText(insurance, "insurance_description", "Description", doc.insuranceDescription);
        addText(insurance, "insurance_start_date", "Start Date", doc.insuranceStartDate);
        addText(insurance, "carrier_relationship", "Carrier Relationship", doc.carrierRelationship);
        data.groups.push_back(std::move(insurance));

        return data;
    }

    bool supportsPKI() const override
    {
        return true;
    }

    std::vector<plugin::CertificateData> readCertificates(smartcard::PCSCConnection& conn) const override
    {
        healthcard::HealthCard card(conn);
        auto certs = card.readCertificates();

        std::vector<plugin::CertificateData> result;
        for (const auto& cert : certs) {
            result.push_back({cert.label, cert.derBytes, cert.keyFID, cert.keySizeBits});
        }
        return result;
    }

    int getPINTriesLeft(smartcard::PCSCConnection& conn) const override
    {
        healthcard::HealthCard card(conn);
        return card.getPINTriesLeft().retriesLeft;
    }

    plugin::PINResult changePIN(smartcard::PCSCConnection& conn, const std::string& oldPin,
                                const std::string& newPin) const override
    {
        healthcard::HealthCard card(conn);
        auto r = card.changePIN(oldPin, newPin);
        return {r.success, r.retriesLeft, r.blocked};
    }
};

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<HealthCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
