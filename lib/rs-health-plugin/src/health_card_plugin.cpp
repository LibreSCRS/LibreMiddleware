// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <rshealth/healthcard.h>
#include <rshealth/healthtypes.h>
#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>

namespace {

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
        return readCardStreaming(conn, nullptr);
    }

    plugin::CardData readCardStreaming(smartcard::PCSCConnection& conn, GroupCallback onGroup) const override
    {
        healthcard::HealthCard card(conn);
        auto doc = card.readDocumentData();

        plugin::CardData data;
        data.cardType = "rs-health";

        auto emitGroup = [&](plugin::CardFieldGroup&& group) {
            if (onGroup)
                onGroup(data.cardType, group);
            data.groups.push_back(std::move(group));
        };

        {
            plugin::CardFieldGroup personal;
            personal.groupKey = "personal";
            personal.groupLabel = "Personal Data";
            plugin::addTextField(personal, "given_name", "Given Name", doc.givenName);
            plugin::addTextField(personal, "given_name_latin", "Given Name (Latin)", doc.givenNameLatin);
            plugin::addTextField(personal, "family_name", "Family Name", doc.familyName);
            plugin::addTextField(personal, "family_name_latin", "Family Name (Latin)", doc.familyNameLatin);
            plugin::addTextField(personal, "parent_name", "Parent Name", doc.parentName);
            plugin::addTextField(personal, "parent_name_latin", "Parent Name (Latin)", doc.parentNameLatin);
            plugin::addTextField(personal, "date_of_birth", "Date of Birth", doc.dateOfBirth);
            plugin::addTextField(personal, "gender", "Gender", doc.gender);
            plugin::addTextField(personal, "personal_number", "JMBG", doc.personalNumber);
            plugin::addTextField(personal, "insurant_number", "LBO", doc.insurantNumber);
            emitGroup(std::move(personal));
        }

        {
            plugin::CardFieldGroup insurance;
            insurance.groupKey = "insurance";
            insurance.groupLabel = "Insurance";
            plugin::addTextField(insurance, "insurer_name", "Insurer", doc.insurerName);
            plugin::addTextField(insurance, "insurer_id", "Insurer ID", doc.insurerId);
            plugin::addTextField(insurance, "card_id", "Card ID", doc.cardId);
            plugin::addTextField(insurance, "date_of_issue", "Date of Issue", doc.dateOfIssue);
            plugin::addTextField(insurance, "date_of_expiry", "Date of Expiry", doc.dateOfExpiry);
            plugin::addTextField(insurance, "valid_until", "Valid Until", doc.validUntil);
            if (doc.permanentlyValid) {
                insurance.fields.push_back(
                    {"permanently_valid", "Permanently Valid", plugin::FieldType::Text, {'t', 'r', 'u', 'e'}});
            }
            plugin::addTextField(insurance, "insurance_basis_rzzo", "Basis", doc.insuranceBasisRzzo);
            plugin::addTextField(insurance, "insurance_description", "Description", doc.insuranceDescription);
            plugin::addTextField(insurance, "insurance_start_date", "Start Date", doc.insuranceStartDate);
            emitGroup(std::move(insurance));
        }

        {
            plugin::CardFieldGroup address;
            address.groupKey = "address";
            address.groupLabel = "Address";
            plugin::addTextField(address, "street", "Street", doc.street);
            plugin::addTextField(address, "address_number", "Number", doc.addressNumber);
            plugin::addTextField(address, "apartment", "Apartment", doc.apartment);
            plugin::addTextField(address, "place", "Place", doc.place);
            plugin::addTextField(address, "municipality", "Municipality", doc.municipality);
            plugin::addTextField(address, "country", "Country", doc.country);
            emitGroup(std::move(address));
        }

        {
            plugin::CardFieldGroup carrier;
            carrier.groupKey = "carrier";
            carrier.groupLabel = "Carrier";
            if (doc.carrierFamilyMember) {
                carrier.fields.push_back(
                    {"carrier_family_member", "Family Member", plugin::FieldType::Text, {'t', 'r', 'u', 'e'}});
            }
            plugin::addTextField(carrier, "carrier_given_name", "Given Name", doc.carrierGivenName);
            plugin::addTextField(carrier, "carrier_family_name", "Family Name", doc.carrierFamilyName);
            plugin::addTextField(carrier, "carrier_relationship", "Relationship", doc.carrierRelationship);
            plugin::addTextField(carrier, "carrier_id_number", "ID Number", doc.carrierIdNumber);
            plugin::addTextField(carrier, "carrier_insurant_number", "LBO", doc.carrierInsurantNumber);
            emitGroup(std::move(carrier));
        }

        {
            plugin::CardFieldGroup taxpayer;
            taxpayer.groupKey = "taxpayer";
            taxpayer.groupLabel = "Taxpayer";
            plugin::addTextField(taxpayer, "taxpayer_name", "Name", doc.taxpayerName);
            plugin::addTextField(taxpayer, "taxpayer_id_number", "ID Number", doc.taxpayerIdNumber);
            plugin::addTextField(taxpayer, "taxpayer_residence", "Residence", doc.taxpayerResidence);
            plugin::addTextField(taxpayer, "taxpayer_activity_code", "Activity Code", doc.taxpayerActivityCode);
            emitGroup(std::move(taxpayer));
        }

        return data;
    }
};

} // namespace

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<HealthCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
