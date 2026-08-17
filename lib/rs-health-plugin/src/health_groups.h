// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <LibreSCRS/Plugin/CardData.h>

#include <healthtypes.h>

#include <string>
#include <string_view>
#include <utility>

namespace healthcard {

// The rs-health field-group model, built from an already-read document.
//
// Extracted from the plugin's doReadCard so the group shape is unit-testable
// without a card: every addText is guarded, because CardFieldGroup::addText
// REFUSES an empty value when the group has no prior field (documented
// std::logic_error — a reference into an empty vector cannot exist), and a
// real card class walks straight into that corner: an insurant who is their
// OWN insurance carrier has every carrier field empty, so the carrier
// group's first value is empty and the whole read died on the throw
// (Leg-7 bench catch, 2026-08-17). A group with no surviving fields is not
// emitted at all — an empty section is nothing to render.
[[nodiscard]] inline LibreSCRS::Plugin::CardData buildHealthGroups(const HealthDocumentData& doc)
{
    using LibreSCRS::Plugin::CardFieldGroup;

    LibreSCRS::Plugin::CardData data;
    data.cardType = "rs-health";

    const auto addIfPresent = [](CardFieldGroup& group, std::string_view key, std::string_view label,
                                 std::string_view value) {
        if (!value.empty()) {
            group.addText(key, label, value);
        }
    };
    const auto addFlag = [](CardFieldGroup& group, std::string_view key, std::string_view label) {
        group.fields.push_back(
            {std::string{key}, std::string{label}, LibreSCRS::Plugin::FieldType::Text, {'t', 'r', 'u', 'e'}});
    };
    const auto emitIfNonEmpty = [&data](CardFieldGroup&& group) {
        if (!group.fields.empty()) {
            data.groups.push_back(std::move(group));
        }
    };

    {
        CardFieldGroup personal;
        personal.groupKey = "personal";
        personal.groupLabel = "Personal Data";
        addIfPresent(personal, "given_name", "Given Name", doc.givenName);
        addIfPresent(personal, "given_name_latin", "Given Name (Latin)", doc.givenNameLatin);
        addIfPresent(personal, "family_name", "Family Name", doc.familyName);
        addIfPresent(personal, "family_name_latin", "Family Name (Latin)", doc.familyNameLatin);
        addIfPresent(personal, "parent_name", "Parent Name", doc.parentName);
        addIfPresent(personal, "parent_name_latin", "Parent Name (Latin)", doc.parentNameLatin);
        addIfPresent(personal, "date_of_birth", "Date of Birth", doc.dateOfBirth);
        addIfPresent(personal, "gender", "Gender", doc.gender);
        addIfPresent(personal, "personal_number", "JMBG", doc.personalNumber);
        addIfPresent(personal, "insurant_number", "LBO", doc.insurantNumber);
        emitIfNonEmpty(std::move(personal));
    }

    {
        CardFieldGroup insurance;
        insurance.groupKey = "insurance";
        insurance.groupLabel = "Insurance";
        addIfPresent(insurance, "insurer_name", "Insurer", doc.insurerName);
        addIfPresent(insurance, "insurer_id", "Insurer ID", doc.insurerId);
        addIfPresent(insurance, "card_id", "Card ID", doc.cardId);
        addIfPresent(insurance, "date_of_issue", "Date of Issue", doc.dateOfIssue);
        addIfPresent(insurance, "date_of_expiry", "Date of Expiry", doc.dateOfExpiry);
        addIfPresent(insurance, "valid_until", "Valid Until", doc.validUntil);
        if (doc.permanentlyValid) {
            addFlag(insurance, "permanently_valid", "Permanently Valid");
        }
        addIfPresent(insurance, "insurance_basis_rzzo", "Basis", doc.insuranceBasisRzzo);
        addIfPresent(insurance, "insurance_description", "Description", doc.insuranceDescription);
        addIfPresent(insurance, "insurance_start_date", "Start Date", doc.insuranceStartDate);
        emitIfNonEmpty(std::move(insurance));
    }

    {
        CardFieldGroup address;
        address.groupKey = "address";
        address.groupLabel = "Address";
        addIfPresent(address, "street", "Street", doc.street);
        addIfPresent(address, "address_number", "Number", doc.addressNumber);
        addIfPresent(address, "apartment", "Apartment", doc.apartment);
        addIfPresent(address, "place", "Place", doc.place);
        addIfPresent(address, "municipality", "Municipality", doc.municipality);
        addIfPresent(address, "country", "Country", doc.country);
        emitIfNonEmpty(std::move(address));
    }

    {
        CardFieldGroup carrier;
        carrier.groupKey = "carrier";
        carrier.groupLabel = "Carrier";
        if (doc.carrierFamilyMember) {
            addFlag(carrier, "carrier_family_member", "Family Member");
        }
        addIfPresent(carrier, "carrier_given_name", "Given Name", doc.carrierGivenName);
        addIfPresent(carrier, "carrier_family_name", "Family Name", doc.carrierFamilyName);
        addIfPresent(carrier, "carrier_relationship", "Relationship", doc.carrierRelationship);
        addIfPresent(carrier, "carrier_id_number", "ID Number", doc.carrierIdNumber);
        addIfPresent(carrier, "carrier_insurant_number", "LBO", doc.carrierInsurantNumber);
        emitIfNonEmpty(std::move(carrier));
    }

    {
        CardFieldGroup taxpayer;
        taxpayer.groupKey = "taxpayer";
        taxpayer.groupLabel = "Taxpayer";
        addIfPresent(taxpayer, "taxpayer_name", "Name", doc.taxpayerName);
        addIfPresent(taxpayer, "taxpayer_id_number", "ID Number", doc.taxpayerIdNumber);
        addIfPresent(taxpayer, "taxpayer_residence", "Residence", doc.taxpayerResidence);
        addIfPresent(taxpayer, "taxpayer_activity_code", "Activity Code", doc.taxpayerActivityCode);
        emitIfNonEmpty(std::move(taxpayer));
    }

    return data;
}

} // namespace healthcard
