// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>
#include <vehiclecard/vehiclecard.h>
#include <vehiclecard/vehicletypes.h>

namespace {

void addText(plugin::CardFieldGroup& group, const std::string& key, const std::string& label, const std::string& val)
{
    if (!val.empty()) {
        group.fields.push_back({key, label, plugin::FieldType::Text, {val.begin(), val.end()}});
    }
}

} // namespace

class VehicleCardPlugin : public plugin::CardPlugin
{
public:
    std::string pluginId() const override
    {
        return "vehicle";
    }
    std::string displayName() const override
    {
        return "Vehicle Registration";
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
        return vehiclecard::VehicleCard::probe(conn);
    }

    plugin::CardData readCard(smartcard::PCSCConnection& conn) const override
    {
        return readCardStreaming(conn, nullptr);
    }

    plugin::CardData readCardStreaming(smartcard::PCSCConnection& conn, GroupCallback onGroup) const override
    {
        vehiclecard::VehicleCard card(conn);
        auto doc = card.readDocumentData();

        plugin::CardData data;
        data.cardType = "vehicle";

        auto emitGroup = [&](plugin::CardFieldGroup&& group) {
            if (onGroup)
                onGroup(data.cardType, group);
            data.groups.push_back(std::move(group));
        };

        // Vehicle
        {
            plugin::CardFieldGroup veh;
            veh.groupKey = "vehicle";
            veh.groupLabel = "Vehicle";

            addText(veh, "registration_number", "Registration Number", doc.registrationNumber);
            addText(veh, "date_of_first_registration", "First Registration", doc.dateOfFirstRegistration);
            addText(veh, "vehicle_id_number", "VIN", doc.vehicleIdNumber);
            addText(veh, "vehicle_make", "Make", doc.vehicleMake);
            addText(veh, "vehicle_type", "Type", doc.vehicleType);
            addText(veh, "commercial_description", "Model", doc.commercialDescription);
            addText(veh, "vehicle_category", "Category", doc.vehicleCategory);
            addText(veh, "colour_of_vehicle", "Colour", doc.colourOfVehicle);
            addText(veh, "year_of_production", "Year", doc.yearOfProduction);
            addText(veh, "engine_id_number", "Engine ID", doc.engineIdNumber);
            addText(veh, "engine_capacity", "Engine Capacity", doc.engineCapacity);
            addText(veh, "maximum_net_power", "Max Power", doc.maximumNetPower);
            addText(veh, "type_of_fuel", "Fuel", doc.typeOfFuel);
            addText(veh, "vehicle_mass", "Mass", doc.vehicleMass);
            addText(veh, "maximum_permissible_laden_mass", "Max Laden Mass", doc.maximumPermissibleLadenMass);
            addText(veh, "vehicle_load", "Load", doc.vehicleLoad);
            addText(veh, "power_weight_ratio", "Power/Weight", doc.powerWeightRatio);
            addText(veh, "number_of_axes", "Axles", doc.numberOfAxles);
            addText(veh, "number_of_seats", "Seats", doc.numberOfSeats);
            addText(veh, "number_of_standing_places", "Standing Places", doc.numberOfStandingPlaces);
            addText(veh, "expiry_date", "Expiry Date", doc.expiryDate);
            addText(veh, "issuing_date", "Issuing Date", doc.issuingDate);
            addText(veh, "type_approval_number", "Type Approval", doc.typeApprovalNumber);
            addText(veh, "state_issuing", "State", doc.stateIssuing);
            addText(veh, "competent_authority", "Competent Authority", doc.competentAuthority);
            addText(veh, "authority_issuing", "Issuing Authority", doc.authorityIssuing);
            addText(veh, "unambiguous_number", "Unambiguous Number", doc.unambiguousNumber);
            addText(veh, "serial_number", "Serial Number", doc.serialNumber);
            emitGroup(std::move(veh));
        }

        // Owner
        {
            plugin::CardFieldGroup owner;
            owner.groupKey = "owner";
            owner.groupLabel = "Owner";
            addText(owner, "owners_surname_or_business_name", "Surname/Business", doc.ownersSurnameOrBusinessName);
            addText(owner, "owner_name", "Name", doc.ownerName);
            addText(owner, "owner_address", "Address", doc.ownerAddress);
            addText(owner, "owners_personal_no", "Personal Number", doc.ownersPersonalNo);
            emitGroup(std::move(owner));
        }

        // User
        {
            plugin::CardFieldGroup user;
            user.groupKey = "user";
            user.groupLabel = "User";
            addText(user, "users_surname_or_business_name", "Surname/Business", doc.usersSurnameOrBusinessName);
            addText(user, "users_name", "Name", doc.usersName);
            addText(user, "users_address", "Address", doc.usersAddress);
            addText(user, "users_personal_no", "Personal Number", doc.usersPersonalNo);
            emitGroup(std::move(user));
        }

        return data;
    }
};

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<VehicleCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
