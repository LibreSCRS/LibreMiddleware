// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>
#include <vehiclecard/vehiclecard.h>
#include <vehiclecard/vehicletypes.h>

namespace {

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

            plugin::addTextField(veh, "registration_number", "Registration Number", doc.registrationNumber);
            plugin::addTextField(veh, "date_of_first_registration", "First Registration", doc.dateOfFirstRegistration);
            plugin::addTextField(veh, "vehicle_id_number", "VIN", doc.vehicleIdNumber);
            plugin::addTextField(veh, "vehicle_make", "Make", doc.vehicleMake);
            plugin::addTextField(veh, "vehicle_type", "Type", doc.vehicleType);
            plugin::addTextField(veh, "commercial_description", "Model", doc.commercialDescription);
            plugin::addTextField(veh, "vehicle_category", "Category", doc.vehicleCategory);
            plugin::addTextField(veh, "colour_of_vehicle", "Colour", doc.colourOfVehicle);
            plugin::addTextField(veh, "year_of_production", "Year", doc.yearOfProduction);
            plugin::addTextField(veh, "engine_id_number", "Engine ID", doc.engineIdNumber);
            plugin::addTextField(veh, "engine_capacity", "Engine Capacity", doc.engineCapacity);
            plugin::addTextField(veh, "maximum_net_power", "Max Power", doc.maximumNetPower);
            plugin::addTextField(veh, "type_of_fuel", "Fuel", doc.typeOfFuel);
            plugin::addTextField(veh, "vehicle_mass", "Mass", doc.vehicleMass);
            plugin::addTextField(veh, "maximum_permissible_laden_mass", "Max Laden Mass", doc.maximumPermissibleLadenMass);
            plugin::addTextField(veh, "vehicle_load", "Load", doc.vehicleLoad);
            plugin::addTextField(veh, "power_weight_ratio", "Power/Weight", doc.powerWeightRatio);
            plugin::addTextField(veh, "number_of_axes", "Axles", doc.numberOfAxles);
            plugin::addTextField(veh, "number_of_seats", "Seats", doc.numberOfSeats);
            plugin::addTextField(veh, "number_of_standing_places", "Standing Places", doc.numberOfStandingPlaces);
            plugin::addTextField(veh, "expiry_date", "Expiry Date", doc.expiryDate);
            plugin::addTextField(veh, "issuing_date", "Issuing Date", doc.issuingDate);
            plugin::addTextField(veh, "type_approval_number", "Type Approval", doc.typeApprovalNumber);
            plugin::addTextField(veh, "state_issuing", "State", doc.stateIssuing);
            plugin::addTextField(veh, "competent_authority", "Competent Authority", doc.competentAuthority);
            plugin::addTextField(veh, "authority_issuing", "Issuing Authority", doc.authorityIssuing);
            plugin::addTextField(veh, "unambiguous_number", "Unambiguous Number", doc.unambiguousNumber);
            plugin::addTextField(veh, "serial_number", "Serial Number", doc.serialNumber);
            emitGroup(std::move(veh));
        }

        // Owner
        {
            plugin::CardFieldGroup owner;
            owner.groupKey = "owner";
            owner.groupLabel = "Owner";
            plugin::addTextField(owner, "owners_surname_or_business_name", "Surname/Business", doc.ownersSurnameOrBusinessName);
            plugin::addTextField(owner, "owner_name", "Name", doc.ownerName);
            plugin::addTextField(owner, "owner_address", "Address", doc.ownerAddress);
            plugin::addTextField(owner, "owners_personal_no", "Personal Number", doc.ownersPersonalNo);
            emitGroup(std::move(owner));
        }

        // User
        {
            plugin::CardFieldGroup user;
            user.groupKey = "user";
            user.groupLabel = "User";
            plugin::addTextField(user, "users_surname_or_business_name", "Surname/Business", doc.usersSurnameOrBusinessName);
            plugin::addTextField(user, "users_name", "Name", doc.usersName);
            plugin::addTextField(user, "users_address", "Address", doc.usersAddress);
            plugin::addTextField(user, "users_personal_no", "Personal Number", doc.usersPersonalNo);
            emitGroup(std::move(user));
        }

        return data;
    }
};

} // namespace

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<VehicleCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
