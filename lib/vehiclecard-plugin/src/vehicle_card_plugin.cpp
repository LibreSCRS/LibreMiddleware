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
        vehiclecard::VehicleCard card(conn);
        auto doc = card.readDocumentData();

        plugin::CardData data;
        data.cardType = "vehicle";

        plugin::CardFieldGroup reg;
        reg.groupKey = "registration";
        reg.groupLabel = "Registration";
        addText(reg, "registration_number", "Registration Number", doc.registrationNumber);
        addText(reg, "date_of_first_registration", "First Registration", doc.dateOfFirstRegistration);
        addText(reg, "issuing_date", "Issuing Date", doc.issuingDate);
        addText(reg, "expiry_date", "Expiry Date", doc.expiryDate);
        addText(reg, "serial_number", "Serial Number", doc.serialNumber);
        addText(reg, "issuing_authority", "Issuing Authority", doc.authorityIssuing);
        data.groups.push_back(std::move(reg));

        plugin::CardFieldGroup veh;
        veh.groupKey = "vehicle";
        veh.groupLabel = "Vehicle";
        addText(veh, "vehicle_id_number", "VIN", doc.vehicleIdNumber);
        addText(veh, "vehicle_make", "Make", doc.vehicleMake);
        addText(veh, "vehicle_type", "Type", doc.vehicleType);
        addText(veh, "commercial_description", "Model", doc.commercialDescription);
        addText(veh, "vehicle_category", "Category", doc.vehicleCategory);
        addText(veh, "colour", "Colour", doc.colourOfVehicle);
        addText(veh, "year_of_production", "Year", doc.yearOfProduction);
        addText(veh, "engine_capacity", "Engine Capacity", doc.engineCapacity);
        addText(veh, "maximum_net_power", "Max Power", doc.maximumNetPower);
        addText(veh, "type_of_fuel", "Fuel", doc.typeOfFuel);
        addText(veh, "vehicle_mass", "Mass", doc.vehicleMass);
        addText(veh, "number_of_seats", "Seats", doc.numberOfSeats);
        data.groups.push_back(std::move(veh));

        plugin::CardFieldGroup owner;
        owner.groupKey = "owner";
        owner.groupLabel = "Owner";
        addText(owner, "owner_name", "Name", doc.ownerName);
        addText(owner, "owner_surname", "Surname/Business", doc.ownersSurnameOrBusinessName);
        addText(owner, "owner_address", "Address", doc.ownerAddress);
        addText(owner, "owner_personal_no", "Personal Number", doc.ownersPersonalNo);
        addText(owner, "user_name", "User Name", doc.usersName);
        addText(owner, "user_surname", "User Surname/Business", doc.usersSurnameOrBusinessName);
        addText(owner, "user_address", "User Address", doc.usersAddress);
        data.groups.push_back(std::move(owner));

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
