// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>
#include <eu-vrc/eu_vrc_card.h>
#include <eu-vrc/eu_vrc_types.h>

#include <format>
#include <unordered_map>

namespace {

class EuVrcCardPlugin : public plugin::CardPlugin
{
public:
    std::string pluginId() const override
    {
        return "eu-vrc";
    }
    std::string displayName() const override
    {
        return "Vehicle Registration (EU VRC)";
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
        return euvrc::EuVrcCard::probe(conn);
    }

    plugin::CardData readCard(smartcard::PCSCConnection& conn) const override
    {
        return readCardStreaming(conn, nullptr);
    }

    plugin::CardData readCardStreaming(smartcard::PCSCConnection& conn, GroupCallback onGroup) const override
    {
        euvrc::EuVrcCard card(conn);
        auto doc = card.readCard();

        plugin::CardData data;
        data.cardType = "eu-vrc";

        auto emitGroup = [&](plugin::CardFieldGroup&& group) {
            if (onGroup)
                onGroup(data.cardType, group);
            data.groups.push_back(std::move(group));
        };

        // Registration
        {
            plugin::CardFieldGroup reg;
            reg.groupKey = "registration";
            reg.groupLabel = "Registration";

            plugin::addTextField(reg, "registration_number", "A: Registration Number", doc.registrationNumber);
            plugin::addTextField(reg, "date_of_first_registration", "B: First Registration", doc.firstRegistration);
            plugin::addTextField(reg, "registration_date", "I: Registration Date", doc.registrationDate);
            plugin::addTextField(reg, "expiry_date", "H: Expiry Date", doc.expiryDate);
            plugin::addTextField(reg, "member_state", "Member State", doc.memberState);
            plugin::addTextField(reg, "competent_authority", "Competent Authority", doc.competentAuthority);
            plugin::addTextField(reg, "issuing_authority", "Issuing Authority", doc.issuingAuthority);
            plugin::addTextField(reg, "document_number", "Document Number", doc.documentNumber);
            plugin::addTextField(reg, "type_approval_number", "K: Type Approval", doc.typeApproval);
            plugin::addTextField(reg, "ownership_status", "C.4: Ownership Status", doc.ownershipStatus);
            plugin::addTextField(reg, "previous_document", "Previous Document", doc.previousDocument);
            emitGroup(std::move(reg));
        }

        // Vehicle
        {
            plugin::CardFieldGroup veh;
            veh.groupKey = "vehicle";
            veh.groupLabel = "Vehicle";

            plugin::addTextField(veh, "vehicle_make", "D.1: Make", doc.vehicleMake);
            plugin::addTextField(veh, "vehicle_type", "D.2: Type", doc.vehicleType);
            plugin::addTextField(veh, "commercial_description", "D.3: Description", doc.commercialDesc);
            plugin::addTextField(veh, "vehicle_id_number", "E: VIN", doc.vin);
            plugin::addTextField(veh, "vehicle_category", "J: Category", doc.vehicleCategory);
            plugin::addTextField(veh, "colour", "R: Colour", doc.colour);
            plugin::addTextField(veh, "engine_capacity", "P.1: Engine Capacity", doc.engineCapacity);
            plugin::addTextField(veh, "maximum_net_power", "P.2: Max Power", doc.maxNetPower);
            plugin::addTextField(veh, "type_of_fuel", "P.3: Fuel", doc.fuelType);
            plugin::addTextField(veh, "engine_id_number", "P.5: Engine ID", doc.engineIdNumber);
            plugin::addTextField(veh, "vehicle_mass", "G: Mass", doc.vehicleMass);
            plugin::addTextField(veh, "maximum_permissible_laden_mass", "F.1: Max Laden Mass", doc.maxLadenMass);
            plugin::addTextField(veh, "power_weight_ratio", "Q: Power/Weight", doc.powerWeightRatio);
            plugin::addTextField(veh, "number_of_seats", "S.1: Seats", doc.numberOfSeats);
            plugin::addTextField(veh, "number_of_standing_places", "S.2: Standing Places", doc.standingPlaces);
            plugin::addTextField(veh, "number_of_axles", "L: Axles", doc.numberOfAxles);
            plugin::addTextField(veh, "max_speed", "T: Max Speed", doc.maxSpeed);
            plugin::addTextField(veh, "wheelbase", "M: Wheelbase", doc.wheelbase);
            plugin::addTextField(veh, "max_laden_mass_service", "F.2: Max Laden Mass (Service)",
                                 doc.maxLadenMassService);
            plugin::addTextField(veh, "max_laden_mass_whole", "F.3: Max Laden Mass (Whole)", doc.maxLadenMassWhole);
            plugin::addTextField(veh, "braked_trailer_mass", "O.1: Braked Trailer Mass", doc.brakedTrailerMass);
            plugin::addTextField(veh, "unbraked_trailer_mass", "O.2: Unbraked Trailer Mass", doc.unbrakedTrailerMass);
            plugin::addTextField(veh, "rated_engine_speed", "P.4: Rated Engine Speed", doc.ratedEngineSpeed);
            plugin::addTextField(veh, "stationary_sound_level", "U.1: Stationary Sound Level",
                                 doc.stationarySoundLevel);
            plugin::addTextField(veh, "engine_speed_ref", "U.2: Engine Speed (Sound)", doc.engineSpeedRef);
            plugin::addTextField(veh, "drive_by_sound", "U.3: Drive-By Sound", doc.driveBySound);
            plugin::addTextField(veh, "fuel_consumption", "V.7: Fuel Consumption", doc.fuelConsumption);
            plugin::addTextField(veh, "co2_emissions", "V.7: CO2 Emissions", doc.co2);
            plugin::addTextField(veh, "environmental_category", "V.9: Environmental Category", doc.envCategory);
            plugin::addTextField(veh, "fuel_tank_capacity", "W: Fuel Tank Capacity", doc.fuelTankCapacity);
            emitGroup(std::move(veh));
        }

        // Holder
        {
            plugin::CardFieldGroup holder;
            holder.groupKey = "holder";
            holder.groupLabel = "Holder";

            plugin::addTextField(holder, "holder_name", "C.1.1: Name", doc.holderName);
            plugin::addTextField(holder, "holder_other_names", "C.1.2: Other Names", doc.holderOtherNames);
            plugin::addTextField(holder, "holder_address", "C.1.3: Address", doc.holderAddress);
            emitGroup(std::move(holder));
        }

        // Owner (only if non-empty)
        if (!doc.owner2Name.empty()) {
            plugin::CardFieldGroup owner;
            owner.groupKey = "owner";
            owner.groupLabel = "Owner";

            plugin::addTextField(owner, "owner2_name", "C.2: Owner Name", doc.owner2Name);
            emitGroup(std::move(owner));
        }

        // User (only if non-empty)
        if (!doc.userName.empty() || !doc.userOtherNames.empty() || !doc.userAddress.empty()) {
            plugin::CardFieldGroup user;
            user.groupKey = "user";
            user.groupLabel = "User";

            plugin::addTextField(user, "user_name", "C.3: Name", doc.userName);
            plugin::addTextField(user, "user_other_names", "C.3: Other Names", doc.userOtherNames);
            plugin::addTextField(user, "user_address", "C.3: Address", doc.userAddress);
            emitGroup(std::move(user));
        }

        // National Extensions (only if non-empty)
        if (!doc.nationalTags.empty()) {
            // Known Serbian national extension tag names
            static const std::unordered_map<uint32_t, std::pair<std::string, std::string>> serbianTags = {
                {0xC2, {"owners_personal_no", "Owner Personal Number"}},
                {0xC3, {"users_personal_no", "User Personal Number"}},
                {0xC4, {"vehicle_load", "Vehicle Load"}},
                {0xC5, {"year_of_production", "Year of Production"}},
                {0xC9, {"serial_number", "Serial Number"}},
            };

            plugin::CardFieldGroup national;
            national.groupKey = "national";
            national.groupLabel = "National Extensions";

            for (const auto& [tag, value] : doc.nationalTags) {
                auto it = serbianTags.find(tag);
                std::string key = (it != serbianTags.end()) ? it->second.first : std::format("national_{:04X}", tag);
                std::string label = (it != serbianTags.end()) ? it->second.second : std::format("Tag 0x{:02X}", tag);
                plugin::addTextField(national, key, label, value);
            }
            emitGroup(std::move(national));
        }

        return data;
    }
};

} // namespace

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<EuVrcCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
