// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#pragma once

#include <memory>
#include <string>
#include <vector>
#include "vehicletypes.h"

namespace smartcard {
class PCSCConnection;
}

namespace vehiclecard {

class VehicleCard
{
public:
    // Check if a vehicle card is present on the given reader without opening a full session.
    static bool probe(const std::string& readerName);
    static bool probe(smartcard::PCSCConnection& conn);

    explicit VehicleCard(const std::string& readerName);
    explicit VehicleCard(smartcard::PCSCConnection& conn);
    ~VehicleCard();

    VehicleCard(const VehicleCard&) = delete;
    VehicleCard& operator=(const VehicleCard&) = delete;

    VehicleDocumentData readDocumentData();

private:
    std::unique_ptr<smartcard::PCSCConnection> ownedConnection;
    smartcard::PCSCConnection* conn = nullptr;

    bool initCard();
    std::vector<uint8_t> readFile(const std::vector<uint8_t>& fileId);
};

} // namespace vehiclecard
