// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef VEHICLECARD_VEHICLECARD_H
#define VEHICLECARD_VEHICLECARD_H

#include <memory>
#include <string>
#include <vector>
#include "vehicletypes.h"

namespace smartcard {
class PCSCConnection;
}

namespace vehiclecard {

class VehicleCard {
public:
    // Check if a vehicle card is present on the given reader without opening a full session.
    static bool probe(const std::string& readerName);

    explicit VehicleCard(const std::string& readerName);
    ~VehicleCard();

    VehicleCard(const VehicleCard&) = delete;
    VehicleCard& operator=(const VehicleCard&) = delete;

    VehicleDocumentData readDocumentData();

private:
    std::unique_ptr<smartcard::PCSCConnection> connection;

    bool initCard();
    std::vector<uint8_t> readFile(const std::vector<uint8_t>& fileId);
};

} // namespace vehiclecard

#endif // VEHICLECARD_VEHICLECARD_H
