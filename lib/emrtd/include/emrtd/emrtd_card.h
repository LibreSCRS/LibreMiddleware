// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <emrtd/emrtd_types.h>
#include <emrtd/crypto/secure_messaging.h>
#include <emrtd/crypto/types.h>

#include <map>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

namespace smartcard {
class PCSCConnection;
}

namespace emrtd {

class EMRTDCard
{
public:
    EMRTDCard(smartcard::PCSCConnection& conn, const MRZData& mrz);
    EMRTDCard(smartcard::PCSCConnection& conn, const std::string& can);
    ~EMRTDCard();

    AuthResult authenticate();
    std::vector<int> readCOM();
    std::map<int, std::vector<uint8_t>> readAllDataGroups();
    std::optional<std::vector<uint8_t>> readDataGroup(int dgNumber);
    std::optional<std::vector<uint8_t>> readSOD();

private:
    smartcard::PCSCConnection& conn;
    std::variant<MRZData, std::string> credentials;
    std::unique_ptr<crypto::SecureMessaging> sm;
    crypto::SMAlgorithm smAlgo = crypto::SMAlgorithm::DES3;

    bool selectApplet();
    std::vector<uint8_t> readCardAccess();
    std::optional<std::vector<uint8_t>> readFile(uint16_t fid);
    std::vector<uint8_t> transmitSecure(const std::vector<uint8_t>& apdu);
    void recover();
    bool recovering = false;
};

} // namespace emrtd
