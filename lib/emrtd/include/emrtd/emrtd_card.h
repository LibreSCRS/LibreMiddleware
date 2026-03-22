// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <emrtd/emrtd_types.h>
#include <emrtd/crypto/secure_messaging.h>
#include <emrtd/crypto/types.h>
#include <smartcard/apdu.h>

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

    /// Transmit an APDU through the active Secure Messaging channel.
    /// Returns decrypted response data, or nullopt on SM/transmit error.
    /// An empty vector means success with no response data (e.g. SELECT with P2=0x0C).
    std::optional<std::vector<uint8_t>> transmitSecure(const std::vector<uint8_t>& apdu);

    /// Transmit an APDUCommand through SM with real inner SW forwarding.
    /// Used by the SM TransmitFilter so that callers (e.g. PKCS#15 readSelectedFile)
    /// can see the real status word (e.g. 6282 end-of-file) from inside the SM envelope.
    smartcard::APDUResponse transmitSecureAPDU(const smartcard::APDUCommand& cmd);

    /// True when Secure Messaging is established (after successful PACE/BAC).
    bool hasSecureMessaging() const { return sm != nullptr; }

private:
    smartcard::PCSCConnection& conn;
    std::variant<MRZData, std::string> credentials;
    std::unique_ptr<crypto::SecureMessaging> sm;
    crypto::SMAlgorithm smAlgo = crypto::SMAlgorithm::DES3;

    bool selectApplet();
    std::vector<uint8_t> readCardAccess();
    std::optional<std::vector<uint8_t>> readFile(uint16_t fid);
    void recover();
    bool recovering = false;
};

} // namespace emrtd
