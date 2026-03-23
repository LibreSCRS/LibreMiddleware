// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "smartcard/pkcs11_card_provider.h"
#include "smartcard/pcsc_connection.h"

#include <map>
#include <memory>

namespace cardedge {

// Generic PKCS#11 provider for all Serbian CardEdge cards (eID, health, PKS).
// Matches the OpenSC srbeid driver behavior: single provider, unified token info.
class CardEdgePKCS11Provider : public smartcard::PKCS11CardProvider
{
public:
    CardEdgePKCS11Provider() = default;
    ~CardEdgePKCS11Provider() override;

    std::shared_ptr<smartcard::PKCS11CardProvider> createInstance() const override;
    bool probe(const std::string& readerName) override;
    void connect(const std::string& readerName) override;
    smartcard::PKCS11TokenInfo getTokenInfo() override;
    std::vector<smartcard::PKCS11ObjectInfo> getObjects() override;
    unsigned long login(unsigned long userType, const std::vector<uint8_t>& pin) override;
    unsigned long logout() override;
    std::vector<uint8_t> signData(const std::vector<uint8_t>& keyId, const std::vector<uint8_t>& data) override;
    void reconnectCard() override;

private:
    std::unique_ptr<smartcard::PCSCConnection> connection;
    std::map<std::vector<uint8_t>, uint16_t> keyReferenceMap; // CKA_ID -> key FID
};

} // namespace cardedge
