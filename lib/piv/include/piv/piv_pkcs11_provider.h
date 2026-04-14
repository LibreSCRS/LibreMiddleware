// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "smartcard/pkcs11_card_provider.h"
#include "smartcard/pcsc_connection.h"
#include "smartcard/secure_buffer.h"

#include <map>
#include <memory>

namespace piv {

class PIVCard;

class PivPKCS11Provider : public smartcard::PKCS11CardProvider
{
public:
    PivPKCS11Provider();
    ~PivPKCS11Provider() override;
    PivPKCS11Provider(PivPKCS11Provider&&) noexcept;
    PivPKCS11Provider& operator=(PivPKCS11Provider&&) noexcept;

    std::shared_ptr<smartcard::PKCS11CardProvider> createInstance() const override;
    bool probe(const std::string& readerName) override;
    void connect(const std::string& readerName) override;
    smartcard::PKCS11TokenInfo getTokenInfo() override;
    std::vector<smartcard::PKCS11ObjectInfo> getObjects() override;
    unsigned long login(unsigned long userType, const std::vector<uint8_t>& pin) override;
    unsigned long logout() override;
    std::vector<uint8_t> signData(const std::vector<uint8_t>& keyId, const std::vector<uint8_t>& data) override;
    bool supportsPSS() const override
    {
        return false;
    }
    void reconnectCard() override;

private:
    std::unique_ptr<smartcard::PCSCConnection> connection;
    std::unique_ptr<PIVCard> card;
    struct KeyInfo
    {
        uint8_t keyRef;
        size_t keySizeBytes;
        uint8_t algId;
    };
    std::map<std::vector<uint8_t>, KeyInfo> keyInfoMap; // CKA_ID -> PIV key info
    smartcard::SecureBuffer cachedPin;
};

} // namespace piv
