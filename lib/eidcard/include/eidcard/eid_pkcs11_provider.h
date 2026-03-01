// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef EIDCARD_EID_PKCS11_PROVIDER_H
#define EIDCARD_EID_PKCS11_PROVIDER_H

#include "smartcard/pkcs11_card_provider.h"
#include <map>
#include <memory>

namespace eidcard {

class EIdCard;

class EIdPKCS11Provider : public smartcard::PKCS11CardProvider {
public:
    EIdPKCS11Provider() = default;
    ~EIdPKCS11Provider() override;

    std::shared_ptr<smartcard::PKCS11CardProvider> createInstance() const override;
    bool probe(const std::string& readerName) override;
    void connect(const std::string& readerName) override;
    smartcard::PKCS11TokenInfo getTokenInfo() override;
    std::vector<smartcard::PKCS11ObjectInfo> getObjects() override;
    unsigned long login(unsigned long userType,
                        const std::vector<uint8_t>& pin) override;
    unsigned long logout() override;
    std::vector<uint8_t> signData(const std::vector<uint8_t>& keyId,
                                   const std::vector<uint8_t>& data) override;
    void reconnectCard() override;

private:
    std::unique_ptr<EIdCard> card;
    std::map<std::vector<uint8_t>, uint16_t> keyReferenceMap;  // CKA_ID -> key FID
};

} // namespace eidcard

#endif // EIDCARD_EID_PKCS11_PROVIDER_H
