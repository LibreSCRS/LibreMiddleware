// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "smartcard/pkcs11_card_provider.h"
#include "smartcard/pcsc_connection.h"
#include "smartcard/secure_buffer.h"
#include "pkcs15/pkcs15_types.h"

#include <map>
#include <memory>

namespace emrtd::crypto {
class SecureMessaging;
}

namespace pkcs15 {

class PKCS15Card;

// Generic PKCS#11 provider for PKCS#15-compliant cards.
class Pkcs15PKCS11Provider : public smartcard::PKCS11CardProvider
{
public:
    Pkcs15PKCS11Provider();
    ~Pkcs15PKCS11Provider() override;
    Pkcs15PKCS11Provider(Pkcs15PKCS11Provider&&) noexcept;
    Pkcs15PKCS11Provider& operator=(Pkcs15PKCS11Provider&&) noexcept;

    std::shared_ptr<smartcard::PKCS11CardProvider> createInstance() const override;
    bool probe(const std::string& readerName) override;
    void connect(const std::string& readerName) override;
    smartcard::PKCS11TokenInfo getTokenInfo() override;
    std::vector<smartcard::PKCS11ObjectInfo> getObjects() override;
    unsigned long login(unsigned long userType, const std::vector<uint8_t>& pin) override;
    unsigned long logout() override;
    std::vector<uint8_t> signData(const std::vector<uint8_t>& keyId, const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> signMessage(const std::vector<uint8_t>& keyId, const std::vector<uint8_t>& digestInfo,
                                     const std::vector<uint8_t>& rawData, unsigned long mechanismType) override;
    void reconnectCard() override;

private:
    std::unique_ptr<smartcard::PCSCConnection> connection;
    std::unique_ptr<PKCS15Card> card;
    std::map<std::vector<uint8_t>, size_t> keyIndexMap; // CKA_ID -> index into privateKeys
    std::vector<PrivateKeyInfo> privateKeys;
    std::vector<PinInfo> pins;
    smartcard::SecureBuffer cachedPin; // PIN value for sign-time re-verification

    void ensureProfile();
    const PinInfo& findPinForKey(const PrivateKeyInfo& key) const;
    static bool isUserPin(const PinInfo& pin);

    bool paceRequired = false;
    std::vector<uint8_t> cardAccessData;
    std::unique_ptr<emrtd::crypto::SecureMessaging> sm;

    // Per-reader PACE probe results, keyed by reader name.
    // Avoids race when multiple readers are probed on the shared template instance.
    // createInstance() uses lastProbedReader to look up the correct entry.
    struct PaceProbeResult
    {
        bool paceRequired = false;
        std::vector<uint8_t> cardAccessData;
    };
    std::map<std::string, PaceProbeResult> paceProbeResults;
    std::string lastProbedReader;

    bool probeForPace(smartcard::PCSCConnection& conn, PaceProbeResult& result);
    void installSmFilter();
};

} // namespace pkcs15
