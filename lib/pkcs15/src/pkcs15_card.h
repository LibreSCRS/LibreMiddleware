// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "pkcs15_types.h"

#include <LibreSCRS/Plugin/CredentialCounters.h>
#include <smartcard/secure_buffer.h>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
}

namespace pkcs15 {

class PKCS15Card
{
public:
    explicit PKCS15Card(LibreSCRS::SecureChannel::ISecureChannel& channel);

    bool probe();        // Try AID SELECT, then EF.DIR fallback
    bool selectApplet(); // Re-select using the method that worked in probe()

    // CardMap interop: read / seed the discovered state so it survives
    // across PKCS15Card instances against the same physical card.
    // `path` empty == "AID-only SELECT worked"; `selectP2` is the
    // probed SELECT FILE P2 value (0x0C with FCI, 0x00 without).
    [[nodiscard]] const std::vector<uint8_t>& pkcs15PathView() const noexcept
    {
        return pkcs15Path;
    }
    [[nodiscard]] uint8_t fileSelectP2View() const noexcept
    {
        return fileSelectP2;
    }
    void seedDiscoveredState(std::vector<uint8_t> path, uint8_t selectP2) noexcept
    {
        pkcs15Path = std::move(path);
        fileSelectP2 = selectP2;
    }
    PKCS15Profile readProfile();
    TokenInfo readTokenInfo(); // Lightweight: reads only EF(TokenInfo), no certs/keys/PINs
    std::vector<uint8_t> readCertificate(const CertificateInfo& cert);
    PinResult verifyPIN(const PinInfo& pin, std::string_view pinValue);
    PinResult changePIN(const PinInfo& pin, std::string_view oldPin, std::string_view newPin);
    int getPINTriesLeft(const PinInfo& pin);
    // Read the credential's full DOCP counters. Non-9000 / parse miss ⇒ all
    // absent (graceful). Read-only; never decrements a counter.
    LibreSCRS::Plugin::CredentialCounters readCounters(const PinInfo& pin);
    std::vector<uint8_t> sign(const PrivateKeyInfo& key, std::string_view pin, const PinInfo& pinInfo,
                              const std::vector<uint8_t>& digestInfo, const std::vector<uint8_t>& rawData,
                              SignScheme scheme);

private:
    struct KeyRefInfo
    {
        uint8_t keyTag;
        std::vector<uint8_t> keyRefData;
    };
    static KeyRefInfo resolveKeyRef(const PrivateKeyInfo& key);
    std::vector<uint8_t> tryMsePso(uint8_t sigAlgo, const KeyRefInfo& keyRef, const std::vector<uint8_t>& psoData,
                                   uint16_t expectedSigLen, uint16_t& lastSW);
    /// @brief MSE:Set CT with an OID-style algorithm reference (DO 80 with a
    ///        full BSI TR-03110 / ISO 7816-8 OID instead of the legacy 1-byte
    ///        algo). Required by certain IAS-ECC hash-on-card SSCDs (e.g.
    ///        SCE 8.0-C2V0) and other BSI-aligned QSCD cards which reject
    ///        the single-byte form.
    std::vector<uint8_t> tryMsePsoOid(std::span<const uint8_t> algoOid, const KeyRefInfo& keyRef,
                                      const std::vector<uint8_t>& psoData, uint16_t expectedSigLen, uint16_t& lastSW);
    static LibreSCRS::SmartCard::Internal::SecureBuffer encodePIN(std::string_view pin, const PinInfo& pinInfo);
    // Returns: 1=success, 0=wrong PIN (0x63Cx), -1=other failure
    int verifyPinInline(const PinInfo& pinInfo, const LibreSCRS::SmartCard::Internal::SecureBuffer& pinData);
    static std::vector<uint8_t> extractRawHash(const std::vector<uint8_t>& digestInfo);
    bool selectByPath(std::span<const uint8_t> path, uint8_t selectP2 = 0x00);
    std::vector<uint8_t> readSelectedFile();
    bool probeViaEfDir(); // EF.DIR fallback: read MF/2F00, find PKCS#15 path

    LibreSCRS::SecureChannel::ISecureChannel& channel;
    std::vector<uint8_t> pkcs15Path; // Path discovered from EF.DIR (empty = use AID)
    uint8_t fileSelectP2 = 0x00;     // Discovered during probe/first selectByPath
};

} // namespace pkcs15
