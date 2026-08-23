// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief A synthetic eMRTD chip for Chip Authentication tests: an EC key pair,
///        the DG14/DG15 DER that advertises it, and channels that speak the
///        card side of the CA / AA protocols. Everything is built from the
///        spec, never from card bytes, so the tests carry no personal data.
///
/// The honest fake in @ref EcdhCaCardChannel actually runs card-side ECDH
/// against the terminal's ephemeral key and derives the same session keys, so
/// a real plain→CA→SM upgrade can be driven and a wrong-key clone is caught on
/// the wire rather than by a hand-set flag.

#include "apdu.h"
#include "chip_auth_card_oracle.h"
#include "crypto_utils.h"

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

namespace LibreSCRS::Test {

// --- BER-TLV helpers -------------------------------------------------------

inline void appendBer(std::vector<std::uint8_t>& out, std::size_t len)
{
    if (len < 0x80) {
        out.push_back(static_cast<std::uint8_t>(len));
    } else if (len <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(len));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<std::uint8_t>(len >> 8));
        out.push_back(static_cast<std::uint8_t>(len & 0xFF));
    }
}

inline std::vector<std::uint8_t> tlv(std::uint8_t tag, const std::vector<std::uint8_t>& value)
{
    std::vector<std::uint8_t> out;
    out.push_back(tag);
    appendBer(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

// --- EC card key -----------------------------------------------------------

struct EcDeleter
{
    void operator()(EVP_PKEY* p) const noexcept
    {
        EVP_PKEY_free(p);
    }
};
using EcKeyPtr = std::unique_ptr<EVP_PKEY, EcDeleter>;

/// A P-256 chip key: the private key stays on the "card" (this object), the
/// SubjectPublicKeyInfo DER goes into DG14/DG15.
struct EcCardKey
{
    EcKeyPtr pkey;
    std::vector<std::uint8_t> spkiDer;           // SubjectPublicKeyInfo
    std::vector<std::uint8_t> pointUncompressed; // 0x04 || X || Y

    static EcCardKey generate()
    {
        EcCardKey out;
        EVP_PKEY* raw = EVP_EC_gen("P-256");
        if (raw == nullptr) {
            throw std::runtime_error("EVP_EC_gen failed");
        }
        out.pkey.reset(raw);

        unsigned char* der = nullptr;
        const int len = i2d_PUBKEY(raw, &der);
        if (len <= 0) {
            throw std::runtime_error("i2d_PUBKEY failed");
        }
        out.spkiDer.assign(der, der + len);
        OPENSSL_free(der);

        std::size_t plen = 0;
        if (EVP_PKEY_get_octet_string_param(raw, "pub", nullptr, 0, &plen) != 1) {
            throw std::runtime_error("pub size query failed");
        }
        out.pointUncompressed.resize(plen);
        if (EVP_PKEY_get_octet_string_param(raw, "pub", out.pointUncompressed.data(), plen, &plen) != 1) {
            throw std::runtime_error("pub read failed");
        }
        out.pointUncompressed.resize(plen);
        return out;
    }
};

// OID content bytes (after tag+len).
// id-CA-ECDH-AES-CBC-CMAC-128 = 0.4.0.127.0.7.2.2.3.2.2
inline std::vector<std::uint8_t> oidCaEcdhAes128()
{
    return {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x02};
}
// id-PK-ECDH = 0.4.0.127.0.7.2.2.1.2
inline std::vector<std::uint8_t> oidPkEcdh()
{
    return {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01, 0x02};
}

/// DG14 (tag 0x6E) advertising one ChipAuthenticationInfo (AES-128) and one
/// ChipAuthenticationPublicKeyInfo carrying @p spki. No keyId in either, so
/// performChipAuth pairs them by the "both absent" rule.
inline std::vector<std::uint8_t> buildDg14(const std::vector<std::uint8_t>& spki)
{
    // ChipAuthenticationInfo: SEQ { OID(id-CA-ECDH-AES-128), INTEGER version=1 }
    std::vector<std::uint8_t> caInfo;
    {
        auto oid = tlv(0x06, oidCaEcdhAes128());
        std::vector<std::uint8_t> version = {0x02, 0x01, 0x01};
        std::vector<std::uint8_t> seqBody = oid;
        seqBody.insert(seqBody.end(), version.begin(), version.end());
        caInfo = tlv(0x30, seqBody);
    }
    // ChipAuthenticationPublicKeyInfo: SEQ { OID(id-PK-ECDH), SubjectPublicKeyInfo }
    std::vector<std::uint8_t> pkInfo;
    {
        auto oid = tlv(0x06, oidPkEcdh());
        std::vector<std::uint8_t> seqBody = oid;
        seqBody.insert(seqBody.end(), spki.begin(), spki.end()); // spki is already a SEQUENCE (0x30..)
        pkInfo = tlv(0x30, seqBody);
    }
    std::vector<std::uint8_t> setBody = caInfo;
    setBody.insert(setBody.end(), pkInfo.begin(), pkInfo.end());
    auto set = tlv(0x31, setBody);
    return tlv(0x6E, set);
}

/// DG15 (tag 0x6F) carrying a SubjectPublicKeyInfo for Active Authentication.
inline std::vector<std::uint8_t> buildDg15(const std::vector<std::uint8_t>& spki)
{
    return tlv(0x6F, spki);
}

// --- Card-side ECDH + SM --------------------------------------------------

/// One physical fake chip presented as an ISecureChannel usable as the
/// @c current channel in performChipAuth / ChipAuthChannel::establish. It
/// answers MSE:Set AT and GENERAL AUTHENTICATE on the plain leg, derives the
/// CA session keys card-side via ECDH, and (once established) hands out an
/// @ref AesSmCardOracle for the SM leg.
class EcdhCaCardChannel final : public LibreSCRS::SecureChannel::ISecureChannel
{
public:
    EcdhCaCardChannel(const EcCardKey& key, LibreSCRS::SmartCard::AppletAid aid)
        : staticKey(key.pkey.get()), currentAid(std::move(aid))
    {}

    // Script a status-word refusal at a given INS (0x22 MSE, 0x86 GA); when set
    // the channel returns that SW instead of processing the command.
    void refuseIns(std::uint8_t ins, std::uint8_t sw1, std::uint8_t sw2)
    {
        refusedIns = ins;
        refusedSw1 = sw1;
        refusedSw2 = sw2;
    }

    // After the handshake, corrupt the card's MAC key so the terminal's proof
    // exchange fails — the clone signal.
    void makeClone()
    {
        cloned = true;
    }

    // The SM oracle initialised during GENERAL AUTHENTICATE; null before that.
    [[nodiscard]] std::shared_ptr<AesSmCardOracle> smOracle() const noexcept
    {
        return sm;
    }

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override
    {
        return currentAid;
    }
    [[nodiscard]] LibreSCRS::SecureChannel::ChannelState state() const noexcept override
    {
        return LibreSCRS::SecureChannel::ChannelState::Open;
    }

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken /*token*/) override
    {
        if (refusedIns && cmd.ins == *refusedIns) {
            return {{}, refusedSw1, refusedSw2};
        }
        if (cmd.ins == 0x22) { // MSE:Set AT
            return {{}, 0x90, 0x00};
        }
        if (cmd.ins == 0x86) { // GENERAL AUTHENTICATE
            deriveFromGa(cmd.data);
            return {{}, 0x90, 0x00};
        }
        return {{}, 0x6D, 0x00};
    }

    void close() override {}

protected:
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept override
    {
        currentAid = std::move(aid);
    }
    void replaceKeys(LibreSCRS::SecureChannel::SessionKeys /*keys*/) noexcept override {}

private:
    // Parse 7C { 80 <terminal ephemeral point> }, ECDH with the static key,
    // KDF the CA session keys, and stand up the card-side SM oracle.
    void deriveFromGa(const std::vector<std::uint8_t>& gaData)
    {
        namespace det = emrtd::crypto::detail;
        std::vector<std::uint8_t> point = extractPoint(gaData);
        if (point.empty()) {
            return;
        }
        auto z = ecdh(point);
        if (z.empty()) {
            return;
        }
        auto kEnc = det::kdf(z, 1, false, 16);
        auto kMac = det::kdf(z, 2, false, 16);
        if (cloned) {
            kMac[0] ^= 0xFF; // wrong keys: the proof exchange must fail
        }
        sm = std::make_shared<AesSmCardOracle>(kEnc, kMac, std::vector<std::uint8_t>(16, 0x00));
    }

    static std::vector<std::uint8_t> extractPoint(const std::vector<std::uint8_t>& gaData)
    {
        // 7C len 80 len <point>
        if (gaData.size() < 4 || gaData[0] != 0x7C) {
            return {};
        }
        std::size_t pos = 2; // skip 7C + 1-byte len (small frames)
        if (pos + 2 > gaData.size() || gaData[pos] != 0x80) {
            return {};
        }
        const std::size_t len = gaData[pos + 1];
        pos += 2;
        if (pos + len > gaData.size()) {
            return {};
        }
        return {gaData.begin() + static_cast<std::ptrdiff_t>(pos),
                gaData.begin() + static_cast<std::ptrdiff_t>(pos + len)};
    }

    std::vector<std::uint8_t> ecdh(const std::vector<std::uint8_t>& peerPoint)
    {
        // Rebuild the terminal's ephemeral public key on P-256 from its point.
        EVP_PKEY* peerRaw = nullptr;
        OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM_BLD_push_utf8_string(bld, "group", "P-256", 0);
        OSSL_PARAM_BLD_push_octet_string(bld, "pub", peerPoint.data(), peerPoint.size());
        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
        EVP_PKEY_CTX* fromctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        std::vector<std::uint8_t> z;
        if (fromctx != nullptr && params != nullptr && EVP_PKEY_fromdata_init(fromctx) == 1 &&
            EVP_PKEY_fromdata(fromctx, &peerRaw, EVP_PKEY_PUBLIC_KEY, params) == 1 && peerRaw != nullptr) {
            EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(staticKey, nullptr);
            std::size_t zlen = 0;
            if (dctx != nullptr && EVP_PKEY_derive_init(dctx) == 1 && EVP_PKEY_derive_set_peer(dctx, peerRaw) == 1 &&
                EVP_PKEY_derive(dctx, nullptr, &zlen) == 1) {
                z.resize(zlen);
                if (EVP_PKEY_derive(dctx, z.data(), &zlen) == 1) {
                    z.resize(zlen);
                } else {
                    z.clear();
                }
            }
            EVP_PKEY_CTX_free(dctx);
        }
        EVP_PKEY_free(peerRaw);
        EVP_PKEY_CTX_free(fromctx);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        return z;
    }

    EVP_PKEY* staticKey; // borrowed from the EcCardKey (must outlive this)
    LibreSCRS::SmartCard::AppletAid currentAid;
    std::optional<std::uint8_t> refusedIns;
    std::uint8_t refusedSw1 = 0x69;
    std::uint8_t refusedSw2 = 0x82;
    bool cloned = false;
    std::shared_ptr<AesSmCardOracle> sm;
};

} // namespace LibreSCRS::Test
