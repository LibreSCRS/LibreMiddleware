// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <emrtd/crypto/bac.h>
#include "crypto_utils.h"

#include <smartcard/apdu.h>
#include <smartcard/pcsc_connection.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <stdexcept>

namespace emrtd::crypto {

BACKeys deriveBACKeys(const std::string& documentNumber, const std::string& dateOfBirth,
                      const std::string& dateOfExpiry)
{
    // Pad document number to 9 characters with '<'
    std::string paddedDocNo = documentNumber;
    while (paddedDocNo.size() < 9)
        paddedDocNo += '<';

    // Build MRZ_information
    std::string mrzInfo = paddedDocNo + std::to_string(detail::computeCheckDigit(paddedDocNo)) + dateOfBirth +
                          std::to_string(detail::computeCheckDigit(dateOfBirth)) + dateOfExpiry +
                          std::to_string(detail::computeCheckDigit(dateOfExpiry));

    // K_seed = SHA-1(MRZ_information)[0:16]
    std::vector<uint8_t> mrzBytes(mrzInfo.begin(), mrzInfo.end());
    uint8_t hash[EVP_MAX_MD_SIZE];
    size_t hashLen = 0;
    if (!EVP_Q_digest(nullptr, "SHA1", nullptr, mrzBytes.data(), mrzBytes.size(), hash, &hashLen))
        throw std::runtime_error("deriveBACKeys: SHA-1 digest failed");
    std::vector<uint8_t> kSeed(hash, hash + 16);

    // Derive K_Enc = KDF(K_seed, 1) and K_MAC = KDF(K_seed, 2)
    BACKeys keys;
    keys.encKey = detail::kdf(kSeed, 1, true);
    keys.macKey = detail::kdf(kSeed, 2, true);
    return keys;
}

std::optional<SessionKeys> performBAC(smartcard::PCSCConnection& conn, const BACKeys& keys)
{
    // Step 1: GET CHALLENGE — receive 8-byte RND.ICC
    smartcard::APDUCommand getChallenge{0x00, 0x84, 0x00, 0x00, {}, 0x08, true};
    auto response = conn.transmit(getChallenge);
    if (!response.isSuccess() || response.data.size() < 8)
        return std::nullopt;
    std::vector<uint8_t> rndICC(response.data.begin(), response.data.begin() + 8);

    // Step 2: Generate RND.IFD (8 bytes) and K.IFD (16 bytes)
    std::vector<uint8_t> rndIFD(8);
    std::vector<uint8_t> kIFD(16);
    if (RAND_bytes(rndIFD.data(), 8) != 1 || RAND_bytes(kIFD.data(), 16) != 1)
        return std::nullopt;

    // Step 3: Build S = RND.IFD || RND.ICC || K.IFD (32 bytes)
    std::vector<uint8_t> s;
    s.insert(s.end(), rndIFD.begin(), rndIFD.end());
    s.insert(s.end(), rndICC.begin(), rndICC.end());
    s.insert(s.end(), kIFD.begin(), kIFD.end());

    // Step 4: Encrypt S (already 32 bytes = block-aligned, NO padding before encryption)
    // Then MAC the encrypted result (WITH padding for MAC input)
    auto eIFD = detail::des3Encrypt(keys.encKey, s);
    auto mIFD = detail::retailMAC(keys.macKey, detail::pad(eIFD, 8));

    // Step 5: MUTUAL AUTHENTICATE — send E.IFD || M.IFD (40 bytes)
    std::vector<uint8_t> cmdData;
    cmdData.insert(cmdData.end(), eIFD.begin(), eIFD.end());
    cmdData.insert(cmdData.end(), mIFD.begin(), mIFD.end());

    smartcard::APDUCommand mutualAuth{0x00, 0x82, 0x00, 0x00, cmdData, 0x28, true};
    response = conn.transmit(mutualAuth);
    if (!response.isSuccess() || response.data.size() < 40)
        return std::nullopt;

    // Step 6: Extract E.ICC (32 bytes) and M.ICC (8 bytes)
    std::vector<uint8_t> eICC(response.data.begin(), response.data.begin() + 32);
    std::vector<uint8_t> mICC(response.data.begin() + 32, response.data.begin() + 40);

    // Step 7: Verify M.ICC
    auto expectedMAC = detail::retailMAC(keys.macKey, detail::pad(eICC, 8));
    if (mICC != expectedMAC)
        return std::nullopt;

    // Step 8: Decrypt E.ICC → R = RND.ICC' || RND.IFD' || K.ICC
    // Data is exactly 32 bytes (block-aligned encryption without padding)
    auto r = detail::des3Decrypt(keys.encKey, eICC);
    if (r.size() < 32)
        return std::nullopt;

    // Verify RND.IFD' matches (bytes 8-15 of decrypted data)
    if (!std::equal(rndIFD.begin(), rndIFD.end(), r.begin() + 8))
        return std::nullopt;

    // Step 9: Extract K.ICC and derive session keys
    std::vector<uint8_t> kICC(r.begin() + 16, r.begin() + 32);

    // K_seed_session = K.IFD XOR K.ICC
    std::vector<uint8_t> kSeedSession(16);
    for (size_t i = 0; i < 16; ++i)
        kSeedSession[i] = kIFD[i] ^ kICC[i];

    SessionKeys session;
    session.encKey = detail::kdf(kSeedSession, 1, true);
    session.macKey = detail::kdf(kSeedSession, 2, true);

    // SSC = last 4 bytes of RND.ICC || last 4 bytes of RND.IFD
    session.ssc.resize(8);
    std::copy(rndICC.begin() + 4, rndICC.end(), session.ssc.begin());
    std::copy(rndIFD.begin() + 4, rndIFD.end(), session.ssc.begin() + 4);

    return session;
}

} // namespace emrtd::crypto
