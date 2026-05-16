// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "bac.h"
#include "crypto_utils.h"

#include <apdu.h>
#include <smartcard/pcsc_connection.h>

#include <openssl/crypto.h>
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
    OPENSSL_cleanse(hash, sizeof(hash));

    // Derive K_Enc = KDF(K_seed, 1) and K_MAC = KDF(K_seed, 2)
    BACKeys keys;
    keys.encKey = detail::kdf(kSeed, 1, true);
    keys.macKey = detail::kdf(kSeed, 2, true);

    OPENSSL_cleanse(kSeed.data(), kSeed.size());
    OPENSSL_cleanse(mrzBytes.data(), mrzBytes.size());
    return keys;
}

std::optional<SessionKeys> performBAC(LibreSCRS::SmartCard::Internal::PCSCConnection& conn, const BACKeys& keys)
{
    // Scope guard to cleanse all key material on every exit path.
    // Covers BOTH the long-lived randoms/halves and every intermediate
    // buffer that transiently carries K.IFD / K.ICC plaintext or the
    // 3DES ciphertext over them. Recovering K.IFD || K.ICC from freed
    // heap would reproduce kSeedSession (= K.IFD XOR K.ICC) and thereby
    // every session key derived below — so cleanse aggressively.
    std::vector<uint8_t> rndICC, rndIFD, kIFD, kICC, kSeedSession;
    std::vector<uint8_t> s, eIFD, mIFD, cmdData, eICC, mICC, expectedMAC, r;
    struct KeyCleaner
    {
        std::vector<uint8_t>&rndICC, &rndIFD, &kIFD, &kICC, &kSeedSession;
        std::vector<uint8_t>&s, &eIFD, &mIFD, &cmdData, &eICC, &mICC, &expectedMAC, &r;
        ~KeyCleaner()
        {
            auto cleanse = [](std::vector<uint8_t>& v) {
                if (!v.empty())
                    OPENSSL_cleanse(v.data(), v.size());
            };
            cleanse(rndICC);
            cleanse(rndIFD);
            cleanse(kIFD);
            cleanse(kICC);
            cleanse(kSeedSession);
            cleanse(s);
            cleanse(eIFD);
            cleanse(mIFD);
            cleanse(cmdData);
            cleanse(eICC);
            cleanse(mICC);
            cleanse(expectedMAC);
            cleanse(r);
        }
    } keyCleaner{rndICC, rndIFD, kIFD, kICC, kSeedSession, s, eIFD, mIFD, cmdData, eICC, mICC, expectedMAC, r};

    // Step 1: GET CHALLENGE — receive 8-byte RND.ICC
    LibreSCRS::SmartCard::Internal::APDUCommand getChallenge{0x00, 0x84, 0x00, 0x00, {}, 0x08, true};
    auto response = conn.transmit(getChallenge);
    if (!response.isSuccess() || response.data.size() < 8)
        return std::nullopt;
    rndICC.assign(response.data.begin(), response.data.begin() + 8);

    // Step 2: Generate RND.IFD (8 bytes) and K.IFD (16 bytes)
    rndIFD.resize(8);
    kIFD.resize(16);
    if (RAND_bytes(rndIFD.data(), 8) != 1 || RAND_bytes(kIFD.data(), 16) != 1)
        return std::nullopt;

    // Step 3: Build S = RND.IFD || RND.ICC || K.IFD (32 bytes)
    s.insert(s.end(), rndIFD.begin(), rndIFD.end());
    s.insert(s.end(), rndICC.begin(), rndICC.end());
    s.insert(s.end(), kIFD.begin(), kIFD.end());

    // Step 4: Encrypt S (already 32 bytes = block-aligned, NO padding before encryption)
    // Then MAC the encrypted result (WITH padding for MAC input)
    eIFD = detail::des3Encrypt(keys.encKey, s);
    mIFD = detail::retailMAC(keys.macKey, detail::pad(eIFD, 8));

    // Step 5: MUTUAL AUTHENTICATE — send E.IFD || M.IFD (40 bytes)
    cmdData.insert(cmdData.end(), eIFD.begin(), eIFD.end());
    cmdData.insert(cmdData.end(), mIFD.begin(), mIFD.end());

    LibreSCRS::SmartCard::Internal::APDUCommand mutualAuth{0x00, 0x82, 0x00, 0x00, cmdData, 0x28, true};
    response = conn.transmit(mutualAuth);
    if (!response.isSuccess() || response.data.size() < 40)
        return std::nullopt;

    // Step 6: Extract E.ICC (32 bytes) and M.ICC (8 bytes)
    eICC.assign(response.data.begin(), response.data.begin() + 32);
    mICC.assign(response.data.begin() + 32, response.data.begin() + 40);

    // Step 7: Verify M.ICC
    expectedMAC = detail::retailMAC(keys.macKey, detail::pad(eICC, 8));
    if (mICC.size() != expectedMAC.size() || CRYPTO_memcmp(mICC.data(), expectedMAC.data(), mICC.size()) != 0)
        return std::nullopt;

    // Step 8: Decrypt E.ICC → R = RND.ICC' || RND.IFD' || K.ICC
    // Data is exactly 32 bytes (block-aligned encryption without padding)
    r = detail::des3Decrypt(keys.encKey, eICC);
    if (r.size() < 32)
        return std::nullopt;

    // Verify RND.ICC' matches (bytes 0-7) — required by ICAO 9303 for MITM protection
    if (!std::equal(rndICC.begin(), rndICC.end(), r.begin()))
        return std::nullopt;

    // Verify RND.IFD' matches (bytes 8-15 of decrypted data)
    if (!std::equal(rndIFD.begin(), rndIFD.end(), r.begin() + 8))
        return std::nullopt;

    // Step 9: Extract K.ICC and derive session keys
    kICC.assign(r.begin() + 16, r.begin() + 32);

    // K_seed_session = K.IFD XOR K.ICC
    kSeedSession.resize(16);
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
