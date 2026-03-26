// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <emrtd/crypto/types.h>

#include <openssl/crypto.h>

#include <optional>
#include <vector>

namespace emrtd::crypto {

struct UnprotectResult
{
    std::vector<uint8_t> data;
    uint8_t sw1 = 0;
    uint8_t sw2 = 0;
};

class SecureMessaging
{
public:
    SecureMessaging(SessionKeys keys, SMAlgorithm algo);
    ~SecureMessaging()
    {
        auto cleanse = [](std::vector<uint8_t>& v) {
            if (!v.empty())
                OPENSSL_cleanse(v.data(), v.size());
        };
        cleanse(keys.encKey);
        cleanse(keys.macKey);
        cleanse(keys.ssc);
    }

    // Wrap command APDU with SM (encrypt data + compute MAC).
    // Input: plain command APDU (CLA INS P1 P2 [Lc data] [Le])
    // Output: SM-protected APDU with DO'87 (encrypted data), DO'97 (Le), DO'8E (MAC)
    std::vector<uint8_t> protect(const std::vector<uint8_t>& commandApdu);

    // Unwrap response APDU: verify MAC (DO'8E), decrypt data (DO'87).
    // Returns decrypted response data, or nullopt if MAC verification fails.
    // Input includes SW1 SW2 at the end.
    std::optional<std::vector<uint8_t>> unprotect(const std::vector<uint8_t>& responseApdu);

    // Like unprotect(), but returns the inner SW from DO'99 along with decrypted data.
    // Needed by transmitSecureAPDU to forward real status words (e.g. 6282 end-of-file).
    std::optional<UnprotectResult> unprotectWithSW(const std::vector<uint8_t>& responseApdu);

private:
    SessionKeys keys;
    SMAlgorithm algo;

    std::vector<uint8_t> computeMAC(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> computeAESIV() const;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data) const;
    size_t blockSize() const;
};

} // namespace emrtd::crypto
