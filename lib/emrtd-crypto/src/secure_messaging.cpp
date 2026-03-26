// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <emrtd/crypto/secure_messaging.h>
#include "crypto_utils.h"

#include <openssl/crypto.h>
#include <stdexcept>

namespace emrtd::crypto {

// ---------------------------------------------------------------------------
// BER-TLV length encoding helper
// ---------------------------------------------------------------------------
static void appendLength(std::vector<uint8_t>& out, size_t len)
{
    if (len < 128) {
        out.push_back(static_cast<uint8_t>(len));
    } else if (len <= 255) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(len));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
    }
}

// ---------------------------------------------------------------------------
// TLV parser: returns {tag, value} pairs from a byte range
// ---------------------------------------------------------------------------
struct TLVObject
{
    uint8_t tag;
    std::vector<uint8_t> value;
    // Byte range of the entire TLV (tag + length + value) in the original buffer
    size_t startOffset;
    size_t totalLen;
};

static std::vector<TLVObject> parseTLV(const std::vector<uint8_t>& buf, size_t offset, size_t end)
{
    std::vector<TLVObject> result;
    while (offset < end) {
        // Skip padding bytes (0x00)
        if (buf[offset] == 0x00) {
            ++offset;
            continue;
        }
        if (offset >= end)
            break;

        TLVObject obj;
        obj.startOffset = offset;
        obj.tag = buf[offset++];

        if (offset >= end)
            break;

        size_t len = 0;
        if (buf[offset] < 0x80) {
            len = buf[offset++];
        } else if (buf[offset] == 0x81) {
            ++offset;
            if (offset >= end)
                break;
            len = buf[offset++];
        } else if (buf[offset] == 0x82) {
            ++offset;
            if (offset + 1 >= end)
                break;
            len = (static_cast<size_t>(buf[offset]) << 8) | buf[offset + 1];
            offset += 2;
        } else {
            break; // unsupported multi-byte length
        }

        if (offset + len > end)
            break;

        obj.value.assign(buf.begin() + static_cast<ptrdiff_t>(offset),
                         buf.begin() + static_cast<ptrdiff_t>(offset + len));
        obj.totalLen = (offset + len) - obj.startOffset;
        offset += len;
        result.push_back(std::move(obj));
    }
    return result;
}

// ---------------------------------------------------------------------------
// SecureMessaging implementation
// ---------------------------------------------------------------------------

SecureMessaging::SecureMessaging(SessionKeys k, SMAlgorithm a) : keys(std::move(k)), algo(a) {}

size_t SecureMessaging::blockSize() const
{
    return (algo == SMAlgorithm::DES3) ? 8u : 16u;
}

std::vector<uint8_t> SecureMessaging::computeMAC(const std::vector<uint8_t>& data) const
{
    if (algo == SMAlgorithm::DES3)
        return detail::retailMAC(keys.macKey, data);
    else
        return detail::aesCMAC(keys.macKey, data);
}

std::vector<uint8_t> SecureMessaging::computeAESIV() const
{
    // BSI TR-03110 Part 3, Section E.1: IV = E(K_Enc, SSC)
    // AES-ECB encrypt the SSC to derive the IV for AES-CBC encryption/decryption.
    return detail::aesEncrypt(keys.encKey, keys.ssc);
}

std::vector<uint8_t> SecureMessaging::encrypt(const std::vector<uint8_t>& data) const
{
    if (algo == SMAlgorithm::DES3)
        return detail::des3Encrypt(keys.encKey, data);
    else
        return detail::aesEncrypt(keys.encKey, data, computeAESIV());
}

std::vector<uint8_t> SecureMessaging::decrypt(const std::vector<uint8_t>& data) const
{
    if (algo == SMAlgorithm::DES3)
        return detail::des3Decrypt(keys.encKey, data);
    else
        return detail::aesDecrypt(keys.encKey, data, computeAESIV());
}

// ---------------------------------------------------------------------------
// protect — wrap a plain command APDU with SM
// ---------------------------------------------------------------------------
std::vector<uint8_t> SecureMessaging::protect(const std::vector<uint8_t>& commandApdu)
{
    if (commandApdu.size() < 4)
        throw std::invalid_argument("APDU too short");

    detail::incrementSSC(keys.ssc);

    const size_t bs = blockSize();

    uint8_t cla = commandApdu[0];
    uint8_t ins = commandApdu[1];
    uint8_t p1 = commandApdu[2];
    uint8_t p2 = commandApdu[3];

    // Parse Lc, data, Le from the command APDU (ISO 7816-4 short form only)
    std::vector<uint8_t> cmdData;
    std::optional<uint8_t> le;

    if (commandApdu.size() == 4) {
        // Case 1: no data, no Le
    } else if (commandApdu.size() == 5) {
        // Case 2: no data, Le present (Le=0 means 256)
        le = commandApdu[4];
    } else {
        // Case 3 or 4: Lc present
        size_t lc = commandApdu[4];
        if (commandApdu.size() < 5 + lc)
            throw std::invalid_argument("APDU data shorter than Lc");
        cmdData.assign(commandApdu.begin() + 5, commandApdu.begin() + 5 + static_cast<ptrdiff_t>(lc));
        if (commandApdu.size() == 5 + lc + 1) {
            // Case 4: data + Le
            le = commandApdu[5 + lc];
        }
    }

    // Set SM CLA indicator
    uint8_t claProtected = cla | 0x0C;

    // Build padded header for MAC computation
    std::vector<uint8_t> header = {claProtected, ins, p1, p2};
    auto paddedHeader = detail::pad(header, bs);

    // DO'87: encrypted command data (if any)
    std::vector<uint8_t> do87;
    if (!cmdData.empty()) {
        auto paddedData = detail::pad(cmdData, bs);
        auto encryptedData = encrypt(paddedData);

        // DO'87 = tag 0x87 | len | 0x01 | encrypted bytes
        do87.push_back(0x87);
        appendLength(do87, 1 + encryptedData.size());
        do87.push_back(0x01); // padding indicator
        do87.insert(do87.end(), encryptedData.begin(), encryptedData.end());
    }

    // DO'97: Le — only present when the original command expects response data (Case 2/4).
    // ICAO 9303 Part 11 Section 9.8.6: "If the command APDU includes Le: Construct DO'97".
    // Case 1/3 commands (no Le) must NOT include DO'97 — some cards (e.g. Georgian eID)
    // reject it with SW=6700 on MSE:Set AT.
    std::vector<uint8_t> do97;
    if (le.has_value()) {
        do97 = {0x97, 0x01, le.value()};
    }

    // Build MAC input: SSC || padded header || DO'87 || DO'97, then pad to blockSize
    std::vector<uint8_t> macInput;
    macInput.insert(macInput.end(), keys.ssc.begin(), keys.ssc.end());
    macInput.insert(macInput.end(), paddedHeader.begin(), paddedHeader.end());
    macInput.insert(macInput.end(), do87.begin(), do87.end());
    macInput.insert(macInput.end(), do97.begin(), do97.end());
    auto paddedMacInput = detail::pad(macInput, bs);

    auto mac = computeMAC(paddedMacInput);
    mac.resize(8); // truncate to 8 bytes

    // DO'8E: MAC
    std::vector<uint8_t> do8e = {0x8E, 0x08};
    do8e.insert(do8e.end(), mac.begin(), mac.end());

    // Assemble protected APDU body
    std::vector<uint8_t> body;
    body.insert(body.end(), do87.begin(), do87.end());
    body.insert(body.end(), do97.begin(), do97.end());
    body.insert(body.end(), do8e.begin(), do8e.end());

    // Build final APDU: CLA' INS P1 P2 Lc' body 00
    if (body.size() > 255)
        throw std::runtime_error("SM protect: body exceeds short-form APDU Lc limit (255 bytes)");

    std::vector<uint8_t> result;
    result.push_back(claProtected);
    result.push_back(ins);
    result.push_back(p1);
    result.push_back(p2);
    result.push_back(static_cast<uint8_t>(body.size()));
    result.insert(result.end(), body.begin(), body.end());
    result.push_back(0x00); // Le = accept any response length

    return result;
}

// ---------------------------------------------------------------------------
// unprotect — verify MAC and decrypt SM response APDU
// ---------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> SecureMessaging::unprotect(const std::vector<uint8_t>& responseApdu)
{
    if (responseApdu.size() < 2)
        return std::nullopt;

    detail::incrementSSC(keys.ssc);

    const size_t bs = blockSize();

    // SW1 SW2 are the last two bytes
    size_t dataEnd = responseApdu.size() - 2;

    // Parse TLV objects from the response body (before SW1 SW2)
    auto tlvObjects = parseTLV(responseApdu, 0, dataEnd);

    std::vector<uint8_t> do87Value; // encrypted data (with 0x01 prefix stripped later)
    std::vector<uint8_t> do87Raw;   // the full DO'87 TLV bytes for MAC
    std::vector<uint8_t> do99Raw;   // the full DO'99 TLV bytes for MAC
    std::vector<uint8_t> receivedMAC;

    for (const auto& obj : tlvObjects) {
        if (obj.tag == 0x87) {
            do87Value = obj.value;
            // Reconstruct raw TLV bytes from the original buffer
            do87Raw.assign(responseApdu.begin() + static_cast<ptrdiff_t>(obj.startOffset),
                           responseApdu.begin() + static_cast<ptrdiff_t>(obj.startOffset + obj.totalLen));
        } else if (obj.tag == 0x99) {
            do99Raw.assign(responseApdu.begin() + static_cast<ptrdiff_t>(obj.startOffset),
                           responseApdu.begin() + static_cast<ptrdiff_t>(obj.startOffset + obj.totalLen));
        } else if (obj.tag == 0x8E) {
            receivedMAC = obj.value;
        }
    }

    if (receivedMAC.empty())
        return std::nullopt;

    // Verify MAC FIRST (authenticate-then-decrypt per ICAO spec)
    // MAC input: SSC || DO'87 (if any) || DO'99, padded to blockSize
    std::vector<uint8_t> macInput;
    macInput.insert(macInput.end(), keys.ssc.begin(), keys.ssc.end());
    macInput.insert(macInput.end(), do87Raw.begin(), do87Raw.end());
    macInput.insert(macInput.end(), do99Raw.begin(), do99Raw.end());
    auto paddedMacInput = detail::pad(macInput, bs);

    auto expectedMAC = computeMAC(paddedMacInput);
    expectedMAC.resize(8);

    if (receivedMAC.size() < 8 || CRYPTO_memcmp(expectedMAC.data(), receivedMAC.data(), 8) != 0)
        return std::nullopt;

    // Decrypt DO'87 if present
    if (!do87Value.empty()) {
        // Strip the 0x01 padding indicator byte
        if (do87Value[0] != 0x01)
            return std::nullopt;
        std::vector<uint8_t> ciphertext(do87Value.begin() + 1, do87Value.end());
        auto decrypted = decrypt(ciphertext);
        return detail::unpad(decrypted);
    }

    // No encrypted data — check inner SW from DO'99
    // If the card returned an error SW (not 90xx/61xx/62xx/63xx), treat as failure
    if (do99Raw.size() >= 4) {
        uint8_t sw1 = do99Raw[2];
        if (sw1 != 0x90 && sw1 != 0x61 && sw1 != 0x62 && sw1 != 0x63)
            return std::nullopt;
    }

    // Success with no response data (e.g. SELECT with P2=0x0C)
    return std::vector<uint8_t>{};
}

// ---------------------------------------------------------------------------
// unprotectWithSW — like unprotect, but returns the inner SW from DO'99
// ---------------------------------------------------------------------------
std::optional<UnprotectResult> SecureMessaging::unprotectWithSW(const std::vector<uint8_t>& responseApdu)
{
    if (responseApdu.size() < 2)
        return std::nullopt;

    detail::incrementSSC(keys.ssc);

    const size_t bs = blockSize();

    // SW1 SW2 are the last two bytes (outer/transport SW)
    size_t dataEnd = responseApdu.size() - 2;

    // Parse TLV objects from the response body (before SW1 SW2)
    auto tlvObjects = parseTLV(responseApdu, 0, dataEnd);

    std::vector<uint8_t> do87Value;
    std::vector<uint8_t> do87Raw;
    std::vector<uint8_t> do99Raw;
    std::vector<uint8_t> do99Value;
    std::vector<uint8_t> receivedMAC;

    for (const auto& obj : tlvObjects) {
        if (obj.tag == 0x87) {
            do87Value = obj.value;
            do87Raw.assign(responseApdu.begin() + static_cast<ptrdiff_t>(obj.startOffset),
                           responseApdu.begin() + static_cast<ptrdiff_t>(obj.startOffset + obj.totalLen));
        } else if (obj.tag == 0x99) {
            do99Value = obj.value;
            do99Raw.assign(responseApdu.begin() + static_cast<ptrdiff_t>(obj.startOffset),
                           responseApdu.begin() + static_cast<ptrdiff_t>(obj.startOffset + obj.totalLen));
        } else if (obj.tag == 0x8E) {
            receivedMAC = obj.value;
        }
    }

    if (receivedMAC.empty())
        return std::nullopt;

    // Verify MAC FIRST (authenticate-then-decrypt per ICAO spec)
    std::vector<uint8_t> macInput;
    macInput.insert(macInput.end(), keys.ssc.begin(), keys.ssc.end());
    macInput.insert(macInput.end(), do87Raw.begin(), do87Raw.end());
    macInput.insert(macInput.end(), do99Raw.begin(), do99Raw.end());
    auto paddedMacInput = detail::pad(macInput, bs);

    auto expectedMAC = computeMAC(paddedMacInput);
    expectedMAC.resize(8);

    if (receivedMAC.size() < 8 || CRYPTO_memcmp(expectedMAC.data(), receivedMAC.data(), 8) != 0)
        return std::nullopt;

    // Extract inner SW from DO'99
    UnprotectResult result;
    if (do99Value.size() >= 2) {
        result.sw1 = do99Value[0];
        result.sw2 = do99Value[1];
    }

    // Decrypt DO'87 if present
    if (!do87Value.empty()) {
        if (do87Value[0] != 0x01)
            return std::nullopt;
        std::vector<uint8_t> ciphertext(do87Value.begin() + 1, do87Value.end());
        auto decrypted = decrypt(ciphertext);
        auto unpadded = detail::unpad(decrypted);
        result.data = std::move(unpadded);
    }

    return result;
}

} // namespace emrtd::crypto
