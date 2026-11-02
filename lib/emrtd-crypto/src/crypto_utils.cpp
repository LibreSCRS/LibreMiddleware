// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "crypto_utils.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

namespace emrtd::crypto::detail {

// ---- adjustParity ----

void adjustParity(std::vector<uint8_t>& key)
{
    for (auto& byte : key) {
        // Count set bits in bits 7..1
        int bits = 0;
        for (int i = 1; i < 8; ++i) {
            if (byte & (1 << i))
                ++bits;
        }
        // Set bit 0 so total parity is odd
        if (bits % 2 == 0)
            byte |= 0x01;
        else
            byte &= ~0x01;
    }
}

// ---- kdf ----

std::vector<uint8_t> kdf(const std::vector<uint8_t>& seed, uint32_t counter, bool des3, size_t keyLen)
{
    // Build input: seed || counter (4 bytes big-endian)
    std::vector<uint8_t> input(seed);
    input.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
    input.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
    input.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
    input.push_back(static_cast<uint8_t>(counter & 0xFF));

    // Hash selection uses "matched security level" approach:
    // SHA-1 (20 bytes) for key lengths up to 20 bytes (3DES, AES-128),
    // SHA-256 (32 bytes) for larger keys (AES-192, AES-256).
    const char* algo = (keyLen <= 20) ? "SHA1" : "SHA256";
    unsigned char digest[64] = {};
    size_t digestLen = 0;

    if (!EVP_Q_digest(nullptr, algo, nullptr, input.data(), input.size(), digest, &digestLen)) {
        throw std::runtime_error("kdf: EVP_Q_digest failed");
    }

    if (keyLen > digestLen) {
        throw std::invalid_argument("kdf: requested keyLen exceeds hash output length");
    }

    std::vector<uint8_t> key(digest, digest + keyLen);
    OPENSSL_cleanse(digest, sizeof(digest));

    if (des3) {
        adjustParity(key);
    }

    return key;
}

// ---- computeCheckDigit ----

int computeCheckDigit(const std::string& input)
{
    // ICAO 9303 Part 3 Section 4.9 — weights 7, 3, 1 repeating
    static const int weights[3] = {7, 3, 1};
    int sum = 0;
    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        int val = 0;
        if (c >= '0' && c <= '9') {
            val = c - '0';
        } else if (c >= 'A' && c <= 'Z') {
            val = c - 'A' + 10;
        } else if (c == '<') {
            val = 0;
        } else {
            throw std::invalid_argument("computeCheckDigit: invalid MRZ character");
        }
        sum += val * weights[i % 3];
    }
    return sum % 10;
}

// ---- buildMrzInformation ----

std::string buildMrzInformation(std::string_view documentNumber, std::string_view dateOfBirth,
                                std::string_view dateOfExpiry)
{
    std::string paddedDocNo(documentNumber);
    while (paddedDocNo.size() < 9)
        paddedDocNo += '<';

    std::string dob(dateOfBirth);
    std::string doe(dateOfExpiry);
    return paddedDocNo + std::to_string(computeCheckDigit(paddedDocNo)) + dob + std::to_string(computeCheckDigit(dob)) +
           doe + std::to_string(computeCheckDigit(doe));
}

// ---- pad / unpad ----

std::vector<uint8_t> pad(const std::vector<uint8_t>& data, size_t blockSize)
{
    std::vector<uint8_t> padded(data);
    padded.push_back(0x80);
    while (padded.size() % blockSize != 0) {
        padded.push_back(0x00);
    }
    return padded;
}

std::vector<uint8_t> unpad(const std::vector<uint8_t>& data)
{
    // Scan from end, skip 0x00 bytes, then remove the 0x80 marker
    size_t i = data.size();
    while (i > 0 && data[i - 1] == 0x00) {
        --i;
    }
    if (i == 0 || data[i - 1] != 0x80) {
        throw std::runtime_error("unpad: invalid ISO 9797-1 Method 2 padding");
    }
    return std::vector<uint8_t>(data.begin(), data.begin() + static_cast<ptrdiff_t>(i - 1));
}

// ---- 3DES encrypt/decrypt ----

std::vector<uint8_t> des3Encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data,
                                 const std::vector<uint8_t>& iv)
{
    if (key.size() != 16) {
        throw std::invalid_argument("des3Encrypt: key must be 16 bytes (2-key 3DES)");
    }

    std::vector<uint8_t> ivBuf = iv.empty() ? std::vector<uint8_t>(8, 0x00) : iv;
    if (ivBuf.size() != 8) {
        throw std::invalid_argument("des3Encrypt: IV must be 8 bytes");
    }

    auto ctx =
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw std::runtime_error("des3Encrypt: EVP_CIPHER_CTX_new failed");
    }

    if (!EVP_EncryptInit_ex(ctx.get(), EVP_des_ede_cbc(), nullptr, key.data(), ivBuf.data())) {
        throw std::runtime_error("des3Encrypt: EVP_EncryptInit_ex failed");
    }
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

    std::vector<uint8_t> out(data.size() + 8);
    int outLen1 = 0, outLen2 = 0;

    if (!EVP_EncryptUpdate(ctx.get(), out.data(), &outLen1, data.data(), static_cast<int>(data.size()))) {
        throw std::runtime_error("des3Encrypt: EVP_EncryptUpdate failed");
    }
    if (!EVP_EncryptFinal_ex(ctx.get(), out.data() + outLen1, &outLen2)) {
        throw std::runtime_error("des3Encrypt: EVP_EncryptFinal_ex failed");
    }

    out.resize(static_cast<size_t>(outLen1 + outLen2));
    return out;
}

std::vector<uint8_t> des3Decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data,
                                 const std::vector<uint8_t>& iv)
{
    if (key.size() != 16) {
        throw std::invalid_argument("des3Decrypt: key must be 16 bytes (2-key 3DES)");
    }

    std::vector<uint8_t> ivBuf = iv.empty() ? std::vector<uint8_t>(8, 0x00) : iv;
    if (ivBuf.size() != 8) {
        throw std::invalid_argument("des3Decrypt: IV must be 8 bytes");
    }

    auto ctx =
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw std::runtime_error("des3Decrypt: EVP_CIPHER_CTX_new failed");
    }

    if (!EVP_DecryptInit_ex(ctx.get(), EVP_des_ede_cbc(), nullptr, key.data(), ivBuf.data())) {
        throw std::runtime_error("des3Decrypt: EVP_DecryptInit_ex failed");
    }
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

    std::vector<uint8_t> out(data.size() + 8);
    int outLen1 = 0, outLen2 = 0;

    if (!EVP_DecryptUpdate(ctx.get(), out.data(), &outLen1, data.data(), static_cast<int>(data.size()))) {
        throw std::runtime_error("des3Decrypt: EVP_DecryptUpdate failed");
    }
    if (!EVP_DecryptFinal_ex(ctx.get(), out.data() + outLen1, &outLen2)) {
        throw std::runtime_error("des3Decrypt: EVP_DecryptFinal_ex failed");
    }

    out.resize(static_cast<size_t>(outLen1 + outLen2));
    return out;
}

// ---- AES encrypt/decrypt ----

static const EVP_CIPHER* selectAESCipher(size_t keySize)
{
    switch (keySize) {
    case 16:
        return EVP_aes_128_cbc();
    case 24:
        return EVP_aes_192_cbc();
    case 32:
        return EVP_aes_256_cbc();
    default:
        throw std::invalid_argument("selectAESCipher: key must be 16, 24, or 32 bytes");
    }
}

std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data,
                                const std::vector<uint8_t>& iv)
{
    const EVP_CIPHER* cipher = selectAESCipher(key.size());

    std::vector<uint8_t> ivBuf = iv.empty() ? std::vector<uint8_t>(16, 0x00) : iv;
    if (ivBuf.size() != 16) {
        throw std::invalid_argument("aesEncrypt: IV must be 16 bytes");
    }

    auto ctx =
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw std::runtime_error("aesEncrypt: EVP_CIPHER_CTX_new failed");
    }

    if (!EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key.data(), ivBuf.data())) {
        throw std::runtime_error("aesEncrypt: EVP_EncryptInit_ex failed");
    }
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

    std::vector<uint8_t> out(data.size() + 16);
    int outLen1 = 0, outLen2 = 0;

    if (!EVP_EncryptUpdate(ctx.get(), out.data(), &outLen1, data.data(), static_cast<int>(data.size()))) {
        throw std::runtime_error("aesEncrypt: EVP_EncryptUpdate failed");
    }
    if (!EVP_EncryptFinal_ex(ctx.get(), out.data() + outLen1, &outLen2)) {
        throw std::runtime_error("aesEncrypt: EVP_EncryptFinal_ex failed");
    }

    out.resize(static_cast<size_t>(outLen1 + outLen2));
    return out;
}

std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data,
                                const std::vector<uint8_t>& iv)
{
    const EVP_CIPHER* cipher = selectAESCipher(key.size());

    std::vector<uint8_t> ivBuf = iv.empty() ? std::vector<uint8_t>(16, 0x00) : iv;
    if (ivBuf.size() != 16) {
        throw std::invalid_argument("aesDecrypt: IV must be 16 bytes");
    }

    auto ctx =
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw std::runtime_error("aesDecrypt: EVP_CIPHER_CTX_new failed");
    }

    if (!EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data(), ivBuf.data())) {
        throw std::runtime_error("aesDecrypt: EVP_DecryptInit_ex failed");
    }
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

    std::vector<uint8_t> out(data.size() + 16);
    int outLen1 = 0, outLen2 = 0;

    if (!EVP_DecryptUpdate(ctx.get(), out.data(), &outLen1, data.data(), static_cast<int>(data.size()))) {
        throw std::runtime_error("aesDecrypt: EVP_DecryptUpdate failed");
    }
    if (!EVP_DecryptFinal_ex(ctx.get(), out.data() + outLen1, &outLen2)) {
        throw std::runtime_error("aesDecrypt: EVP_DecryptFinal_ex failed");
    }

    out.resize(static_cast<size_t>(outLen1 + outLen2));
    return out;
}

// ---- retailMAC ----

std::vector<uint8_t> retailMAC(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data)
{
    if (key.size() != 16) {
        throw std::invalid_argument("retailMAC: key must be 16 bytes");
    }
    if (data.empty() || data.size() % 8 != 0) {
        throw std::invalid_argument("retailMAC: data must be non-empty and block-aligned (8 bytes)");
    }

    // ISO 9797-1 MAC Algorithm 3: single-DES CBC with Ka over the blocks,
    // the last one finished with 3DES (Ka, Kb, Ka). Both are expressed with
    // two-key 3DES-EDE in the default provider: EDE with Ka||Ka is single DES
    // with Ka, and EDE with Ka||Kb over the last block chained on the CBC
    // value so far is E_Ka(D_Kb(E_Ka(h ^ x))). Single DES itself
    // (EVP_des_cbc) would need OpenSSL's legacy provider.
    std::vector<uint8_t> kaKa(key.begin(), key.begin() + 8);
    kaKa.insert(kaKa.end(), key.begin(), key.begin() + 8);

    std::vector<uint8_t> chained(8, 0x00);
    if (data.size() > 8) {
        const std::vector<uint8_t> head(data.begin(), data.end() - 8);
        auto headCipher = des3Encrypt(kaKa, head);
        chained.assign(headCipher.end() - 8, headCipher.end());
        OPENSSL_cleanse(headCipher.data(), headCipher.size());
    }
    OPENSSL_cleanse(kaKa.data(), kaKa.size());

    const std::vector<uint8_t> lastBlock(data.end() - 8, data.end());
    return des3Encrypt(key, lastBlock, chained);
}

// ---- aesCMAC ----

std::vector<uint8_t> aesCMAC(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data)
{
    const char* cipherName = nullptr;
    switch (key.size()) {
    case 16:
        cipherName = "AES-128-CBC";
        break;
    case 24:
        cipherName = "AES-192-CBC";
        break;
    case 32:
        cipherName = "AES-256-CBC";
        break;
    default:
        throw std::invalid_argument("aesCMAC: key must be 16, 24, or 32 bytes");
    }

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
    if (!mac) {
        throw std::runtime_error("aesCMAC: EVP_MAC_fetch(CMAC) failed");
    }

    auto ctx = std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>(EVP_MAC_CTX_new(mac), EVP_MAC_CTX_free);
    EVP_MAC_free(mac);
    if (!ctx) {
        throw std::runtime_error("aesCMAC: EVP_MAC_CTX_new failed");
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, const_cast<char*>(cipherName), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx.get(), key.data(), key.size(), params)) {
        throw std::runtime_error("aesCMAC: EVP_MAC_init failed");
    }
    if (!EVP_MAC_update(ctx.get(), data.data(), data.size())) {
        throw std::runtime_error("aesCMAC: EVP_MAC_update failed");
    }

    std::vector<uint8_t> fullMAC(16);
    size_t macLen = 0;
    if (!EVP_MAC_final(ctx.get(), fullMAC.data(), &macLen, fullMAC.size())) {
        throw std::runtime_error("aesCMAC: EVP_MAC_final failed");
    }

    // Truncate to 8 bytes per ICAO 9303
    fullMAC.resize(8);
    return fullMAC;
}

// ---- incrementSSC ----

void incrementSSC(std::vector<uint8_t>& ssc)
{
    // Big-endian increment with carry
    for (int i = static_cast<int>(ssc.size()) - 1; i >= 0; --i) {
        if (++ssc[static_cast<size_t>(i)] != 0x00) {
            break; // No carry
        }
    }

    // Check for wrap-around (all zeros means overflow)
    bool allZero = true;
    for (auto b : ssc) {
        if (b != 0) {
            allZero = false;
            break;
        }
    }
    if (allZero) {
        throw std::overflow_error("SSC wrap-around detected");
    }
}

// Decode an ASN.1 OID from raw bytes to dotted notation string
std::string oidBytesToString(const uint8_t* data, size_t len)
{
    if (len == 0)
        return {};

    std::string result;
    // First byte encodes two components: first*40 + second
    result += std::to_string(data[0] / 40) + "." + std::to_string(data[0] % 40);

    // Remaining bytes use variable-length encoding (base-128, high bit = continuation)
    unsigned long value = 0;
    for (size_t i = 1; i < len; ++i) {
        if (value > (std::numeric_limits<unsigned long>::max() >> 7))
            return {}; // overflow protection
        value = (value << 7) | (data[i] & 0x7F);
        if ((data[i] & 0x80) == 0) {
            result += "." + std::to_string(value);
            value = 0;
        }
    }
    return result;
}

// Encode a dotted OID string to DER OID bytes (without tag/length)
std::vector<uint8_t> oidStringToBytes(const std::string& oid)
{
    std::vector<unsigned long> components;
    size_t start = 0;
    while (start < oid.size()) {
        size_t dot = oid.find('.', start);
        if (dot == std::string::npos)
            dot = oid.size();
        components.push_back(std::stoul(oid.substr(start, dot - start)));
        start = dot + 1;
    }

    if (components.size() < 2)
        return {};
    if (components[0] > 2 || (components[0] < 2 && components[1] > 39))
        return {};

    std::vector<uint8_t> bytes;
    unsigned long firstByte = components[0] * 40 + components[1];
    if (firstByte > 255)
        return {};
    bytes.push_back(static_cast<uint8_t>(firstByte));

    for (size_t i = 2; i < components.size(); ++i) {
        unsigned long val = components[i];
        // Base-128 encode with continuation bits
        std::vector<uint8_t> encoded;
        encoded.push_back(static_cast<uint8_t>(val & 0x7F));
        val >>= 7;
        while (val > 0) {
            encoded.push_back(static_cast<uint8_t>((val & 0x7F) | 0x80));
            val >>= 7;
        }
        std::reverse(encoded.begin(), encoded.end());
        bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    }
    return bytes;
}

} // namespace emrtd::crypto::detail
