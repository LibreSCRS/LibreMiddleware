// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "crypto_utils.h"

#include <openssl/core_names.h>
#include <openssl/des.h>
#include <openssl/evp.h>

// Suppress OpenSSL 3 deprecation warnings for low-level DES API.
// The low-level DES_* functions are used intentionally in retailMAC to avoid
// the legacy provider requirement that EVP_des_cbc() imposes in OpenSSL 3.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

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

    const char* algo = des3 ? "SHA1" : "SHA256";
    unsigned char digest[64] = {};
    size_t digestLen = 0;

    if (!EVP_Q_digest(nullptr, algo, nullptr, input.data(), input.size(), digest, &digestLen)) {
        throw std::runtime_error("kdf: EVP_Q_digest failed");
    }

    if (keyLen > digestLen) {
        throw std::invalid_argument("kdf: requested keyLen exceeds hash output length");
    }

    std::vector<uint8_t> key(digest, digest + keyLen);

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

    // Split into Ka (first 8 bytes) and Kb (last 8 bytes)
    // ISO 9797-1 MAC Algorithm 3: single-DES-CBC with Ka over all blocks, then
    // 3DES-EDE decrypt-encrypt (Kb, Ka) on the last block.
    // We use low-level DES_* APIs to avoid the OpenSSL 3 legacy provider requirement
    // that EVP_des_cbc() imposes.

    DES_cblock ivBlock = {};
    DES_key_schedule ksA{}, ksB{};

    // DES_set_key_unchecked does not validate parity/weak-key — required for test vectors.
    // The header declares const_DES_cblock as non-const pointer; cast accordingly.
    DES_set_key_unchecked(reinterpret_cast<DES_cblock*>(const_cast<uint8_t*>(key.data())), &ksA);
    DES_set_key_unchecked(reinterpret_cast<DES_cblock*>(const_cast<uint8_t*>(key.data() + 8)), &ksB);

    // Step 1: single-DES CBC with Ka over all data blocks
    std::vector<uint8_t> intermediate(data.size());
    DES_cblock iv1 = {};
    DES_ncbc_encrypt(data.data(), intermediate.data(), static_cast<long>(data.size()), &ksA, &iv1, DES_ENCRYPT);

    // Last CBC output block (8 bytes)
    std::vector<uint8_t> lastBlock(intermediate.end() - 8, intermediate.end());

    // Step 2: decrypt last block with Kb (single-DES)
    std::vector<uint8_t> decrypted(8);
    DES_cblock iv2 = {};
    DES_ncbc_encrypt(lastBlock.data(), decrypted.data(), 8, &ksB, &iv2, DES_DECRYPT);

    // Step 3: re-encrypt with Ka (single-DES)
    std::vector<uint8_t> mac(8);
    DES_cblock iv3 = {};
    DES_ncbc_encrypt(decrypted.data(), mac.data(), 8, &ksA, &iv3, DES_ENCRYPT);

    return mac;
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

} // namespace emrtd::crypto::detail

#pragma GCC diagnostic pop
