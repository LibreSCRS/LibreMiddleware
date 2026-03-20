// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace emrtd::crypto::detail {

// ICAO 9303 Key Derivation Function: KDF(K_seed, counter)
// SHA-1 based for BAC (3DES), SHA-256 based for PACE (AES)
// Returns key with adjusted parity bits (3DES only)
// keyLen: output key length in bytes (default 16; use 24 for AES-192, 32 for AES-256)
std::vector<uint8_t> kdf(const std::vector<uint8_t>& seed, uint32_t counter, bool des3 = true, size_t keyLen = 16);

// ICAO 9303 check digit computation for MRZ fields
int computeCheckDigit(const std::string& input);

// ISO 9797-1 Method 2 padding
std::vector<uint8_t> pad(const std::vector<uint8_t>& data, size_t blockSize);
std::vector<uint8_t> unpad(const std::vector<uint8_t>& data);

// ISO 9797-1 MAC Algorithm 3 (Retail MAC) using 3DES
std::vector<uint8_t> retailMAC(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);

// AES-CMAC (RFC 4493), truncated to 8 bytes per ICAO
std::vector<uint8_t> aesCMAC(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);

// 3DES-CBC encrypt/decrypt (2-key, 16-byte key)
// Empty iv = 8 zero bytes internally
std::vector<uint8_t> des3Encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data,
                                 const std::vector<uint8_t>& iv = {});
std::vector<uint8_t> des3Decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data,
                                 const std::vector<uint8_t>& iv = {});

// AES-CBC encrypt/decrypt
// Empty iv = 16 zero bytes internally
std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data,
                                const std::vector<uint8_t>& iv = {});
std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data,
                                const std::vector<uint8_t>& iv = {});

// Adjust DES key parity bits (set odd parity on each byte)
void adjustParity(std::vector<uint8_t>& key);

// Increment SSC (big-endian byte array)
void incrementSSC(std::vector<uint8_t>& ssc);

} // namespace emrtd::crypto::detail
