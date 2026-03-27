// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <array>
#include <cstdint>

namespace piv::protocol {

// PIV AID (NIST SP 800-73-4)
constexpr std::array<uint8_t, 8> AID = {0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10};

// GET DATA instruction
constexpr uint8_t INS_GET_DATA = 0xCB;
constexpr uint8_t GET_DATA_P1  = 0x3F;
constexpr uint8_t GET_DATA_P2  = 0xFF;

// VERIFY instruction
constexpr uint8_t INS_VERIFY = 0x20;

// PIV data object identifiers (used inside tag 5C in GET DATA command)
constexpr std::array<uint8_t, 3> OBJ_CCC             = {0x5F, 0xC1, 0x07};
constexpr std::array<uint8_t, 3> OBJ_CHUID            = {0x5F, 0xC1, 0x02};
constexpr std::array<uint8_t, 1> OBJ_DISCOVERY        = {0x7E};
constexpr std::array<uint8_t, 3> OBJ_PRINTED_INFO     = {0x5F, 0xC1, 0x09};
constexpr std::array<uint8_t, 3> OBJ_KEY_HISTORY      = {0x5F, 0xC1, 0x0C};

// Certificate containers
constexpr std::array<uint8_t, 3> OBJ_CERT_PIV_AUTH    = {0x5F, 0xC1, 0x05};  // key ref 9A
constexpr std::array<uint8_t, 3> OBJ_CERT_DIGITAL_SIG = {0x5F, 0xC1, 0x0A};  // key ref 9C
constexpr std::array<uint8_t, 3> OBJ_CERT_KEY_MGMT    = {0x5F, 0xC1, 0x0B};  // key ref 9D
constexpr std::array<uint8_t, 3> OBJ_CERT_CARD_AUTH   = {0x5F, 0xC1, 0x01};  // key ref 9E

// Retired certificate containers: {0x5F, 0xC1, 0x0D + i} for i in 0..19

// Key references
constexpr uint8_t KEY_PIV_AUTH    = 0x9A;
constexpr uint8_t KEY_DIGITAL_SIG = 0x9C;
constexpr uint8_t KEY_KEY_MGMT    = 0x9D;
constexpr uint8_t KEY_CARD_AUTH   = 0x9E;
// Retired: 0x82 + i for i in 0..19

// PIN key references
constexpr uint8_t PIN_APPLICATION = 0x80;
constexpr uint8_t PIN_GLOBAL      = 0x00;

// Discovery object PIN usage policy bits (first byte of tag 5F2F)
constexpr uint8_t PIN_POLICY_APP_PIN_PRIMARY = 0x40;
constexpr uint8_t PIN_POLICY_GLOBAL_PIN      = 0x20;
constexpr uint8_t PIN_POLICY_OCC             = 0x10;

} // namespace piv::protocol
