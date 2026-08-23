// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"
#include "secure_messaging.h"
#include <LibreSCRS/CancelToken.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
}

namespace emrtd::crypto {

struct ChipAuthInfo
{
    std::vector<uint8_t> oid;
    int version = 0;
    std::optional<int> keyId;
};

struct ChipAuthPublicKey
{
    std::vector<uint8_t> oid;
    std::vector<uint8_t> publicKey; // SubjectPublicKeyInfo DER
    std::optional<int> keyId;
};

struct ChipAuthResult
{
    enum Status { PASSED, FAILED, NOT_PERFORMED, NOT_SUPPORTED };
    Status chipAuthentication = NOT_PERFORMED;
    Status activeAuthentication = NOT_PERFORMED;
    /// @brief True when the FAILED verdict is a card-side STATUS-WORD refusal
    ///        of a protocol APDU (MSE:Set AT / GENERAL AUTHENTICATE for CA,
    ///        INTERNAL AUTHENTICATE for AA) — as opposed to a local crypto
    ///        failure or a bad signature. On a plain channel this lets the
    ///        caller report NOT_PERFORMED (the contact interface may legitimately
    ///        SM-gate the protocol) rather than accusing the card; inside an
    ///        SM tunnel a refusal of an advertised capability still maps to
    ///        FAILED. Never set on the empty-response or verification krak.
    bool chipRefusedProtocol = false;
    std::string protocol;
    std::string errorDetail;
    std::optional<SessionKeys> newSessionKeys;
    SMAlgorithm newAlgorithm = SMAlgorithm::AES;
};

bool parseDG14(const std::vector<uint8_t>& dg14Raw, std::vector<ChipAuthInfo>& caInfos,
               std::vector<ChipAuthPublicKey>& caKeys);

/// @brief Run BSI TR-03110 Chip Authentication over the supplied secure
///        channel. The post-handshake SM key replacement is the caller's
///        responsibility: on @ref ChipAuthResult::PASSED with
///        @ref newSessionKeys populated, invoke
///        @ref LibreSCRS::SecureChannel::ISecureChannel::replaceKeys with
///        the new key block (mapping @ref newAlgorithm to the corresponding
///        @c SmCipher). The protocol's General Authenticate APDUs flow
///        through the channel — no separate SM wrap is performed here.
ChipAuthResult performChipAuth(LibreSCRS::SecureChannel::ISecureChannel& channel, const std::vector<uint8_t>& dg14Raw,
                               LibreSCRS::CancelToken token = {});
} // namespace emrtd::crypto
