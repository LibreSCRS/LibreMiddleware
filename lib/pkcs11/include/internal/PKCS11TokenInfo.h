// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Plain-data descriptor mirroring @c CK_TOKEN_INFO for the
///        @ref LibreSCRS::Pkcs11::Internal multi-PIN slot model.

#include <string>

namespace LibreSCRS::Pkcs11::Internal {

/// @brief POD descriptor of a logical PKCS#11 token (one per PIN).
///
/// One @ref PKCS11TokenInfo instance describes the token presented by a
/// single @ref PKCS11Slot. In the multi-PIN model a physical card
/// surfaces N tokens — one for each authenticator (PIN, signing PIN,
/// admin PIN, …) — so the @ref pinLabel field disambiguates which
/// authenticator this token is gated by.
///
/// All string fields are UTF-8 and are NOT space-padded to PKCS#11
/// fixed-width fields; the marshalling layer pads / truncates when
/// emitting @c CK_TOKEN_INFO over the C ABI.
///
/// @par Thread-safety
/// Aggregate value type. Concurrent reads of the same instance are safe
/// once it has been published; concurrent writes are not. Producers
/// must hold the owning slot's mutex during construction; consumers
/// receive snapshots by value.
///
/// @since 4.1
struct PKCS11TokenInfo
{
    /// @brief Token label (e.g. @c "eID Auth", @c "eID Sign").
    std::string label;

    /// @brief Card / token manufacturer string.
    std::string manufacturerId;

    /// @brief Card model (e.g. @c "Gemalto IDPrime", @c "CardEdge").
    std::string model;

    /// @brief Token serial number, ASCII.
    std::string serialNumber;

    /// @brief Human-readable label for the PIN gating this token
    ///        (e.g. @c "User PIN", @c "Signing PIN"). The multi-PIN
    ///        refactor uses this both in @c CKA_LABEL surfacing and in
    ///        UI prompts; @c std::string (NOT @c LocalizedText) is
    ///        deliberate — translation happens upstream when the
    ///        provider populates this struct.
    std::string pinLabel;

    /// @brief @c CK_TOKEN_INFO @c flags bitfield as published to PKCS#11
    ///        clients. Common bits: @c CKF_TOKEN_INITIALIZED,
    ///        @c CKF_LOGIN_REQUIRED, @c CKF_USER_PIN_INITIALIZED.
    unsigned long flags = 0;

    /// @brief Maximum accepted PIN length in characters/bytes.
    unsigned long maxPinLen = 16;

    /// @brief Minimum accepted PIN length in characters/bytes.
    unsigned long minPinLen = 4;

    /// @brief @c CK_TOKEN_INFO @c ulTotalPublicMemory.
    unsigned long totalPublicMemory = 0;

    /// @brief @c CK_TOKEN_INFO @c ulFreePublicMemory.
    unsigned long freePublicMemory = 0;

    /// @brief @c CK_TOKEN_INFO @c ulTotalPrivateMemory.
    unsigned long totalPrivateMemory = 0;

    /// @brief @c CK_TOKEN_INFO @c ulFreePrivateMemory.
    unsigned long freePrivateMemory = 0;

    /// @brief Hardware version, major component.
    unsigned char hardwareVersionMajor = 0;

    /// @brief Hardware version, minor component.
    unsigned char hardwareVersionMinor = 0;

    /// @brief Firmware version, major component.
    unsigned char firmwareVersionMajor = 0;

    /// @brief Firmware version, minor component.
    unsigned char firmwareVersionMinor = 0;
};

} // namespace LibreSCRS::Pkcs11::Internal
