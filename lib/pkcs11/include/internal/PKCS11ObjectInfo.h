// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Plain-data descriptor of a single PKCS#11 object (cert, key,
///        public key, data) surfaced by an @ref LibreSCRS::Pkcs11::Internal::PKCS11Slot.

#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal {

/// @brief POD descriptor of a single PKCS#11 object (key, certificate,
///        public key, or data object) enumerated from a slot.
///
/// One @ref PKCS11ObjectInfo per @c CKO_* object visible under the
/// owning @ref PKCS11Slot. The marshalling layer translates this struct
/// into the @c CK_ATTRIBUTE template returned by
/// @c C_GetAttributeValue; transient session-bound bookkeeping
/// (handle, find-cursors) lives in @ref PKCS11Library and never reaches
/// this descriptor.
///
/// @par Key-material fields
/// @ref modulus / @ref publicExponent are populated for RSA private and
/// public key objects (parsed from the paired certificate's
/// @c SubjectPublicKeyInfo); both are empty for ECC keys, certificates,
/// and data objects. @ref ecParams / @ref ecPoint are populated for ECC
/// keys (DER-encoded named curve OID and uncompressed point octet
/// string respectively) and empty for RSA / non-key classes. @ref
/// keyReference carries a card-internal reference (PIV: e.g. @c 0x9C
/// digital-signature key; PKCS#15: @c keyReference from the PrKDF;
/// CardEdge: applet-specific). For card families where the surface key
/// data is not available pre-IO (e.g. CardEdge srbeid hides the modulus
/// until the first sign), the populating subclass MAY leave these
/// fields empty; the surrounding library layer must tolerate that.
///
/// @par Thread-safety
/// Aggregate value type. Treat instances as immutable after the slot
/// publishes them under its mutex; consumers operate on copies.
///
/// @since 4.1
struct PKCS11ObjectInfo
{
    /// @brief @c CKA_CLASS — @c CKO_CERTIFICATE, @c CKO_PRIVATE_KEY,
    ///        @c CKO_PUBLIC_KEY, @c CKO_DATA, …
    unsigned long objectClass = 0;

    /// @brief @c CKA_KEY_TYPE — @c CKK_RSA, @c CKK_EC, … Zero when
    ///        @ref objectClass does not denote a key.
    unsigned long keyType = 0;

    /// @brief @c CKA_LABEL, UTF-8.
    std::string label;

    /// @brief @c CKA_ID — opaque byte string used to pair certs with
    ///        their corresponding private keys.
    std::vector<std::uint8_t> id;

    /// @brief @c CKA_VALUE — DER-encoded certificate body for
    ///        certificate objects; empty for private keys (raw key
    ///        material is never extractable). For data objects this
    ///        carries the raw object value.
    std::vector<std::uint8_t> value;

    /// @brief @c CKA_SUBJECT — DER-encoded subject name for certificate
    ///        objects. Empty for non-certificate classes.
    std::vector<std::uint8_t> subject;

    /// @brief @c CKA_TOKEN — true for token-resident objects (the
    ///        common case in this refactor; session objects are not
    ///        surfaced).
    bool token = true;

    /// @brief @c CKA_PRIVATE — true when access requires authentication.
    bool privateObj = false;

    /// @brief @c CKA_SENSITIVE — true for keys whose value is hidden
    ///        from @c C_GetAttributeValue.
    bool sensitive = false;

    /// @brief @c CKA_EXTRACTABLE — true when the key may be wrapped /
    ///        exported off the token. Smart-card keys are typically
    ///        false.
    bool extractable = false;

    /// @brief @c CKA_MODULUS — RSA modulus (big-endian). Populated for
    ///        RSA key objects from the paired certificate's
    ///        @c SubjectPublicKeyInfo; empty for ECC keys, certificates,
    ///        and data objects. Drives RSA signature-size derivation.
    /// @since 4.1
    std::vector<std::uint8_t> modulus;

    /// @brief @c CKA_PUBLIC_EXPONENT — RSA public exponent (big-endian).
    ///        Populated for RSA key objects only; empty for ECC and
    ///        non-key classes.
    /// @since 4.1
    std::vector<std::uint8_t> publicExponent;

    /// @brief @c CKA_EC_PARAMS — DER-encoded named curve OID parameters.
    ///        Populated for ECC key objects only; empty for RSA and
    ///        non-key classes.
    /// @since 4.1
    std::vector<std::uint8_t> ecParams;

    /// @brief @c CKA_EC_POINT — DER-encoded OCTET STRING wrapping the
    ///        uncompressed EC public point. Populated for ECC key
    ///        objects only; empty for RSA and non-key classes.
    /// @since 4.1
    std::vector<std::uint8_t> ecPoint;

    /// @brief Card-internal key reference. PIV uses key references such
    ///        as @c 0x9C (digital signature); PKCS#15 derives this from
    ///        the PrKDF entry; CardEdge populates an applet-specific
    ///        identifier. Zero when not applicable.
    /// @since 4.1
    std::uint8_t keyReference{0};
};

} // namespace LibreSCRS::Pkcs11::Internal
