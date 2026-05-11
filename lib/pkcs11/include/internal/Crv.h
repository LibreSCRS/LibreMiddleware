// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief PKCS#11 v2.40 @c CK_RV return-code constants used by the
///        @ref LibreSCRS::Pkcs11::Internal multi-PIN refactor.
///
/// The PKCS#11 standard headers under @c lib/pkcs11/include/pkcs11/ define
/// these as preprocessor macros (e.g. @c CKR_OK, @c CKR_PIN_INCORRECT).
/// Within the new internal multi-PIN type system we prefer typed C++
/// constants so the values can be passed through @c std::expected /
/// @c [[nodiscard]] return paths without inviting implicit conversions
/// or shadowing the macro identifiers across translation units. The
/// numeric values intentionally match the PKCS#11 v2.40 spec.

namespace LibreSCRS::Pkcs11::Internal::Crv {

/// @brief Operation completed successfully.
/// @since 4.1
inline constexpr unsigned long Ok = 0UL;

/// @brief User-initiated cancellation (matches @c CKR_CANCEL).
/// @since 4.1
inline constexpr unsigned long Cancel = 1UL;

/// @brief Allocation failure on the host (matches @c CKR_HOST_MEMORY).
/// @since 4.1
inline constexpr unsigned long HostMemory = 2UL;

/// @brief Slot identifier does not refer to a known slot
///        (matches @c CKR_SLOT_ID_INVALID).
/// @since 4.1
inline constexpr unsigned long SlotIdInvalid = 3UL;

/// @brief Generic, non-specific failure (matches @c CKR_GENERAL_ERROR).
/// @since 4.1
inline constexpr unsigned long GeneralError = 5UL;

/// @brief Operation could not complete (matches @c CKR_FUNCTION_FAILED).
/// @since 4.1
inline constexpr unsigned long FunctionFailed = 6UL;

/// @brief Caller passed invalid argument(s) (matches @c CKR_ARGUMENTS_BAD).
/// @since 4.1
inline constexpr unsigned long ArgumentsBad = 7UL;

/// @brief Card / reader hardware error (matches @c CKR_DEVICE_ERROR).
/// @since 4.1
inline constexpr unsigned long DeviceError = 0x30UL;

/// @brief Token ran out of memory (matches @c CKR_DEVICE_MEMORY).
/// @since 4.1
inline constexpr unsigned long DeviceMemory = 0x31UL;

/// @brief Card was removed mid-operation (matches @c CKR_DEVICE_REMOVED).
/// @since 4.1
inline constexpr unsigned long DeviceRemoved = 0x32UL;

/// @brief Supplied PIN was wrong (matches @c CKR_PIN_INCORRECT).
/// @since 4.1
inline constexpr unsigned long PinIncorrect = 0xA0UL;

/// @brief Supplied PIN failed format/charset rules
///        (matches @c CKR_PIN_INVALID).
/// @since 4.1
inline constexpr unsigned long PinInvalid = 0xA1UL;

/// @brief Supplied PIN was outside the accepted length range
///        (matches @c CKR_PIN_LEN_RANGE).
/// @since 4.1
inline constexpr unsigned long PinLenRange = 0xA2UL;

/// @brief PIN expired and must be changed before further use
///        (matches @c CKR_PIN_EXPIRED).
/// @since 4.1
inline constexpr unsigned long PinExpired = 0xA3UL;

/// @brief PIN locked out — retries exhausted (matches @c CKR_PIN_LOCKED).
/// @since 4.1
inline constexpr unsigned long PinLocked = 0xA4UL;

/// @brief Session was closed by the token / library
///        (matches @c CKR_SESSION_CLOSED).
/// @since 4.1
inline constexpr unsigned long SessionClosed = 0xB0UL;

/// @brief Session handle does not refer to an open session
///        (matches @c CKR_SESSION_HANDLE_INVALID).
/// @since 4.1
inline constexpr unsigned long SessionHandleInvalid = 0xB3UL;

/// @brief Operation requires authentication that has not occurred
///        (matches @c CKR_USER_NOT_LOGGED_IN).
/// @since 4.1
inline constexpr unsigned long UserNotLoggedIn = 0x101UL;

/// @brief A user is already authenticated for this session
///        (matches @c CKR_USER_ALREADY_LOGGED_IN).
/// @since 4.1
inline constexpr unsigned long UserAlreadyLoggedIn = 0x100UL;

/// @brief No card present in the slot (matches @c CKR_TOKEN_NOT_PRESENT).
/// @since 4.1
inline constexpr unsigned long TokenNotPresent = 0xE0UL;

/// @brief Mechanism is unknown to the token
///        (matches @c CKR_MECHANISM_INVALID).
/// @since 4.1
inline constexpr unsigned long MechanismInvalid = 0x70UL;

} // namespace LibreSCRS::Pkcs11::Internal::Crv
