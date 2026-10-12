// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// A conformant PKCS#11 client for real-card tests: a key published with
// CKA_ALWAYS_AUTHENTICATE wants its PIN again for every operation (PKCS#11
// v2.40 section 4.9), given with C_Login(CKU_CONTEXT_SPECIFIC) after
// C_SignInit. Self-contained: brings in <pkcs11/pkcs11.h> with the same
// platform macros the tests define, so the include order does not matter.

#pragma once

#include "pin_guard.h"

#ifndef CK_PTR
#define CK_PTR *
#endif
#ifndef CK_DECLARE_FUNCTION
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#endif
#ifndef CK_DECLARE_FUNCTION_POINTER
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#endif
#ifndef CK_CALLBACK_FUNCTION
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#endif
#ifndef NULL_PTR
#define NULL_PTR nullptr
#endif

#include <gtest/gtest.h>
#include <pkcs11/pkcs11.h>

#include <cstdio>
#include <string>

namespace LibreSCRS::Tests::E2E {

[[nodiscard]] inline bool keyAsksForPinPerOperation(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
    CK_BBOOL value = CK_FALSE;
    CK_ATTRIBUTE attribute{CKA_ALWAYS_AUTHENTICATE, &value, sizeof(value)};
    return C_GetAttributeValue(session, key, &attribute, 1) == CKR_OK && value != CK_FALSE;
}

/// After C_SignInit: authorise THIS operation when the key asks for it.
/// @p pin is the bare PIN -- never the "CAN:PIN" form the session login takes.
/// @return CKR_OK when the key does not ask; otherwise C_Login's answer.
[[nodiscard]] inline CK_RV loginForOperationIfRequired(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                                                       const std::string& pin)
{
    if (!keyAsksForPinPerOperation(session, key))
        return CKR_OK;
    std::string bytes = pin;
    return C_Login(session, CKU_CONTEXT_SPECIFIC, reinterpret_cast<CK_UTF8CHAR_PTR>(bytes.data()),
                   static_cast<CK_ULONG>(bytes.size()));
}

/// The answers that say the PIN itself was wrong or is now unusable -- the
/// same set the session-login guard treats as a PIN failure.
[[nodiscard]] inline bool isPinFailure(CK_RV rv) noexcept
{
    return rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LOCKED || rv == CKR_PIN_INVALID || rv == CKR_PIN_LEN_RANGE;
}

[[nodiscard]] inline std::string ckrName(CK_RV rv)
{
    switch (rv) {
    case CKR_PIN_INCORRECT:
        return "CKR_PIN_INCORRECT";
    case CKR_PIN_LOCKED:
        return "CKR_PIN_LOCKED";
    case CKR_PIN_INVALID:
        return "CKR_PIN_INVALID";
    case CKR_PIN_LEN_RANGE:
        return "CKR_PIN_LEN_RANGE";
    case CKR_USER_NOT_LOGGED_IN:
        return "CKR_USER_NOT_LOGGED_IN";
    case CKR_USER_TYPE_INVALID:
        return "CKR_USER_TYPE_INVALID";
    case CKR_OPERATION_NOT_INITIALIZED:
        return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_FUNCTION_FAILED:
        return "CKR_FUNCTION_FAILED";
    case CKR_DEVICE_ERROR:
        return "CKR_DEVICE_ERROR";
    case CKR_DEVICE_REMOVED:
        return "CKR_DEVICE_REMOVED";
    case CKR_TOKEN_NOT_PRESENT:
        return "CKR_TOKEN_NOT_PRESENT";
    default: {
        char hex[24];
        std::snprintf(hex, sizeof(hex), "0x%08lX", static_cast<unsigned long>(rv));
        return hex;
    }
    }
}

} // namespace LibreSCRS::Tests::E2E

/// Authorise the operation C_SignInit just started. A refusal of the PIN
/// itself marks g_pinFailed and ends the test, so the suite never spends a
/// second try of the card's retry counter (pin_guard.h); any other refusal
/// fails this test alone.
#define OPERATION_LOGIN_OR_ABORT(session, key, pin)                                                                    \
    do {                                                                                                               \
        const CK_RV operationLoginRv = ::LibreSCRS::Tests::E2E::loginForOperationIfRequired((session), (key), (pin));  \
        if (operationLoginRv != CKR_OK) {                                                                              \
            const std::string operationLoginDetail =                                                                   \
                "C_Login(CKU_CONTEXT_SPECIFIC) rv=" + ::LibreSCRS::Tests::E2E::ckrName(operationLoginRv);              \
            if (::LibreSCRS::Tests::E2E::isPinFailure(operationLoginRv))                                               \
                ::LibreSCRS::Tests::E2E::markPinFailedAndAbort(__LINE__, operationLoginDetail);                        \
            else                                                                                                       \
                ADD_FAILURE() << operationLoginDetail;                                                                 \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)
