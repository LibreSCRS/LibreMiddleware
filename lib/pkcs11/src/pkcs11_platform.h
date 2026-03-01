// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

// Platform-specific PKCS#11 macros (must be defined before including pkcs11.h)

#ifndef PKCS11_PLATFORM_H
#define PKCS11_PLATFORM_H

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) \
    __attribute__((visibility("default"))) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11/pkcs11.h"

#endif // PKCS11_PLATFORM_H
