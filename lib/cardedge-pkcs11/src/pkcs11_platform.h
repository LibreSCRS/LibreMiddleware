// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Platform-specific PKCS#11 macros (must be defined before including pkcs11.h)

#pragma once

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) __attribute__((visibility("default"))) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "cardedge-pkcs11/pkcs11.h"
