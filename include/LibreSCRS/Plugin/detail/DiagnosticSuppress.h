// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS/Plugin/detail/DiagnosticSuppress.h is internal to LibreMiddleware"
#endif

/// @file
/// @brief Cross-compiler macros for narrow diagnostic suppression.
/// Centralised to avoid scattering compiler-specific pragmas through the
/// codebase. Use sparingly; prefer fixing warnings over suppressing them.

#if defined(__clang__) || defined(__GNUC__)
#define LIBRESCRS_SUPPRESS_DEPRECATED_PUSH                                                                             \
    _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#define LIBRESCRS_SUPPRESS_DEPRECATED_POP _Pragma("GCC diagnostic pop")
#else
#define LIBRESCRS_SUPPRESS_DEPRECATED_PUSH
#define LIBRESCRS_SUPPRESS_DEPRECATED_POP
#endif
