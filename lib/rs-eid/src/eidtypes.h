// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <rs_types.h>

namespace eidcard {

using PhotoData = LibreSCRS::RsEId::Core::PhotoData;

// The verdict type belongs to the core, which owns the trust decision; this
// alias keeps existing eidcard:: call sites unchanged.
using VerificationResult = LibreSCRS::RsEId::Core::VerificationResult;

} // namespace eidcard
