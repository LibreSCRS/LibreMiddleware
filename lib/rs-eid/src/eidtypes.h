// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <rs_types.h>

namespace eidcard {

enum class CardType : int { Unknown = 0, Apollo2008 = 1, Gemalto2014 = 2, ForeignerIF2020 = 3 };

// The national-data vocabulary lives in the core so the annex reader can share
// it with the CardEdge readers; these aliases keep eidcard:: call sites intact.
using DocumentData = LibreSCRS::RsEId::Core::DocumentData;
using FixedPersonalData = LibreSCRS::RsEId::Core::FixedPersonalData;
using VariablePersonalData = LibreSCRS::RsEId::Core::VariablePersonalData;
using PhotoData = LibreSCRS::RsEId::Core::PhotoData;

// The verdict type belongs to the core, which owns the trust decision; this
// alias keeps existing eidcard:: call sites unchanged.
using VerificationResult = LibreSCRS::RsEId::Core::VerificationResult;

} // namespace eidcard
