// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <string>
#include <string_view>

namespace LibreSCRS::SmartCard::Internal {

// Reorder an all-digit 8-character date string into the human display form
// "DD.MM.YYYY". Anything that is not exactly 8 digits is returned unchanged.
//
// formatDateDMY: input already in day-month-year order ("DDMMYYYY") — only
// dot separators are inserted. Used by the Serbian eID / health TLV readers.
//
// formatDateYMD: input in year-month-day order ("YYYYMMDD") — the components
// are reordered to "DD.MM.YYYY". Used by the EU VRC reader and the eMRTD DG12
// date-of-issue field.
std::string formatDateDMY(std::string_view raw);
std::string formatDateYMD(std::string_view raw);

} // namespace LibreSCRS::SmartCard::Internal
