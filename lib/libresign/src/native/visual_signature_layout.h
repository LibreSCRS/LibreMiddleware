// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

/// @file
/// @brief Auto-fit constants shared by the layout and the PAdES appearance
///        stream; the public floor and leading live in VisualSignatureLayout.h.

namespace LibreSCRS::Signing {

/// @brief Hard ceiling on the auto-fit font size in PDF user units.
///
/// 72pt = one inch. Useful only for wide-aspect annotation boxes; the
/// binary search will normally never reach this value for the typical
/// 200×50 default rectangle.
inline constexpr float kMaxAppearanceFontSize = 72.0f;

/// @brief Inset, in PDF user units, applied to every edge of the
///        annotation rectangle before layout and when drawing the text.
///
/// Available width = `box.width - 2 * kAppearanceTextMargin`.
/// Available height = `box.height - 2 * kAppearanceTextMargin`.
inline constexpr float kAppearanceTextMargin = 4.0f;

} // namespace LibreSCRS::Signing
