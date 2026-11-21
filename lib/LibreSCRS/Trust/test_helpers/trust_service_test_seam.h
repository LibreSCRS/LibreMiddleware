// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief The verification certificate the trust store service's test copy
///        gives the Trusted Lists it fetches.
///
/// Declared for the consumers of the build-tree-only
/// @c LibreSCRS_TrustService_ForTests archive and defined there only: the
/// shipped libLibreSCRS_Trust has no way to replace the certificate a list is
/// verified against.

#pragma once

#include <string>

namespace LibreSCRS::Trust::Testing {

/// Every list the test copy fetches from now on is verified against the
/// certificate in @p path (PEM or DER) instead of a pinned one; empty restores
/// the shipped behaviour. Process-wide.
void setTrustedListSigningCertificate(std::string path);

} // namespace LibreSCRS::Trust::Testing
