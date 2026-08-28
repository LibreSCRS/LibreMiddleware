// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Test-only ATR-override seam for @ref
///        LibreSCRS::SmartCard::Internal::PCSCConnection.
///
/// This translation unit is compiled into the build-tree-only
/// @ref LibreSCRS_SmartCard_TestHelpers archive — it is never installed and
/// never linked into any shipped @c libLibreSCRS_*.so. Production builds
/// therefore never carry @ref
/// LibreSCRS::SmartCard::Internal::PCSCConnection::setDetachedAtr in their
/// dynamic export set: the setter is the only member of the seam that can
/// arm it, so keeping its definition out of the shipped libraries closes the
/// dlsym-reachable path while the @c detachedAtr member and the
/// @c card == 0 branch in @ref PCSCConnection::getATR stay in the
/// production class (the branch is inert until a test arms it, and moving
/// the member would change the class layout).
///
/// Kept in @c pcsc_connection.cpp the definition did not stay private: that
/// TU is compiled at default visibility into @c libSmartCard_Impl.a, and
/// @c emrtd::crypto::performBAC / @c performPACE take a
/// @c PCSCConnection&, so linking @c LibreSCRS_SecureChannel extracts the
/// whole object and the @c *LibreSCRS::* glob in
/// @c cmake/librescrs-public-exports.map promotes every LibreSCRS-mentioning
/// symbol in it. A hidden-visibility attribute on the declaration is not an
/// alternative: the Darwin export filter is a mangled-prefix allowlist with
/// no un-export form, so only moving the definition works on both platforms.
///
/// The setter cannot live in the archive's own namespace the way
/// @ref detail::ChannelInjector::installForTesting does — it is a declared
/// member of a production class — but the effect is the same: the archive
/// is linked by the test executables that need the seam and by nothing
/// else. @c lib/smartcard/src is on this target's PRIVATE include path, so
/// the internal core-transport header resolves the same way it does for
/// @c SmartCard_Impl's own sources.

#include <pcsc_connection.h>

#include <cstdint>
#include <utility>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

void PCSCConnection::setDetachedAtr(std::vector<uint8_t> atr)
{
    detachedAtr = std::move(atr);
}

} // namespace LibreSCRS::SmartCard::Internal
