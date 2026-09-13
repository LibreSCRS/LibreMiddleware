// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief The arming half of every @ref
///        LibreSCRS::SmartCard::Internal::PCSCConnection test seam.
///
/// This translation unit is compiled into the build-tree-only
/// @ref LibreSCRS_SmartCard_TestHelpers archive — it is never installed and
/// never linked into any shipped @c libLibreSCRS_*.so. It holds the
/// definitions of the six members that can ARM a seam:
///
/// - @c setTransmitFilter / @c clearTransmitFilter — the typed-APDU filter,
///   also the diagnostic hook the build-tree @c card_mapper tool installs to
///   log the wire;
/// - @c setDetachedRawResponder — the raw-byte responder that lets a test
///   play the card side of a live SM tunnel;
/// - @c setDetachedAtr — the synthetic-ATR override for detached
///   connections;
/// - @c setDetachedTransactionFailure — makes a detached
///   @c beginTransaction() throw, so a caller that must contain that throw
///   can be measured doing it;
/// - @c setDetachedTransactionReleaseObserver — runs test code at the moment
///   a detached @c endTransaction() takes effect, which is the only point at
///   which the ORDER of a release against its caller's later work can be
///   sampled.
///
/// Production builds therefore carry none of the six in their dynamic
/// export set, so no shipped library offers a dlsym-reachable way to arm a
/// seam. The members they write (@c transmitFilter, @c detachedRawResponder,
/// @c detachedAtr, @c detachedTransactionRv, @c detachedReleaseObserver) and
/// the branches that read them
/// stay in the production
/// class: each branch is inert until a test arms it, and moving the members
/// would change the class layout. They are declared at the TAIL of that class
/// for the same reason: appending grows it without moving a production offset
/// that separately-packaged objects have already compiled in.
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
#include <functional>
#include <utility>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

void PCSCConnection::setTransmitFilter(TransmitFilter filter)
{
    transmitFilter = std::move(filter);
}

void PCSCConnection::clearTransmitFilter()
{
    transmitFilter = nullptr;
}

void PCSCConnection::setDetachedRawResponder(RawResponder responder)
{
    detachedRawResponder = std::move(responder);
}

void PCSCConnection::setDetachedAtr(std::vector<uint8_t> atr)
{
    detachedAtr = std::move(atr);
}

void PCSCConnection::setDetachedTransactionFailure(LONG rv)
{
    detachedTransactionRv = rv;
}

void PCSCConnection::setDetachedTransactionReleaseObserver(std::function<void()> observer)
{
    detachedReleaseObserver = std::move(observer);
}

} // namespace LibreSCRS::SmartCard::Internal
