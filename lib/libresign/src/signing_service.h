// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"

namespace libresign {

class SigningKey;

class SigningService
{
public:
    virtual ~SigningService() = default;

    // Configure trust lists and revocation sources.
    // Default implementation is a no-op (native backend uses bundled certs).
    virtual bool configure(const TrustConfig& /*config*/)
    {
        return true;
    }

    /// @brief Sign @p request.document with @p key, a key the caller holds:
    ///        in production the key signs through the card plugin on the
    ///        session the host holds for the reader. A document that already
    ///        carries a signature in @p request.format gains one more where
    ///        the format holds the document it signs.
    virtual SigningResult sign(const SigningRequest& request, SigningKey& key) = 0;
};

} // namespace libresign
