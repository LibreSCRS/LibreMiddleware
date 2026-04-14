// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/signing_service_factory.h"

#ifdef LIBRESIGN_HAS_DSS
#include "libresign/dss/dss_signing_service.h"
#endif

#ifdef LIBRESIGN_HAS_NATIVE
#include "libresign/native/native_signing_service.h"
#endif

#include <stdexcept>

namespace libresign {

std::unique_ptr<SigningService> createSigningService(Backend backend)
{
    switch (backend) {
#ifdef LIBRESIGN_HAS_DSS
    case Backend::DSS:
        return std::make_unique<DSSSigningService>();
#endif
#ifdef LIBRESIGN_HAS_NATIVE
    case Backend::Native:
        return std::make_unique<NativeSigningService>();
#endif
    default:
        return nullptr;
    }
}

} // namespace libresign
