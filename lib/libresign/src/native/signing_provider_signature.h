// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

typedef struct ossl_dispatch_st OSSL_DISPATCH;
typedef struct ossl_algorithm_st OSSL_ALGORITHM;

namespace libresign::detail {

// Dispatch + algorithm tables for signature — assembled in
// signing_provider_signature.cpp, consumed by the provider's
// query_operation callback.
extern const OSSL_DISPATCH sigDispatch[];
extern const OSSL_ALGORITHM sigAlgorithms[];

} // namespace libresign::detail
