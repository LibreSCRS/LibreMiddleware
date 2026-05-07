// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "signing_service.h"

#include <memory>

namespace libresign {

enum class Backend { Native, DSS };

std::unique_ptr<SigningService> createSigningService(Backend backend);

} // namespace libresign
