// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "dss/dss_service_manager.h"

#include <string>

namespace libresign {

class DSSPathResolver
{
public:
    static DSSServiceManager::Config resolve();

private:
    static std::string executableDir();
};

} // namespace libresign
