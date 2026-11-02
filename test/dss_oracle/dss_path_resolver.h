// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "dss_oracle/dss_service_manager.h"

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
