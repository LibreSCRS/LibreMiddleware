// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "card_scanner.h"

#include <string>

namespace card_mapper {

// Generate a draft *_protocol.h header from scan results
std::string generateProtocolHeader(const std::string& name, const ScanResult& scanResult);

} // namespace card_mapper
