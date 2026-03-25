// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "output_formatter.h"

#include <smartcard/pcsc_connection.h>

#include <string>
#include <vector>

namespace card_mapper {

// Returns static metadata for a known plugin (no card needed)
AppletInfo getPluginInfo(const std::string& pluginName);

// Returns list of known plugin names
std::vector<std::string> getKnownPlugins();

// Reads card and populates AppletInfo with actual values from card
// Requires a connected PCSCConnection with card present
AppletInfo mapPlugin(const std::string& pluginName, smartcard::PCSCConnection& conn, bool verbose);

} // namespace card_mapper
