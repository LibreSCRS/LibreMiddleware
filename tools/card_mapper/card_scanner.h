// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "output_formatter.h"

#include <smartcard/pcsc_connection.h>

#include <string>
#include <utility>
#include <vector>

namespace card_mapper {

// An AID probe is a sequence of SELECT commands.
// An applet is detected only when ALL commands in the sequence succeed.
// Simple AIDs have a sequence of length 1; multi-step selections (e.g. vehicle)
// have longer sequences.
struct AidProbe
{
    std::string name;                                // human-readable identifier
    std::vector<uint8_t> canonicalAid;               // the AID used for profile matching
    std::vector<std::vector<uint8_t>> selectSequence; // SELECT commands in order
    uint8_t lastP2 = 0x00;                           // P2 for the last SELECT (some use 0x0C)
};

struct ScanResult
{
    std::vector<uint8_t> atr;
    std::vector<AppletInfo> detectedApplets;
    ProfileInfo profile;
};

// Scan unknown card: detect applets, walk file systems
ScanResult discoverCard(smartcard::PCSCConnection& conn, bool verbose);

// Get list of FID ranges to probe
std::vector<std::pair<uint16_t, uint16_t>> getProbeRanges();

// Get all known AID probes
std::vector<AidProbe> getAllKnownProbes();

// Match detected canonical AIDs to a known profile name (empty if unknown)
std::string matchProfile(const std::vector<std::vector<uint8_t>>& detectedAIDs);

} // namespace card_mapper
