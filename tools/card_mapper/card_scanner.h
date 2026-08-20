// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "output_formatter.h"

#include <pcsc_connection.h>

#include <cstddef>
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
    std::string name;                                 // human-readable identifier
    std::vector<uint8_t> canonicalAid;                // the AID used for profile matching
    std::vector<std::vector<uint8_t>> selectSequence; // SELECT commands in order
    uint8_t lastP2 = 0x00;                            // P2 for the last SELECT (some use 0x0C)
};

struct ScanResult
{
    std::vector<uint8_t> atr;
    std::vector<AppletInfo> detectedApplets;
    ProfileInfo profile;
};

// Scan unknown card: detect applets, walk file systems
ScanResult discoverCard(LibreSCRS::SmartCard::Internal::PCSCConnection& conn, bool verbose);

// Get list of FID ranges to probe
std::vector<std::pair<uint16_t, uint16_t>> getProbeRanges();

// Get all known AID probes
std::vector<AidProbe> getAllKnownProbes();

// Match detected canonical AIDs to a known profile name (empty if unknown)
std::string matchProfile(const std::vector<std::vector<uint8_t>>& detectedAIDs);

// Whether a completed file-identifier sweep means "no file-system applet is
// selected" rather than "this card holds no files".
//
// 6A86 is "incorrect P1/P2". A card whose file-system applet has been
// deselected -- by anything, including a tool that ran before this one and
// left another applet current -- answers it to EVERY ISO SELECT FILE until the
// card is reset, and SCARD_LEAVE_CARD on disconnect does not undo that. A
// sweep then finds nothing and reports a card with no files, which is a
// measurement of the session rather than of the card. Sweeping thousands of
// identifiers and getting that one answer to every single one is not what a
// populated card looks like, and not what an empty one looks like either.
//
// @param probed   file identifiers the sweep actually tried
// @param rejected how many of them answered 6A86
// @param found    files the sweep located
[[nodiscard]] bool sweepSuggestsNoAppletSelected(std::size_t probed, std::size_t rejected, std::size_t found);

} // namespace card_mapper
