// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace smartcard {
class PCSCConnection;
}

namespace euvrc {

struct AidSequence
{
    std::string name;
    std::vector<std::vector<uint8_t>> selectCommands;
    uint8_t lastP2 = 0x00;
};

struct FileFid
{
    uint8_t fidHi;
    uint8_t fidLo;
    std::string name;
    bool isBerTlv; // true for D0xx data files, false for E0xx/C0xx binary
};

// All known AID sequences (EU standard first, then national)
std::vector<AidSequence> getAllKnownAidSequences();

// EU standard file FIDs (Directive 2003/127/EC Table 1)
std::vector<FileFid> getStandardFileFids();

// National extension FIDs to probe
std::vector<FileFid> getNationalExtensionFids();

// Detect EU VRC on a live connection. Returns true if card is an EU VRC.
// On success, the applet is selected and ready for file reading.
bool detect(smartcard::PCSCConnection& conn);

// Probe without modifying state (for canHandleConnection)
bool probe(smartcard::PCSCConnection& conn);

} // namespace euvrc
