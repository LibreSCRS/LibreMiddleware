// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

struct CliOptions
{
    bool discover = false;
    bool pluginMode = false;
    std::string pluginName;
    std::string outputFile;
    std::string outputDir = "docs/cards/";
    bool scaffold = false;
    std::string scaffoldName;
    bool verbose = false;
    std::string readerName;
    std::string mrz;
    std::string can;
    uint8_t pinRef = 0;
    bool pinRequested = false;
    bool help = false;
    bool version = false;
};

CliOptions parseOptions(int argc, const char* argv[]);
void printHelp();
void printVersion();
