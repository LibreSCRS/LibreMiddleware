// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "cli_options.h"

#include <cstdlib>
#include <iostream>
#include <string>

CliOptions parseOptions(int argc, const char* argv[])
{
    CliOptions opts;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--help")
        {
            opts.help = true;
            return opts;
        }
        else if (arg == "--version")
        {
            opts.version = true;
            return opts;
        }
        else if (arg == "--discover")
        {
            opts.discover = true;
        }
        else if (arg == "--plugin")
        {
            opts.pluginMode = true;
            if (i + 1 < argc)
            {
                opts.pluginName = argv[++i];
            }
            else
            {
                throw std::runtime_error("--plugin requires a plugin name");
            }
        }
        else if (arg == "--output")
        {
            if (i + 1 < argc)
            {
                opts.outputFile = argv[++i];
            }
            else
            {
                throw std::runtime_error("--output requires a file path");
            }
        }
        else if (arg == "--output-dir")
        {
            if (i + 1 < argc)
            {
                opts.outputDir = argv[++i];
            }
            else
            {
                throw std::runtime_error("--output-dir requires a directory path");
            }
        }
        else if (arg == "--scaffold")
        {
            opts.scaffold = true;
            if (i + 1 < argc)
            {
                opts.scaffoldName = argv[++i];
            }
            else
            {
                throw std::runtime_error("--scaffold requires a plugin name");
            }
        }
        else if (arg == "--verbose")
        {
            opts.verbose = true;
        }
        else if (arg == "--reader")
        {
            if (i + 1 < argc)
            {
                opts.readerName = argv[++i];
            }
            else
            {
                throw std::runtime_error("--reader requires a reader name");
            }
        }
        else if (arg == "--mrz")
        {
            if (i + 1 < argc)
            {
                opts.mrz = argv[++i];
            }
            else
            {
                throw std::runtime_error("--mrz requires an MRZ string");
            }
        }
        else if (arg == "--can")
        {
            if (i + 1 < argc)
            {
                opts.can = argv[++i];
            }
            else
            {
                throw std::runtime_error("--can requires a CAN string");
            }
        }
        else if (arg == "--pin")
        {
            opts.pinRequested = true;
            if (i + 1 < argc)
            {
                std::string refStr = argv[++i];
                // Parse hex (0x80) or decimal reference
                if (refStr.size() > 2 && refStr[0] == '0' && (refStr[1] == 'x' || refStr[1] == 'X'))
                {
                    opts.pinRef = static_cast<uint8_t>(std::strtoul(refStr.c_str(), nullptr, 16));
                }
                else
                {
                    opts.pinRef = static_cast<uint8_t>(std::strtoul(refStr.c_str(), nullptr, 10));
                }
            }
            else
            {
                throw std::runtime_error("--pin requires a reference number");
            }
        }
        else
        {
            throw std::runtime_error("unknown option: " + arg);
        }
    }

    // --help and --version already returned early above

    // Validate: exactly one mode required
    if (opts.discover && opts.pluginMode)
    {
        throw std::runtime_error("cannot use --discover and --plugin together");
    }
    if (!opts.discover && !opts.pluginMode)
    {
        throw std::runtime_error("one of --discover or --plugin is required (use --help for usage)");
    }

    // --scaffold only with --discover
    if (opts.scaffold && !opts.discover)
    {
        throw std::runtime_error("--scaffold can only be used with --discover");
    }

    // --output only with --plugin
    if (!opts.outputFile.empty() && !opts.pluginMode)
    {
        throw std::runtime_error("--output can only be used with --plugin");
    }

    return opts;
}

void printHelp()
{
    std::cout <<
R"(card_mapper — Smart card file system mapper and documentation generator

USAGE:
    card_mapper --discover [OPTIONS]
    card_mapper --plugin <name> [OPTIONS]

MODES:
    --discover              Scan an unknown card: detect applets, walk file
                            system, generate applet and profile documentation
    --plugin <name>         Map a known plugin's applet using its protocol
                            definitions (eid, vehicle, health, emrtd, cardedge)

OPTIONS:
    --output <file>         Write single applet doc to <file> (--plugin mode)
    --output-dir <dir>      Write applet + profile docs to <dir> (--discover mode)
                            Default: docs/cards/
    --scaffold <name>       Generate draft *_protocol.h for new plugin (--discover only)
    --verbose               Append APDU trace section to output
    --reader <name>         Use specific PC/SC reader (default: first available)
    --mrz <MRZ>             Authenticate via PACE using MRZ (eMRTD)
    --can <CAN>             Authenticate via PACE-CAN (eMRTD)
    --pin <ref>             Prompt for PIN interactively for given reference
    --help                  Show this help message
    --version               Show version

EXAMPLES:
    # Scan unknown card, write docs to default location
    card_mapper --discover

    # Scan unknown card with APDU trace, save to specific directory
    card_mapper --discover --verbose --output-dir /tmp/card-docs/

    # Scan unknown card and scaffold a new plugin
    card_mapper --discover --scaffold mynewcard

    # Map Serbian eID applet from a card in the reader
    card_mapper --plugin eid --output docs/cards/applets/eid-serbian-applet.md

    # Map eMRTD applet with PACE-MRZ authentication
    card_mapper --plugin emrtd --mrz "P<SRBSMITH<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<1234567890SRB8501011M3012315<<<<<<<<<<<<<<02" --verbose

    # Map eMRTD applet with PACE-CAN authentication
    card_mapper --plugin emrtd --can 123456

    # Map CardEdge applet with PIN (prompts interactively)
    card_mapper --plugin cardedge --pin 0x80

    # Use a specific reader when multiple are connected
    card_mapper --discover --reader "Alcor Micro AU9560"

    # Full workflow: discover card, scaffold plugin, with trace
    card_mapper --discover --scaffold neweid --verbose --output-dir docs/cards/

SEE ALSO:
    docs/cards/              Generated documentation
    docs/CONTRIBUTING-PLUGIN.md  Guide for adding new plugins
)";
}

void printVersion()
{
    std::cout << "card_mapper version 0.1.0\n";
}
