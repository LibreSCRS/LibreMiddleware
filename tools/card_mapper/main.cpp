// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "apdu_logger.h"
#include "card_scanner.h"
#include "cli_options.h"
#include "output_formatter.h"
#include "plugin_mapper.h"
#include "scaffold_generator.h"

#include <emrtd/emrtd_card.h>
#include <smartcard/pcsc_connection.h>

#include <cstdlib>
#include <memory>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace {

std::string getReaderName(const CliOptions& opts)
{
    if (!opts.readerName.empty()) {
        return opts.readerName;
    }

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty()) {
        throw std::runtime_error("no PC/SC readers found");
    }
    return readers[0];
}

void writeToFile(const std::string& path, const std::string& content)
{
    std::filesystem::path filepath(path);
    std::filesystem::create_directories(filepath.parent_path());

    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("cannot open file for writing: " + path);
    }
    out << content;
    std::cerr << "Wrote: " << path << "\n";
}

int runPluginMode(const CliOptions& opts)
{
    auto readerName = getReaderName(opts);
    smartcard::PCSCConnection conn(readerName);

    auto appletInfo = card_mapper::mapPlugin(opts.pluginName, conn, opts.verbose);
    auto doc = card_mapper::formatAppletDoc(appletInfo);

    if (!opts.outputFile.empty()) {
        writeToFile(opts.outputFile, doc);
    } else {
        std::cout << doc;
    }

    return EXIT_SUCCESS;
}

int runDiscoverMode(const CliOptions& opts)
{
    auto readerName = getReaderName(opts);
    smartcard::PCSCConnection conn(readerName);

    // PACE authentication + SM filter — enables scanning applets
    // that require prior authentication (e.g. PKCS#15 on contactless)
    std::unique_ptr<emrtd::EMRTDCard> emrTDCard;
    if (!opts.can.empty()) {
        emrTDCard = std::make_unique<emrtd::EMRTDCard>(conn, opts.can);
        auto authResult = emrTDCard->authenticate();
        if (!authResult.success)
            throw std::runtime_error("PACE failed: " + authResult.error);
        std::cerr << "PACE authentication: OK (SM active)\n";

        conn.setTransmitFilter(
            [&emrTDCard](const smartcard::APDUCommand& cmd) { return emrTDCard->transmitSecureAPDU(cmd); });
    }

    auto scanResult = card_mapper::discoverCard(conn, opts.verbose);

    // Output applet docs
    for (const auto& applet : scanResult.detectedApplets) {
        auto doc = card_mapper::formatAppletDoc(applet);

        if (opts.outputDir.empty() || opts.outputDir == "-") {
            std::cout << doc << "\n---\n\n";
        } else {
            std::string filename = applet.pluginName + "-applet.md";
            writeToFile(opts.outputDir + "/applets/" + filename, doc);
        }
    }

    // Output profile doc
    auto profileDoc = card_mapper::formatProfileDoc(scanResult.profile);
    if (opts.outputDir.empty() || opts.outputDir == "-") {
        std::cout << profileDoc;
    } else {
        std::string profileFilename = scanResult.profile.name + ".md";
        writeToFile(opts.outputDir + "/profiles/" + profileFilename, profileDoc);
    }

    // Scaffold if requested
    if (opts.scaffold) {
        auto header = card_mapper::generateProtocolHeader(opts.scaffoldName, scanResult);
        auto headerPath = "lib/" + opts.scaffoldName + "/src/" + opts.scaffoldName + "_protocol.h";
        writeToFile(headerPath, header);
    }

    // Summary
    std::cerr << "\nScan summary:\n";
    std::cerr << "  ATR: " << card_mapper::formatHex(scanResult.atr) << "\n";
    std::cerr << "  Detected applets: " << scanResult.detectedApplets.size() << "\n";
    std::cerr << "  Profile: " << scanResult.profile.name << "\n";

    return EXIT_SUCCESS;
}

} // anonymous namespace

int main(int argc, const char* argv[])
{
    try {
        auto opts = parseOptions(argc, argv);
        if (opts.help) {
            printHelp();
            return EXIT_SUCCESS;
        }
        if (opts.version) {
            printVersion();
            return EXIT_SUCCESS;
        }

        if (opts.pluginMode) {
            return runPluginMode(opts);
        } else if (opts.discover) {
            return runDiscoverMode(opts);
        }

        std::cerr << "card_mapper: no mode selected\n";
        return EXIT_FAILURE;
    } catch (const std::exception& e) {
        std::cerr << "card_mapper: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
}
