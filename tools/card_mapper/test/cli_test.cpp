// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "cli_options.h"

#include <gtest/gtest.h>

TEST(CliOptions, DiscoverModeDefault)
{
    const char* argv[] = {"card_mapper", "--discover"};
    auto opts = parseOptions(2, argv);
    EXPECT_TRUE(opts.discover);
    EXPECT_FALSE(opts.pluginMode);
    EXPECT_EQ(opts.outputDir, "docs/cards/");
    EXPECT_FALSE(opts.verbose);
}

TEST(CliOptions, PluginModeWithOutput)
{
    const char* argv[] = {"card_mapper", "--plugin", "eid", "--output", "out.md"};
    auto opts = parseOptions(5, argv);
    EXPECT_FALSE(opts.discover);
    EXPECT_TRUE(opts.pluginMode);
    EXPECT_EQ(opts.pluginName, "eid");
    EXPECT_EQ(opts.outputFile, "out.md");
}

TEST(CliOptions, DiscoverWithScaffold)
{
    const char* argv[] = {"card_mapper", "--discover", "--scaffold", "newcard"};
    auto opts = parseOptions(4, argv);
    EXPECT_TRUE(opts.discover);
    EXPECT_TRUE(opts.scaffold);
    EXPECT_EQ(opts.scaffoldName, "newcard");
}

TEST(CliOptions, VerboseFlag)
{
    const char* argv[] = {"card_mapper", "--discover", "--verbose"};
    auto opts = parseOptions(3, argv);
    EXPECT_TRUE(opts.verbose);
}

TEST(CliOptions, ReaderSelection)
{
    const char* argv[] = {"card_mapper", "--discover", "--reader", "Alcor Micro"};
    auto opts = parseOptions(4, argv);
    EXPECT_EQ(opts.readerName, "Alcor Micro");
}

TEST(CliOptions, AuthFlags)
{
    const char* argv[] = {"card_mapper", "--plugin", "emrtd", "--mrz", "P<SRB..."};
    auto opts = parseOptions(5, argv);
    EXPECT_EQ(opts.mrz, "P<SRB...");
}

TEST(CliOptions, CanAuth)
{
    const char* argv[] = {"card_mapper", "--plugin", "emrtd", "--can", "123456"};
    auto opts = parseOptions(5, argv);
    EXPECT_EQ(opts.can, "123456");
}

TEST(CliOptions, PinRef)
{
    const char* argv[] = {"card_mapper", "--plugin", "cardedge", "--pin", "0x80"};
    auto opts = parseOptions(5, argv);
    EXPECT_TRUE(opts.pinRequested);
    EXPECT_EQ(opts.pinRef, 0x80);
}

TEST(CliOptions, OutputDir)
{
    const char* argv[] = {"card_mapper", "--discover", "--output-dir", "/tmp/docs/"};
    auto opts = parseOptions(4, argv);
    EXPECT_EQ(opts.outputDir, "/tmp/docs/");
}

TEST(CliOptions, HelpFlag)
{
    const char* argv[] = {"card_mapper", "--help"};
    auto opts = parseOptions(2, argv);
    EXPECT_TRUE(opts.help);
}

TEST(CliOptions, VersionFlag)
{
    const char* argv[] = {"card_mapper", "--version"};
    auto opts = parseOptions(2, argv);
    EXPECT_TRUE(opts.version);
}

TEST(CliOptions, NoModeFails)
{
    const char* argv[] = {"card_mapper"};
    EXPECT_THROW(parseOptions(1, argv), std::runtime_error);
}

TEST(CliOptions, BothModesFails)
{
    const char* argv[] = {"card_mapper", "--discover", "--plugin", "eid"};
    EXPECT_THROW(parseOptions(4, argv), std::runtime_error);
}

TEST(CliOptions, ScaffoldWithoutDiscoverFails)
{
    const char* argv[] = {"card_mapper", "--plugin", "eid", "--scaffold", "newcard"};
    EXPECT_THROW(parseOptions(5, argv), std::runtime_error);
}

TEST(CliOptions, OutputWithDiscoverDoesNotFail)
{
    // --output-dir is valid with --discover; --output is only valid with --plugin
    const char* argv[] = {"card_mapper", "--discover"};
    EXPECT_NO_THROW(parseOptions(2, argv));
}
