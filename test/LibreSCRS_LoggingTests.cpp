// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Unit cover for the public logging facade LibreSCRS::log.
//
// Every case that installs a sink must leave the process as it found it: the
// facade is a process-global, the sinks below capture stack locals by
// reference, and a leaked sink outliving its captures is a use-after-free in
// whatever case runs next. TearDown() — not the end of the test body — does
// the restore, because a failing ASSERT_* returns early and would skip it.

#include <LibreSCRS/Logging.h>

#include <gtest/gtest.h>

#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

struct Captured
{
    LibreSCRS::log::Level level;
    std::string line;
};

class LoggingFacadeTest : public ::testing::Test
{
protected:
    void TearDown() override
    {
        LibreSCRS::log::resetForTest();
    }

    std::vector<Captured> captured;

    void installCapturingSink(std::string category = "test.librescrs")
    {
        LibreSCRS::log::init([this](LibreSCRS::log::Level level,
                                    std::string_view line) { captured.push_back({level, std::string(line)}); },
                             std::move(category));
    }
};

TEST_F(LoggingFacadeTest, SinkReceivesSeverityAndFormattedLine)
{
    installCapturingSink();

    LibreSCRS::log::info("first");
    LibreSCRS::log::warn("second");
    LibreSCRS::log::error("third");

    ASSERT_EQ(captured.size(), 3u);
    EXPECT_EQ(captured[0].level, LibreSCRS::log::Level::Info);
    EXPECT_EQ(captured[1].level, LibreSCRS::log::Level::Warn);
    EXPECT_EQ(captured[2].level, LibreSCRS::log::Level::Error);

    // The layout is a contract, not an implementation detail: journald reads
    // the leading <N> syslog priority off the front of the line, and the
    // LibreAgent/LibreLinux/LibreDarwin facades emit the identical shape.
    EXPECT_EQ(captured[0].line, "<6>test.librescrs info: first\n");
    EXPECT_EQ(captured[1].line, "<4>test.librescrs warning: second\n");
    EXPECT_EQ(captured[2].line, "<3>test.librescrs error: third\n");
}

TEST_F(LoggingFacadeTest, FormattingVariantsSubstituteArguments)
{
    installCapturingSink("test.fmt");

    LibreSCRS::log::infof("reader {} of {}", 2, 5);
    LibreSCRS::log::warnf("backing off {}ms", 250);
    LibreSCRS::log::errorf("callback threw: {}", std::string_view{"boom"});

    ASSERT_EQ(captured.size(), 3u);
    EXPECT_EQ(captured[0].line, "<6>test.fmt info: reader 2 of 5\n");
    EXPECT_EQ(captured[1].line, "<4>test.fmt warning: backing off 250ms\n");
    EXPECT_EQ(captured[2].line, "<3>test.fmt error: callback threw: boom\n");
}

TEST_F(LoggingFacadeTest, CategoryIsWhateverTheConsumerInjected)
{
    installCapturingSink("com.example.host");
    LibreSCRS::log::info("hello");

    ASSERT_EQ(captured.size(), 1u);
    EXPECT_NE(captured[0].line.find("com.example.host"), std::string::npos);
    EXPECT_EQ(captured[0].line.find("rs.librescrs"), std::string::npos);
}

TEST_F(LoggingFacadeTest, EmptySinkFallsBackToTheBuiltInStream)
{
    // init() with an empty std::function is the documented way back to the
    // built-in sink without going through the test-only reset.
    installCapturingSink();
    LibreSCRS::log::init(LibreSCRS::log::LogSink{}, "test.fallback");

    std::ostringstream sink;
    auto* previous = std::clog.rdbuf(sink.rdbuf());
    LibreSCRS::log::warn("to the stream");
    std::clog.rdbuf(previous);

    EXPECT_TRUE(captured.empty()) << "an emptied sink must stop receiving lines";
    EXPECT_EQ(sink.str(), "<4>test.fallback warning: to the stream\n");
}

TEST_F(LoggingFacadeTest, ResetForTestDropsTheSinkAndTheCategory)
{
    installCapturingSink("test.leaky");
    LibreSCRS::log::info("captured");
    ASSERT_EQ(captured.size(), 1u);

    LibreSCRS::log::resetForTest();

    std::ostringstream sink;
    auto* previous = std::clog.rdbuf(sink.rdbuf());
    LibreSCRS::log::info("after reset");
    std::clog.rdbuf(previous);

    EXPECT_EQ(captured.size(), 1u) << "resetForTest left the injected sink installed";
    // Both halves of the reset are asserted: the sink is gone AND the default
    // category is back. A reset that only dropped the sink would leave the
    // next case emitting under the previous test's category.
    EXPECT_EQ(sink.str(), "<6>rs.librescrs info: after reset\n");
}

} // namespace
