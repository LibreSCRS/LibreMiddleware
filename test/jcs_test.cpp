// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "native/jcs.h"

#include <json.hpp>

#include <limits>
#include <stdexcept>
#include <string>

using libresign::jcsDump;

TEST(JCS, SimpleObjectSortsKeys)
{
    nlohmann::json j = nlohmann::json::parse(R"({"b":1,"a":2})");
    EXPECT_EQ(jcsDump(j), R"({"a":2,"b":1})");
}

TEST(JCS, NestedObjects)
{
    nlohmann::json j = nlohmann::json::parse(R"({"z":{"y":1,"x":2},"a":3})");
    EXPECT_EQ(jcsDump(j), R"({"a":3,"z":{"x":2,"y":1}})");
}

TEST(JCS, ArraysPreserveOrder)
{
    nlohmann::json j = nlohmann::json::parse(R"([{"b":1,"a":2},3])");
    EXPECT_EQ(jcsDump(j), R"([{"a":2,"b":1},3])");
}

TEST(JCS, StringEscapes)
{
    nlohmann::json j = nlohmann::json::parse(R"({"k":"hello\nworld"})");
    EXPECT_EQ(jcsDump(j), R"({"k":"hello\nworld"})");
}

TEST(JCS, RFC8785_Example1_Sort)
{
    // RFC 8785 §3.2.3 — keys sorted lexicographically.
    nlohmann::json j = nlohmann::json::parse(R"({"c":1,"a":2,"b":3})");
    EXPECT_EQ(jcsDump(j), R"({"a":2,"b":3,"c":1})");
}

TEST(JCS, UnicodeEscapesPreservedInPassthrough)
{
    // Multi-byte UTF-8 values pass through without \uXXXX escaping
    // per RFC 8785 §3.2.4 (canonical form is UTF-8).
    nlohmann::json j = nlohmann::json::parse(R"({"k":"ščć"})");
    EXPECT_EQ(jcsDump(j), R"({"k":"ščć"})");
}

TEST(JCS, IntegerNotFloat)
{
    nlohmann::json j;
    j["count"] = 42;
    EXPECT_EQ(jcsDump(j), R"({"count":42})");
}

TEST(JCS, NestedArrayOfObjects)
{
    nlohmann::json j = nlohmann::json::parse(R"([{"b":2,"a":1},{"d":4,"c":3}])");
    EXPECT_EQ(jcsDump(j), R"([{"a":1,"b":2},{"c":3,"d":4}])");
}

TEST(JCS, NonAsciiKeyThrows)
{
    nlohmann::json j;
    j["ščć"] = 1;
    EXPECT_THROW(jcsDump(j), std::runtime_error);
}

TEST(JCS, NonFiniteNumberThrows)
{
    nlohmann::json j;
    j["x"] = std::numeric_limits<double>::infinity();
    EXPECT_THROW(jcsDump(j), std::runtime_error);
}

TEST(JCS, ControlCharsEscaped)
{
    nlohmann::json j;
    std::string v;
    v.push_back('a');
    v.push_back(static_cast<char>(0x01));
    v.push_back('b');
    j["k"] = v;
    EXPECT_EQ(jcsDump(j), "{\"k\":\"a\\u0001b\"}");
}

TEST(JCS, NullAndBoolPrimitives)
{
    nlohmann::json j;
    j["a"] = nullptr;
    j["b"] = true;
    j["c"] = false;
    EXPECT_EQ(jcsDump(j), R"({"a":null,"b":true,"c":false})");
}
