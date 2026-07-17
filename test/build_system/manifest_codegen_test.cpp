// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// 4.0 hardening: codegen golden-output test for manifest2header.py.
// The Python tool lowers the per-plugin manifest.json into a constexpr
// header consumed by the plugin's supportedAtrs() override; this test
// pins the exact textual output and confirms invalid manifests are
// rejected at codegen time (schema gate, not later at compile time).

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

namespace {

std::string readFile(const fs::path& p)
{
    std::ifstream in(p);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

} // namespace

TEST(ManifestCodegen, GoldenOutputMatches)
{
    const fs::path fixtures{LIBRESCRS_FIXTURE_DIR};
    const fs::path generated = fs::temp_directory_path() / "_librescrs_generated_manifest.h";

    const std::string command = std::string{LIBRESCRS_PYTHON_EXECUTABLE} + " " + LIBRESCRS_MANIFEST2HEADER_PATH +
                                " --input " + (fixtures / "sample_manifest.json").string() + " --output " +
                                generated.string() + " --schema " + LIBRESCRS_MANIFEST_SCHEMA_PATH;
    const int rc = std::system(command.c_str());
    ASSERT_EQ(rc, 0) << "manifest2header invocation failed";

    EXPECT_EQ(readFile(generated), readFile(fixtures / "expected_manifest.h"));
}

TEST(ManifestCodegen, InvalidManifestRejected)
{
    const fs::path fixtures{LIBRESCRS_FIXTURE_DIR};
    const fs::path generated = fs::temp_directory_path() / "_librescrs_invalid_manifest.h";

    const std::string command = std::string{LIBRESCRS_PYTHON_EXECUTABLE} + " " + LIBRESCRS_MANIFEST2HEADER_PATH +
                                " --input " + (fixtures / "invalid_manifest.json").string() + " --output " +
                                generated.string() + " --schema " + LIBRESCRS_MANIFEST_SCHEMA_PATH + " >/dev/null 2>&1";
    const int rc = std::system(command.c_str());
    EXPECT_NE(rc, 0) << "invalid manifest should have been rejected by schema validation";
}

// Belt-and-braces: even if jsonschema is silently bypassed (stripped CI
// image, future schema relaxation, etc.), the pluginId regex inside
// manifest2header.py must reject identifiers that would corrupt the
// generated `namespace` declaration. The malformed fixture uses a
// pluginId crafted to break out of the `namespace { … }` block; the
// codegen must fail with a non-zero exit before any output is written.
TEST(ManifestCodegen, MalformedPluginIdRejected)
{
    const fs::path fixtures{LIBRESCRS_FIXTURE_DIR};
    const fs::path generated = fs::temp_directory_path() / "_librescrs_malformed_plugin_id.h";

    const std::string command = std::string{LIBRESCRS_PYTHON_EXECUTABLE} + " " + LIBRESCRS_MANIFEST2HEADER_PATH +
                                " --input " + (fixtures / "malformed_plugin_id_manifest.json").string() + " --output " +
                                generated.string() + " --schema " + LIBRESCRS_MANIFEST_SCHEMA_PATH + " >/dev/null 2>&1";
    const int rc = std::system(command.c_str());
    EXPECT_NE(rc, 0) << "malformed pluginId must be rejected before C++ codegen";
}
