// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "native/pades_module.h"
#include "native/pkcs11_module_manager.h"
#include "native/pkcs11_token.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

using namespace libresign;
namespace fs = std::filesystem;

namespace {

bool haveTool(const char* cmd)
{
    std::string probe = std::string(cmd) + " -v >/dev/null 2>&1";
    return std::system(probe.c_str()) == 0;
}

std::string runPdftotext(const fs::path& pdf)
{
    fs::path txt = pdf;
    txt.replace_extension(".txt");
    std::string cmd = "pdftotext -layout '" + pdf.string() + "' '" + txt.string() + "'";
    int rc = std::system(cmd.c_str());
    if (rc != 0)
        return {};
    std::ifstream in(txt);
    std::string contents((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return contents;
}

std::vector<uint8_t> testPdfBytes()
{
    auto s = libresign::test::buildTestPdf();
    return {s.begin(), s.end()};
}

class PAdESUnicodeE2ETest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
        if (!haveTool("pdftotext"))
            GTEST_SKIP() << "pdftotext (poppler-utils) not installed";
    }
    const char* softHsmPath = nullptr;
    libresign::Pkcs11ModuleManager manager;
};

} // namespace

TEST_F(PAdESUnicodeE2ETest, SerbianLatinSignerIsSearchable)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{0});
    PAdESModule pades;

    VisualSignatureParams v;
    v.enabled = true;
    v.page = -1;
    v.x = 50;
    v.y = 50;
    v.width = 250;
    v.height = 60;
    v.text = "Potpisao: Hiršl Ćirković\nDatum: 2026-04-24";

    auto result = pades.sign(testPdfBytes(), token, SignatureLevel::B_B, {}, v);
    ASSERT_TRUE(result.success) << result.errorMessage;

    fs::path out = fs::temp_directory_path() / "pades_unicode_latin.pdf";
    std::ofstream(out, std::ios::binary)
        .write(reinterpret_cast<const char*>(result.signedDocument.data()),
               static_cast<std::streamsize>(result.signedDocument.size()));

    std::string extracted = runPdftotext(out);
    EXPECT_NE(extracted.find("Hiršl"), std::string::npos) << "pdftotext output did not contain 'Hiršl'. Extracted:\n"
                                                          << extracted;
    EXPECT_NE(extracted.find("Ćirković"), std::string::npos);
    EXPECT_NE(extracted.find("2026-04-24"), std::string::npos);
    fs::remove(out);
    fs::remove(fs::path(out).replace_extension(".txt"));
}

TEST_F(PAdESUnicodeE2ETest, SerbianCyrillicSignerIsSearchable)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{0});
    PAdESModule pades;

    VisualSignatureParams v;
    v.enabled = true;
    v.page = -1;
    v.x = 50;
    v.y = 50;
    v.width = 250;
    v.height = 60;
    v.text = "Потписао: Петар Петровић\nДатум: 2026-04-24";

    auto result = pades.sign(testPdfBytes(), token, SignatureLevel::B_B, {}, v);
    ASSERT_TRUE(result.success) << result.errorMessage;

    fs::path out = fs::temp_directory_path() / "pades_unicode_cyr.pdf";
    std::ofstream(out, std::ios::binary)
        .write(reinterpret_cast<const char*>(result.signedDocument.data()),
               static_cast<std::streamsize>(result.signedDocument.size()));

    std::string extracted = runPdftotext(out);
    EXPECT_NE(extracted.find("Петар"), std::string::npos) << "pdftotext output did not contain 'Петар'. Extracted:\n"
                                                          << extracted;
    EXPECT_NE(extracted.find("Петровић"), std::string::npos);
    fs::remove(out);
    fs::remove(fs::path(out).replace_extension(".txt"));
}

TEST_F(PAdESUnicodeE2ETest, MixedSignerIsSearchable)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{0});
    PAdESModule pades;

    VisualSignatureParams v;
    v.enabled = true;
    v.page = -1;
    v.x = 50;
    v.y = 50;
    v.width = 300;
    v.height = 70;
    v.text = "Signed by: Hiršl (Латиница + Ћирилица)\nДатум / Date: 2026-04-24";

    auto result = pades.sign(testPdfBytes(), token, SignatureLevel::B_B, {}, v);
    ASSERT_TRUE(result.success) << result.errorMessage;

    fs::path out = fs::temp_directory_path() / "pades_unicode_mixed.pdf";
    std::ofstream(out, std::ios::binary)
        .write(reinterpret_cast<const char*>(result.signedDocument.data()),
               static_cast<std::streamsize>(result.signedDocument.size()));

    std::string extracted = runPdftotext(out);
    EXPECT_NE(extracted.find("Hiršl"), std::string::npos);
    EXPECT_NE(extracted.find("Латиница"), std::string::npos);
    EXPECT_NE(extracted.find("Ћирилица"), std::string::npos);
    fs::remove(out);
    fs::remove(fs::path(out).replace_extension(".txt"));
}
