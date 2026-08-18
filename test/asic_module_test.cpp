// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/asic_module.h"
#include "native/pkcs11_module_manager.h"
#include "native/pkcs11_token.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"

// miniz declarations for ZIP reading in tests (implementation in LibreSign via miniz.c)
#include "miniz.h"

#include <cstring>

using namespace libresign;

class ASiCModuleSoftHSMTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
        auto slot = libresign::test::findSoftHsmTestSlot(manager.acquire(softHsmPath));
        if (!slot)
            GTEST_SKIP() << "SoftHSM2 token '" << libresign::test::kSoftHsmTokenLabel << "' not initialised";
        testSlot = *slot;
    }
    const char* softHsmPath = nullptr;
    libresign::Pkcs11ModuleManager manager;
    unsigned long testSlot = 0;
};

TEST_F(ASiCModuleSoftHSMTest, SignWithCAdES_ProducesValidZip)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    ASiCModule asic;

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    auto result = asic.signWithCAdES(data, "test.txt", token, SignatureLevel::B_B, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.signedDocument.empty());

    // Verify ZIP magic bytes (PK\x03\x04)
    ASSERT_GE(result.signedDocument.size(), 4u);
    EXPECT_EQ(result.signedDocument[0], 'P');
    EXPECT_EQ(result.signedDocument[1], 'K');

    // Parse ZIP and verify ASiC-E structure
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    ASSERT_TRUE(mz_zip_reader_init_mem(&zip, result.signedDocument.data(), result.signedDocument.size(), 0));

    int numFiles = static_cast<int>(mz_zip_reader_get_num_files(&zip));
    EXPECT_GE(numFiles, 4); // mimetype, document, manifest, signature

    // First entry must be "mimetype"
    char filename[256];
    mz_zip_reader_get_filename(&zip, 0, filename, sizeof(filename));
    EXPECT_STREQ(filename, "mimetype");

    // Verify mimetype is stored uncompressed (method 0)
    mz_zip_archive_file_stat stat;
    ASSERT_TRUE(mz_zip_reader_file_stat(&zip, 0, &stat));
    EXPECT_EQ(stat.m_method, 0u);

    // Extract and verify mimetype content
    size_t mimetypeSize = 0;
    void* mimetypeData = mz_zip_reader_extract_to_heap(&zip, 0, &mimetypeSize, 0);
    ASSERT_NE(mimetypeData, nullptr);
    std::string mimetypeStr(static_cast<char*>(mimetypeData), mimetypeSize);
    EXPECT_EQ(mimetypeStr, "application/vnd.etsi.asic-e+zip");
    free(mimetypeData); // NOLINT

    // Verify all expected entries exist
    EXPECT_GE(mz_zip_reader_locate_file(&zip, "test.txt", nullptr, 0), 0);
    // ETSI EN 319 162-1 names the per-signature manifest ASiCManifest<nnn>.xml
    // and pairs it with the signature entry carrying the same suffix.
    EXPECT_GE(mz_zip_reader_locate_file(&zip, "META-INF/ASiCManifest001.xml", nullptr, 0), 0);
    EXPECT_GE(mz_zip_reader_locate_file(&zip, "META-INF/signature001.p7s", nullptr, 0), 0);

    // Verify document content round-trips
    int docIdx = mz_zip_reader_locate_file(&zip, "test.txt", nullptr, 0);
    ASSERT_GE(docIdx, 0);
    size_t docSize = 0;
    void* docData = mz_zip_reader_extract_to_heap(&zip, static_cast<mz_uint>(docIdx), &docSize, 0);
    ASSERT_NE(docData, nullptr);
    std::vector<uint8_t> extracted(static_cast<uint8_t*>(docData), static_cast<uint8_t*>(docData) + docSize);
    EXPECT_EQ(extracted, data);
    free(docData); // NOLINT

    // Verify signature is valid DER (starts with SEQUENCE tag 0x30)
    int sigIdx = mz_zip_reader_locate_file(&zip, "META-INF/signature001.p7s", nullptr, 0);
    ASSERT_GE(sigIdx, 0);
    size_t sigSize = 0;
    void* sigData = mz_zip_reader_extract_to_heap(&zip, static_cast<mz_uint>(sigIdx), &sigSize, 0);
    ASSERT_NE(sigData, nullptr);
    ASSERT_GT(sigSize, 0u);
    EXPECT_EQ(static_cast<uint8_t*>(sigData)[0], 0x30);
    free(sigData); // NOLINT

    mz_zip_reader_end(&zip);
}

#else
TEST(ASiCModuleTest, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif
