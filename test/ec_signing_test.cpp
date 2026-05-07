// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "native/native_signing_service.h"
#include "types.h"
#include "signing_test_support.h"

#include <cstdlib>
#include <string>
#include <vector>

// EC card E2E signing test.
// Requires physical EC card: set LIBRESCRS_TEST_EC_PIN and LIBRESCRS_TEST_EC_TOKEN.
// Skips gracefully if env vars are not set.

using namespace libresign::test;

class ECSigningTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        SKIP_IF_PIN_FAILED();

        const char* pin = std::getenv("LIBRESCRS_TEST_EC_PIN");
        const char* token = std::getenv("LIBRESCRS_TEST_EC_TOKEN");

        if (!pin || !token) {
            GTEST_SKIP() << "EC card env vars not set (LIBRESCRS_TEST_EC_PIN, LIBRESCRS_TEST_EC_TOKEN)";
        }

        ecPin = pin;
        ecToken = token;
        pkcs11Module = pkcs11ModulePath();
    }

    std::string ecPin;
    std::string ecToken;
    std::string pkcs11Module;
};

TEST_F(ECSigningTest, CAdES_BB_ECDSA)
{
    libresign::NativeSigningService service;
    libresign::SigningRequest req;
    std::string content = "EC CAdES B-B test document.";
    req.document = std::vector<uint8_t>(content.begin(), content.end());
    req.fileName = "test.txt";
    req.format = libresign::SignatureFormat::CAdES;
    req.level = libresign::SignatureLevel::B_B;
    req.allowExpiredCertificate = true;

    auto result = service.sign(req, pkcs11Module, libresign::as_pin(ecPin), "", ecToken);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());
}

TEST_F(ECSigningTest, XAdES_BB_ECDSA_Detached)
{
    libresign::NativeSigningService service;
    libresign::SigningRequest req;
    std::string content = "EC XAdES B-B test document.";
    req.document = std::vector<uint8_t>(content.begin(), content.end());
    req.fileName = "test.xml";
    req.format = libresign::SignatureFormat::XAdES;
    req.level = libresign::SignatureLevel::B_B;
    req.packaging = libresign::SignaturePackaging::DETACHED;
    req.allowExpiredCertificate = true;

    auto result = service.sign(req, pkcs11Module, libresign::as_pin(ecPin), "", ecToken);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());
}

TEST_F(ECSigningTest, JAdES_BB_ECDSA)
{
    libresign::NativeSigningService service;
    libresign::SigningRequest req;
    std::string content = "EC JAdES B-B test document.";
    req.document = std::vector<uint8_t>(content.begin(), content.end());
    req.fileName = "test.txt";
    req.format = libresign::SignatureFormat::JAdES;
    req.level = libresign::SignatureLevel::B_B;
    req.allowExpiredCertificate = true;

    auto result = service.sign(req, pkcs11Module, libresign::as_pin(ecPin), "", ecToken);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());
}
