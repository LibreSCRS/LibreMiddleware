// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "native/native_signing_service.h"
#include "signing_test_support.h"
#include "types.h"

#include <cstdlib>
#include <string>
#include <vector>

// EC card E2E signing tests. Two layers:
//
//   1. Single-format smoke tests at B-B for CAdES / XAdES-Detached / JAdES.
//      Gated on LIBRESCRS_TEST_EC_PIN + LIBRESCRS_TEST_EC_TOKEN; skip if
//      unset.
//   2. Parametric matrix at B-LTA across every format and packaging the
//      signing service supports. Additionally gated on
//      LIBRESCRS_TEST_EC_CURVE — when unset the matrix tests skip outright
//      (curve provides the per-card curve hint used by the test selector).
//
// The matrix covers the same shape as the RSA E2E suite so an EC-equipped
// card exercises the LT/LTA paths alongside the existing RSA coverage.

using namespace libresign::test;

namespace {
struct ECEnv
{
    std::string pin;
    std::string token;
    std::string curve;
    std::string module;
    bool valid = false;
    std::string skipReason;
};

ECEnv readECEnv()
{
    ECEnv env;
    const char* pin = std::getenv("LIBRESCRS_TEST_EC_PIN");
    const char* token = std::getenv("LIBRESCRS_TEST_EC_TOKEN");
    if (!pin || !token) {
        env.skipReason = "EC card env vars not set (LIBRESCRS_TEST_EC_PIN, LIBRESCRS_TEST_EC_TOKEN)";
        return env;
    }
    env.pin = pin;
    env.token = token;
    env.module = pkcs11ModulePath();

    const char* curve = std::getenv("LIBRESCRS_TEST_EC_CURVE");
    if (curve)
        env.curve = curve;

    env.valid = true;
    return env;
}
} // namespace

class ECSigningTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        SKIP_IF_PIN_FAILED();
        env = readECEnv();
        if (!env.valid)
            GTEST_SKIP() << env.skipReason;
    }

    ECEnv env;
};

TEST_F(ECSigningTest, CAdES_BB_ECDSA)
{
    libresign::NativeSigningService service;
    libresign::SigningRequest req;
    std::string content = "EC CAdES B-B test document.";
    req.document = std::vector<uint8_t>(content.begin(), content.end());
    req.fileName = "test.txt";
    req.format = libresign::SignatureFormat::Cades;
    req.level = libresign::SignatureLevel::B_B;
    req.allowExpiredCertificate = true;

    auto result = service.sign(req, env.module, libresign::as_pin(env.pin), "", env.token);
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
    req.format = libresign::SignatureFormat::Xades;
    req.level = libresign::SignatureLevel::B_B;
    req.packaging = libresign::SignaturePackaging::Detached;
    req.allowExpiredCertificate = true;

    auto result = service.sign(req, env.module, libresign::as_pin(env.pin), "", env.token);
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
    req.format = libresign::SignatureFormat::Jades;
    req.level = libresign::SignatureLevel::B_B;
    req.allowExpiredCertificate = true;

    auto result = service.sign(req, env.module, libresign::as_pin(env.pin), "", env.token);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());
}

// ---- Parametric B-LTA matrix across every format and packaging ----

struct ECCase
{
    const char* name;
    libresign::SignatureFormat fmt;
    libresign::SignatureLevel lvl;
    libresign::SignaturePackaging pkg;
};

std::ostream& operator<<(std::ostream& os, const ECCase& c)
{
    return os << c.name;
}

class ECSigningMatrixTest : public ::testing::TestWithParam<ECCase>
{
protected:
    void SetUp() override
    {
        SKIP_IF_PIN_FAILED();
        env = readECEnv();
        if (!env.valid)
            GTEST_SKIP() << env.skipReason;
        if (env.curve.empty())
            GTEST_SKIP() << "LIBRESCRS_TEST_EC_CURVE not set (P-256 / P-384 / P-521)";
    }

    ECEnv env;
};

TEST_P(ECSigningMatrixTest, SignsAtLevelAndFormat)
{
    SKIP_IF_PIN_FAILED();
    const auto& tc = GetParam();

    libresign::NativeSigningService service;
    libresign::SigningRequest req;
    std::string content = std::string("EC matrix: ") + tc.name;

    // Format-specific minimal payload — PAdES wants a real PDF; everything
    // else is happy with raw bytes.
    if (tc.fmt == libresign::SignatureFormat::Pades) {
        auto pdf = buildTestPdf();
        req.document = std::vector<uint8_t>(pdf.begin(), pdf.end());
        req.fileName = "test.pdf";
    } else {
        req.document = std::vector<uint8_t>(content.begin(), content.end());
        req.fileName = "test.bin";
    }
    req.format = tc.fmt;
    req.level = tc.lvl;
    req.packaging = tc.pkg;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result = service.sign(req, env.module, libresign::as_pin(env.pin), "", env.token);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << "EC " << tc.name << " sign: " << result.errorMessage;
    EXPECT_FALSE(result.signedDocument.empty());
}

INSTANTIATE_TEST_SUITE_P(
    ECMatrix, ECSigningMatrixTest,
    ::testing::Values(ECCase{"CAdES_BLTA", libresign::SignatureFormat::Cades, libresign::SignatureLevel::B_LTA,
                             libresign::SignaturePackaging::Detached},
                      ECCase{"PAdES_BLTA", libresign::SignatureFormat::Pades, libresign::SignatureLevel::B_LTA,
                             libresign::SignaturePackaging::Enveloped},
                      ECCase{"XAdES_BLTA_Det", libresign::SignatureFormat::Xades, libresign::SignatureLevel::B_LTA,
                             libresign::SignaturePackaging::Detached},
                      ECCase{"XAdES_BLTA_Env", libresign::SignatureFormat::Xades, libresign::SignatureLevel::B_LTA,
                             libresign::SignaturePackaging::Enveloped},
                      ECCase{"JAdES_BLTA", libresign::SignatureFormat::Jades, libresign::SignatureLevel::B_LTA,
                             libresign::SignaturePackaging::Detached},
                      ECCase{"AsicE_BLTA", libresign::SignatureFormat::AsicE, libresign::SignatureLevel::B_LTA,
                             libresign::SignaturePackaging::Detached}),
    [](const ::testing::TestParamInfo<ECCase>& info) { return std::string{info.param.name}; });
