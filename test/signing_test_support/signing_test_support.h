// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "types.h"
#include <gtest/gtest.h>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

class DSSValidationClient;
namespace libresign {
class DSSServiceManager;
}

namespace libresign::test {

// ---- Test configuration from env vars ----
struct TestConfig
{
    std::string pin;          // LIBRESCRS_TEST_PIN
    std::string readerName;   // LIBRESCRS_TEST_READER (full PCSC reader name)
    std::string keyAlias;     // LIBRESCRS_TEST_KEY_ALIAS (empty = first signing key)
    std::string pkcs11Module; // auto-detected
    std::string dssJarPath;   // auto-detected
};

struct TestConfigResult
{
    TestConfig config;
    bool valid = false;
    std::string skipReason;
};

TestConfigResult readTestConfig();

// ---- PKCS#11 helpers ----
std::string pkcs11ModulePath();

// ---- PIN guard ----
extern bool g_pinFailed;
void checkPinFailure(const SigningResult& result);

#define SKIP_IF_PIN_FAILED()                                                                                           \
    do {                                                                                                               \
        if (::libresign::test::g_pinFailed)                                                                            \
            GTEST_SKIP() << "Skipped: previous PIN failure";                                                           \
    } while (0)

// ---- SoftHSM helper ----
// Requires SoftHSM2 setup:
//   softhsm2-util --init-token --slot 0 --label test-token --so-pin 0000 --pin 1234
//   pkcs11-tool --module <path>/libsofthsm2.so --login --pin 1234
//       --keypairgen --key-type rsa:2048 --label test-key
const char* findSoftHsmPath();

// ---- DSS test environment (shared instance for signing + validation) ----
class SigningTestEnvironment : public ::testing::Environment
{
public:
    void SetUp() override;
    void TearDown() override;
    static DSSValidationClient* validator();
    static bool available();
    static libresign::DSSServiceManager* manager();
    static bool trustConfigured();

private:
    struct Impl;
    static std::unique_ptr<Impl> impl;
};

/// Validate a signed document via the DSS oracle.
///
/// Asserts no signature reports `TOTAL_FAILED`. On oracle failure
/// (transport / parse / configuration), trips `ADD_FAILURE()` with the
/// diagnostic so the calling test fails loudly instead of being silently
/// skipped — DSS is a hard requirement, not optional.
///
/// @param result            Signing result whose `signedDocument` is validated.
/// @param format            ETSI signature format string (e.g. `"PAdES"`,
///                          `"XAdES"`, `"CAdES"`, `"JAdES"`, `"ASiC_E"`).
/// @param packaging         Packaging hint passed to the oracle
///                          (`"ENVELOPED"`, `"ENVELOPING"`, `"DETACHED"`).
/// @param originalDoc       Optional original document bytes — required for
///                          DETACHED signatures so the oracle can resolve the
///                          reference.
/// @param expectedSigCount  If set, assert the DSS oracle reports exactly
///                          this many signatures in the document.
/// @param expectedBaselineLevel
///                          If set, assert at least one signature reported by
///                          the oracle carries this ETSI baseline level
///                          string (e.g. `"PAdES_BASELINE_LT"`,
///                          `"PAdES_BASELINE_LTA"`, `"XAdES_BASELINE_LTA"`).
void validateSignature(const SigningResult& result, const std::string& format,
                       const std::string& packaging = "ENVELOPED", std::span<const uint8_t> originalDoc = {},
                       std::optional<int> expectedSigCount = std::nullopt,
                       std::optional<std::string> expectedBaselineLevel = std::nullopt);

// ---- Test data helpers ----
std::string buildTestPdf();
/// Multi-page variant — emits a minimal PDF with @p pageCount pages, each
/// 612 x 792 points. Used by the visual-signature tests that need to place
/// a signature on a non-first page.
std::string buildTestPdf(int pageCount);
std::string buildTestXml();

} // namespace libresign::test
