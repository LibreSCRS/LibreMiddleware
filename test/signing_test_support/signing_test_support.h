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
} // namespace libresign

namespace libresign::test {

// ---- Test configuration from env vars ----
struct TestConfig
{
    std::string pin;        // LIBRESCRS_TEST_PIN
    std::string readerName; // LIBRESCRS_TEST_READER (full PCSC reader name)
    std::string keyAlias;   // LIBRESCRS_TEST_KEY_ALIAS (empty = first signing key)
    std::string dssJarPath; // auto-detected
};

struct TestConfigResult
{
    TestConfig config;
    bool valid = false;
    std::string skipReason;
};

TestConfigResult readTestConfig();

// ---- PIN guard ----
extern bool g_pinFailed;
/// Latch @ref g_pinFailed and skip when the card refused the PIN or reports it
/// blocked, so no later test spends another try.
void checkPinFailure(const SigningResult& result);

#define SKIP_IF_PIN_FAILED()                                                                                           \
    do {                                                                                                               \
        if (::libresign::test::g_pinFailed)                                                                            \
            GTEST_SKIP() << "Skipped: previous PIN failure";                                                           \
    } while (0)

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

/// @brief Is the ETSI validation oracle mandatory for this run?
///
/// `LIBRESCRS_REQUIRE_DSS_ORACLE=1` turns every quiet return into a hard
/// failure: a missing archive fails the environment instead of printing a
/// note, and @ref validateSignature fails the test instead of returning. CI
/// runs in that mode on the leg that compiles the oracle in. The default
/// stays the specified behaviour — skip silently when the oracle is absent —
/// so a developer without a JRE is not blocked.
bool dssOracleIsMandatory();

/// @brief Is the trust configuration POST enabled for this run?
///
/// `LIBRESCRS_TEST_DSS_TRUST=1`. Off by default: the levels and the structural
/// warnings this suite asserts are properties of the bytes, and they were
/// correct under `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND` too. Leaving it
/// off makes the leg hermetic apart from the Maven fetch.
bool dssTrustConfigRequested();

/// Validate a signed document via the DSS oracle.
///
/// Asserts no signature reports `TOTAL_FAILED`, that no signature carries a
/// structural-invalidity warning, and that at least one signature carries
/// @p expectedBaselineLevel. On oracle failure (transport / parse /
/// configuration), trips `ADD_FAILURE()` with the diagnostic so the calling
/// test fails loudly instead of being silently skipped.
///
/// @param result            Signing result whose `signedDocument` is validated.
/// @param format            ETSI signature format string (e.g. `"PAdES"`,
///                          `"XAdES"`, `"CAdES"`, `"JAdES"`, `"ASiC_E"`).
/// @param expectedBaselineLevel
///                          The ETSI baseline level at least one signature
///                          reported by the oracle MUST carry (e.g.
///                          `"PAdES_BASELINE_B"`, `"XAdES_BASELINE_LTA"`).
///                          Mandatory, and deliberately so: it was optional
///                          and supplied at four of forty-three call sites,
///                          which is how a whole format shipped a level below
///                          what the product claims past a green suite.
/// @param packaging         Packaging hint passed to the oracle
///                          (`"ENVELOPED"`, `"ENVELOPING"`, `"DETACHED"`).
/// @param originalDoc       Optional original document bytes — required for
///                          DETACHED signatures so the oracle can resolve the
///                          reference.
/// @param expectedSigCount  If set, assert the DSS oracle reports exactly
///                          this many signatures in the document.
void validateSignature(const SigningResult& result, const std::string& format, const std::string& expectedBaselineLevel,
                       const std::string& packaging = "ENVELOPED", std::span<const uint8_t> originalDoc = {},
                       std::optional<int> expectedSigCount = std::nullopt);

// ---- Test data helpers ----
std::string buildTestPdf();
/// Multi-page variant — emits a minimal PDF with @p pageCount pages, each
/// 612 x 792 points. Used by the visual-signature tests that need to place
/// a signature on a non-first page.
std::string buildTestPdf(int pageCount);
std::string buildTestXml();

} // namespace libresign::test
