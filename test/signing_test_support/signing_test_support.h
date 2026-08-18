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
class Pkcs11ModuleHandle;
} // namespace libresign

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

// ---- SoftHSM helpers ----
// Requires SoftHSM2 setup. A bare `--keypairgen` is NOT enough: every
// format module reads the signer certificate off the token, so a token
// carrying only a key pair fails the whole tier with "No certificate
// found on token". Import a key + matching certificate under one CKA_ID:
//
//   softhsm2-util --init-token --slot 0 --label test-token --so-pin 0000 --pin 1234
//   openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
//       -keyout key.pem -out cert.pem -subj "/CN=LibreSCRS SoftHSM Test Signer"
//   openssl rsa  -in key.pem  -outform DER -out key.der
//   openssl x509 -in cert.pem -outform DER -out cert.der
//   pkcs11-tool --module <path>/libsofthsm2.so --login --pin 1234 \
//       --write-object key.der  --type privkey --label test-key --id 01
//   pkcs11-tool --module <path>/libsofthsm2.so --login --pin 1234 \
//       --write-object cert.der --type cert    --label test-key --id 01
//
// A self-signed leaf with no issuer on the token is deliberate: it keeps
// the on-token chain at length 1, which is what the long-term revocation
// gate treats as an unproven terminal.
//
// Add a SECOND key/cert pair whose certificate is already expired, so the
// signer-expiry policy can be exercised without waiting for a clock. Same
// token, same PIN, distinct CKA_ID and label. Both notBefore and notAfter
// are in the past, which is what X509_cmp_current_time(notAfter) reports
// as expired:
//
//   openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
//       -not_before 20200101000000Z -not_after 20210101000000Z \
//       -keyout ekey.pem -out ecert.pem \
//       -subj "/CN=LibreSCRS SoftHSM Expired Test Signer"
//   openssl rsa  -in ekey.pem  -outform DER -out ekey.der
//   openssl x509 -in ecert.pem -outform DER -out ecert.der
//   pkcs11-tool --module <path>/libsofthsm2.so --token-label test-token \
//       --login --pin 1234 \
//       --write-object ekey.der  --type privkey --label expired-key --id 02
//   pkcs11-tool --module <path>/libsofthsm2.so --token-label test-token \
//       --login --pin 1234 \
//       --write-object ecert.der --type cert    --label expired-key --id 02
//
// The extra pair does not lengthen the chain the valid signer reports:
// Pkcs11Token::certificateChain seeds the chain with the CKA_ID-matched
// signer and only appends certificates that actually verify it, and two
// unrelated self-signed leaves verify nothing of each other.
const char* findSoftHsmPath();

/// Default label of the test token created by the setup above.
inline constexpr const char* kSoftHsmTokenLabel = "test-token";

/// Label (and, byte-for-byte, the CKA_LABEL) of the expired signer pair
/// provisioned by the second recipe above. Its CKA_ID is `{0x02}`.
inline constexpr const char* kSoftHsmExpiredKeyLabel = "expired-key";

/// @brief Resolve the raw PKCS#11 slot ID that carries the initialised
///        SoftHSM2 token labelled @p tokenLabel.
///
/// `softhsm2-util --init-token --slot 0` does NOT keep the token on slot
/// 0: SoftHSM2 >= 2.2 reassigns the freshly initialised token to a
/// randomly generated slot ID and leaves slot 0 as an uninitialised
/// spare. A hardcoded `Pkcs11Token::TestSlotId{0}` therefore fails the
/// whole SoftHSM tier with `CKR_SLOT_ID_INVALID` on `C_OpenSession`.
/// Enumerate `C_GetSlotList(tokenPresent = CK_TRUE)` and match the label
/// reported by `C_GetTokenInfo` instead.
///
/// @param module     Live handle from @ref libresign::Pkcs11ModuleManager
///                   (the manager has already run `C_Initialize`).
/// @param tokenLabel Token label to look for. `CK_TOKEN_INFO::label` is a
///                   blank-padded, non-NUL-terminated 32-byte field; the
///                   padding is trimmed before comparison.
/// @return The slot ID, or `std::nullopt` when the module exposes no slot
///         carrying that token — callers `GTEST_SKIP()` on `nullopt` so a
///         machine without a provisioned SoftHSM store (CI) stays green.
std::optional<unsigned long> findSoftHsmTestSlot(const libresign::Pkcs11ModuleHandle& module,
                                                 const char* tokenLabel = kSoftHsmTokenLabel);

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
