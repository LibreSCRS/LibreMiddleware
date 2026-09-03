// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "signing_test_support/signing_test_support.h"

#ifdef LIBRESIGN_HAS_NATIVE

#include "dss_validation_client.h"
#include "native/native_signing_service.h"
#include "native/pkcs11_module_manager.h"
#include "types.h"

#include <cstdlib>
#include <cstring>
#include <ostream>
#include <span>
#include <string>
#include <vector>

using namespace libresign;
using ::testing::Contains;
using ::testing::HasSubstr;
using ::testing::Not;

// ---------------------------------------------------------------------------
// What an independent ETSI validator has to say about every signature this
// engine emits. The end-to-end suite already ran that validator and printed
// what came back; nothing asserted it. These cases assert it.
//
// The token is the software one CI provisions on both platforms, so the whole
// suite runs wherever the validator does — no card, no reader, no PIN.
// ---------------------------------------------------------------------------

namespace {

enum class DocKind { Pdf, PlainText, AsciiZeroCsv };

struct ConformanceCase
{
    const char* name;          // gtest name suffix
    DocKind doc;               // payload shape
    SignatureFormat format;    // what the caller asks for
    const char* oracleFormat;  // "PAdES" | "XAdES" | "CAdES" | "ASiC_E"
    const char* packaging;     // "ENVELOPED" | "DETACHED"
    const char* expectedLevel; // level the validator MUST report
};

// ASiC-E reports the level of the CAdES signature it wraps, which is what the
// end-to-end suite already asserts for its own ASiC-E cases.
inline constexpr ConformanceCase kConformanceCases[] = {
    {"Pdf_Pades", DocKind::Pdf, SignatureFormat::Pades, "PAdES", "ENVELOPED", "PAdES_BASELINE_B"},
    {"Text_Xades", DocKind::PlainText, SignatureFormat::Xades, "XAdES", "DETACHED", "XAdES_BASELINE_B"},
    {"Text_Cades", DocKind::PlainText, SignatureFormat::Cades, "CAdES", "DETACHED", "CAdES_BASELINE_B"},
    {"Text_AsicE", DocKind::PlainText, SignatureFormat::AsicE, "ASiC_E", "DETACHED", "CAdES_BASELINE_B"},
    {"AsciiZeroCsv_Cades", DocKind::AsciiZeroCsv, SignatureFormat::Cades, "CAdES", "DETACHED", "CAdES_BASELINE_B"},
    {"AsciiZeroCsv_AsicE", DocKind::AsciiZeroCsv, SignatureFormat::AsicE, "ASiC_E", "DETACHED", "CAdES_BASELINE_B"},
    {"AsciiZeroCsv_Xades", DocKind::AsciiZeroCsv, SignatureFormat::Xades, "XAdES", "DETACHED", "XAdES_BASELINE_B"},
};

// Without this gtest prints the parameter as a raw 40-byte hex dump, which
// says nothing about which case failed.
void PrintTo(const ConformanceCase& c, std::ostream* os)
{
    *os << c.name << " (" << c.oracleFormat << '/' << c.packaging << " -> " << c.expectedLevel << ')';
}

/// A CSV whose very first byte is the ASCII digit zero — the same octet as a
/// DER SEQUENCE tag. Nothing about it is a signature.
constexpr const char* kAsciiZeroCsv = "0,name,amount\n0,first,12\n1,second,34\n";

constexpr const char* kPlainText = "Conformance payload. Ordinary text, no leading DER-ish byte.\n";

bool oracleIsMandatory()
{
    const char* v = std::getenv("LIBRESCRS_REQUIRE_DSS_ORACLE");
    return v && std::strcmp(v, "1") == 0;
}

enum class OracleStatus {
    Ok,          ///< the validator answered and reported at least one signature
    Unavailable, ///< no validator in this run, and the run did not demand one
    Failed,      ///< the validator was reached and something already failed
};

} // namespace

class SoftHSM : public ::testing::TestWithParam<ConformanceCase>
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
        Pkcs11ModuleManager probe;
        auto slot = libresign::test::findSoftHsmTestSlot(probe.acquire(softHsmPath));
        if (!slot)
            GTEST_SKIP() << "SoftHSM2 token '" << libresign::test::kSoftHsmTokenLabel << "' not initialised";
        service.setTestSlotId(*slot);
    }

    static std::vector<uint8_t> payload(DocKind kind)
    {
        std::string s;
        switch (kind) {
        case DocKind::Pdf:
            s = libresign::test::buildTestPdf();
            break;
        case DocKind::PlainText:
            s = kPlainText;
            break;
        case DocKind::AsciiZeroCsv:
            s = kAsciiZeroCsv;
            break;
        }
        return {s.begin(), s.end()};
    }

    /// Sign GetParam()'s document at B-B and return the result. The document
    /// bytes are handed back through @p original because the detached cases
    /// need them again to resolve the reference at the validator.
    SigningResult signCase(std::vector<uint8_t>& original)
    {
        const auto& p = GetParam();
        original = payload(p.doc);

        SigningRequest req;
        req.document = original;
        req.fileName = p.doc == DocKind::Pdf ? "test.pdf" : "test.txt";
        req.format = p.format;
        req.packaging =
            p.format == SignatureFormat::Pades ? SignaturePackaging::Enveloped : SignaturePackaging::Detached;
        req.level = SignatureLevel::B_B;

        return service.sign(req, softHsmPath, libresign::as_pin("1234"), "test-key", "");
    }

    /// Run the emitted bytes past the independent validator.
    ///
    /// Reports Unavailable when there is no validator in this run, having
    /// already failed the test if the run demanded one. The oracle is
    /// opt-in-mandatory for exactly the reason this suite exists: a gate
    /// allowed to quietly do nothing is not a gate.
    OracleStatus validate(const SigningResult& result, std::span<const uint8_t> original, ValidationResult& out)
    {
        if (!libresign::test::SigningTestEnvironment::available()) {
            if (oracleIsMandatory()) {
                ADD_FAILURE() << "LIBRESCRS_REQUIRE_DSS_ORACLE=1 but the ETSI validator is unavailable";
                return OracleStatus::Failed;
            }
            return OracleStatus::Unavailable;
        }
        auto* client = libresign::test::SigningTestEnvironment::validator();
        EXPECT_NE(client, nullptr);
        if (!client)
            return OracleStatus::Failed;

        const auto& p = GetParam();
        out = client->validate(result.signedDocument, p.oracleFormat, p.packaging, original);
        if (!out.error.empty()) {
            ADD_FAILURE() << "ETSI validator failed: " << out.error;
            return OracleStatus::Failed;
        }
        EXPECT_GT(out.signatureCount, 0) << "validator reports no signature at all";
        return out.signatureCount > 0 ? OracleStatus::Ok : OracleStatus::Failed;
    }

    const char* softHsmPath = nullptr;
    NativeSigningService service;
};

INSTANTIATE_TEST_SUITE_P(SigningConformance, SoftHSM, ::testing::ValuesIn(kConformanceCases),
                         [](const ::testing::TestParamInfo<ConformanceCase>& info) {
                             return std::string(info.param.name);
                         });

// The product claims to emit ETSI baseline signatures. This is the only place
// that asserts an independent implementation agrees.
//
// Deliberately routed through the shared validateSignature rather than the
// fixture's own client call: that helper carries the mandatory-level and
// structural-warning assertions the end-to-end suite depends on, and every one
// of ITS call sites is behind a card gate. Without this case, the shared gate
// would itself be code no run executes.
TEST_P(SoftHSM, ReachesExpectedBaselineLevel)
{
    std::vector<uint8_t> original;
    auto result = signCase(original);
    ASSERT_TRUE(result.success) << "sign() failed: " << result.errorMessage;

    if (!libresign::test::SigningTestEnvironment::available()) {
        if (!oracleIsMandatory())
            GTEST_SKIP() << "ETSI validator unavailable";
    }

    const auto& p = GetParam();
    libresign::test::validateSignature(result, p.oracleFormat, p.expectedLevel, p.packaging, original);
}

// A structurally invalid signature is one no other implementation has to
// accept. The validator says so on every document; until now nothing listened.
TEST_P(SoftHSM, CarriesNoStructuralWarning)
{
    std::vector<uint8_t> original;
    auto result = signCase(original);
    ASSERT_TRUE(result.success) << "sign() failed: " << result.errorMessage;

    ValidationResult vr;
    const auto status = validate(result, original, vr);
    if (status == OracleStatus::Unavailable)
        GTEST_SKIP() << "ETSI validator unavailable";
    if (status != OracleStatus::Ok)
        return;

    for (size_t i = 0; i < vr.signatures.size(); ++i) {
        EXPECT_THAT(vr.signatures[i].warnings, Not(Contains(HasSubstr("structure of the signature is not valid"))))
            << "signature " << i;
    }
}

#else
TEST(SigningConformance, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif

// Custom main: the ETSI validator lives in this environment, and a suite
// without it registered would validate nothing while looking green.
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new libresign::test::SigningTestEnvironment);
    return RUN_ALL_TESTS();
}
