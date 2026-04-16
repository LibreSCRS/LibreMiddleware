// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "signing_test_support.h"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>

#ifdef LIBRESIGN_HAS_DSS_ORACLE
#include "libresign/dss/dss_service_manager.h"
#include "libresign/http_client.h"
#include "../dss_validation_client.h"
#include <json.hpp>
#endif

namespace libresign::test {

// ---- PIN guard ----

bool g_pinFailed = false;

void checkPinFailure(const SigningResult& result)
{
    if (result.success)
        return;

    const auto& msg = result.errorMessage;
    if (msg.find("CKR_PIN_INCORRECT") != std::string::npos || msg.find("CKR_PIN_LOCKED") != std::string::npos ||
        msg.find("0x000000A0") != std::string::npos || msg.find("0x000000A4") != std::string::npos) {
        g_pinFailed = true;
        GTEST_SKIP() << "PIN failure detected, skipping remaining tests: " << msg;
    }
}

// ---- PKCS#11 helpers ----

std::string pkcs11ModulePath()
{
    return std::string(CMAKE_SOURCE_DIR) + "/build/lib/pkcs11/librescrs-pkcs11.so";
}

// ---- Config ----

TestConfigResult readTestConfig()
{
    TestConfigResult r;

    const char* pin = std::getenv("LIBRESCRS_TEST_PIN");
    if (!pin || std::string(pin).empty()) {
        r.skipReason = "LIBRESCRS_TEST_PIN not set";
        return r;
    }
    r.config.pin = pin;

    const char* token = std::getenv("LIBRESCRS_TEST_TOKEN");
    if (!token || std::string(token).empty()) {
        r.skipReason = "LIBRESCRS_TEST_TOKEN not set";
        return r;
    }
    r.config.tokenLabel = token;

    const char* alias = std::getenv("LIBRESCRS_TEST_KEY_ALIAS");
    if (alias)
        r.config.keyAlias = alias;

    r.config.pkcs11Module = pkcs11ModulePath();
    r.config.dssJarPath = std::string(CMAKE_SOURCE_DIR) + "/tools/dss-service/target/dss-service-1.0.0-SNAPSHOT.jar";

    r.valid = true;
    return r;
}

// ---- SoftHSM helper ----

const char* findSoftHsmPath()
{
    static const char* paths[] = {
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    };

    for (const auto* path : paths) {
        if (std::filesystem::exists(path))
            return path;
    }
    return nullptr;
}

// ---- DSS validation environment ----

#ifdef LIBRESIGN_HAS_DSS_ORACLE

struct SigningTestEnvironment::Impl
{
    std::unique_ptr<DSSServiceManager> dssManager;
    std::unique_ptr<DSSValidationClient> validationClient;
    std::string baseUrl;
    std::string socketPath;
    bool trustOk = false;
};

std::unique_ptr<SigningTestEnvironment::Impl> SigningTestEnvironment::impl;

void SigningTestEnvironment::SetUp()
{
    impl = std::make_unique<Impl>();

    std::string jarPath = std::string(CMAKE_SOURCE_DIR) + "/tools/dss-service/target/dss-service-1.0.0-SNAPSHOT.jar";

    if (!std::filesystem::exists(jarPath)) {
        std::cerr << "[SigningTestEnvironment] DSS JAR not found at " << jarPath << ", validation will be skipped\n";
        return;
    }

    DSSServiceManager::Config cfg;
    cfg.jarPath = jarPath;
    cfg.startupTimeout = std::chrono::seconds{60};

    impl->dssManager = std::make_unique<DSSServiceManager>(std::move(cfg));
    auto result = impl->dssManager->ensureRunning();
    if (!result) {
        std::cerr << "[SigningTestEnvironment] DSS failed to start: " << result.error << "\n";
        impl->dssManager.reset();
        return;
    }

    impl->baseUrl = result.baseUrl;
    impl->socketPath = impl->dssManager->unixSocketPath();

    // Configure trust with Serbian TL
    try {
        HttpClient http;
        nlohmann::json trustCfg;
        trustCfg["trustedLists"] =
            nlohmann::json::array({{{"url", "https://www.mit.gov.rs/TrustedList/TSL-RS.xml"},
                                    {"isLotl", false},
                                    {"eager", true}}});
        trustCfg["crlEnabled"] = true;
        trustCfg["ocspEnabled"] = true;

        auto resp = http.post(impl->baseUrl + "/config", trustCfg.dump(), 30, impl->socketPath);
        if (resp.statusCode == 200) {
            impl->trustOk = true;
            std::cerr << "[SigningTestEnvironment] Trust configured successfully\n";
        } else {
            std::cerr << "[SigningTestEnvironment] Trust config failed: HTTP " << resp.statusCode << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[SigningTestEnvironment] Trust config failed: " << e.what() << "\n";
    }

    impl->validationClient = std::make_unique<DSSValidationClient>(impl->baseUrl, impl->socketPath);
}

void SigningTestEnvironment::TearDown()
{
    if (impl && impl->dssManager)
        impl->dssManager->stop();
    impl.reset();
}

DSSValidationClient* SigningTestEnvironment::validator()
{
    if (impl && impl->validationClient)
        return impl->validationClient.get();
    return nullptr;
}

bool SigningTestEnvironment::available()
{
    return impl && impl->validationClient;
}

libresign::DSSServiceManager* SigningTestEnvironment::manager()
{
    if (impl && impl->dssManager)
        return impl->dssManager.get();
    return nullptr;
}

bool SigningTestEnvironment::trustConfigured()
{
    return impl && impl->trustOk;
}

// ---- Validate signature ----

void validateSignature(const SigningResult& result, const std::string& format, const std::string& packaging,
                       std::span<const uint8_t> originalDoc)
{
    if (!SigningTestEnvironment::available()) {
        std::cerr << "[validateSignature] DSS not available, skipping validation\n";
        return;
    }

    auto* client = SigningTestEnvironment::validator();
    ASSERT_NE(client, nullptr);

    auto vr = client->validate(result.signedDocument, format, packaging, originalDoc);

    if (!vr.error.empty()) {
        std::cerr << "[validateSignature] Validation error: " << vr.error << "\n";
        return;
    }

    ASSERT_GT(vr.signatureCount, 0) << "Expected at least one signature";

    for (size_t i = 0; i < vr.signatures.size(); ++i) {
        const auto& sig = vr.signatures[i];
        EXPECT_NE(sig.indication, "TOTAL_FAILED") << "Signature " << i << " TOTAL_FAILED"
                                                  << (sig.subIndication.empty() ? "" : " (" + sig.subIndication + ")");

        std::cerr << "[validateSignature] Sig " << i << ": " << sig.indication;
        if (!sig.subIndication.empty())
            std::cerr << " (" << sig.subIndication << ")";
        std::cerr << "\n";

        for (const auto& w : sig.warnings)
            std::cerr << "  warning: " << w << "\n";
        for (const auto& e : sig.errors)
            std::cerr << "  error: " << e << "\n";
    }
}

#else // !LIBRESIGN_HAS_DSS_ORACLE

struct SigningTestEnvironment::Impl
{};
std::unique_ptr<SigningTestEnvironment::Impl> SigningTestEnvironment::impl;

void SigningTestEnvironment::SetUp() {}
void SigningTestEnvironment::TearDown() {}
DSSValidationClient* SigningTestEnvironment::validator()
{
    return nullptr;
}
bool SigningTestEnvironment::available()
{
    return false;
}
libresign::DSSServiceManager* SigningTestEnvironment::manager()
{
    return nullptr;
}
bool SigningTestEnvironment::trustConfigured()
{
    return false;
}

void validateSignature(const SigningResult& /*result*/, const std::string& /*format*/, const std::string& /*packaging*/,
                       std::span<const uint8_t> /*originalDoc*/)
{
    std::cerr << "[validateSignature] DSS not compiled, skipping validation\n";
}

#endif // LIBRESIGN_HAS_DSS_ORACLE

// ---- Test data helpers ----

std::string buildTestPdf()
{
    // Minimal valid PDF with correct xref offsets
    std::string header = "%PDF-1.4\n";
    std::string obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
    std::string obj2 = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";
    std::string obj3 = "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n";

    size_t off1 = header.size();
    size_t off2 = off1 + obj1.size();
    size_t off3 = off2 + obj2.size();
    size_t xrefOff = off3 + obj3.size();

    std::string xref = "xref\n0 4\n";
    xref += "0000000000 65535 f \n";

    auto fmtOffset = [](size_t off) {
        std::string s = std::to_string(off);
        while (s.size() < 10)
            s = "0" + s;
        return s + " 00000 n \n";
    };

    xref += fmtOffset(off1);
    xref += fmtOffset(off2);
    xref += fmtOffset(off3);

    std::string trailer = "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n" + std::to_string(xrefOff) + "\n%%EOF\n";

    return header + obj1 + obj2 + obj3 + xref + trailer;
}

std::string buildTestXml()
{
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<document><body>Test document</body></document>";
}

} // namespace libresign::test
