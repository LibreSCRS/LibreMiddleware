// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// OpenSC fallback hardware integration test.
//
// Preconditions for non-trivial tests:
//   1. PKS card inserted in a reader
//   2. OPENSC_CONF pointing to opensc.conf that includes the upstream
//      srbeid driver (OpenSC 0.27.0+)
//
// Environment:
//   OPENSC_CONF          (required at runtime)
//   LIBRESCRS_TEST_PIN   (optional; tests 5 and 6 SKIP if unset)

#include <gtest/gtest.h>

#include "pin_guard.h"

#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using LibreSCRS::Plugin::CardPlugin;
using LibreSCRS::Plugin::CardPluginService;
using LibreSCRS::Plugin::PINResult;
using LibreSCRS::Plugin::ReadResult;
using LibreSCRS::Plugin::SignMechanism;
using LibreSCRS::Plugin::SignResult;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::MonitorService;

// PIN guard: g_pinFailed / SKIP_IF_PIN_FAILED come from the shared
// test/include/pin_guard.h (single source of truth across real-card
// test binaries). Local re-definitions were legacy leftovers.

// ---------------------------------------------------------------------------
// Diagnostics helpers (anonymous namespace).
// ---------------------------------------------------------------------------

namespace {

std::string firstHexBytes(const std::vector<uint8_t>& bytes, size_t n = 32)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    const size_t count = std::min(n, bytes.size());
    out.reserve(count * 3);
    for (size_t i = 0; i < count; ++i) {
        out.push_back(hex[bytes[i] >> 4]);
        out.push_back(hex[bytes[i] & 0x0F]);
        out.push_back(' ');
    }
    if (!out.empty())
        out.pop_back();
    return out;
}

std::string opensslLastError()
{
    unsigned long e = ERR_get_error();
    if (e == 0)
        return "(no OpenSSL error on stack)";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(buf);
}

// Sign a fixed SHA-256 DigestInfo("test") with @p keyRef through the (now
// bridged) opensc plugin and verify the PKCS#1 v1.5 signature against the
// certificate's RSA public key. Returns an AssertionResult so callers can
// EXPECT_TRUE it inside a loop with a descriptive message. Mirrors Test06's
// single-shot logic; reused by the repeat-no-corruption regression (Test07).
::testing::AssertionResult signVerifyOnce(CardPlugin& plugin, CardSession& session, std::uint16_t keyRef,
                                          const std::vector<std::uint8_t>& certDer)
{
    const std::vector<uint8_t> payload = {'t', 'e', 's', 't'};
    unsigned char digest[32];
    {
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        if (!md)
            return ::testing::AssertionFailure() << "EVP_MD_CTX_new failed";
        unsigned int n = 0;
        const bool ok = EVP_DigestInit_ex(md, EVP_sha256(), nullptr) == 1 &&
                        EVP_DigestUpdate(md, payload.data(), payload.size()) == 1 &&
                        EVP_DigestFinal_ex(md, digest, &n) == 1 && n == 32u;
        EVP_MD_CTX_free(md);
        if (!ok)
            return ::testing::AssertionFailure() << "SHA-256 of payload failed";
    }

    // DigestInfo DER prefix for SHA-256 (RFC 3447 §9.2, table A.2.4).
    static constexpr std::array<uint8_t, 19> kSha256DigestInfoPrefix = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                        0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                        0x01, 0x05, 0x00, 0x04, 0x20};
    std::vector<uint8_t> signInput;
    signInput.reserve(kSha256DigestInfoPrefix.size() + 32);
    signInput.insert(signInput.end(), kSha256DigestInfoPrefix.begin(), kSha256DigestInfoPrefix.end());
    signInput.insert(signInput.end(), digest, digest + 32);

    const auto sigResult = plugin.sign(session, keyRef, signInput, SignMechanism::RSA_PKCS);
    if (!sigResult.ok())
        return ::testing::AssertionFailure() << "sign outcome != Ok (" << static_cast<int>(sigResult.outcome) << ")";
    if (sigResult.signature.empty())
        return ::testing::AssertionFailure() << "empty signature despite Ok outcome";

    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

    const unsigned char* p = certDer.data();
    X509Ptr x{d2i_X509(nullptr, &p, static_cast<long>(certDer.size())), &X509_free};
    if (!x)
        return ::testing::AssertionFailure() << "d2i_X509 failed";
    EvpPkeyPtr pkey{X509_get_pubkey(x.get()), &EVP_PKEY_free};
    if (!pkey)
        return ::testing::AssertionFailure() << "X509_get_pubkey failed";
    EvpPkeyCtxPtr vctx{EVP_PKEY_CTX_new(pkey.get(), nullptr), &EVP_PKEY_CTX_free};
    if (!vctx || EVP_PKEY_verify_init(vctx.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(vctx.get(), RSA_PKCS1_PADDING) != 1 ||
        EVP_PKEY_CTX_set_signature_md(vctx.get(), EVP_sha256()) != 1)
        return ::testing::AssertionFailure() << "verify context setup failed: " << opensslLastError();

    const int vres = EVP_PKEY_verify(vctx.get(), sigResult.signature.data(), sigResult.signature.size(), digest, 32);
    if (vres != 1)
        return ::testing::AssertionFailure() << "signature did not verify (sig " << firstHexBytes(sigResult.signature)
                                             << "); OpenSSL: " << opensslLastError();
    return ::testing::AssertionSuccess();
}

} // namespace

// ---------------------------------------------------------------------------
// Fixture — suite-wide state so the PIN session opened in Test 5 is reused by
// Test 6 (avoids a second verifyPIN that would consume another retry).
// ---------------------------------------------------------------------------

class OpenSCFallbackPKS : public ::testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        registry = std::make_unique<CardPluginService>(std::filesystem::path(PLUGIN_DIR));
        if (registry->plugins().empty()) {
            registry.reset();
            GTEST_SKIP() << "No plugins loaded from " << PLUGIN_DIR << " — check build";
        }

        MonitorService monitor;
        auto readersOpt = monitor.listReaders();
        if (!readersOpt || readersOpt->empty()) {
            registry.reset();
            GTEST_SKIP() << "No smart card readers found";
        }

        for (const auto& readerName : *readersOpt) {
            auto opened = CardSession::open(readerName);
            if (!opened.has_value())
                continue; // reader without card or transient PC/SC error → keep trying

            // findAllCandidates does the two-phase probe (ATR first, then
            // canHandleConnection AID probe), de-duped and sorted by
            // probePriority ascending. opensc-plugin (priority 800) claims
            // the PKS card via sc_pkcs15_bind through the upstream srbeid
            // driver. This fixture specifically tests the OpenSC fallback
            // path, so we accept only readers where the front candidate is
            // opensc-plugin — other cards (e.g., NAM CL claimed by emrtd
            // for display) are skipped here even if a plugin claims them.
            auto candidates = registry->findAllCandidates(opened->atr(), *opened);
            if (candidates.empty())
                continue;
            if (candidates.front()->pluginId() != "opensc")
                continue;

            session = std::move(*opened);
            plugin = candidates.front();
            return;
        }

        registry.reset();
        GTEST_SKIP() << "No reader returned a card with opensc-plugin as front "
                        "candidate — confirm PKS card is inserted";
    }

    static void TearDownTestSuite()
    {
        // Reset order: session before registry. Plugins owned by the
        // registry's shared_ptrs may hold per-session state via the unwrap
        // detail bridge; destroying the registry first could free the plugin
        // while the session it references is still live.
        session.reset();
        plugin.reset();
        registry.reset();
    }

    // Suite-wide state — initialized by SetUpTestSuite, shared across all
    // TEST_F cases in this fixture so Test05's PIN session is reused by
    // Test06 rather than spending a second verification against the card's
    // PIN retry budget.
    static std::unique_ptr<CardPluginService> registry;
    static std::optional<CardSession> session;
    static std::shared_ptr<CardPlugin> plugin;
};

std::unique_ptr<CardPluginService> OpenSCFallbackPKS::registry;
std::optional<CardSession> OpenSCFallbackPKS::session;
std::shared_ptr<CardPlugin> OpenSCFallbackPKS::plugin;

// ---------------------------------------------------------------------------
// Test 1 — registry routed the card to opensc-plugin.
// ---------------------------------------------------------------------------

TEST_F(OpenSCFallbackPKS, Test01RegistryPicksOpenSCPlugin)
{
    ASSERT_NE(plugin, nullptr);
    EXPECT_EQ(plugin->pluginId(), "opensc")
        << "Expected opensc-plugin to claim PKS — got '" << plugin->pluginId() << "'";
}

// ---------------------------------------------------------------------------
// Test 2 — readCard returns populated token info (label).
// PIN state is surfaced via the typed CardPlugin::getPINList() override
// (PinStatusEntry vector), not via the readCard() data groups; this test
// exercises the token-info group only.
// ---------------------------------------------------------------------------

TEST_F(OpenSCFallbackPKS, Test02ReadCardReturnsTokenInfo)
{
    ASSERT_NE(plugin, nullptr);
    ASSERT_TRUE(session.has_value());

    auto result = plugin->readCard(*session);
    ASSERT_EQ(result.status, ReadResult::Status::Ok)
        << "readCard returned non-Ok status (status enum value " << static_cast<int>(result.status) << ")";
    ASSERT_TRUE(result.data.has_value()) << "readCard Status::Ok but data optional empty";

    const auto& data = *result.data;
    EXPECT_EQ(data.cardType, "opensc") << "cardType should identify opensc fallback";

    const auto tokenIdx = data.findGroup("token");
    ASSERT_TRUE(tokenIdx.has_value()) << "readCard did not produce a 'token' group";
    const auto& tokenGroup = data.groupAt(*tokenIdx);

    auto fieldByKey = [&](std::string_view key) -> const LibreSCRS::Plugin::CardField* {
        for (const auto& f : tokenGroup.fields) {
            if (f.key == key)
                return &f;
        }
        return nullptr;
    };

    const auto* labelField = fieldByKey("label");
    ASSERT_NE(labelField, nullptr) << "token group missing 'label' field";
    const auto labelText = labelField->textValue();
    ASSERT_TRUE(labelText.has_value()) << "label field is not FieldType::Text (textValue returned nullopt)";
    EXPECT_FALSE(labelText->empty()) << "Token label empty";

    // serial_number is optional in PKCS#15 TokenInfo (PKS cards don't
    // populate it); if the plugin emits it, we still require it be
    // non-empty.
    const auto* serialField = fieldByKey("serial_number");
    if (serialField != nullptr) {
        const auto serialText = serialField->textValue();
        if (serialText.has_value()) {
            EXPECT_FALSE(serialText->empty()) << "Token serial present but empty";
        }
    }
    // else: serial is optional per PKCS#15 spec (PKS cards omit it)
}

// ---------------------------------------------------------------------------
// Test 3 — readCertificates returns parseable X.509 DER.
// ---------------------------------------------------------------------------

TEST_F(OpenSCFallbackPKS, Test03ReadCertificatesReturnsParseableDER)
{
    ASSERT_NE(plugin, nullptr);
    ASSERT_TRUE(session.has_value());

    auto certs = plugin->readCertificates(*session);
    ASSERT_FALSE(certs.empty()) << "readCertificates returned zero certificates";

    for (size_t i = 0; i < certs.size(); ++i) {
        const auto& der = certs[i].derBytes;
        ASSERT_FALSE(der.empty()) << "cert[" << i << "] DER empty";

        const unsigned char* p = der.data();
        X509* x = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
        ASSERT_NE(x, nullptr) << "cert[" << i << "] d2i_X509 failed. "
                              << "First bytes: " << firstHexBytes(der) << ". "
                              << "OpenSSL: " << opensslLastError();

        X509_NAME* subj = X509_get_subject_name(x);
        ASSERT_NE(subj, nullptr) << "cert[" << i << "] has null subject";
        const int entryCount = X509_NAME_entry_count(subj);
        EXPECT_GT(entryCount, 0) << "cert[" << i << "] subject DN has zero RDN entries";

        X509_free(x);
    }
}

// ---------------------------------------------------------------------------
// Test 4 — PIN tries-left baseline. Refuses to run if already partially used.
// Latches g_pinFailed on failure so tests 5 and 6 SKIP.
// ---------------------------------------------------------------------------

TEST_F(OpenSCFallbackPKS, Test04GetPINTriesLeftBaseline)
{
    SKIP_IF_PIN_FAILED();
    ASSERT_NE(plugin, nullptr);
    ASSERT_TRUE(session.has_value());

    const auto triesOpt = plugin->readCounters(*session).retriesLeft;
    if (!triesOpt.has_value()) {
        // A nullopt retry count here is not a card failure (this is a non-PIN
        // GET_INFO read, no lockout): on a dev box with a PKS card seated but
        // OPENSC_CONF unset, the srbeid driver is unwired so the count is
        // simply unreadable. Skip rather than hard-fail — mirrors the effective
        // driver-wiring guard the PIN-consuming Test05/Test06 rely on. When the
        // driver IS wired the count is readable and the assertions below still
        // apply (we do NOT weaken them in that case).
        if (const char* conf = std::getenv("OPENSC_CONF"); !conf || *conf == '\0')
            GTEST_SKIP() << "getPINTriesLeft returned nullopt and OPENSC_CONF is unset — srbeid driver "
                            "unwired, PIN retry count unreadable; skipping baseline";
        FAIL() << "getPINTriesLeft returned nullopt — plugin did not report a PIN retry count "
                  "(OPENSC_CONF is set, so the srbeid driver should be wired)";
    }
    if (*triesOpt < 3) {
        ::LibreSCRS::Tests::E2E::g_pinFailed.store(true, std::memory_order_relaxed);
        FAIL() << "PIN tries-left baseline is " << *triesOpt
               << " (expected 3) — card partially used; refusing to run PIN-consuming tests";
    }
    EXPECT_EQ(*triesOpt, 3) << "PKS baseline PIN retry count should be 3";
}

// ---------------------------------------------------------------------------
// Test 5 — verifyPIN succeeds; tries-left unchanged after.
// First PIN-consuming test. Session kept warm for Test 6.
// SKIPs if LIBRESCRS_TEST_PIN is not set.
// ---------------------------------------------------------------------------

TEST_F(OpenSCFallbackPKS, Test05VerifyPINSucceeds)
{
    SKIP_IF_PIN_FAILED();
    ASSERT_NE(plugin, nullptr);
    ASSERT_TRUE(session.has_value());

    const char* pinEnv = std::getenv("LIBRESCRS_TEST_PIN");
    if (!pinEnv || *pinEnv == '\0')
        GTEST_SKIP() << "LIBRESCRS_TEST_PIN not set — skipping PIN-dependent tests";

    LibreSCRS::Secure::String pin{std::string_view{pinEnv}};

    const auto triesBeforeOpt = plugin->readCounters(*session).retriesLeft;
    const int triesBefore = triesBeforeOpt.value_or(-1);

    const auto result = plugin->verifyPIN(*session, pin);
    if (!result.ok()) {
        ::LibreSCRS::Tests::E2E::g_pinFailed.store(true, std::memory_order_relaxed);
        FAIL() << "verifyPIN failed. retriesLeft="
               << (result.retriesLeft.has_value() ? std::to_string(*result.retriesLeft) : std::string("nullopt"))
               << ", blocked=" << (result.blocked ? "true" : "false") << ", triesBefore=" << triesBefore
               << ", outcome=" << static_cast<int>(result.outcome) << ". All subsequent PIN-consuming tests will SKIP.";
    }

    // Post-verify tries_left reporting is unreliable on the srbeid driver
    // path — the iso7816 pin_cmd GET_INFO handler returns SW=9000 when the
    // card is already logged in without updating tries_left, so the value
    // may surface as nullopt or 3 after a successful verify. Treat the
    // success signal as result.ok() here; the sign smoke in Test06 is the
    // ultimate authentication proof.
    const auto triesAfterOpt = plugin->readCounters(*session).retriesLeft;
    if (triesAfterOpt.has_value()) {
        EXPECT_EQ(*triesAfterOpt, 3) << "Post-verify getPINTriesLeft, when populated, should be 3; got "
                                     << *triesAfterOpt;
    }
    if (result.retriesLeft.has_value()) {
        EXPECT_EQ(*result.retriesLeft, 3)
            << "PINResult::retriesLeft, when populated, should be 3 on success; got " << *result.retriesLeft;
    }
}

// ---------------------------------------------------------------------------
// Test 6 — sign with the first enumerated key; verify signature against the
// matching cert's public key. Reuses PIN session from Test 5 (no extra verify).
// SKIPs if LIBRESCRS_TEST_PIN unset or g_pinFailed latched.
//
// OpenSC plugin's sign passes `data` verbatim into sc_pkcs15_compute_signature
// with RSA_PAD_PKCS1 padding, so the caller must hand it a DigestInfo-wrapped
// hash. We compute SHA-256("test"), prepend the SHA-256 DigestInfo DER prefix,
// then sign that. Verification uses EVP_PKEY_verify with RSA_PKCS1_PADDING +
// SHA-256 md, which expects the raw hash and a PKCS#1 v1.5 signature over
// DigestInfo — matching what we just produced.
// ---------------------------------------------------------------------------

TEST_F(OpenSCFallbackPKS, Test06SignRSAAuthKeyProducesValidSignature)
{
    SKIP_IF_PIN_FAILED();
    ASSERT_NE(plugin, nullptr);
    ASSERT_TRUE(session.has_value());

    const char* pin = std::getenv("LIBRESCRS_TEST_PIN");
    if (!pin || *pin == '\0')
        GTEST_SKIP() << "LIBRESCRS_TEST_PIN not set";

    const auto keyRefs = plugin->discoverKeyReferences(*session);
    ASSERT_FALSE(keyRefs.empty()) << "discoverKeyReferences returned no keys";
    const std::uint16_t firstKeyRef = keyRefs.front().reference;

    const auto certs = plugin->readCertificates(*session);
    ASSERT_FALSE(certs.empty());
    const auto& firstCertDer = certs.front().derBytes;

    const std::vector<uint8_t> payload = {'t', 'e', 's', 't'};

    // SHA-256(payload)
    unsigned char digest[32];
    {
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        ASSERT_NE(md, nullptr);
        ASSERT_EQ(EVP_DigestInit_ex(md, EVP_sha256(), nullptr), 1);
        ASSERT_EQ(EVP_DigestUpdate(md, payload.data(), payload.size()), 1);
        unsigned int n = 0;
        ASSERT_EQ(EVP_DigestFinal_ex(md, digest, &n), 1);
        ASSERT_EQ(n, 32u);
        EVP_MD_CTX_free(md);
    }

    // DigestInfo DER prefix for SHA-256 (RFC 3447 §9.2, table A.2.4)
    static constexpr std::array<uint8_t, 19> kSha256DigestInfoPrefix = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                        0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                        0x01, 0x05, 0x00, 0x04, 0x20};
    std::vector<uint8_t> signInput;
    signInput.reserve(kSha256DigestInfoPrefix.size() + 32);
    signInput.insert(signInput.end(), kSha256DigestInfoPrefix.begin(), kSha256DigestInfoPrefix.end());
    signInput.insert(signInput.end(), digest, digest + 32);

    const auto sigResult = plugin->sign(*session, firstKeyRef, signInput, SignMechanism::RSA_PKCS);
    ASSERT_TRUE(sigResult.ok()) << "sign returned outcome != Ok (outcome enum value "
                                << static_cast<int>(sigResult.outcome) << ")";
    ASSERT_FALSE(sigResult.signature.empty()) << "sign returned empty signature despite Ok outcome";
    EXPECT_EQ(sigResult.signature.size(), 256u)
        << "RSA-2048 signature expected 256 bytes, got " << sigResult.signature.size();

    // Parse cert + extract public key. RAII wrappers ensure the OpenSSL
    // handles are freed even when an intermediate ASSERT triggers an early
    // return from this TEST_F body (gtest's fatal-assertion semantics).
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

    const unsigned char* p = firstCertDer.data();
    X509Ptr x{d2i_X509(nullptr, &p, static_cast<long>(firstCertDer.size())), &X509_free};
    ASSERT_NE(x.get(), nullptr);
    EvpPkeyPtr pkey{X509_get_pubkey(x.get()), &EVP_PKEY_free};
    ASSERT_NE(pkey.get(), nullptr);

    // EVP_PKEY_verify with RSA_PKCS1_PADDING + SHA-256 md expects the raw hash
    // and a PKCS#1 v1.5 signature over the DigestInfo. Matches our signInput.
    EvpPkeyCtxPtr vctx{EVP_PKEY_CTX_new(pkey.get(), nullptr), &EVP_PKEY_CTX_free};
    ASSERT_NE(vctx.get(), nullptr);
    ASSERT_EQ(EVP_PKEY_verify_init(vctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(vctx.get(), RSA_PKCS1_PADDING), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(vctx.get(), EVP_sha256()), 1);

    const int vres = EVP_PKEY_verify(vctx.get(), sigResult.signature.data(), sigResult.signature.size(), digest, 32);
    EXPECT_EQ(vres, 1) << "Signature did not verify. "
                       << "Signature first bytes: " << firstHexBytes(sigResult.signature) << ". "
                       << "Payload: 'test'. "
                       << "KeyRef: 0x" << std::hex << firstKeyRef << std::dec << ". "
                       << "OpenSSL: " << opensslLastError();
}

// ---------------------------------------------------------------------------
// Test 7 — single-session bridge regression (2026-06-12 HW smoke).
//
// Before the bridge, the opensc plugin opened its OWN second libopensc
// connection; a raw sign on that path could corrupt pcscd state so EVERY
// subsequent CardSession::open failed ("Could not establish the card channel")
// until pcscd was restarted, and the sign itself intermittently failed because
// nothing serialised the second connection against the agent's held session.
//
// With the bridge there is exactly one connection. This test signs five times
// in a row (each verified against the cert pubkey) and then confirms a FRESH
// CardSession::open on the same reader still succeeds — the direct
// no-session-corruption check. Reuses Test05's warm PIN session.
// SKIPs if LIBRESCRS_TEST_PIN unset or g_pinFailed latched.
// ---------------------------------------------------------------------------

TEST_F(OpenSCFallbackPKS, Test07BridgedSignRepeatsWithoutSessionCorruption)
{
    SKIP_IF_PIN_FAILED();
    ASSERT_NE(plugin, nullptr);
    ASSERT_TRUE(session.has_value());

    const char* pin = std::getenv("LIBRESCRS_TEST_PIN");
    if (!pin || *pin == '\0')
        GTEST_SKIP() << "LIBRESCRS_TEST_PIN not set";

    const auto keyRefs = plugin->discoverKeyReferences(*session);
    ASSERT_FALSE(keyRefs.empty()) << "discoverKeyReferences returned no keys";
    const std::uint16_t keyRef = keyRefs.front().reference;

    const auto certs = plugin->readCertificates(*session);
    ASSERT_FALSE(certs.empty());
    const std::vector<std::uint8_t> certDer = certs.front().derBytes;

    const std::string readerName = session->readerName();

    // Five back-to-back signs, each fully verified. Pre-bridge this loop would
    // wedge the card session partway through.
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(signVerifyOnce(*plugin, *session, keyRef, certDer))
            << "bridged sign iteration " << i << " of 5 failed";
    }

    // The card must remain openable — a fresh connection on the same reader
    // succeeds (this is exactly what failed pre-bridge until a pcscd restart).
    auto reopened = CardSession::open(readerName);
    EXPECT_TRUE(reopened.has_value())
        << "CardSession::open('" << readerName
        << "') failed after five signs — session corruption regressed (would need a pcscd restart)";
}
