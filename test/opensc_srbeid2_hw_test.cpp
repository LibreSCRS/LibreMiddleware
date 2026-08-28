// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Second-generation Serbian eID hardware integration test (contactless).
//
// Exercises the full opensc-plugin tunnel path against a real card on the
// contactless interface: CAN prompt -> PACE -> deferred bind under the live
// SM channel -> CAN-hidden credential enumeration -> PIN verify -> pre-hashed
// ECDSA signature (asserted at exactly 2*ceil(field/8) bytes and verified
// with OpenSSL against the on-card certificate).
//
// Preconditions (all tests SKIP when unmet):
//   * a second-generation card on a contactless reader
//   * LIBRESCRS_TEST_CAN  (the card's CAN; hidden by the emulator)
//   * LIBRESCRS_TEST_PIN  (the user PIN, guarded)
//   * the vendored libopensc carrying the srbeid2 driver (the local
//     hardware-verification override; without it opensc declines the card)

#include <gtest/gtest.h>

#include "pin_guard.h"

#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using LibreSCRS::Plugin::CardPlugin;
using LibreSCRS::Plugin::CardPluginService;
using LibreSCRS::Plugin::SignMechanism;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::MonitorService;
using LibreSCRS::Tests::E2E::markPinFailedAndAbort;

namespace {

std::optional<std::string> envOpt(const char* name)
{
    const char* v = std::getenv(name);
    if (v == nullptr || v[0] == '\0')
        return std::nullopt;
    return std::string{v};
}

// Verify a raw r||s ECDSA signature against the certificate's EC public key.
// The card (via sc_asn1_sig_value_sequence_to_rs) returns the canonical
// fixed-width r||s; OpenSSL's verify wants a DER ECDSA-Sig-Value, so rebuild
// one from the two halves.
::testing::AssertionResult ecdsaVerifyRaw(const std::vector<std::uint8_t>& certDer,
                                          const std::vector<std::uint8_t>& rawSig,
                                          const std::vector<std::uint8_t>& digest)
{
    if (rawSig.size() % 2 != 0)
        return ::testing::AssertionFailure() << "raw signature length " << rawSig.size() << " is not even";
    const std::size_t half = rawSig.size() / 2;

    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using SigPtr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

    const unsigned char* p = certDer.data();
    X509Ptr x{d2i_X509(nullptr, &p, static_cast<long>(certDer.size())), &X509_free};
    if (!x)
        return ::testing::AssertionFailure() << "d2i_X509 failed";
    EvpPkeyPtr pkey{X509_get_pubkey(x.get()), &EVP_PKEY_free};
    if (!pkey)
        return ::testing::AssertionFailure() << "X509_get_pubkey failed";

    SigPtr sig{ECDSA_SIG_new(), &ECDSA_SIG_free};
    BIGNUM* r = BN_bin2bn(rawSig.data(), static_cast<int>(half), nullptr);
    BIGNUM* s = BN_bin2bn(rawSig.data() + half, static_cast<int>(half), nullptr);
    if (!sig || !r || !s || ECDSA_SIG_set0(sig.get(), r, s) != 1)
        return ::testing::AssertionFailure() << "ECDSA_SIG assembly failed";

    unsigned char* der = nullptr;
    const int derLen = i2d_ECDSA_SIG(sig.get(), &der);
    if (derLen <= 0)
        return ::testing::AssertionFailure() << "i2d_ECDSA_SIG failed";
    // OPENSSL_free is a macro, not a callable — wrap it for the RAII deleter.
    const auto freeDer = [](unsigned char* p) { OPENSSL_free(p); };
    std::unique_ptr<unsigned char, decltype(freeDer)> derOwner{der, freeDer};

    using CtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    CtxPtr vctx{EVP_PKEY_CTX_new(pkey.get(), nullptr), &EVP_PKEY_CTX_free};
    if (!vctx || EVP_PKEY_verify_init(vctx.get()) != 1)
        return ::testing::AssertionFailure() << "verify init failed";
    const int vres =
        EVP_PKEY_verify(vctx.get(), derOwner.get(), static_cast<std::size_t>(derLen), digest.data(), digest.size());
    return vres == 1 ? ::testing::AssertionSuccess()
                     : ::testing::AssertionFailure() << "ECDSA signature did not verify (vres=" << vres << ")";
}

} // namespace

class SrbEid2ContactlessHw : public ::testing::Test
{
protected:
    // Find the reader whose card is claimed by the opensc plugin as the FRONT
    // candidate (opensc priority 800 outranks pkcs15's 900). Installs a CAN
    // credential provider on the session so the deferred-PACE activation can
    // complete. Leaves `session` / `plugin` populated on success; SKIPs when
    // no such reader/card is present.
    void SetUp() override
    {
        const auto can = envOpt("LIBRESCRS_TEST_CAN");
        if (!can)
            GTEST_SKIP() << "LIBRESCRS_TEST_CAN not set";

        registry = std::make_unique<CardPluginService>(std::filesystem::path(PLUGIN_DIR));
        if (!registry->isUsable())
            GTEST_SKIP() << "no plugins loaded from " << PLUGIN_DIR;

        auto readers = MonitorService{}.listReaders();
        if (!readers || readers->empty())
            GTEST_SKIP() << "no readers";

        for (const auto& name : *readers) {
            auto opened = CardSession::open(name);
            if (!opened)
                continue;
            auto candidate = std::make_shared<CardSession>(std::move(*opened));
            candidate->setCredentialProvider([can](const LibreSCRS::Auth::AuthRequirement&) {
                ++g_canPrompts;
                std::vector<LibreSCRS::Auth::CredentialEntry> values;
                values.push_back({"can", LibreSCRS::Secure::String{*can}});
                return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
            });

            const auto candidates = registry->findAllCandidates(candidate->atr(), *candidate);
            // The second-generation contactless card is dual-claimed: emrtd
            // (LDS applet) and opensc (PKI) both handle it, with opensc ahead
            // of the generic pkcs15 parser. Find the opensc candidate that
            // declared PACE-gated (Can) — a contact PIV/CardEdge card also
            // fronts opensc but is None, so this filter lands on the srbeid2
            // CL card specifically. Assert opensc precedes pkcs15 (the
            // routing guarantee) while accepting emrtd ahead of both.
            std::shared_ptr<CardPlugin> opensc;
            std::optional<std::size_t> openscPos, pkcs15Pos;
            for (std::size_t i = 0; i < candidates.size(); ++i) {
                const auto& id = candidates[i]->pluginId();
                if (id == "opensc") {
                    opensc = candidates[i];
                    openscPos = i;
                } else if (id == "pkcs15") {
                    pkcs15Pos = i;
                }
            }
            if (opensc && opensc->preReadAuth(*candidate) == LibreSCRS::Auth::PreReadAuthMethod::Can) {
                if (pkcs15Pos)
                    EXPECT_LT(*openscPos, *pkcs15Pos) << "opensc must precede pkcs15 for the second-gen card";
                session = candidate;
                plugin = opensc;
                readerName = name;
                return;
            }
        }
        GTEST_SKIP() << "no reader presented a PACE-gated second-generation card claimed by opensc "
                        "(needs the srbeid2 driver override + the card on a contactless reader)";
    }

    static int g_canPrompts;
    std::unique_ptr<CardPluginService> registry;
    std::shared_ptr<CardSession> session;
    std::shared_ptr<CardPlugin> plugin;
    std::string readerName;
};

int SrbEid2ContactlessHw::g_canPrompts = 0;

TEST_F(SrbEid2ContactlessHw, FullContactlessFlowThroughPlugin)
{
    SKIP_IF_PIN_FAILED();
    const auto pin = envOpt("LIBRESCRS_TEST_PIN");
    if (!pin)
        GTEST_SKIP() << "LIBRESCRS_TEST_PIN not set";

    // The claim deferred the bind behind the PACE gate.
    ASSERT_EQ(plugin->preReadAuth(*session), LibreSCRS::Auth::PreReadAuthMethod::Can);

    // Enumeration under the live SM tunnel: the CAN was consumed by PACE
    // activation, and the emulator hides it — no credential row may carry the
    // CAN reference (0x02) or a "can"-shaped label.
    g_canPrompts = 0;
    const auto pins = plugin->getPINList(*session);
    EXPECT_GT(g_canPrompts, 0) << "the enumeration must drive the CAN prompt (PACE), not fall back";
    for (const auto& entry : pins) {
        EXPECT_NE(entry.reference, 0x02) << "CAN reference leaked into the PIN list";
    }

    // Resolve the signing certificate + its EC key reference.
    const auto certs = plugin->readCertificates(*session);
    ASSERT_FALSE(certs.empty()) << "no certificates enumerated";
    const LibreSCRS::Plugin::CertificateData* signing = nullptr;
    for (const auto& c : certs) {
        if (c.keyFID.has_value()) {
            signing = &c;
            break;
        }
    }
    ASSERT_NE(signing, nullptr) << "no certificate carried a key reference";
    ASSERT_TRUE(signing->keySizeBits.has_value()) << "signing cert reported no key size";
    const std::uint16_t fieldBits = *signing->keySizeBits;
    ASSERT_GT(fieldBits, 0);

    // PIN verify through the tunnel. Guard the retry counter: any non-Ok
    // outcome marks the suite PIN-failed and aborts, so a wrong value can
    // never burn a second attempt on the card.
    const auto pr = plugin->verifyPIN(*session, LibreSCRS::Secure::String{*pin});
    if (pr.outcome != LibreSCRS::Plugin::PINResultOutcome::Ok)
        markPinFailedAndAbort(__LINE__, "verifyPIN outcome=" + std::to_string(static_cast<int>(pr.outcome)));

    // Pre-hashed ECDSA over SHA-384 (P-384 card): sign the digest of a fixed
    // payload and require the canonical fixed-width r||s length.
    const std::vector<std::uint8_t> payload = {'s', 'r', 'b', 'e', 'i', 'd', '2'};
    std::vector<std::uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int digestLen = 0;
    ASSERT_EQ(EVP_Digest(payload.data(), payload.size(), digest.data(), &digestLen, EVP_sha384(), nullptr), 1);
    digest.resize(digestLen);

    const auto sr = plugin->sign(*session, *signing->keyFID, digest, SignMechanism::ECDSA_SHA384);
    ASSERT_EQ(sr.outcome, LibreSCRS::Plugin::SignResultOutcome::Ok)
        << "sign outcome != Ok (" << static_cast<int>(sr.outcome) << ")";

    const std::size_t expectedLen = 2 * ((static_cast<std::size_t>(fieldBits) + 7) / 8);
    EXPECT_EQ(sr.signature.size(), expectedLen)
        << "ECDSA signature must be exactly 2*ceil(field/8) bytes (" << expectedLen << " for a " << fieldBits
        << "-bit field), got " << sr.signature.size();

    EXPECT_TRUE(ecdsaVerifyRaw(signing->derBytes, sr.signature, digest));
}
