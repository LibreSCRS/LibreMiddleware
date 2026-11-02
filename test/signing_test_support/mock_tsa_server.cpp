// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "mock_tsa_server.h"

#include "loopback_http_server.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>
#include <LibreSCRS_internal/Crypto/OpenSslPtrCms.h>

using LibreSCRS::Internal::Crypto::Asn1ObjectPtr;
using LibreSCRS::Internal::Crypto::BioPtr;
using LibreSCRS::Internal::Crypto::EvpPkeyPtr;
using LibreSCRS::Internal::Crypto::TsRespPtr;
using LibreSCRS::Internal::Crypto::X509Ptr;
using LibreSCRS::Internal::Crypto::X509StackBorrowedPtr;

namespace libresign::test {

namespace {

// Test policy arc used by OpenSSL's own time-stamp test configuration. The
// client sends no reqPolicy, so the responder stamps this as the default.
constexpr const char* kTsaPolicyOid = "1.2.3.4.1";

struct TsRespCtxDeleter
{
    void operator()(TS_RESP_CTX* p) const
    {
        TS_RESP_CTX_free(p);
    }
};

using TsRespCtxPtr = std::unique_ptr<TS_RESP_CTX, TsRespCtxDeleter>;

void addExtension(X509* cert, X509* issuer, int nid, const char* value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (!ext)
        throw std::runtime_error(std::string("MockTsaServer: X509V3_EXT_conf_nid failed for ") + value);
    const int rc = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    if (rc != 1)
        throw std::runtime_error("MockTsaServer: X509_add_ext failed");
}

/// The key and certificate a responder signs with.
struct Identity
{
    EvpPkeyPtr key;
    X509Ptr cert;
};

/// Generate a time-stamping certificate, issued by @p issuerKey /
/// @p issuerCert, or self-signed when both are null.
///
/// `TS_RESP_CTX_set_signer_cert` runs `X509_check_purpose` with
/// `X509_PURPOSE_TIMESTAMP_SIGN`, which requires an extended key usage that is
/// present, CRITICAL, and consists of id-kp-timeStamping — plus, when a key
/// usage is present, digitalSignature or nonRepudiation. A certificate missing
/// any of that is rejected outright, so the extension set below is a hard
/// requirement rather than decoration.
Identity makeAuthority(EVP_PKEY* issuerKey, X509* issuerCert)
{
    EvpPkeyPtr key(EVP_RSA_gen(2048));
    if (!key)
        throw std::runtime_error("MockTsaServer: EVP_RSA_gen failed");

    X509Ptr cert(X509_new());
    if (!cert)
        throw std::runtime_error("MockTsaServer: X509_new failed");

    if (X509_set_version(cert.get(), X509_VERSION_3) != 1)
        throw std::runtime_error("MockTsaServer: X509_set_version failed");

    unsigned char serialBytes[8];
    if (RAND_bytes(serialBytes, sizeof(serialBytes)) != 1)
        throw std::runtime_error("MockTsaServer: RAND_bytes failed");
    serialBytes[0] = static_cast<unsigned char>(serialBytes[0] & 0x7F); // keep the serial positive
    BIGNUM* bn = BN_bin2bn(serialBytes, sizeof(serialBytes), nullptr);
    if (!bn)
        throw std::runtime_error("MockTsaServer: BN_bin2bn failed");
    ASN1_INTEGER* serial = BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert.get()));
    BN_free(bn);
    if (!serial)
        throw std::runtime_error("MockTsaServer: BN_to_ASN1_INTEGER failed");

    if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()), 24 * 3600))
        throw std::runtime_error("MockTsaServer: X509_gmtime_adj failed");

    if (X509_set_pubkey(cert.get(), key.get()) != 1)
        throw std::runtime_error("MockTsaServer: X509_set_pubkey failed");

    X509_NAME* subject = X509_get_subject_name(cert.get());
    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("LibreSCRS Mock Time-Stamp Authority"), -1,
                                   -1, 0) != 1)
        throw std::runtime_error("MockTsaServer: X509_NAME_add_entry_by_txt failed");
    X509* issuer = issuerCert ? issuerCert : cert.get();
    if (X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer)) != 1)
        throw std::runtime_error("MockTsaServer: X509_set_issuer_name failed");

    addExtension(cert.get(), issuer, NID_basic_constraints, "critical,CA:FALSE");
    addExtension(cert.get(), issuer, NID_key_usage, "critical,digitalSignature,nonRepudiation");
    addExtension(cert.get(), issuer, NID_ext_key_usage, "critical,timeStamping");
    addExtension(cert.get(), issuer, NID_subject_key_identifier, "hash");
    if (issuerCert)
        addExtension(cert.get(), issuer, NID_authority_key_identifier, "keyid:always");

    if (X509_sign(cert.get(), issuerKey ? issuerKey : key.get(), EVP_sha256()) == 0)
        throw std::runtime_error("MockTsaServer: X509_sign failed");

    return Identity{std::move(key), std::move(cert)};
}

std::string trustFixture(const char* name)
{
    return std::string(CMAKE_SOURCE_DIR) + "/test/fixtures/trust/" + name;
}

/// The test Trusted-List key and certificate, which issue the anchored
/// authority's certificate.
Identity loadIssuer()
{
    Identity issuer;
    if (std::FILE* f = std::fopen(trustFixture("test-tl-signing-key.pem").c_str(), "r")) {
        issuer.key.reset(PEM_read_PrivateKey(f, nullptr, nullptr, nullptr));
        std::fclose(f);
    }
    if (std::FILE* f = std::fopen(trustFixture("test-tl-signing-cert.pem").c_str(), "r")) {
        issuer.cert.reset(PEM_read_X509(f, nullptr, nullptr, nullptr));
        std::fclose(f);
    }
    if (!issuer.key || !issuer.cert)
        throw std::runtime_error("MockTsaServer: cannot read the test Trusted-List key and certificate");
    return issuer;
}

struct Anchored
{
    Identity issuer;
    std::shared_ptr<Identity> authority;
};

/// Issued once per process: every anchored instance signs with the same key,
/// so a test can name the anchor before it starts a server.
const Anchored& anchored()
{
    static const Anchored shared = [] {
        Anchored a;
        a.issuer = loadIssuer();
        a.authority = std::make_shared<Identity>(makeAuthority(a.issuer.key.get(), a.issuer.cert.get()));
        return a;
    }();
    return shared;
}

std::vector<uint8_t> derOf(X509* cert)
{
    unsigned char* der = nullptr;
    const int len = i2d_X509(cert, &der);
    if (len <= 0 || !der)
        throw std::runtime_error("MockTsaServer: i2d_X509 failed");
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

} // namespace

struct MockTsaServer::Impl
{
    std::shared_ptr<Identity> identity;
    // Constructed last: its worker thread starts inside the constructor and
    // calls back into respond(), so the identity must already be there.
    std::unique_ptr<LoopbackHttpServer> http;

    /// Build a granted TimeStampResp over @p derRequest. Returns empty on any
    /// responder failure; the caller then closes the connection without a
    /// reply, which the client reports as a transport error.
    std::vector<uint8_t> respond(std::span<const uint8_t> derRequest)
    {
        TsRespCtxPtr ctx(TS_RESP_CTX_new());
        if (!ctx)
            return {};
        if (TS_RESP_CTX_set_signer_cert(ctx.get(), identity->cert.get()) != 1)
            return {};
        if (TS_RESP_CTX_set_signer_key(ctx.get(), identity->key.get()) != 1)
            return {};
        if (TS_RESP_CTX_set_signer_digest(ctx.get(), EVP_sha256()) != 1)
            return {};

        Asn1ObjectPtr policy(OBJ_txt2obj(kTsaPolicyOid, 1));
        if (!policy || TS_RESP_CTX_set_def_policy(ctx.get(), policy.get()) != 1)
            return {};
        // The client always requests SHA-256; an unlisted digest is answered
        // with a rejection rather than a token.
        if (TS_RESP_CTX_add_md(ctx.get(), EVP_sha256()) != 1)
            return {};

        // Carry the authority certificate inside the token so the ESSCertID
        // in the signing-certificate attribute resolves to a present cert.
        X509StackBorrowedPtr certs(sk_X509_new_null());
        if (!certs || sk_X509_push(certs.get(), identity->cert.get()) <= 0)
            return {};
        if (TS_RESP_CTX_set_certs(ctx.get(), certs.get()) != 1)
            return {};

        BioPtr reqBio(BIO_new_mem_buf(derRequest.data(), static_cast<int>(derRequest.size())));
        if (!reqBio)
            return {};
        TsRespPtr resp(TS_RESP_create_response(ctx.get(), reqBio.get()));
        if (!resp)
            return {};

        unsigned char* der = nullptr;
        const int len = i2d_TS_RESP(resp.get(), &der);
        if (len <= 0 || !der)
            return {};
        std::vector<uint8_t> out(der, der + len);
        OPENSSL_free(der);
        return out;
    }
};

MockTsaServer::MockTsaServer(Authority authority) : impl(std::make_unique<Impl>())
{
    impl->identity = authority == Authority::Anchored ? anchored().authority
                                                      : std::make_shared<Identity>(makeAuthority(nullptr, nullptr));

    Impl* raw = impl.get();
    impl->http = std::make_unique<LoopbackHttpServer>(
        "application/timestamp-reply", [raw](std::span<const uint8_t> body) { return raw->respond(body); });
}

MockTsaServer::~MockTsaServer() = default;

std::string MockTsaServer::url() const
{
    return impl->http->url("/tsa");
}

uint16_t MockTsaServer::port() const
{
    return impl->http->port();
}

int MockTsaServer::servedCount() const
{
    return impl->http->servedCount();
}

std::vector<uint8_t> MockTsaServer::trustAnchor()
{
    return derOf(anchored().issuer.cert.get());
}

std::vector<uint8_t> MockTsaServer::anchoredCertificate()
{
    return derOf(anchored().authority->cert.get());
}

} // namespace libresign::test
