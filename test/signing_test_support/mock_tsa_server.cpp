// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "mock_tsa_server.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace libresign::test {

namespace {

// Test policy arc used by OpenSSL's own time-stamp test configuration. The
// client sends no reqPolicy, so the responder stamps this as the default.
constexpr const char* kTsaPolicyOid = "1.2.3.4.1";

struct EvpPkeyDeleter
{
    void operator()(EVP_PKEY* p) const
    {
        EVP_PKEY_free(p);
    }
};
struct X509Deleter
{
    void operator()(X509* p) const
    {
        X509_free(p);
    }
};
struct Asn1ObjDeleter
{
    void operator()(ASN1_OBJECT* p) const
    {
        ASN1_OBJECT_free(p);
    }
};
struct BioDeleter
{
    void operator()(BIO* p) const
    {
        BIO_free(p);
    }
};
struct TsRespCtxDeleter
{
    void operator()(TS_RESP_CTX* p) const
    {
        TS_RESP_CTX_free(p);
    }
};
struct TsRespDeleter
{
    void operator()(TS_RESP* p) const
    {
        TS_RESP_free(p);
    }
};
struct StackOfX509Deleter
{
    void operator()(STACK_OF(X509) * p) const
    {
        // The stack borrows its element; free the container only.
        sk_X509_free(p);
    }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using Asn1ObjPtr = std::unique_ptr<ASN1_OBJECT, Asn1ObjDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using TsRespCtxPtr = std::unique_ptr<TS_RESP_CTX, TsRespCtxDeleter>;
using TsRespPtr = std::unique_ptr<TS_RESP, TsRespDeleter>;
using StackOfX509Ptr = std::unique_ptr<STACK_OF(X509), StackOfX509Deleter>;

void addExtension(X509* cert, int nid, const char* value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (!ext)
        throw std::runtime_error(std::string("MockTsaServer: X509V3_EXT_conf_nid failed for ") + value);
    const int rc = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    if (rc != 1)
        throw std::runtime_error("MockTsaServer: X509_add_ext failed");
}

/// Generate the self-signed authority the responder signs with.
///
/// `TS_RESP_CTX_set_signer_cert` runs `X509_check_purpose` with
/// `X509_PURPOSE_TIMESTAMP_SIGN`, which requires an extended key usage that is
/// present, CRITICAL, and consists of id-kp-timeStamping — plus, when a key
/// usage is present, digitalSignature or nonRepudiation. A certificate missing
/// any of that is rejected outright, so the extension set below is a hard
/// requirement rather than decoration.
void makeAuthority(EvpPkeyPtr& keyOut, X509Ptr& certOut)
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
    if (X509_set_issuer_name(cert.get(), subject) != 1)
        throw std::runtime_error("MockTsaServer: X509_set_issuer_name failed");

    addExtension(cert.get(), NID_basic_constraints, "critical,CA:FALSE");
    addExtension(cert.get(), NID_key_usage, "critical,digitalSignature,nonRepudiation");
    addExtension(cert.get(), NID_ext_key_usage, "critical,timeStamping");
    addExtension(cert.get(), NID_subject_key_identifier, "hash");

    if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0)
        throw std::runtime_error("MockTsaServer: X509_sign failed");

    keyOut = std::move(key);
    certOut = std::move(cert);
}

/// Case-insensitive `Content-Length:` lookup over an HTTP header block.
long parseContentLength(const std::string& headers)
{
    std::string lower;
    lower.reserve(headers.size());
    for (char c : headers)
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

    const auto pos = lower.find("content-length:");
    if (pos == std::string::npos)
        return -1;
    const auto valueStart = pos + std::string("content-length:").size();
    const auto lineEnd = lower.find("\r\n", valueStart);
    if (lineEnd == std::string::npos)
        return -1;
    return std::strtol(headers.substr(valueStart, lineEnd - valueStart).c_str(), nullptr, 10);
}

bool sendAll(int fd, const char* data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        const ssize_t n = ::send(fd, data + sent, len - sent, 0);
        if (n <= 0)
            return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

} // namespace

struct MockTsaServer::Impl
{
    int fd = -1;
    uint16_t boundPort = 0;
    std::thread worker;
    std::atomic<bool> stopFlag{false};
    std::atomic<int> served{0};
    EvpPkeyPtr key;
    X509Ptr cert;

    /// Build a granted TimeStampResp over @p derRequest. Returns empty on any
    /// responder failure; the caller then closes the connection without a
    /// reply, which the client reports as a transport error.
    std::vector<uint8_t> respond(const std::string& derRequest)
    {
        TsRespCtxPtr ctx(TS_RESP_CTX_new());
        if (!ctx)
            return {};
        if (TS_RESP_CTX_set_signer_cert(ctx.get(), cert.get()) != 1)
            return {};
        if (TS_RESP_CTX_set_signer_key(ctx.get(), key.get()) != 1)
            return {};
        if (TS_RESP_CTX_set_signer_digest(ctx.get(), EVP_sha256()) != 1)
            return {};

        Asn1ObjPtr policy(OBJ_txt2obj(kTsaPolicyOid, 1));
        if (!policy || TS_RESP_CTX_set_def_policy(ctx.get(), policy.get()) != 1)
            return {};
        // The client always requests SHA-256; an unlisted digest is answered
        // with a rejection rather than a token.
        if (TS_RESP_CTX_add_md(ctx.get(), EVP_sha256()) != 1)
            return {};

        // Carry the authority certificate inside the token so the ESSCertID
        // in the signing-certificate attribute resolves to a present cert.
        StackOfX509Ptr certs(sk_X509_new_null());
        if (!certs || sk_X509_push(certs.get(), cert.get()) <= 0)
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

    void handle(int client)
    {
        std::string acc;
        char buf[2048];
        while (acc.find("\r\n\r\n") == std::string::npos) {
            const ssize_t n = ::recv(client, buf, sizeof(buf), 0);
            if (n <= 0)
                return;
            acc.append(buf, static_cast<size_t>(n));
            if (acc.size() > 256 * 1024)
                return;
        }

        const auto headerEnd = acc.find("\r\n\r\n") + 4;
        const std::string headers = acc.substr(0, headerEnd);
        std::string body = acc.substr(headerEnd);

        const long contentLength = parseContentLength(headers);
        if (contentLength < 0)
            return;
        while (body.size() < static_cast<size_t>(contentLength)) {
            const ssize_t n = ::recv(client, buf, sizeof(buf), 0);
            if (n <= 0)
                return;
            body.append(buf, static_cast<size_t>(n));
        }
        body.resize(static_cast<size_t>(contentLength));

        const auto der = respond(body);
        if (der.empty())
            return; // no reply — the client surfaces a transport failure

        std::string reply = "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: " +
                            std::to_string(der.size()) + "\r\nConnection: close\r\n\r\n";
        if (!sendAll(client, reply.data(), reply.size()))
            return;
        if (!sendAll(client, reinterpret_cast<const char*>(der.data()), der.size()))
            return;
        served.fetch_add(1);
    }

    void runLoop()
    {
        while (!stopFlag.load()) {
            const int client = ::accept(fd, nullptr, nullptr);
            if (client < 0) {
                if (stopFlag.load())
                    return;
                continue;
            }
            handle(client);
            ::close(client);
        }
    }
};

MockTsaServer::MockTsaServer() : impl(std::make_unique<Impl>())
{
    makeAuthority(impl->key, impl->cert);

    impl->fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (impl->fd < 0)
        throw std::runtime_error("MockTsaServer: socket() failed");
    int one = 1;
    ::setsockopt(impl->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(impl->fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(impl->fd);
        throw std::runtime_error("MockTsaServer: bind() failed");
    }
    if (::listen(impl->fd, 4) < 0) {
        ::close(impl->fd);
        throw std::runtime_error("MockTsaServer: listen() failed");
    }

    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    if (::getsockname(impl->fd, reinterpret_cast<sockaddr*>(&bound), &len) < 0) {
        ::close(impl->fd);
        throw std::runtime_error("MockTsaServer: getsockname() failed");
    }
    impl->boundPort = ntohs(bound.sin_port);

    Impl* raw = impl.get();
    impl->worker = std::thread([raw] { raw->runLoop(); });
}

MockTsaServer::~MockTsaServer()
{
    impl->stopFlag.store(true);
    if (impl->fd >= 0) {
        // Unblock the accept() the worker is parked in.
        const int wakeFd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (wakeFd >= 0) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(impl->boundPort);
            ::connect(wakeFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            ::close(wakeFd);
        }
    }
    if (impl->worker.joinable())
        impl->worker.join();
    if (impl->fd >= 0) {
        ::close(impl->fd);
        impl->fd = -1;
    }
}

std::string MockTsaServer::url() const
{
    return "http://127.0.0.1:" + std::to_string(impl->boundPort) + "/tsa";
}

uint16_t MockTsaServer::port() const
{
    return impl->boundPort;
}

int MockTsaServer::servedCount() const
{
    return impl->served.load();
}

} // namespace libresign::test
