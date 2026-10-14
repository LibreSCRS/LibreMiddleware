// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ecdsa_signature.h"

#include <ber.h>

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <algorithm>
#include <climits>
#include <cstddef>
#include <utility>

namespace pkcs15 {

namespace {

using LibreSCRS::Internal::Crypto::BnPtr;
using LibreSCRS::Internal::Crypto::EcdsaSigPtr;
using LibreSCRS::Internal::Crypto::EvpPkeyCtxPtr;
using LibreSCRS::Internal::Crypto::X509Ptr;

// The widest field a card's curve has: P-521, 66 bytes.
constexpr std::size_t kMaxFieldBytes = 66;

// A definite length at bytes[pos], in the two forms an ECDSA reply needs:
// short, or 81 xx. The decode is the shared BER one; how much this call site
// accepts is its own. Advances pos past the length.
std::optional<std::size_t> readLength(std::span<const std::uint8_t> bytes, std::size_t& pos)
{
    const auto parsed = LibreSCRS::SmartCard::Internal::tryParseLength(bytes.data(), bytes.size(), pos);
    if (!parsed.ok || parsed.next - pos > 2)
        return std::nullopt;
    pos = parsed.next;
    return parsed.length;
}

// An INTEGER at bytes[pos], its content read as an unsigned big-endian number:
// leading 00 bytes dropped, a set top bit kept as magnitude. Written
// right-aligned into @p out, which is zeroed first. False when it is no
// INTEGER, is empty, overruns @p bytes, or is wider than @p out.
bool readUnsigned(std::span<const std::uint8_t> bytes, std::size_t& pos, std::span<std::uint8_t> out)
{
    if (pos >= bytes.size() || bytes[pos] != 0x02)
        return false;
    ++pos;
    const auto length = readLength(bytes, pos);
    if (!length || *length == 0 || *length > bytes.size() - pos)
        return false;
    auto content = bytes.subspan(pos, *length);
    pos += *length;
    while (!content.empty() && content.front() == 0x00)
        content = content.subspan(1);
    if (content.size() > out.size())
        return false;
    std::fill(out.begin(), out.end(), std::uint8_t{0});
    std::copy(content.begin(), content.end(), out.end() - static_cast<std::ptrdiff_t>(content.size()));
    return true;
}

// The SEQUENCE { r, s } reading of @p reply, as fixed-width r || s.
std::optional<std::vector<std::uint8_t>> readSequence(std::span<const std::uint8_t> reply, std::size_t fieldBytes)
{
    std::size_t pos = 0;
    if (reply.empty() || reply[pos] != 0x30)
        return std::nullopt;
    ++pos;
    const auto length = readLength(reply, pos);
    if (!length || *length != reply.size() - pos)
        return std::nullopt; // the SEQUENCE is the whole reply: nothing trails it
    std::vector<std::uint8_t> raw(2 * fieldBytes);
    const std::span<std::uint8_t> halves(raw);
    if (!readUnsigned(reply, pos, halves.first(fieldBytes)) || !readUnsigned(reply, pos, halves.subspan(fieldBytes)) ||
        pos != reply.size())
        return std::nullopt; // exactly two INTEGERs, and they fill it
    return raw;
}

} // namespace

std::optional<std::vector<std::uint8_t>> ecdsaRawFromCardReply(std::span<const std::uint8_t> reply,
                                                               std::size_t fieldBytes, const EcdsaRawCheck& verifies)
{
    if (fieldBytes == 0 || fieldBytes > kMaxFieldBytes || reply.empty() || !verifies)
        return std::nullopt;
    std::optional<std::vector<std::uint8_t>> accepted;
    std::size_t acceptedCount = 0;
    if (auto fromSequence = readSequence(reply, fieldBytes); fromSequence && verifies(*fromSequence)) {
        accepted = std::move(fromSequence);
        ++acceptedCount;
    }
    if (reply.size() == 2 * fieldBytes) {
        std::vector<std::uint8_t> asRaw(reply.begin(), reply.end());
        // The same bytes from both readings are one candidate, not two.
        if (!(accepted && *accepted == asRaw) && verifies(asRaw)) {
            accepted = std::move(asRaw);
            ++acceptedCount;
        }
    }
    if (acceptedCount != 1)
        return std::nullopt; // nothing verifies, or two readings both claim to
    return accepted;
}

bool ecdsaRawVerifiesWithCertificate(std::span<const std::uint8_t> certDer, std::span<const std::uint8_t> hash,
                                     std::span<const std::uint8_t> rawRs) noexcept
{
    if (certDer.empty() || certDer.size() > static_cast<std::size_t>(LONG_MAX) || hash.empty() || rawRs.empty() ||
        rawRs.size() % 2 != 0 || rawRs.size() / 2 > static_cast<std::size_t>(INT_MAX))
        return false;
    const unsigned char* p = certDer.data();
    const X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(certDer.size())));
    if (!cert)
        return false;
    EVP_PKEY* publicKey = X509_get0_pubkey(cert.get());
    if (publicKey == nullptr || EVP_PKEY_get_base_id(publicKey) != EVP_PKEY_EC)
        return false;
    const int half = static_cast<int>(rawRs.size() / 2);
    // Leading zeros do not change r or s, so a signature at another width
    // would verify all the same; the halves must be the curve's width.
    if (half != (EVP_PKEY_get_bits(publicKey) + 7) / 8)
        return false;
    // The raw-to-DER step also exists in libresign (ecdsaRawToDer); the two
    // libraries share no internal home, so it is repeated rather than linked.
    BnPtr r(BN_bin2bn(rawRs.data(), half, nullptr));
    BnPtr s(BN_bin2bn(rawRs.data() + half, half, nullptr));
    const EcdsaSigPtr sig(ECDSA_SIG_new());
    if (!r || !s || !sig || ECDSA_SIG_set0(sig.get(), r.get(), s.get()) != 1)
        return false;
    (void)r.release(); // owned by sig from here on
    (void)s.release();
    unsigned char* der = nullptr;
    const int derLength = i2d_ECDSA_SIG(sig.get(), &der);
    if (derLength <= 0)
        return false;
    const EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(publicKey, nullptr));
    const bool verified =
        ctx && EVP_PKEY_verify_init(ctx.get()) == 1 &&
        EVP_PKEY_verify(ctx.get(), der, static_cast<std::size_t>(derLength), hash.data(), hash.size()) == 1;
    OPENSSL_free(der);
    return verified;
}

} // namespace pkcs15
