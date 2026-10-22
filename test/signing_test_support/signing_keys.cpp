// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "signing_keys.h"

#include <stdexcept>
#include <utility>

namespace libresign::test {

SoftSigningKey::SoftSigningKey(const LibreSCRS::TestSupport::RsaTestKey& key) : key(key) {}

std::vector<std::uint8_t> SoftSigningKey::sign(std::span<const std::uint8_t> hash, const std::string& /*algorithm*/,
                                               std::span<const std::uint8_t> /*rawData*/)
{
    ++signCalls;
    auto signature = key.signPkcs1(nullptr, hash);
    if (signature.empty())
        throw std::runtime_error("SoftSigningKey: OpenSSL refused to sign");
    return signature;
}

std::vector<std::uint8_t> SoftSigningKey::certificate() const
{
    return key.certDer;
}

std::vector<std::vector<std::uint8_t>> SoftSigningKey::certificateChain() const
{
    return resolvedChain.empty() ? std::vector<std::vector<std::uint8_t>>{key.certDer} : resolvedChain;
}

void SoftSigningKey::setResolvedChain(std::vector<std::vector<std::uint8_t>> chain, ChainTermination termination)
{
    resolvedChain = std::move(chain);
    this->termination = resolvedChain.empty() ? ChainTermination::Unterminated : termination;
}

ChainTermination SoftSigningKey::chainTermination() const
{
    return termination;
}

const LibreSCRS::TestSupport::RsaTestKey& validSignerKey()
{
    static const auto key = LibreSCRS::TestSupport::makeRsaTestKey("LibreSCRS Test Signer", 0, 10L * 365 * 24 * 3600);
    return key;
}

const LibreSCRS::TestSupport::RsaTestKey& expiredSignerKey()
{
    static const auto key = LibreSCRS::TestSupport::makeRsaTestKey("LibreSCRS Expired Test Signer",
                                                                   -2L * 365 * 24 * 3600, -1L * 365 * 24 * 3600);
    return key;
}

} // namespace libresign::test
