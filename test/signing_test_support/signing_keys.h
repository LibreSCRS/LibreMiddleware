// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// The key the signing tests sign with when no card is involved: one held in
// memory. card_signing_key.h reaches a real card's.

#include "native/signing_key.h"
#include "rsa_test_key.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace libresign::test {

/// A SigningKey whose RSA key lives in memory, with a self-signed certificate:
/// the stand-in for a card's key wherever a test needs only a key that signs.
/// It signs the DigestInfo the engine hands an RSA key (PKCS#1 v1.5), reports
/// the leaf alone as its chain until one is resolved, and counts its signatures.
class SoftSigningKey final : public SigningKey
{
public:
    /// @p key is borrowed and must outlive this signing key.
    explicit SoftSigningKey(const LibreSCRS::TestSupport::RsaTestKey& key);

    std::vector<std::uint8_t> sign(std::span<const std::uint8_t> hash, const std::string& algorithm,
                                   std::span<const std::uint8_t> rawData) override;
    std::vector<std::uint8_t> certificate() const override;
    std::vector<std::vector<std::uint8_t>> certificateChain() const override;
    void setResolvedChain(std::vector<std::vector<std::uint8_t>> chain, ChainTermination termination) override;
    ChainTermination chainTermination() const override;

    int signCalls = 0;

private:
    const LibreSCRS::TestSupport::RsaTestKey& key;
    std::vector<std::vector<std::uint8_t>> resolvedChain;
    ChainTermination termination = ChainTermination::Unterminated;
};

/// The signer every in-memory test signs with: self-signed and valid. One
/// key per test process, so every signature a process makes carries the same
/// certificate, as a provisioned token's would.
const LibreSCRS::TestSupport::RsaTestKey& validSignerKey();

/// A second signer, distinct from @ref validSignerKey, whose certificate
/// expired a year ago: the signer-expiry policy and the two-signer cases.
const LibreSCRS::TestSupport::RsaTestKey& expiredSignerKey();

} // namespace libresign::test
