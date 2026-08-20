// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "rs_digest_binding.h"

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace LibreSCRS::RsEId::Core {
namespace {

using LibreSCRS::Internal::Crypto::EvpMdCtxPtr;

[[nodiscard]] bool slotEquals(std::span<const std::uint8_t> content, std::size_t slot,
                              const std::array<std::uint8_t, kDigestSize>& digest) noexcept
{
    return CRYPTO_memcmp(digest.data(), content.data() + slot * kDigestSize, kDigestSize) == 0;
}

} // namespace

std::optional<std::array<std::uint8_t, kDigestSize>> sha256(std::span<const std::uint8_t> data)
{
    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        return std::nullopt;
    }

    std::array<std::uint8_t, kDigestSize> out{};
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), out.data(), nullptr) != 1) {
        return std::nullopt;
    }
    return out;
}

bool matchDigests(std::span<const std::uint8_t> signedContent, std::span<const BlockCandidates> blocks,
                  DigestBinding binding)
{
    if (signedContent.size() < kDigestSize || blocks.empty()) {
        return false;
    }
    const std::size_t slots = signedContent.size() / kDigestSize;

    // Both rules below belong to Positional alone. The shipped CardEdge path
    // truncates a ragged tail and never compared block count to slot count, and
    // this must not move behaviour on generations already in the field.
    if (binding == DigestBinding::Positional && (signedContent.size() % kDigestSize != 0 || blocks.size() > slots)) {
        return false;
    }

    for (std::size_t i = 0; i < blocks.size(); ++i) {
        bool matched = false;
        for (const auto& candidate : blocks[i]) {
            if (candidate.empty()) {
                continue;
            }
            const auto digest = sha256(candidate);
            if (!digest) {
                continue;
            }
            if (binding == DigestBinding::Positional) {
                matched = i < slots && slotEquals(signedContent, i, *digest);
            } else {
                for (std::size_t slot = 0; slot < slots && !matched; ++slot) {
                    matched = slotEquals(signedContent, slot, *digest);
                }
            }
            if (matched) {
                break;
            }
        }
        if (!matched) {
            return false;
        }
    }
    return true;
}

} // namespace LibreSCRS::RsEId::Core
