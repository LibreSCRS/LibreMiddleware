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

[[nodiscard]] bool candidatesMatchSlot(std::span<const std::uint8_t> content, std::size_t slot,
                                       const BlockCandidates& candidates)
{
    for (const auto& candidate : candidates) {
        if (candidate.empty()) {
            continue;
        }
        const auto digest = sha256(candidate);
        if (digest && slotEquals(content, slot, *digest)) {
            return true;
        }
    }
    return false;
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

bool matchDigests(std::span<const std::uint8_t> signedContent, std::span<const SlotInput> slots)
{
    if (signedContent.size() < kDigestSize || slots.empty() || signedContent.size() != slots.size() * kDigestSize) {
        return false;
    }

    bool checkedOne = false;
    for (std::size_t i = 0; i < slots.size(); ++i) {
        const auto* candidates = std::get_if<BlockCandidates>(&slots[i]);
        if (!candidates) {
            continue; // SkipSlot: counted, not examined
        }
        if (!candidatesMatchSlot(signedContent, i, *candidates)) {
            return false;
        }
        checkedOne = true;
    }
    return checkedOne;
}

} // namespace LibreSCRS::RsEId::Core
