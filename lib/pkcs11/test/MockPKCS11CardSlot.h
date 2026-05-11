// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Header-only mocks for the @ref LibreSCRS::Pkcs11::Internal type
///        contract tests. Counters @ref slotDtorCount and
///        @ref cardDtorCount let lifecycle tests assert
///        slots-destroyed-before-card.

#include "internal/Crv.h"
#include "internal/PKCS11Card.h"
#include "internal/PKCS11Slot.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal::Test {

/// @brief Atomic counter incremented by @ref MockSlot's destructor.
inline std::atomic<int> slotDtorCount{0};

/// @brief Atomic counter incremented by @ref MockCard's destructor.
inline std::atomic<int> cardDtorCount{0};

/// @brief Minimal concrete @ref PKCS11Slot for type-contract tests.
class MockSlot final : public PKCS11Slot
{
public:
    MockSlot(std::weak_ptr<PKCS11Card> parentCard, std::vector<std::uint8_t> pinId, std::string pinLabel)
        : PKCS11Slot(std::move(parentCard), std::move(pinId), std::move(pinLabel))
    {}

    ~MockSlot() override
    {
        slotDtorCount.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] unsigned long login(unsigned long /*userType*/, std::span<const std::uint8_t> /*pin*/) override
    {
        return Crv::Ok;
    }

    [[nodiscard]] unsigned long logout() override
    {
        return Crv::Ok;
    }

    [[nodiscard]] std::vector<PKCS11ObjectInfo> enumerateObjects() override
    {
        return {};
    }

    [[nodiscard]] std::vector<std::uint8_t> signData(std::span<const std::uint8_t> /*data*/,
                                                     unsigned long /*mechanism*/,
                                                     std::span<const std::uint8_t> /*keyId*/) override
    {
        return {};
    }

    [[nodiscard]] std::vector<std::uint8_t> signWithDigestInfo(std::span<const std::uint8_t> /*digestInfo*/,
                                                               std::span<const std::uint8_t> /*rawData*/,
                                                               unsigned long /*mechanism*/,
                                                               std::span<const std::uint8_t> /*keyId*/) override
    {
        return {};
    }

    [[nodiscard]] std::size_t signatureSize(std::span<const std::uint8_t> /*keyId*/) const override
    {
        return 256u;
    }

    [[nodiscard]] std::vector<unsigned long> mechanisms() const override
    {
        return {};
    }

    /// @brief Test helper: assign @ref cachedTokenInfo from a subclass
    ///        (replaces the deleted base-class @c setTokenInfo setter).
    void setCachedTokenInfoForTest(PKCS11TokenInfo info)
    {
        std::scoped_lock lock(slotMutex);
        cachedTokenInfo = std::move(info);
    }
};

/// @brief Minimal concrete @ref PKCS11Card for type-contract tests.
///
/// @ref bind() records @p readerName and pushes one @ref MockSlot. The
/// concrete-card hooks (@ref establishPACE, @ref completeBind,
/// @ref reconnectInline) all return @ref Crv::Ok unconditionally.
class MockCard final : public PKCS11Card
{
public:
    MockCard() = default;

    ~MockCard() override
    {
        cardDtorCount.fetch_add(1, std::memory_order_relaxed);
    }

    /// @brief Pre-bind setter: configure how many extra slots beyond the
    ///        default one @ref bind() should populate. MUST be called
    ///        BEFORE @ref bind() — preserves the @ref PKCS11Card
    ///        post-bind @c slots immutability invariant.
    void setExtraSlotCountBeforeBind(std::size_t extra) noexcept
    {
        extraSlots = extra;
    }

    [[nodiscard]] unsigned long bind(const std::string& reader) override
    {
        readerName = reader;
        slots.push_back(
            std::make_shared<MockSlot>(weak_from_this(), std::vector<std::uint8_t>{}, std::string{"Mock PIN"}));
        for (std::size_t i = 0; i < extraSlots; ++i) {
            slots.push_back(
                std::make_shared<MockSlot>(weak_from_this(), std::vector<std::uint8_t>{}, std::string{"Mock PIN"}));
        }
        return Crv::Ok;
    }

protected:
    [[nodiscard]] unsigned long establishPACE() override
    {
        return Crv::Ok;
    }

    [[nodiscard]] unsigned long completeBind() override
    {
        return Crv::Ok;
    }

private:
    [[nodiscard]] unsigned long reconnectInline() override
    {
        return Crv::Ok;
    }

    std::size_t extraSlots{0};
};

} // namespace LibreSCRS::Pkcs11::Internal::Test
