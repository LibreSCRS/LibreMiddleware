// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Unit tests for the FNV-1a stable @c CK_SLOT_ID helper
///        (@ref LibreSCRS::Pkcs11::Internal::computeSlotId).

#include "internal/SlotIdHash.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal::Test {
namespace {

class SlotIdHash : public ::testing::Test
{};

TEST_F(SlotIdHash, SameInputProducesSameId)
{
    const std::string reader = "Mock Reader 0";
    const std::vector<std::uint8_t> pinId{0x01, 0x02, 0x03};
    const auto a = computeSlotId(reader, pinId, SlotKind::Auth);
    const auto b = computeSlotId(reader, pinId, SlotKind::Auth);
    EXPECT_EQ(a, b);
}

TEST_F(SlotIdHash, DifferentPinIdProducesDifferentId)
{
    const std::string reader = "Mock Reader 0";
    const std::vector<std::uint8_t> pinIdA{0x01};
    const std::vector<std::uint8_t> pinIdB{0x02};
    const auto a = computeSlotId(reader, pinIdA, SlotKind::Auth);
    const auto b = computeSlotId(reader, pinIdB, SlotKind::Auth);
    EXPECT_NE(a, b);
}

TEST_F(SlotIdHash, DifferentKindProducesDifferentId)
{
    const std::string reader = "Mock Reader 0";
    const std::vector<std::uint8_t> pinId{0x01};
    const auto a = computeSlotId(reader, pinId, SlotKind::Auth);
    const auto b = computeSlotId(reader, pinId, SlotKind::Sign);
    EXPECT_NE(a, b);
}

TEST_F(SlotIdHash, DifferentReaderProducesDifferentId)
{
    const std::vector<std::uint8_t> pinId{0x01};
    const auto a = computeSlotId("Mock Reader 0", pinId, SlotKind::Auth);
    const auto b = computeSlotId("Mock Reader 1", pinId, SlotKind::Auth);
    EXPECT_NE(a, b);
}

TEST_F(SlotIdHash, NoCollisionInRealisticCardinality)
{
    // 32 readers x 4 PINs x 4 kinds = 512 distinct inputs. We assert that
    // FNV-1a maps all of them to distinct 32-bit hashes (zero collisions
    // at this realistic-deployment scale).
    constexpr std::array<SlotKind, 4> kinds{
        SlotKind::Auth,
        SlotKind::Sign,
        SlotKind::Enc,
        SlotKind::Generic,
    };
    std::set<std::uint32_t> seen;
    for (int reader = 0; reader < 32; ++reader) {
        const std::string readerName = "Mock Reader " + std::to_string(reader);
        for (std::uint8_t pin = 0; pin < 4; ++pin) {
            const std::vector<std::uint8_t> pinId{pin};
            for (auto kind : kinds) {
                const auto id = computeSlotId(readerName, pinId, kind);
                EXPECT_TRUE(seen.insert(id).second)
                    << "collision at reader=" << reader << " pin=" << static_cast<int>(pin)
                    << " kind=" << slotKindTag(kind);
            }
        }
    }
    EXPECT_EQ(seen.size(), 512u);
}

} // namespace
} // namespace LibreSCRS::Pkcs11::Internal::Test
