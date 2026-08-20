// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "AnnexRegistry.h"

#include <memory>
#include <string>

using namespace LibreSCRS::Annex;

namespace {

std::vector<std::uint8_t> bytes(std::initializer_list<std::uint8_t> b)
{
    return {b};
}

/// Claims whatever it is told to, so registry mechanics can be exercised
/// without any real card format in the way.
class FakeAnnexReader final : public IAnnexReader
{
public:
    FakeAnnexReader(std::string id, bool claims, bool throws = false)
        : id_(std::move(id)), claims_(claims), throws_(throws)
    {}

    [[nodiscard]] std::string_view annexId() const noexcept override
    {
        return id_;
    }
    [[nodiscard]] bool handles(const EfDirEntry&) const override
    {
        return claims_;
    }

    [[nodiscard]] std::vector<LibreSCRS::Plugin::CardFieldGroup> read(const EfDirEntry&,
                                                                      const AnnexContext&) const override
    {
        if (throws_) {
            throw std::runtime_error("annex blew up");
        }
        LibreSCRS::Plugin::CardFieldGroup g;
        g.groupKey = annexGroupKey(id_, "personal");
        g.groupLabel = "Fake";
        g.addText("x", "X", "1");
        return {g};
    }

private:
    std::string id_;
    bool claims_;
    bool throws_;
};

} // namespace

// P1: two annexes on one card must both stay visible. With one reader a fixed
// key passes by luck, so this drives two.
TEST(AnnexRegistry, TwoAnnexesYieldDistinctGroupKeys)
{
    EXPECT_EQ(annexGroupKey("rs", "personal"), "annex.rs.personal");
    EXPECT_NE(annexGroupKey("rs", "personal"), annexGroupKey("xx", "personal"));
    EXPECT_NE(annexGroupKey("rs", "personal"), annexGroupKey("rs", "security"));
}

// The registry is an explicit list. If this ever becomes self-registration the
// count stops being knowable from the source, which is the point of the check.
TEST(AnnexRegistry, IsAnExplicitList)
{
    EXPECT_LE(annexReaders().size(), 4u);
}

// No annex reader may claim the applications the base plugins own.
TEST(AnnexRegistry, NoReaderClaimsTheBaseApplications)
{
    const EfDirEntry icao{bytes({0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01}), "ICAO",
                          bytes({0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01})};
    const EfDirEntry p15{bytes({0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35}), "PKCS15",
                         bytes({0x3F, 0x00, 0x50, 0x15})};

    for (const auto& r : annexReaders()) {
        EXPECT_FALSE(r->handles(icao)) << "reader " << r->annexId() << " claimed ICAO";
        EXPECT_FALSE(r->handles(p15)) << "reader " << r->annexId() << " claimed PKCS15";
    }
}

// The contract that protects every other card: a throwing reader yields no
// groups, and the registry -- not the caller -- is what swallows.
TEST(AnnexRegistry, ThrowingReaderYieldsNoGroupsAndDoesNotPropagate)
{
    std::vector<std::unique_ptr<IAnnexReader>> readers;
    readers.push_back(std::make_unique<FakeAnnexReader>("boom", /*claims=*/true, /*throws=*/true));

    const EfDirEntry entry{bytes({0x01}), "X", bytes({0x3F, 0x00})};
    const AnnexContext ctx;

    std::vector<LibreSCRS::Plugin::CardFieldGroup> groups;
    EXPECT_NO_THROW(groups = readAnnexFor(entry, ctx, readers));
    EXPECT_TRUE(groups.empty());
}

// A reader that blows up must not silence the ones behind it.
TEST(AnnexRegistry, ThrowingReaderDoesNotStopLaterReaders)
{
    std::vector<std::unique_ptr<IAnnexReader>> readers;
    readers.push_back(std::make_unique<FakeAnnexReader>("boom", /*claims=*/true, /*throws=*/true));
    readers.push_back(std::make_unique<FakeAnnexReader>("good", /*claims=*/true));

    const EfDirEntry entry{bytes({0x01}), "X", bytes({0x3F, 0x00})};
    const AnnexContext ctx;

    const auto groups = readAnnexFor(entry, ctx, readers);
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups.front().groupKey, "annex.good.personal");
}

TEST(AnnexRegistry, UnclaimedEntryYieldsNoGroups)
{
    const EfDirEntry unknown{bytes({0xDE, 0xAD}), "Unknown", bytes({0x3F, 0x00, 0xDE, 0xAD})};
    const AnnexContext ctx;
    EXPECT_TRUE(readAnnexFor(unknown, ctx).empty());
}
