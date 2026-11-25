// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// How the contact reader finds the document type and reads a file, against a
// detached PCSCConnection played by CardEdgeFileRig. A detached connection cannot
// reconnect, so a read that reached the reconnect step would throw: the tests
// below that expect no retry therefore fail on it, not only on a select count.

#include <gtest/gtest.h>

#include "apdu.h"
#include "cardedge_file_rig.h"
#include "eidcard.h"
#include "pcsc_connection.h"
#include "rs-eid-core/synthetic_annex.h"

#include <rs_document_profile.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <stdexcept>
#include <utility>
#include <vector>

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Internal::PCSCConnection;
namespace Core = LibreSCRS::RsEId::Core;
using LibreSCRS::RsEId::Test::CardEdgeFileRig;
using LibreSCRS::RsEId::Test::SelectShape;

namespace {

std::vector<std::uint8_t> aidOf(std::string_view code)
{
    for (const auto& p : Core::documentProfiles()) {
        if (p.code == code)
            return {p.aid.begin(), p.aid.end()};
    }
    return {};
}

// A connection answered by the rig, counting READ BINARY commands on the way.
// A single answer carries at most perAnswer bytes, the way a card (or a
// transport that shrank the Le) answers a longer ask; asked logs what each
// READ BINARY asked for.
struct Wired
{
    PCSCConnection conn{PCSCConnection::DetachedTag{}, "fake-cardedge"};
    CardEdgeFileRig rig;
    int reads = 0;
    std::size_t perAnswer = std::numeric_limits<std::size_t>::max();
    std::vector<std::pair<std::size_t, std::size_t>> asked; // offset, le

    Wired()
    {
        conn.setTransmitFilter([this](const APDUCommand& cmd) {
            auto resp = rig(cmd);
            if (cmd.ins == 0xB0) {
                ++reads;
                asked.emplace_back((static_cast<std::size_t>(cmd.p1) << 8) | cmd.p2, cmd.le);
                if (resp.data.size() > perAnswer)
                    resp.data.resize(perAnswer);
            }
            return resp;
        });
    }
};

std::vector<std::uint8_t> allocationFile(std::uint16_t fid, std::size_t size)
{
    return Core::TestData::makeContainer(fid, {{2625, "SSecFormat"}, {2626, "MUP Resursi CA 4"}}, size);
}

} // namespace

TEST(CardReaderGemaltoTest, SerrpIsResidencePermit)
{
    Wired w;
    w.rig.acceptAid(aidOf("RP"));
    eidcard::EIdCard card(w.conn);
    EXPECT_EQ(card.profile().code, "RP");
}

TEST(CardReaderGemaltoTest, SerelIsServiceId)
{
    Wired w;
    w.rig.rejectOtherAidsWith(0x6A82);
    w.rig.acceptAid(aidOf("EL"));
    eidcard::EIdCard card(w.conn);
    EXPECT_EQ(card.profile().code, "EL");
}

TEST(CardReaderGemaltoTest, NoApplicationThrows)
{
    Wired w;
    EXPECT_THROW(eidcard::EIdCard card(w.conn), std::runtime_error);
}

class ProbeOrderTest : public ::testing::TestWithParam<std::uint16_t>
{};

// The ID/IF/RP chip answers 6700 to an AID it does not host, the EL chip 6A82;
// both mean "not this one".
TEST_P(ProbeOrderTest, ProbeOrderIsIdIfRpEl)
{
    {
        Wired w;
        w.rig.rejectOtherAidsWith(GetParam());
        w.rig.acceptAid(aidOf("ID"));
        w.rig.acceptAid(aidOf("IF"));
        eidcard::EIdCard card(w.conn);
        EXPECT_EQ(card.profile().code, "ID");
        ASSERT_EQ(w.rig.selectedAids().size(), 1u);
        EXPECT_EQ(w.rig.selectedAids()[0], aidOf("ID"));
    }
    {
        Wired w;
        w.rig.rejectOtherAidsWith(GetParam());
        w.rig.acceptAid(aidOf("EL"));
        eidcard::EIdCard card(w.conn);
        EXPECT_EQ(card.profile().code, "EL");
        const std::vector<std::vector<std::uint8_t>> expected{aidOf("ID"), aidOf("IF"), aidOf("RP"), aidOf("EL")};
        EXPECT_EQ(w.rig.selectedAids(), expected);
    }
}

INSTANTIATE_TEST_SUITE_P(RejectStatus, ProbeOrderTest, ::testing::Values(0x6700, 0x6A82));

class ShapeTest : public ::testing::TestWithParam<SelectShape>
{};

// Protected: SELECT 9000, READ 6982. The status is final, so there is no
// re-select and no reconnect (which a detached connection would throw on).
TEST_P(ShapeTest, FinalStatusIsNotRetried)
{
    Wired w;
    w.rig.selectReplyShape(GetParam());
    w.rig.acceptAid(aidOf("ID"));
    w.rig.protectFile(0x0F12, 530);
    eidcard::EIdCard card(w.conn);

    const std::vector<std::uint16_t> fids{0x0F12};
    EXPECT_NO_THROW({
        const auto& files = card.load(fids);
        EXPECT_EQ(files.count(0x0F12), 0u);
    });
    EXPECT_EQ(w.rig.reconnects(), 0);
    EXPECT_EQ(w.rig.selectsOf(0x0F12), 1);
    EXPECT_EQ(w.reads, 1);
}

TEST_P(ShapeTest, AbsentFileIsNotRetried)
{
    Wired w;
    w.rig.selectReplyShape(GetParam());
    w.rig.acceptAid(aidOf("ID"));
    eidcard::EIdCard card(w.conn);

    const std::vector<std::uint16_t> fids{0x0F02};
    EXPECT_NO_THROW({
        const auto& files = card.load(fids);
        EXPECT_EQ(files.count(0x0F02), 0u);
    });
    EXPECT_EQ(w.rig.selectsOf(0x0F02), 1);
}

// 0D10 has no tag/length header (its first bytes read as a length of 0x0D07);
// only the size in the SELECT reply says how much to read.
TEST_P(ShapeTest, AllocationFileReadsWhole)
{
    Wired w;
    w.rig.selectReplyShape(GetParam());
    w.rig.acceptAid(aidOf("ID"));
    std::vector<std::uint8_t> key(141, 0x11);
    key[0] = 0x00;
    key[1] = 0x02;
    key[2] = 0x07;
    key[3] = 0x0D;
    w.rig.addFile(0x0D10, key);
    eidcard::EIdCard card(w.conn);

    const std::vector<std::uint16_t> fids{0x0D10};
    EXPECT_EQ(card.load(fids).at(0x0D10), key);
}

// 800 B on the Gemalto 2014 chip, 530 B on the C2V0 chip, answered 255 bytes
// at a time: more than one READ.
TEST_P(ShapeTest, LongAllocationFileReadsInChunks)
{
    Wired w;
    w.perAnswer = 255;
    w.rig.selectReplyShape(GetParam());
    w.rig.acceptAid(aidOf("ID"));
    const auto file = allocationFile(0x0F12, GetParam() == SelectShape::Short4 ? 800 : 530);
    w.rig.addFile(0x0F12, file);
    eidcard::EIdCard card(w.conn);

    const std::vector<std::uint16_t> fids{0x0F12};
    EXPECT_EQ(card.load(fids).at(0x0F12), file);
    EXPECT_GE(w.reads, 3);
}

INSTANTIATE_TEST_SUITE_P(Shapes, ShapeTest, ::testing::Values(SelectShape::Long10, SelectShape::Short4));

// A file that gave a final answer once is not asked for again.
TEST(CardReaderGemaltoTest, AbsentFileIsNotSelectedAgain)
{
    Wired w;
    w.rig.acceptAid(aidOf("ID"));
    w.rig.protectFile(0x0F12, 530);
    eidcard::EIdCard card(w.conn);

    const std::vector<std::uint16_t> fids{0x0F12};
    (void)card.load(fids);
    (void)card.load(fids);
    EXPECT_EQ(w.rig.selectsOf(0x0F12), 1);
}

// A read file is kept, and load() returns everything read so far.
TEST(CardReaderGemaltoTest, ReadFileIsNotReadAgain)
{
    Wired w;
    w.rig.acceptAid(aidOf("ID"));
    w.rig.addFile(0x0F02, Core::TestData::makeContainer(0x0F02, {{1546, "400000099"}}, 118));
    w.rig.addFile(0x0F03, Core::TestData::makeContainer(0x0F03, {{1558, "2902000000000"}}, 130));
    eidcard::EIdCard card(w.conn);

    const std::vector<std::uint16_t> first{0x0F02};
    EXPECT_EQ(card.load(first).size(), 1u);
    const std::vector<std::uint16_t> both{0x0F02, 0x0F03};
    EXPECT_EQ(card.load(both).size(), 2u);
    EXPECT_EQ(w.rig.selectsOf(0x0F02), 1);
}

// Header and declared length are the file as far as anything is concerned;
// the padding behind it is not read.
TEST(CardReaderGemaltoTest, HeaderFileEndsAtItsDeclaredLength)
{
    Wired w;
    w.rig.acceptAid(aidOf("ID"));
    const auto file = Core::TestData::makeContainer(0x0F02, {{1546, "400000099"}}, 118);
    w.rig.addFile(0x0F02, file);
    eidcard::EIdCard card(w.conn);

    const std::vector<std::uint16_t> fids{0x0F02};
    const auto& read = card.load(fids).at(0x0F02);
    EXPECT_EQ(read.size(), 4u + 4u + 9u);
    EXPECT_TRUE(std::equal(read.begin(), read.end(), file.begin()));
}

// Transient trouble (here one failed READ) still re-selects and tries again.
TEST(CardReaderGemaltoTest, TransientErrorIsRetried)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-cardedge");
    CardEdgeFileRig rig;
    rig.acceptAid(aidOf("ID"));
    const auto file = Core::TestData::makeContainer(0x0F02, {{1546, "400000099"}}, 0);
    rig.addFile(0x0F02, file);
    bool failed = false;
    conn.setTransmitFilter([&](const APDUCommand& cmd) {
        if (cmd.ins == 0xB0 && !failed) {
            failed = true;
            APDUResponse r;
            r.sw1 = 0x6F;
            r.sw2 = 0x00;
            return r;
        }
        return rig(cmd);
    });
    eidcard::EIdCard card(conn);

    const std::vector<std::uint16_t> fids{0x0F02};
    EXPECT_EQ(card.load(fids).at(0x0F02), file);
    EXPECT_EQ(rig.selectsOf(0x0F02), 2);
}

// A load that throws leaves the file untried, so the next load asks again.
TEST(CardReaderGemaltoTest, ThrownReadIsNotRemembered)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-cardedge");
    CardEdgeFileRig rig;
    rig.acceptAid(aidOf("ID"));
    const auto file = Core::TestData::makeContainer(0x0F02, {{1546, "400000099"}}, 0);
    rig.addFile(0x0F02, file);
    bool failing = true;
    conn.setTransmitFilter([&](const APDUCommand& cmd) {
        if (cmd.ins == 0xB0 && failing) {
            APDUResponse r;
            r.sw1 = 0x6F;
            r.sw2 = 0x00;
            return r;
        }
        return rig(cmd);
    });
    eidcard::EIdCard card(conn);

    const std::vector<std::uint16_t> fids{0x0F02};
    EXPECT_ANY_THROW((void)card.load(fids)); // retries spent; a detached reconnect throws
    failing = false;
    EXPECT_EQ(card.load(fids).at(0x0F02), file);
}

// The rest of the file is asked for in one command; a short answer is
// continued from where it ended, asking for what is still owed.
TEST(CardReaderGemaltoTest, BodyIsAskedForWholeAndShortAnswersAreContinued)
{
    Wired w;
    w.perAnswer = 958;
    w.rig.acceptAid(aidOf("ID"));
    const auto file = allocationFile(0x0F12, 2048);
    w.rig.addFile(0x0F12, file);
    eidcard::EIdCard card(w.conn);

    const std::vector<std::uint16_t> fids{0x0F12};
    EXPECT_EQ(card.load(fids).at(0x0F12), file);
    ASSERT_EQ(w.asked.size(), 3u); // 958 + 958 + 132
    EXPECT_EQ(w.asked[0], (std::pair<std::size_t, std::size_t>{0, 2048}));
    EXPECT_EQ(w.asked[1], (std::pair<std::size_t, std::size_t>{958, 2048 - 958}));
    EXPECT_EQ(w.asked[2], (std::pair<std::size_t, std::size_t>{2 * 958, 2048 - 2 * 958}));
}

TEST(CardReaderGemaltoTest, HeaderFileBodyIsAskedForWhole)
{
    Wired w;
    w.perAnswer = 958;
    w.rig.acceptAid(aidOf("ID"));
    // Header and one long field: 4 + 4 + 2040 declared bytes.
    const auto file = Core::TestData::makeContainer(0x0F02, {{1546, std::string(2040, 'x')}}, 0);
    w.rig.addFile(0x0F02, file);
    eidcard::EIdCard card(w.conn);

    const std::vector<std::uint16_t> fids{0x0F02};
    EXPECT_EQ(card.load(fids).at(0x0F02), file);
    ASSERT_GE(w.asked.size(), 2u);
    EXPECT_EQ(w.asked[0], (std::pair<std::size_t, std::size_t>{0, 4})); // the header
    EXPECT_EQ(w.asked[1], (std::pair<std::size_t, std::size_t>{4, file.size() - 4}));
}

TEST(CardReaderGemaltoTest, NoReadStartsAtTheEndOfTheFile)
{
    Wired w;
    w.perAnswer = 958;
    w.rig.acceptAid(aidOf("ID"));
    const auto file = allocationFile(0x0F12, 1916);
    w.rig.addFile(0x0F12, file);
    eidcard::EIdCard card(w.conn);

    const std::vector<std::uint16_t> fids{0x0F12};
    EXPECT_EQ(card.load(fids).at(0x0F12).size(), 1916u);
    for (const auto& [offset, le] : w.asked)
        EXPECT_LT(offset, file.size());
}
