// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "AnnexDispatch.h"
#include "AnnexRegistry.h"
#include "RsAnnexReader.h"
#include "chip_auth_card_oracle.h"
#include "fake_pcsc_connection.h"
#include "rs-eid-core/synthetic_annex.h"

#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS_internal/SecureChannel/ChipAuthChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>

#include <rs_container.h>
#include <rs_digest_binding.h>
#include <rs_tags.h>

#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <string>
#include <vector>

using namespace LibreSCRS::Annex;
namespace Core = LibreSCRS::RsEId::Core;
namespace Fx = LibreSCRS::RsEId::Core::TestData;
using LibreSCRS::SecureChannel::TestSupport::FakePCSCConnection;

namespace {

constexpr std::uint16_t kDf = 0x0FF3;

/// A card that answers SELECT-by-path and READ BINARY from a file table.
/// Built from the format, never from card bytes.
class FakeAnnexCard
{
public:
    std::map<std::uint16_t, std::vector<std::uint8_t>> files;

    void install(FakePCSCConnection& conn)
    {
        conn.setResponder([this](const LibreSCRS::SmartCard::Internal::APDUCommand& cmd) {
            LibreSCRS::SmartCard::Internal::APDUResponse r;
            if (cmd.ins == 0xA4) {
                // Path is relative to the master file: <df><fid>, no leading 3F00.
                if (cmd.data.size() < 4 || cmd.data[0] != 0x0F || cmd.data[1] != 0xF3) {
                    r.sw1 = 0x6A;
                    r.sw2 = 0x80;
                    return r;
                }
                const auto fid = static_cast<std::uint16_t>((cmd.data[2] << 8) | cmd.data[3]);
                if (!files.count(fid)) {
                    r.sw1 = 0x6A;
                    r.sw2 = 0x82;
                    return r;
                }
                selected = fid;
                r.sw1 = 0x90;
                r.sw2 = 0x00;
                return r;
            }
            if (cmd.ins == 0xB0) {
                const auto& f = files.at(selected);
                const std::size_t off = static_cast<std::size_t>((cmd.p1 << 8) | cmd.p2);
                const std::size_t len = std::min<std::size_t>(cmd.le, off < f.size() ? f.size() - off : 0);
                r.data.assign(f.begin() + static_cast<long>(off), f.begin() + static_cast<long>(off + len));
                r.sw1 = 0x90;
                r.sw2 = 0x00;
                return r;
            }
            r.sw1 = 0x6D;
            r.sw2 = 0x00;
            return r;
        });
    }

private:
    std::uint16_t selected{0};
};

std::vector<std::uint8_t> le(std::uint16_t v)
{
    return {static_cast<std::uint8_t>(v & 0xFF), static_cast<std::uint8_t>(v >> 8)};
}

/// A well-formed annex: manifest, two data files, an id hash, and the fixed
/// object that covers them in the order the manifest implies.
/// @param docData contents of 0F02, so a test can vary it and still get a card
///        whose signed object actually covers what it carries.
FakeAnnexCard goodCard(std::vector<std::pair<std::uint16_t, std::string>> docData = {{1548, "ID000000000"}})
{
    FakeAnnexCard card;
    card.files[0x0F1B] = Fx::makeManifest({0x0F02, 0x0F03, 0x0FA1, 0x0F1C}, 150);
    card.files[0x0F02] = Fx::makeContainer(0x0F02, docData, 157);
    card.files[0x0F03] = Fx::makeContainer(0x0F03, {{1561, "PARENT"}}, 822);
    card.files[0x0FA1] = Fx::makeContainer(0x0FA1, {{554, "0123456789ABCDEF"}}, 26);

    std::vector<std::uint8_t> content;
    for (const auto fid : {0x0F1B, 0x0F02, 0x0F03, 0x0FA1}) {
        const auto tlv = Core::leadingTlv(card.files[static_cast<std::uint16_t>(fid)]);
        const auto d = Core::sha256(*tlv);
        content.insert(content.end(), d->begin(), d->end());
    }
    const auto signed_ = Fx::makeSignedObject(content);

    // The signed object sits inside the same container, behind an inner header.
    std::vector<std::uint8_t> inner{0x10, 0x08};
    const auto lenBytes = le(static_cast<std::uint16_t>(signed_.cms.size()));
    inner.insert(inner.end(), lenBytes.begin(), lenBytes.end());
    inner.insert(inner.end(), signed_.cms.begin(), signed_.cms.end());

    std::vector<std::uint8_t> sodFile = le(0x0F1C);
    const auto outerLen = le(static_cast<std::uint16_t>(inner.size()));
    sodFile.insert(sodFile.end(), outerLen.begin(), outerLen.end());
    sodFile.insert(sodFile.end(), inner.begin(), inner.end());
    card.files[0x0F1C] = sodFile;
    return card;
}

EfDirEntry annexEntry()
{
    return EfDirEntry{{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x4F, 0x44, 0x49, 0x44, 0x01},
                      "Additional Data",
                      {0x3F, 0x00, 0x0F, 0xF3}};
}

std::vector<LibreSCRS::Plugin::CardFieldGroup> readWith(FakeAnnexCard& card, const EfDirEntry& entry)
{
    FakePCSCConnection conn;
    card.install(conn);
    AnnexContext ctx;
    ctx.conn = &conn;
    return RsAnnexReader{}.read(entry, ctx);
}

} // namespace

// EF.DIR states the path from the root, but SELECT-by-path is already relative
// to it and the card rejects the redundant leading identifier.
TEST(RsAnnexReader, DropsTheRedundantMasterFileFromThePath)
{
    EXPECT_EQ(annexDfPath(annexEntry()), (std::vector<std::uint8_t>{0x0F, 0xF3}));
}

TEST(RsAnnexReader, HandlesEntryMatchedByAid)
{
    EXPECT_TRUE(RsAnnexReader{}.handles(annexEntry()));
}

// The identifier has moved once already; a record found only by path must still
// be tried, or the annex vanishes silently on a card that renames it.
TEST(RsAnnexReader, HandlesEntryMatchedByPathWhenAidIsUnknown)
{
    EfDirEntry moved = annexEntry();
    moved.aid = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_TRUE(RsAnnexReader{}.handles(moved));
}

TEST(RsAnnexReader, DoesNotClaimTheBaseApplications)
{
    const EfDirEntry icao{
        {0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01}, "ICAO", {0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01}};
    EXPECT_FALSE(RsAnnexReader{}.handles(icao));
}

TEST(RsAnnexReader, EmitsDataGroupAndItsOwnVerdictGroup)
{
    auto card = goodCard();
    const auto groups = readWith(card, annexEntry());

    ASSERT_EQ(groups.size(), 2u);
    EXPECT_EQ(groups[0].groupKey, "annex.rs.personal");
    EXPECT_EQ(groups[1].groupKey, "annex.rs.security");
    EXPECT_EQ(groups[1].fields.at(0).textValue().value_or(std::string{}), "PASSED");
    // Authenticity is not silently implied by integrity: no anchor was offered,
    // so the signer is unproven and the group says so.
    EXPECT_EQ(groups[1].fields.at(1).key, "annex_authenticity");
    EXPECT_EQ(groups[1].fields.at(1).textValue().value_or(std::string{}), "NOT_PERFORMED");
}

// The contract that protects every other card in the field.
TEST(RsAnnexReader, MissingDedicatedFileYieldsNoGroups)
{
    FakeAnnexCard empty;
    EXPECT_TRUE(readWith(empty, annexEntry()).empty());
}

// A foreign issuer sitting on the same path is dropped on content, not trusted
// because the path matched.
TEST(RsAnnexReader, WithdrawsWhenManifestOuterTagIsNotTheManifestFileId)
{
    auto card = goodCard();
    card.files[0x0F1B] = Fx::makeContainer(0x0F02, {{1537, "05"}}, 150); // wrong outer tag
    EXPECT_TRUE(readWith(card, annexEntry()).empty());
}

TEST(RsAnnexReader, RejectsFileWhoseOuterTagDoesNotMatchItsFileId)
{
    auto card = goodCard();
    card.files[0x0F03] = Fx::makeContainer(0x0F04, {{1561, "PARENT"}}, 822);
    EXPECT_TRUE(readWith(card, annexEntry()).empty());
}

// Item 140 through the reader: a covered file swapped after signing. Nothing is
// published -- personal details that cannot be attributed are withheld, not
// shown with a warning beside them.
TEST(RsAnnexReader, SubstitutedCoveredFileYieldsNoGroups)
{
    auto card = goodCard();
    card.files[0x0F02] = Fx::makeContainer(0x0F02, {{1548, "ID999999999"}}, 157);
    EXPECT_TRUE(readWith(card, annexEntry()).empty());
}

// A missing signed object is the same answer: unverifiable is unpublished.
TEST(RsAnnexReader, MissingSignedObjectYieldsNoGroups)
{
    auto card = goodCard();
    card.files.erase(0x0F1C);
    EXPECT_TRUE(readWith(card, annexEntry()).empty());
}

// D5: tags whose meaning is unconfirmed carry filler on the test card, and a
// wrongly named personal field is worse than an absent one.
TEST(RsAnnexReader, DoesNotPublishTagsOfUnconfirmedMeaning)
{
    // The card is built around this content, so the object covers it and the
    // annex verifies -- otherwise nothing would be published for any reason.
    auto card = goodCard({{1548, "ID000000000"}, {1552, "SC"}, {1681, "X11111111X"}});
    const auto groups = readWith(card, annexEntry());

    ASSERT_FALSE(groups.empty());
    for (const auto& f : groups[0].fields) {
        EXPECT_NE(f.textValue().value_or(std::string{}), "SC");
        EXPECT_NE(f.textValue().value_or(std::string{}), "X11111111X");
    }
}

// --- dispatch ---

namespace {

/// The fake card again, now also answering the master file and EF.DIR, so the
/// dispatcher can find the annex the way the real one does.
class FakeCardWithEfDir
{
public:
    std::map<std::uint16_t, std::vector<std::uint8_t>> files;
    std::vector<std::uint8_t> efDir;

    void install(FakePCSCConnection& conn)
    {
        conn.setResponder([this](const LibreSCRS::SmartCard::Internal::APDUCommand& cmd) {
            LibreSCRS::SmartCard::Internal::APDUResponse r;
            r.sw1 = 0x90;
            r.sw2 = 0x00;

            if (cmd.ins == 0xA4 && cmd.data.size() == 2) {
                selected = static_cast<std::uint16_t>((cmd.data[0] << 8) | cmd.data[1]);
                mfSelected = (selected == 0x3F00);
                return r;
            }
            if (cmd.ins == 0xA4 && cmd.data.size() == 4) {
                mfSelected = false;
                const auto fid = static_cast<std::uint16_t>((cmd.data[2] << 8) | cmd.data[3]);
                if (cmd.data[0] != 0x0F || cmd.data[1] != 0xF3 || !files.count(fid)) {
                    r.sw1 = 0x6A;
                    r.sw2 = 0x82;
                    return r;
                }
                selected = fid;
                return r;
            }
            if (cmd.ins == 0xB0) {
                const std::vector<std::uint8_t>* src = nullptr;
                if (selected == 0x2F00) {
                    src = &efDir;
                } else if (files.count(selected)) {
                    src = &files.at(selected);
                }
                if (src == nullptr) {
                    r.sw1 = 0x6A;
                    r.sw2 = 0x82;
                    return r;
                }
                const std::size_t off = static_cast<std::size_t>((cmd.p1 << 8) | cmd.p2);
                const std::size_t len = std::min<std::size_t>(cmd.le, off < src->size() ? src->size() - off : 0);
                r.data.assign(src->begin() + static_cast<long>(off), src->begin() + static_cast<long>(off + len));
                if (len < cmd.le) {
                    // As the real card does: fewer bytes than asked for ends with
                    // a warning, not 9000.
                    r.sw1 = 0x62;
                    r.sw2 = 0x82;
                }
                return r;
            }
            r.sw1 = 0x6D;
            r.sw2 = 0x00;
            return r;
        });
    }

    [[nodiscard]] bool masterFileSelected() const
    {
        return mfSelected;
    }

private:
    std::uint16_t selected{0};
    bool mfSelected{false};
};

std::vector<std::uint8_t> efDirWithAnnex()
{
    const std::vector<std::uint8_t> aid{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x4F, 0x44, 0x49, 0x44, 0x01};
    const std::string label = "Additional Data";
    const std::vector<std::uint8_t> path{0x3F, 0x00, 0x0F, 0xF3};

    std::vector<std::uint8_t> body;
    body.push_back(0x4F);
    body.push_back(static_cast<std::uint8_t>(aid.size()));
    body.insert(body.end(), aid.begin(), aid.end());
    body.push_back(0x50);
    body.push_back(static_cast<std::uint8_t>(label.size()));
    body.insert(body.end(), label.begin(), label.end());
    body.push_back(0x51);
    body.push_back(static_cast<std::uint8_t>(path.size()));
    body.insert(body.end(), path.begin(), path.end());

    std::vector<std::uint8_t> out{0x61, static_cast<std::uint8_t>(body.size())};
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

FakeCardWithEfDir cardWithAnnex()
{
    FakeCardWithEfDir c;
    c.files = goodCard().files;
    c.efDir = efDirWithAnnex();
    return c;
}

} // namespace

TEST(AnnexDispatch, FindsTheAnnexThroughEfDir)
{
    auto card = cardWithAnnex();
    FakePCSCConnection conn;
    card.install(conn);
    AnnexContext ctx;
    ctx.conn = &conn;

    const auto groups = readAllAnnexes(ctx);
    ASSERT_EQ(groups.size(), 2u);
    EXPECT_EQ(groups[0].groupKey, "annex.rs.personal");
}

// D7: the annex directory must not stay selected, or the next plugin on this
// session starts from a directory it did not choose.
TEST(AnnexDispatch, MasterFileIsSelectedAgainAfterAnnexRead)
{
    auto card = cardWithAnnex();
    FakePCSCConnection conn;
    card.install(conn);
    AnnexContext ctx;
    ctx.conn = &conn;

    ASSERT_FALSE(readAllAnnexes(ctx).empty());
    EXPECT_TRUE(card.masterFileSelected());
}

// ...and also when there was nothing to read at all.
TEST(AnnexDispatch, MasterFileIsSelectedAgainWhenNoAnnexIsPresent)
{
    FakeCardWithEfDir card;
    card.efDir = efDirWithAnnex(); // advertised, but no files behind it
    FakePCSCConnection conn;
    card.install(conn);
    AnnexContext ctx;
    ctx.conn = &conn;

    EXPECT_TRUE(readAllAnnexes(ctx).empty());
    EXPECT_TRUE(card.masterFileSelected());
}

TEST(AnnexDispatch, CardWithoutEfDirYieldsNoGroups)
{
    FakeCardWithEfDir card;
    FakePCSCConnection conn;
    card.install(conn);
    AnnexContext ctx;
    ctx.conn = &conn;

    EXPECT_TRUE(readAllAnnexes(ctx).empty());
}

TEST(AnnexDispatch, NullConnectionYieldsNoGroups)
{
    const AnnexContext ctx;
    EXPECT_TRUE(readAllAnnexes(ctx).empty());
}

// When the read runs over a session-scoped SM channel, the master-file restore
// at the end of the annex pass must clear the channel's cached applet AID: the
// MF select rode the tunnel but did not update the cached AID, so a second
// read's same-applet fast path would otherwise skip the re-SELECT and read the
// master file. After the pass the cached AID must be the empty sentinel.
TEST(AnnexDispatch, MasterFileRestoreClearsCachedAppletOnSmChannel)
{
    // A minimal SM oracle: success to every wrapped SELECT, empty to every
    // wrapped READ, so EF.DIR comes back empty (no annexes) but the wrapped MF
    // restore still runs at scope exit.
    FakePCSCConnection conn;
    auto oracle = std::make_shared<LibreSCRS::Test::AesSmCardOracle>(
        std::vector<std::uint8_t>(16, 0x11), std::vector<std::uint8_t>(16, 0x22), std::vector<std::uint8_t>(16, 0x00));
    // SM commands reach the test double via transmitRaw, which hands the
    // responder a header-only command — replay the full wire frame from
    // rawHistory into the oracle.
    conn.setResponder([&conn, oracle](const LibreSCRS::SmartCard::Internal::APDUCommand&) {
        return oracle->respond(conn.rawHistory().back());
    });

    const LibreSCRS::SmartCard::AppletAid boundAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SecureChannel::SessionKeys keys;
    keys.encKey = LibreSCRS::Secure::Buffer{16, 0x11};
    keys.macKey = LibreSCRS::Secure::Buffer{16, 0x22};
    keys.ssc = LibreSCRS::Secure::Buffer{16, 0x00};
    keys.cipher = LibreSCRS::SecureChannel::SmCipher::Aes;
    LibreSCRS::SecureChannel::ChipAuthChannel channel{conn, boundAid, std::move(keys)};
    ASSERT_FALSE(channel.currentApplet().empty());

    AnnexContext ctx;
    ctx.conn = &conn;
    ctx.channel = &channel;
    (void)readAllAnnexes(ctx);

    EXPECT_TRUE(channel.currentApplet().empty())
        << "the SM channel's cached applet AID must be cleared after the master-file restore";
}

// The clear must not depend on the MF select surviving the wire: a throw out
// of the restore's own dispatch (cancellation, transient PC/SC failure) must
// still leave the cached AID cleared, or the stale-AID same-applet fast path
// re-arms against whatever file the card was actually left on.
TEST(AnnexDispatch, MasterFileRestoreClearsCachedAppletEvenWhenSelectThrows)
{
    FakePCSCConnection conn;
    conn.setResponder(
        [](const LibreSCRS::SmartCard::Internal::APDUCommand&) -> LibreSCRS::SmartCard::Internal::APDUResponse {
            throw std::runtime_error{"wire lost"};
        });

    const LibreSCRS::SmartCard::AppletAid boundAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    LibreSCRS::SecureChannel::SessionKeys keys;
    keys.encKey = LibreSCRS::Secure::Buffer{16, 0x11};
    keys.macKey = LibreSCRS::Secure::Buffer{16, 0x22};
    keys.ssc = LibreSCRS::Secure::Buffer{16, 0x00};
    keys.cipher = LibreSCRS::SecureChannel::SmCipher::Aes;
    LibreSCRS::SecureChannel::ChipAuthChannel channel{conn, boundAid, std::move(keys)};
    ASSERT_FALSE(channel.currentApplet().empty());

    AnnexContext ctx;
    ctx.conn = &conn;
    ctx.channel = &channel;
    try {
        (void)readAllAnnexes(ctx);
    } catch (...) {
        // The read itself may propagate the wire failure; the restore must not
        // depend on it succeeding.
    }

    EXPECT_TRUE(channel.currentApplet().empty())
        << "the cached applet AID must be cleared even when the MF select throws";
}
