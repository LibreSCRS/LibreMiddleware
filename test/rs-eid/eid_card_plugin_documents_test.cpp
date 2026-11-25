// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Reads synthetic Serbian eID document types through the real, dlopen'd rs-eid
// plugin, against a detached connection scripted by CardEdgeFileRig. Signed
// objects are made here, under an ephemeral issuer chain whose anchors reach the
// plugin through a TrustStore; no real card bytes, photos or certificates.

#include <gtest/gtest.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS/Trust/TrustStoreService.h>
#include <session_access.h>
#include <pcsc_connection.h>

#include "cardedge_file_rig.h"
#include "document_fixtures.h"
#include "synthetic_pki.h"

#include <rs_document_profile.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

using LibreSCRS::Plugin::CardData;
using LibreSCRS::Plugin::CardFieldGroup;
using LibreSCRS::RsEId::Test::CardEdgeFileRig;
using LibreSCRS::RsEId::Test::CardFiles;
using LibreSCRS::SmartCard::Internal::APDUCommand;
namespace Core = LibreSCRS::RsEId::Core;
namespace RT = LibreSCRS::RsEId::Test;

namespace {

const std::vector<std::uint8_t> kGemaltoAtr{0x3B, 0xFF, 0x94, 0x00, 0x00, 0x81, 0x31, 0x80, 0x43};

const Core::DocumentProfile& profileOf(std::string_view code)
{
    for (const auto& p : Core::documentProfiles()) {
        if (p.code == code)
            return p;
    }
    throw std::logic_error("no such profile");
}

std::vector<std::uint8_t> aidOf(std::string_view code)
{
    const auto& p = profileOf(code);
    return {p.aid.begin(), p.aid.end()};
}

/// The trust anchors a card read is judged against, handed over the way a host
/// does: through the TrustStore the registry is constructed with.
struct Anchors
{
    std::shared_ptr<LibreSCRS::Trust::TrustStoreService> service;

    explicit Anchors(const std::vector<std::vector<std::uint8_t>>& ders)
    {
        const auto dir =
            std::filesystem::temp_directory_path() / ("rs-eid-plugin-anchors-" + std::to_string(::getpid()));
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);
        int n = 0;
        for (const auto& der : ders) {
            std::ofstream(dir / ("anchor" + std::to_string(n++) + ".cer"), std::ios::binary)
                .write(reinterpret_cast<const char*>(der.data()), static_cast<std::streamsize>(der.size()));
        }
        ::setenv("LIBRESCRS_CERTIFICATES_DIR", dir.c_str(), 1);
        auto created = LibreSCRS::Trust::TrustStoreService::create(LibreSCRS::Trust::TrustConfig{});
        ::unsetenv("LIBRESCRS_CERTIFICATES_DIR");
        std::filesystem::remove_all(dir);
        if (created.has_value())
            service = *created;
    }

    std::shared_ptr<const LibreSCRS::Trust::TrustStore> store() const
    {
        return service ? service->trustStore() : nullptr;
    }
};

/// One card: a detached session answered by a rig.
struct Card
{
    std::unique_ptr<CardEdgeFileRig> rig = std::make_unique<CardEdgeFileRig>();
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> session =
        LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted CardEdge Reader");

    Card(std::string_view code, CardFiles files, const std::vector<std::uint16_t>& protectedFids = {},
         const std::vector<std::uint8_t>& atr = kGemaltoAtr)
    {
        auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*session);
        // The plugin service reads the ATR the session recorded when it opened.
        LibreSCRS::SmartCard::Testing::SessionAccess::setAtr(*session, atr);
        rig->rejectOtherAidsWith(code == "EL" ? 0x6A82 : 0x6700);
        rig->acceptAid(aidOf(code));
        for (auto& [fid, bytes] : files)
            rig->addFile(fid, std::move(bytes));
        for (const auto fid : protectedFids)
            rig->protectFile(fid, 530);
        auto* r = rig.get();
        conn.setTransmitFilter([r](const APDUCommand& cmd) { return (*r)(cmd); });
    }
};

struct Plugin
{
    LibreSCRS::Plugin::CardPluginService registry;
    std::shared_ptr<LibreSCRS::Plugin::CardPlugin> plugin;

    explicit Plugin(std::shared_ptr<const LibreSCRS::Trust::TrustStore> trust = nullptr)
        : registry(std::filesystem::path(PLUGIN_DIR), std::move(trust))
    {
        for (const auto& p : registry.plugins()) {
            if (p->pluginId() == "rs-eid")
                plugin = p;
        }
    }
};

const CardFieldGroup* groupOf(const CardData& data, const std::string& key)
{
    const auto it = std::ranges::find(data.groups, key, &CardFieldGroup::groupKey);
    return it == data.groups.end() ? nullptr : &*it;
}

bool hasField(const CardFieldGroup& group, const std::string& key)
{
    return std::ranges::any_of(group.fields, [&](const auto& f) { return f.key == key; });
}

std::string valueOf(const CardFieldGroup& group, const std::string& key)
{
    for (const auto& f : group.fields) {
        if (f.key == key)
            return {f.value.begin(), f.value.end()};
    }
    return "<absent>";
}

std::set<std::string> keysOf(const CardFieldGroup& group)
{
    std::set<std::string> out;
    for (const auto& f : group.fields)
        out.insert(f.key);
    return out;
}

std::vector<std::string> groupOrder(const CardData& data)
{
    std::vector<std::string> out;
    for (const auto& g : data.groups)
        out.push_back(g.groupKey);
    return out;
}

LibreSCRS::Plugin::ReadResult read(Plugin& p, Card& card)
{
    return p.plugin->readCard(*card.session);
}

using Slots = std::vector<std::vector<std::uint8_t>>;

Slots randomSlots(std::size_t n)
{
    Slots out;
    for (std::size_t i = 0; i < n; ++i)
        out.push_back(RT::sha256({static_cast<std::uint8_t>(i), 0x42}));
    return out;
}

/// Citizen card whose fixed object (0F1C) is replaced by one over @p slots.
CardFiles citizenWithFixedObject(const RT::ResursiChain& chain, const Slots& slots, bool breakSignature = false)
{
    auto files = RT::withSignedObjects(profileOf("ID"), RT::citizenFiles(), chain);
    auto cms = chain.sign(slots);
    if (breakSignature)
        cms[cms.size() - 20] ^= 0xFF;
    files[0x0F1C] = RT::signedObjectFile(0x0F1C, cms);
    return files;
}

std::string fixedVerdict(Plugin& p, Card& card)
{
    const auto rr = read(p, card);
    EXPECT_EQ(rr.status, LibreSCRS::Plugin::ReadResult::Status::Ok) << rr.diagnosticDetail.value_or("<no diag>");
    if (!rr.data)
        return "<no data>";
    const auto* v = groupOf(*rr.data, "verification");
    return v ? valueOf(*v, "fixed_verification") : "<no group>";
}

} // namespace

// The residence permit has no state in its address file, so the address group's
// first field is absent. Reading must still succeed, with the group present and
// no state key.
TEST(RsEidPluginDocumentsTest, ResidencePermitWithoutStateReads)
{
    Plugin p;
    ASSERT_NE(p.plugin, nullptr) << "rs-eid-plugin.so did not load from " << PLUGIN_DIR;
    Card card("RP", RT::residencePermitFiles());

    const auto rr = read(p, card);
    ASSERT_EQ(rr.status, LibreSCRS::Plugin::ReadResult::Status::Ok) << rr.diagnosticDetail.value_or("<no diag>");
    ASSERT_TRUE(rr.data.has_value());

    const auto* address = groupOf(*rr.data, "address");
    ASSERT_NE(address, nullptr);
    EXPECT_FALSE(hasField(*address, "state"));
    EXPECT_TRUE(hasField(*address, "community"));
    EXPECT_EQ(valueOf(*groupOf(*rr.data, "meta"), "card_type"), "RP");
}

TEST(RsEidPluginDocumentsTest, ServiceIdReads)
{
    Plugin p;
    ASSERT_NE(p.plugin, nullptr);
    Card card("EL", RT::serviceIdFiles());

    const auto rr = read(p, card);
    ASSERT_EQ(rr.status, LibreSCRS::Plugin::ReadResult::Status::Ok) << rr.diagnosticDetail.value_or("<no diag>");
    ASSERT_TRUE(rr.data.has_value());
    EXPECT_EQ(valueOf(*groupOf(*rr.data, "meta"), "card_type"), "EL");
    EXPECT_EQ(groupOrder(*rr.data),
              (std::vector<std::string>{"meta", "personal", "service", "document", "photo", "verification"}));
    EXPECT_EQ(groupOf(*rr.data, "address"), nullptr);

    // UTF-16 text, UTF-8 text and ASCII each come out as their own characters.
    const auto& personal = *groupOf(*rr.data, "personal");
    EXPECT_EQ(valueOf(personal, "surname"), "ШАЈЕРМАН");
    EXPECT_EQ(valueOf(personal, "given_name"), "ЈОВАНА");
    EXPECT_EQ(valueOf(personal, "sex"), "М");
    EXPECT_EQ(valueOf(personal, "blood_group"), "A-");
    EXPECT_EQ(valueOf(personal, "date_of_birth"), "31.07.1972");
    const auto& service = *groupOf(*rr.data, "service");
    EXPECT_EQ(valueOf(service, "badge_number"), "00000097");
    EXPECT_EQ(valueOf(service, "rank"), "Načelnik");
    EXPECT_EQ(valueOf(service, "position"), "Šef");
}

// The keys of a CardEdge read are fixed; a card gets exactly those it carries.
TEST(RsEidPluginDocumentsTest, CitizenAndForeignerKeys)
{
    Plugin p;
    ASSERT_NE(p.plugin, nullptr);
    using Keys = std::set<std::string>;

    {
        Card card("ID", RT::citizenFiles());
        const auto rr = read(p, card);
        ASSERT_TRUE(rr.data.has_value());
        EXPECT_EQ(valueOf(*groupOf(*rr.data, "meta"), "card_type"), "ID");
        EXPECT_EQ(keysOf(*groupOf(*rr.data, "document")), (Keys{"doc_reg_no", "document_type", "document_serial_number",
                                                                "issuing_date", "expiry_date", "issuing_authority"}));
        EXPECT_EQ(keysOf(*groupOf(*rr.data, "personal")),
                  (Keys{"personal_number", "surname", "given_name", "parent_given_name", "sex", "place_of_birth",
                        "community_of_birth", "state_of_birth", "state_of_birth_code", "date_of_birth"}));
        EXPECT_EQ(keysOf(*groupOf(*rr.data, "address")), (Keys{"state", "community", "place", "street", "house_number",
                                                               "floor", "apartment_number", "address_date"}));
        EXPECT_EQ(groupOrder(*rr.data),
                  (std::vector<std::string>{"meta", "personal", "address", "document", "photo", "verification"}));
    }
    {
        Card card("IF", RT::foreignerFiles());
        const auto rr = read(p, card);
        ASSERT_TRUE(rr.data.has_value());
        EXPECT_EQ(valueOf(*groupOf(*rr.data, "meta"), "card_type"), "IF");
        EXPECT_EQ(keysOf(*groupOf(*rr.data, "document")),
                  (Keys{"doc_reg_no", "document_type", "document_serial_number", "issuing_date", "expiry_date",
                        "issuing_authority", "card_number"}));
        EXPECT_EQ(keysOf(*groupOf(*rr.data, "personal")),
                  (Keys{"personal_number", "surname", "given_name", "sex", "state_of_birth", "state_of_birth_code",
                        "date_of_birth", "status_of_foreigner", "nationality"}));
        EXPECT_EQ(keysOf(*groupOf(*rr.data, "address")),
                  (Keys{"state", "community", "place", "street", "house_number", "address_date"}));
    }
}

// Whatever a card leaves out, the read still succeeds: a card with a single
// field of a profile shows that field and nothing else, in its group.
TEST(RsEidPluginDocumentsTest, EveryFieldMissingButOneStillReads)
{
    Plugin p;
    ASSERT_NE(p.plugin, nullptr);

    for (const auto& profile : Core::documentProfiles()) {
        for (const auto& f : profile.fields) {
            if ((f.surfaces & static_cast<std::uint8_t>(Core::Surface::CardEdge)) == 0)
                continue;
            const std::string value = f.encoding == Core::TextEncoding::Utf16Le ? RT::detail::utf16le(u"AB")
                                      : f.format == Core::FieldFormat::Date     ? "01012000"
                                                                                : "AB";
            CardFiles files;
            files[f.fid] = Core::TestData::makeContainer(f.fid, {{f.tag, value}});
            Card card(profile.code, std::move(files));

            const auto rr = read(p, card);
            ASSERT_EQ(rr.status, LibreSCRS::Plugin::ReadResult::Status::Ok)
                << profile.code << " " << f.key << ": " << rr.diagnosticDetail.value_or("<no diag>");
            ASSERT_TRUE(rr.data.has_value());
            const auto* group = groupOf(*rr.data, std::string{f.group});
            ASSERT_NE(group, nullptr) << profile.code << " " << f.key;
            EXPECT_EQ(keysOf(*group), std::set<std::string>{std::string{f.key}}) << profile.code << " " << f.key;
        }
    }
}

// The files are read in the order the groups are emitted, so a host can show
// each group when it is there; the photo, the slowest file, comes after the
// document group and is not read before.
TEST(RsEidPluginDocumentsTest, GroupsStreamBeforePhoto)
{
    Plugin p;
    ASSERT_NE(p.plugin, nullptr);
    Card card("ID", RT::citizenFiles());

    std::vector<std::string> emitted;
    int photoSelectsAtDocument = -1;
    int photoSelectsAtPhoto = -1;
    const auto rr = p.plugin->readCard(*card.session, [&](const std::string&, const CardFieldGroup& g) {
        emitted.push_back(g.groupKey);
        if (g.groupKey == "document")
            photoSelectsAtDocument = card.rig->selectsOf(0x0F06);
        if (g.groupKey == "photo")
            photoSelectsAtPhoto = card.rig->selectsOf(0x0F06);
    });
    ASSERT_EQ(rr.status, LibreSCRS::Plugin::ReadResult::Status::Ok) << rr.diagnosticDetail.value_or("<no diag>");

    EXPECT_EQ(emitted, (std::vector<std::string>{"meta", "personal", "address", "document", "photo", "verification"}));
    EXPECT_EQ(photoSelectsAtDocument, 0);
    EXPECT_EQ(photoSelectsAtPhoto, 1);
    // No file is read twice.
    for (const auto& [fid, bytes] : RT::citizenFiles())
        EXPECT_LE(card.rig->selectsOf(fid), 1) << std::hex << fid;
}

// The EL card is told apart from the PKI application on the same chip only by
// its AID; the registry collects every plugin that claims the connection.
TEST(RsEidPluginDocumentsTest, ServiceIdClaimedAlongsidePki)
{
    Plugin p;
    ASSERT_NE(p.plugin, nullptr);
    // Not the Gemalto prefix, so the claim cannot come from the ATR alone.
    const std::vector<std::uint8_t> atr{0x3B, 0x9E, 0x96, 0x80, 0x1F, 0xC7, 0x80, 0x31,
                                        0xE0, 0x73, 0xFE, 0x21, 0x1B, 0x66, 0xD0, 0x01};
    Card card("EL", RT::serviceIdFiles(), {}, atr);

    const auto candidates = p.registry.findAllCandidates(atr, *card.session);
    EXPECT_TRUE(std::ranges::any_of(candidates, [](const auto& c) { return c->pluginId() == "rs-eid"; }));
}

// A covered file the card will not give out cannot be vouched for: the verdict is
// invalid, while the read itself is fine.
TEST(RsEidPluginDocumentsTest, UnreadableCoveredFileIsInvalid)
{
    RT::ResursiChain chain;
    Anchors anchors(chain.anchors());
    ASSERT_NE(anchors.store(), nullptr);
    Plugin p(anchors.store());
    ASSERT_NE(p.plugin, nullptr);
    const auto signedCard = RT::withSignedObjects(profileOf("ID"), RT::citizenFiles(), chain);

    {
        Card control("ID", signedCard);
        EXPECT_EQ(fixedVerdict(p, control), "valid");
    }
    {
        auto files = signedCard;
        files.erase(0x0F12); // the card holds it, protected, not here
        Card card("ID", std::move(files), {0x0F12});
        EXPECT_EQ(fixedVerdict(p, card), "invalid");
    }
}

// A link that fails on the signed object once is not the card refusing it: the
// card verdict is unknown (could not judge), and the fixed verdict, asked later,
// reads the object again and finds it valid. A detached connection cannot
// reconnect, so the read spends its retries and throws.
TEST(RsEidPluginDocumentsTest, TransientSignedObjectFailureIsNotInvalid)
{
    RT::ResursiChain chain;
    Anchors anchors(chain.anchors());
    ASSERT_NE(anchors.store(), nullptr);
    Plugin p(anchors.store());
    ASSERT_NE(p.plugin, nullptr);
    Card card("ID", RT::withSignedObjects(profileOf("ID"), RT::citizenFiles(), chain));

    auto* rig = card.rig.get();
    std::uint16_t current = 0;
    int failures = 2; // the first attempt and the re-select attempt
    LibreSCRS::SmartCard::Internal::connectionOf(*card.session).setTransmitFilter([&, rig](const APDUCommand& cmd) {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x08 && cmd.data.size() == 2)
            current = static_cast<std::uint16_t>((cmd.data[0] << 8) | cmd.data[1]);
        if (cmd.ins == 0xB0 && current == 0x0F1C && failures > 0) {
            --failures;
            LibreSCRS::SmartCard::Internal::APDUResponse r;
            r.sw1 = 0x6F;
            r.sw2 = 0x00;
            return r;
        }
        return (*rig)(cmd);
    });

    const auto rr = read(p, card);
    ASSERT_EQ(rr.status, LibreSCRS::Plugin::ReadResult::Status::Ok) << rr.diagnosticDetail.value_or("<no diag>");
    const auto& v = *groupOf(*rr.data, "verification");
    EXPECT_EQ(valueOf(v, "card_verification"), "unknown");
    EXPECT_EQ(valueOf(v, "fixed_verification"), "valid");
    EXPECT_EQ(valueOf(v, "variable_verification"), "valid");
}

// Eight slots is a layout nobody measured: the object is genuine, the signer is
// ours, and what it covers cannot be judged.
TEST(RsEidPluginDocumentsTest, UnmeasuredLayoutShowsUnknown)
{
    RT::ResursiChain chain;
    Anchors anchors(chain.anchors());
    ASSERT_NE(anchors.store(), nullptr);
    Plugin p(anchors.store());
    ASSERT_NE(p.plugin, nullptr);

    Card card("ID", citizenWithFixedObject(chain, randomSlots(8)));
    EXPECT_EQ(fixedVerdict(p, card), "unknown");
}

// A genuine object of another measured shape, put where the fixed one belongs, is
// not "unknown layout": it is the wrong object.
TEST(RsEidPluginDocumentsTest, ForeignMeasuredLayoutIsInvalid)
{
    RT::ResursiChain chain;
    Anchors anchors(chain.anchors());
    ASSERT_NE(anchors.store(), nullptr);
    Plugin p(anchors.store());
    ASSERT_NE(p.plugin, nullptr);

    for (const std::size_t n : {1u, 7u}) {
        Card card("ID", citizenWithFixedObject(chain, randomSlots(n)));
        EXPECT_EQ(fixedVerdict(p, card), "invalid") << n << " slots";
    }
    {
        // Controls: the measured nine, and the unmeasured eight, from the same signer.
        Card nine("ID", RT::withSignedObjects(profileOf("ID"), RT::citizenFiles(), chain));
        EXPECT_EQ(fixedVerdict(p, nine), "valid");
        Card eight("ID", citizenWithFixedObject(chain, randomSlots(8)));
        EXPECT_EQ(fixedVerdict(p, eight), "unknown");
    }
}

// The signature is judged before the layout, whatever the number of slots.
TEST(RsEidPluginDocumentsTest, BrokenSignatureStaysInvalid)
{
    RT::ResursiChain chain;
    Anchors anchors(chain.anchors());
    ASSERT_NE(anchors.store(), nullptr);
    Plugin p(anchors.store());
    ASSERT_NE(p.plugin, nullptr);

    Card broken("ID", citizenWithFixedObject(chain, randomSlots(8), /*breakSignature=*/true));
    EXPECT_EQ(fixedVerdict(p, broken), "invalid");
    Card intact("ID", citizenWithFixedObject(chain, randomSlots(8)));
    EXPECT_EQ(fixedVerdict(p, intact), "unknown");
}

// Real dumps stay out of the public repository; this runs where they are on disk.
// What it settles is the read itself: the real allocation sizes, the real SELECT
// replies' lengths and the real encodings, through the whole plugin.
TEST(RsEidPluginDocumentsTest, ScannedCardsRead)
{
    const char* scan = std::getenv("LIBRESCRS_RS_EID_SCAN_DIR");
    if (!scan)
        GTEST_SKIP() << "LIBRESCRS_RS_EID_SCAN_DIR not set";
    struct Dump
    {
        std::string dir;
        std::string_view code;
    };
    const std::string s = scan;
    const std::vector<Dump> dumps{{s + "/1-lk/raw/SERID", "ID"},
                                  {s + "/2-lk-stranci/raw/SERIF", "IF"},
                                  {s + "/3-boravisna-dozvola/raw/SERRP", "RP"},
                                  {s + "/4-sluzbena-legitimacija/raw/SEREL", "EL"}};

    Plugin p;
    ASSERT_NE(p.plugin, nullptr);
    for (const auto& d : dumps) {
        CardFiles files;
        for (const auto& spec : profileOf(d.code).files) {
            char name[16];
            std::snprintf(name, sizeof name, "%04X.bin", spec.fid);
            std::ifstream in(d.dir + "/" + name, std::ios::binary);
            if (!in)
                continue;
            files[spec.fid] = {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
        }
        ASSERT_FALSE(files.empty()) << d.dir;
        Card card(d.code, std::move(files));

        const auto rr = read(p, card);
        ASSERT_EQ(rr.status, LibreSCRS::Plugin::ReadResult::Status::Ok) << d.dir;
        ASSERT_TRUE(rr.data.has_value());
        EXPECT_EQ(valueOf(*groupOf(*rr.data, "meta"), "card_type"), std::string{d.code}) << d.dir;
        EXPECT_NE(groupOf(*rr.data, "personal"), nullptr) << d.dir;
        EXPECT_NE(groupOf(*rr.data, "document"), nullptr) << d.dir;
        EXPECT_NE(groupOf(*rr.data, "photo"), nullptr) << d.dir;
    }
}
