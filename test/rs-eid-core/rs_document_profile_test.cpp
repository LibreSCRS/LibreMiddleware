// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "rs-eid/document_fixtures.h"
#include "rs_container.h"
#include "rs_digest_binding.h"
#include "rs_document_profile.h"
#include "synthetic_annex.h"

#include <openssl/bio.h>
#include <openssl/pkcs7.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace LibreSCRS::RsEId::Core;
namespace Fx = LibreSCRS::RsEId::Core::TestData;
namespace Doc = LibreSCRS::RsEId::Test;

namespace {

constexpr std::array<std::uint8_t, 11> kAidId{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x44, 0x01};
constexpr std::array<std::uint8_t, 11> kAidIf{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x46, 0x01};
constexpr std::array<std::uint8_t, 11> kAidRp{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x52, 0x50, 0x01};
constexpr std::array<std::uint8_t, 11> kAidEl{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x45, 0x4C, 0x01};

const DocumentProfile& profile(std::string_view code)
{
    for (const auto& p : documentProfiles()) {
        if (p.code == code) {
            return p;
        }
    }
    ADD_FAILURE() << "no profile " << code;
    return documentProfiles().front();
}

const ProfileGroup* findGroup(const std::vector<ProfileGroup>& groups, std::string_view key)
{
    for (const auto& g : groups) {
        if (g.key == key) {
            return &g;
        }
    }
    return nullptr;
}

std::optional<std::string> valueOf(const std::vector<ProfileGroup>& groups, std::string_view groupKey,
                                   std::string_view fieldKey)
{
    if (const auto* g = findGroup(groups, groupKey)) {
        for (const auto& f : g->fields) {
            if (f.key == fieldKey) {
                return f.value;
            }
        }
    }
    return std::nullopt;
}

std::vector<std::string> groupKeys(const std::vector<ProfileGroup>& groups)
{
    std::vector<std::string> out;
    for (const auto& g : groups) {
        out.push_back(g.key);
    }
    return out;
}

// Put one more TLV FIRST in the container: the reader takes the first occurrence
// of a tag, so a sentinel placed last would hide behind the fixture's own value.
std::vector<std::uint8_t> withLeadingField(const std::vector<std::uint8_t>& file, std::uint16_t tag,
                                           const std::string& value)
{
    const auto tlv = leadingTlv(file);
    EXPECT_TRUE(tlv.has_value());
    std::vector<std::uint8_t> out(tlv->begin(), tlv->begin() + kContainerHeaderSize);
    Fx::appendLe16(out, tag);
    Fx::appendLe16(out, static_cast<std::uint16_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
    out.insert(out.end(), tlv->begin() + kContainerHeaderSize, tlv->end());
    const auto bodyLen = static_cast<std::uint16_t>(out.size() - kContainerHeaderSize);
    out[2] = static_cast<std::uint8_t>(bodyLen & 0xFF);
    out[3] = static_cast<std::uint8_t>(bodyLen >> 8);
    out.resize(std::max(file.size(), out.size()), 0x00);
    return out;
}

} // namespace

TEST(RsDocumentProfile, ResidencePermitGroups)
{
    const auto groups = buildGroups(profile("RP"), Doc::residencePermitFiles(), Surface::CardEdge);

    EXPECT_EQ(valueOf(groups, "personal", "purpose_of_stay"), "KRETANJE U OKVIRU PRIVREDNOG DRUŠTVA");
    EXPECT_EQ(valueOf(groups, "personal", "note"), "JEDINSTVENA DOZVOLA");
    EXPECT_EQ(valueOf(groups, "personal", "state_of_birth_code"), "UTO");
    EXPECT_EQ(valueOf(groups, "document", "document_name"), "DOZVOLA ZA PRIVREMENI BORAVAK I RAD");
    EXPECT_EQ(valueOf(groups, "document", "card_number"), "BD00169609");
    EXPECT_EQ(valueOf(groups, "document", "issuing_date"), "20.11.2026");

    // The card has no 1568; the address group still exists and the placeholder is passed on as is.
    EXPECT_FALSE(valueOf(groups, "address", "state").has_value());
    EXPECT_EQ(valueOf(groups, "address", "address_date"), "01.01.0001");
    EXPECT_EQ(valueOf(groups, "address", "community"), "NOVI BEOGRAD");
}

TEST(RsDocumentProfile, ServiceIdEncodingIsPerField)
{
    const auto groups = buildGroups(profile("EL"), Doc::serviceIdFiles(), Surface::CardEdge);

    EXPECT_EQ(groupKeys(groups), (std::vector<std::string>{"personal", "service", "document"}));

    EXPECT_EQ(valueOf(groups, "personal", "given_name"), "ЈОВАНА");
    EXPECT_EQ(valueOf(groups, "personal", "surname"), "ШАЈЕРМАН");
    EXPECT_EQ(valueOf(groups, "personal", "sex"), "М");          // D0 9C: UTF-8, never UTF-16
    EXPECT_EQ(valueOf(groups, "personal", "blood_group"), "A-"); // 41 2D: ASCII, never U+2D41
    EXPECT_EQ(valueOf(groups, "personal", "date_of_birth"), "31.07.1972");
    EXPECT_EQ(valueOf(groups, "personal", "personal_number"), "3107972777016");
    EXPECT_EQ(valueOf(groups, "service", "status"), "1"); // 31 00: UTF-16
    EXPECT_EQ(valueOf(groups, "service", "badge_number"), "00000097");
    EXPECT_EQ(valueOf(groups, "service", "rank"), "Načelnik");
    EXPECT_EQ(valueOf(groups, "service", "organisational_unit"), "Personalizacija");
    EXPECT_EQ(valueOf(groups, "service", "position"), "Šef");
    EXPECT_EQ(valueOf(groups, "service", "service_address"), "Kneza Miloša 101");
    EXPECT_EQ(valueOf(groups, "document", "doc_reg_no"), "400000097");
    EXPECT_EQ(valueOf(groups, "document", "issuing_date"), "20.11.2026");
    EXPECT_EQ(valueOf(groups, "document", "issuing_authority"), "MUP Republike Srbije");
    EXPECT_EQ(findGroup(groups, "address"), nullptr);
}

TEST(RsDocumentProfile, CitizenGroupsKeepTodaysOrderAndLabels)
{
    const auto groups = buildGroups(profile("ID"), Doc::citizenFiles(), Surface::CardEdge);
    EXPECT_EQ(groupKeys(groups), (std::vector<std::string>{"personal", "address", "document"}));
    EXPECT_EQ(findGroup(groups, "personal")->label, "Personal Data");
    EXPECT_EQ(findGroup(groups, "address")->label, "Address");
    EXPECT_EQ(findGroup(groups, "document")->label, "Document Data");

    const auto* personal = findGroup(groups, "personal");
    ASSERT_NE(personal, nullptr);
    EXPECT_EQ(personal->fields.front().key, "personal_number");
    EXPECT_EQ(personal->fields.front().label, "Personal Number");
    EXPECT_EQ(valueOf(groups, "document", "document_serial_number"), "ID400000099");
    EXPECT_EQ(valueOf(groups, "personal", "date_of_birth"), "29.02.2000");
}

TEST(RsDocumentProfile, DuplicateTagTakesFirst)
{
    auto files = Doc::citizenFiles();
    files[0x0F03] = Fx::makeContainer(0x0F03, {{1559, "PRVO"}, {1559, "DRUGO"}, {1560, "IME"}}, 130);

    const auto groups = buildGroups(profile("ID"), files, Surface::CardEdge);
    EXPECT_EQ(valueOf(groups, "personal", "surname"), "PRVO");
    EXPECT_EQ(valueOf(groups, "personal", "given_name"), "IME");
}

TEST(RsDocumentProfile, UnnamedTagsNeverSurface)
{
    const std::array<std::pair<std::string_view, Doc::CardFiles>, 4> cards{{
        {"ID", Doc::citizenFiles()},
        {"IF", Doc::foreignerFiles()},
        {"RP", Doc::residencePermitFiles()},
        {"EL", Doc::serviceIdFiles()},
    }};
    for (const auto& [code, original] : cards) {
        const auto& p = profile(code);
        ASSERT_FALSE(p.unnamedTags.empty()) << code;
        for (const auto& f : p.fields) {
            EXPECT_EQ(std::count(p.unnamedTags.begin(), p.unnamedTags.end(), f.tag), 0)
                << code << " names unnamed tag " << f.tag << " as " << f.key;
        }
        for (const auto surface : {Surface::CardEdge, Surface::Annex}) {
            for (const std::uint16_t tag : p.unnamedTags) {
                // Plant a sentinel under the unnamed tag in every demographic file of the profile.
                auto files = original;
                for (const auto& spec : p.files) {
                    const auto it = files.find(spec.fid);
                    if (it != files.end() && spec.mode == ReadMode::Header && outerTag(it->second) == spec.fid) {
                        it->second = withLeadingField(it->second, tag, "SENTINEL");
                    }
                }
                bool planted = false;
                for (const auto& [fid, bytes] : files) {
                    const std::string raw(bytes.begin(), bytes.end());
                    planted = planted || raw.find("SENTINEL") != std::string::npos;
                }
                ASSERT_TRUE(planted) << code << " tag " << tag;

                for (const auto& g : buildGroups(p, files, surface)) {
                    for (const auto& f : g.fields) {
                        EXPECT_EQ(f.value.find("SENTINEL"), std::string::npos)
                            << code << " tag " << tag << " leaked as " << f.key;
                    }
                }
            }
        }
    }
}

TEST(RsDocumentProfile, AnnexSurfaceIsTodaysKnownSet)
{
    struct Row
    {
        std::string key;
        std::string label;
    };
    const std::vector<Row> expected{
        {"document_serial", "Document Number"},
        {"parent_given_name", "Parent Given Name"},
        {"community_of_birth", "Community of Birth"},
        {"state_of_birth", "State of Birth"},
        {"state", "State"},
        {"community", "Community"},
        {"place", "Place"},
        {"street", "Street"},
        {"house_number", "House Number"},
        {"house_letter", "House Letter"},
        {"entrance", "Entrance"},
        {"floor", "Floor"},
        {"apartment_number", "Apartment"},
        {"address_date", "Address Date"},
        {"address_label", "Address Label"},
    };

    std::vector<Row> actual;
    for (const auto& f : annexProfile().fields) {
        if ((f.surfaces & static_cast<std::uint8_t>(Surface::Annex)) != 0) {
            actual.push_back({std::string{f.key}, std::string{f.label}});
        }
    }
    ASSERT_EQ(actual.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(actual[i].key, expected[i].key) << i;
        EXPECT_EQ(actual[i].label, expected[i].label) << i;
    }
}

// The sequence the annex emits, group by group: what the annex reader flattens today.
TEST(RsDocumentProfile, AnnexOutputSequenceIsTodays)
{
    RawFiles files;
    files[0x0F02] = Fx::makeContainer(0x0F02, {{1548, "D"}, {1546, "not shown"}}, 60);
    files[0x0F03] = Fx::makeContainer(0x0F03, {{1565, "S"}, {1561, "P"}, {1564, "C"}, {1559, "not shown"}}, 60);
    files[0x0F04] = Fx::makeContainer(0x0F04,
                                      {{1581, "L"},
                                       {1580, "01012020"},
                                       {1578, "A"},
                                       {1575, "F"},
                                       {1574, "E"},
                                       {1573, "H"},
                                       {1572, "N"},
                                       {1571, "T"},
                                       {1570, "Q"},
                                       {1569, "M"},
                                       {1568, "R"}},
                                      120);

    std::vector<std::pair<std::string, std::string>> got;
    for (const auto& g : buildGroups(annexProfile(), files, Surface::Annex)) {
        for (const auto& f : g.fields) {
            got.emplace_back(g.key, f.key);
        }
    }
    const std::vector<std::pair<std::string, std::string>> expected{
        {"personal", "document_serial"},
        {"personal", "parent_given_name"},
        {"personal", "community_of_birth"},
        {"personal", "state_of_birth"},
        {"address", "state"},
        {"address", "community"},
        {"address", "place"},
        {"address", "street"},
        {"address", "house_number"},
        {"address", "house_letter"},
        {"address", "entrance"},
        {"address", "floor"},
        {"address", "apartment_number"},
        {"address", "address_date"},
        {"address", "address_label"},
    };
    EXPECT_EQ(got, expected);
}

TEST(RsDocumentProfile, AnnexEmitsRawDates)
{
    auto files = Doc::citizenFiles();
    const auto annex = buildGroups(annexProfile(), files, Surface::Annex);
    EXPECT_EQ(valueOf(annex, "address", "address_date"), "06082016");

    const auto edge = buildGroups(annexProfile(), files, Surface::CardEdge);
    EXPECT_EQ(valueOf(edge, "address", "address_date"), "06.08.2016");
    // The annex shows no field the CardEdge rows named; its label for the shared tag differs.
    EXPECT_EQ(valueOf(annex, "personal", "document_serial"), "ID400000099");
    EXPECT_FALSE(valueOf(annex, "document", "document_serial_number").has_value());
}

TEST(RsDocumentProfile, AidMapsToCode)
{
    ASSERT_NE(profileForAid(kAidId), nullptr);
    EXPECT_EQ(profileForAid(kAidId)->code, "ID");
    ASSERT_NE(profileForAid(kAidIf), nullptr);
    EXPECT_EQ(profileForAid(kAidIf)->code, "IF");
    ASSERT_NE(profileForAid(kAidRp), nullptr);
    EXPECT_EQ(profileForAid(kAidRp)->code, "RP");
    ASSERT_NE(profileForAid(kAidEl), nullptr);
    EXPECT_EQ(profileForAid(kAidEl)->code, "EL");

    constexpr std::array<std::uint8_t, 11> unknown{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x41, 0x01};
    EXPECT_EQ(profileForAid(unknown), nullptr);
    EXPECT_EQ(profileForAid({}), nullptr);
}

TEST(RsDocumentProfile, PhotoStartsWithJpegMarker)
{
    for (const auto& photoFile : {Doc::citizenFiles().at(0x0F06), Doc::serviceIdFiles().at(0x0D05)}) {
        const auto photo = extractPhoto(photoFile);
        ASSERT_GE(photo.size(), 2u);
        EXPECT_EQ(photo[0], 0xFF);
        EXPECT_EQ(photo[1], 0xD8);
    }

    // Not a JPEG after the 8 header bytes: nothing, rather than bytes the host would feed a decoder.
    EXPECT_TRUE(extractPhoto(Fx::makeContainer(0x0F06, {{0x0110, "not a picture"}}, 0)).empty());
    EXPECT_TRUE(extractPhoto({}).empty());
}

namespace {

constexpr std::array kInventedFiles{FileSpec{0x1001, ReadMode::Header}};
constexpr std::array kInventedGroups{GroupSpec{"vehicle", "Vehicle"}};
constexpr std::array kInventedFields{
    FieldSpec{0x1001, 7, "plate", "Plate", "vehicle", TextEncoding::Utf8, FieldFormat::Text, 1},
    FieldSpec{0x1001, 8, "model", "Model", "vehicle", TextEncoding::Utf16Le, FieldFormat::Text, 1},
};
constexpr std::array<std::uint8_t, 3> kInventedAid{0xA0, 0x01, 0x02};
constexpr DocumentProfile kInvented{"XX", kInventedAid, kInventedFiles, kInventedGroups, kInventedFields, {}, {}, 0, 0};

} // namespace

TEST(RsDocumentProfile, NewProfileNeedsNoCode)
{
    RawFiles files;
    files[0x1001] = Fx::makeContainer(0x1001, {{7, "BG-123-AB"}, {8, Doc::detail::utf16le(u"Fića")}}, 64);

    const auto groups = buildGroups(kInvented, files, Surface::CardEdge);
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups[0].key, "vehicle");
    EXPECT_EQ(groups[0].label, "Vehicle");
    ASSERT_EQ(groups[0].fields.size(), 2u);
    EXPECT_EQ(groups[0].fields[0].value, "BG-123-AB");
    EXPECT_EQ(groups[0].fields[1].value, "Fića");
    EXPECT_EQ(groupFiles(kInvented, "vehicle", Surface::CardEdge), (std::vector<std::uint16_t>{0x1001}));
    EXPECT_TRUE(buildGroups(kInvented, files, Surface::Annex).empty());
}

TEST(RsDocumentProfile, MeasuredSlotCounts)
{
    EXPECT_EQ(measuredSlotCounts(), (std::vector<std::size_t>{1, 7, 9}));
}

TEST(RsDocumentProfile, ProtectedSlotIsFifthOfTheFixedSod)
{
    for (const auto code : {"ID", "IF", "RP", "EL"}) {
        const auto& p = profile(code);
        const auto& fixed = p.sods.front();
        EXPECT_EQ(fixed.fid, p.cardCertSodFid) << code;
        EXPECT_EQ(fixed.role, SodRole::Fixed) << code;
        ASSERT_GE(fixed.slots.size(), 5u) << code;
        EXPECT_EQ(fixed.slots[4], kProtectedSlot) << code;
        EXPECT_EQ(std::count(fixed.slots.begin(), fixed.slots.end(), kProtectedSlot), 1) << code;
    }
}

TEST(RsDocumentProfile, AllocationFileHashesPadding)
{
    const auto padded = Fx::makeContainer(0x0F12, {{2625, "SSecFormat"}}, 530);
    const auto alloc = sodBlock(FileSpec{0x0F12, ReadMode::Allocation}, padded);
    EXPECT_EQ(alloc.size(), 530u);

    const auto manifest = Fx::makeContainer(0x0F1B, {{1537, "05"}}, 148);
    const auto header = sodBlock(FileSpec{0x0F1B, ReadMode::Header}, manifest);
    EXPECT_EQ(header.size(), kContainerHeaderSize + 6u);
    EXPECT_TRUE(std::equal(header.begin(), header.end(), manifest.begin()));

    // A header whose declared length overruns the file is no block at all.
    EXPECT_TRUE(
        sodBlock(FileSpec{0x0F1B, ReadMode::Header}, std::vector<std::uint8_t>{0x1B, 0x0F, 0xFF, 0x00}).empty());
}

namespace {

std::optional<std::vector<std::uint8_t>> readFile(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

RawFiles loadDump(const std::string& dir, const DocumentProfile& p)
{
    RawFiles files;
    for (const auto& spec : p.files) {
        char name[16];
        std::snprintf(name, sizeof name, "%04X.bin", spec.fid);
        if (auto bytes = readFile(dir + "/" + name)) {
            files[spec.fid] = std::move(*bytes);
        }
    }
    return files;
}

// The signed digest slots, taken with OpenSSL straight from the dump: the core never hands them out.
std::vector<std::uint8_t> eContentOf(const std::vector<std::uint8_t>& sodFile)
{
    const auto tlv = leadingTlv(sodFile);
    if (!tlv) {
        return {};
    }
    const auto cms = innerTlvPayload(tlv->subspan(kContainerHeaderSize));
    const std::uint8_t* p = cms.data();
    PKCS7* pkcs7 = d2i_PKCS7(nullptr, &p, static_cast<long>(cms.size()));
    if (!pkcs7) {
        return {};
    }
    BIO* out = BIO_new(BIO_s_mem());
    std::vector<std::uint8_t> content;
    if (PKCS7_verify(pkcs7, nullptr, nullptr, nullptr, out, PKCS7_NOVERIFY | PKCS7_NOSIGS) == 1) {
        char* data = nullptr;
        const long n = BIO_get_mem_data(out, &data);
        content.assign(reinterpret_cast<std::uint8_t*>(data), reinterpret_cast<std::uint8_t*>(data) + n);
    }
    BIO_free(out);
    PKCS7_free(pkcs7);
    return content;
}

std::vector<SlotInput> slotsFor(const DocumentProfile& p, const SodSpec& sod, const RawFiles& files)
{
    std::vector<SlotInput> slots;
    for (const std::uint16_t fid : sod.slots) {
        if (fid == kProtectedSlot) {
            slots.emplace_back(SkipSlot{});
            continue;
        }
        BlockCandidates candidates;
        const auto it = files.find(fid);
        const auto spec = std::find_if(p.files.begin(), p.files.end(), [&](const FileSpec& f) { return f.fid == fid; });
        if (it != files.end() && spec != p.files.end()) {
            candidates.push_back(sodBlock(*spec, it->second));
        }
        slots.emplace_back(std::move(candidates));
    }
    return slots;
}

bool sodBinds(const DocumentProfile& p, std::uint16_t sodFid, const RawFiles& files)
{
    const auto spec = std::find_if(p.sods.begin(), p.sods.end(), [&](const SodSpec& s) { return s.fid == sodFid; });
    EXPECT_NE(spec, p.sods.end());
    const auto sod = files.find(sodFid);
    EXPECT_NE(sod, files.end()) << std::hex << sodFid;
    if (spec == p.sods.end() || sod == files.end()) {
        return false;
    }
    const auto content = eContentOf(sod->second);
    EXPECT_FALSE(content.empty()) << std::hex << sodFid;
    return matchDigests(content, slotsFor(p, *spec, files));
}

} // namespace

// Real dumps stay out of the public repository; this runs where they are on disk.
TEST(RsDocumentProfile, ScannedCardsBindPositionally)
{
    const char* scan = std::getenv("LIBRESCRS_RS_EID_SCAN_DIR");
    const char* measure = std::getenv("LIBRESCRS_RS_EID_MEASURE_DIR");
    if (!scan || !measure) {
        GTEST_SKIP() << "LIBRESCRS_RS_EID_SCAN_DIR / LIBRESCRS_RS_EID_MEASURE_DIR not set";
    }
    const std::string s = scan;
    const std::string m = measure;

    struct Card
    {
        std::string dir;
        std::string_view code;
    };
    const std::vector<Card> bound{
        {s + "/1-lk/raw/SERID", "ID"},
        {s + "/2-lk-stranci/raw/SERIF", "IF"},
        {s + "/3-boravisna-dozvola/raw/SERRP", "RP"},
        {s + "/4-sluzbena-legitimacija/raw/SEREL", "EL"},
        {m + "/gemalto2014-a/SERIF", "IF"},
        {m + "/gemalto2014-lk/SERID", "ID"},
    };
    for (const auto& card : bound) {
        const auto& p = profile(card.code);
        const auto files = loadDump(card.dir, p);
        ASSERT_FALSE(files.empty()) << card.dir;
        for (const auto& sod : p.sods) {
            EXPECT_TRUE(sodBinds(p, sod.fid, files)) << card.dir << " SOD " << std::hex << sod.fid;
        }
    }

    // A test card whose personalisation left some covered files unbound.
    const auto& el = profile("EL");
    const auto elB = loadDump(m + "/el-b/SEREL", el);
    ASSERT_FALSE(elB.empty());
    EXPECT_FALSE(sodBinds(el, 0x0D08, elB));
    EXPECT_FALSE(sodBinds(el, 0x0D0A, elB));
    EXPECT_TRUE(sodBinds(el, 0x0D09, elB));
}
