// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Health-card (rs-health) unit tests. Drives the production HealthCard
// against a detached PCSCConnection plus a TransmitFilter intercepting
// every APDU — same pattern as rs-eid (Wave 5.1).

#include <gtest/gtest.h>

#include "apdu.h"
#include "health_groups.h"
#include "health_protocol.h"
#include "healthcard.h"
#include "healthtypes.h"
#include "pcsc_connection.h"

#include <cstdint>
#include <stdexcept>
#include <vector>

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Internal::PCSCConnection;

namespace {

APDUResponse ok(std::vector<uint8_t> data = {})
{
    APDUResponse r;
    r.data = std::move(data);
    r.sw1 = 0x90;
    r.sw2 = 0x00;
    return r;
}

APDUResponse err(uint8_t sw1, uint8_t sw2)
{
    APDUResponse r;
    r.sw1 = sw1;
    r.sw2 = sw2;
    return r;
}

// Health-card file header: 4 bytes total, LE u16 body length at offset 2.
std::vector<uint8_t> healthHeader(uint16_t contentLen)
{
    return {0xC1, 0xC2, static_cast<uint8_t>(contentLen & 0xFF), static_cast<uint8_t>((contentLen >> 8) & 0xFF)};
}

// Build a TLV record: little-endian tag, little-endian length, value bytes.
void appendTlv(std::vector<uint8_t>& out, uint16_t tag, const std::vector<uint8_t>& value)
{
    out.push_back(static_cast<uint8_t>(tag & 0xFF));
    out.push_back(static_cast<uint8_t>((tag >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value.size() & 0xFF));
    out.push_back(static_cast<uint8_t>((value.size() >> 8) & 0xFF));
    out.insert(out.end(), value.begin(), value.end());
}

// UTF-16 LE bytes for the ASCII portion of a string.
std::vector<uint8_t> ascii16Le(const std::string& s)
{
    std::vector<uint8_t> out;
    for (char c : s) {
        out.push_back(static_cast<uint8_t>(c));
        out.push_back(0x00);
    }
    return out;
}

std::vector<uint8_t> asciiBytes(const std::string& s)
{
    return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace

// --- Type / construction tests (preserved from previous coverage) ---

TEST(HealthGroups, SelfCarrierDocumentBuildsWithoutCarrierOrTaxpayerGroups)
{
    // The Leg-7 bench catch (2026-08-17): an insurant who is their OWN
    // insurance carrier has every carrier field empty, so the carrier
    // group's FIRST addText call carried an empty value — the documented
    // CardFieldGroup::addText corner (std::logic_error: no reference to
    // return) — and the whole read died as CommunicationError after the
    // address group. The builder must survive that document shape, and a
    // group with no surviving fields must not be emitted at all.
    healthcard::HealthDocumentData doc;
    doc.givenName = "NEMANJA";
    doc.familyName = "HIRSL";
    doc.insurerName = "RFZO";
    doc.street = "ULICA";
    // carrier* and taxpayer* stay empty — the self-carrier shape.

    const LibreSCRS::Plugin::CardData data = healthcard::buildHealthGroups(doc);
    EXPECT_EQ(data.cardType, "rs-health");
    ASSERT_EQ(data.groups.size(), 3u);
    EXPECT_EQ(data.groups[0].groupKey, "personal");
    EXPECT_EQ(data.groups[1].groupKey, "insurance");
    EXPECT_EQ(data.groups[2].groupKey, "address");
}

TEST(HealthGroups, FullDocumentBuildsAllFiveGroupsInCanonicalOrder)
{
    healthcard::HealthDocumentData doc;
    doc.givenName = "NEMANJA";
    doc.insurerName = "RFZO";
    doc.street = "ULICA";
    doc.carrierFamilyMember = true;
    doc.carrierGivenName = "NOSILAC";
    doc.taxpayerName = "OBVEZNIK";

    const LibreSCRS::Plugin::CardData data = healthcard::buildHealthGroups(doc);
    ASSERT_EQ(data.groups.size(), 5u);
    EXPECT_EQ(data.groups[0].groupKey, "personal");
    EXPECT_EQ(data.groups[1].groupKey, "insurance");
    EXPECT_EQ(data.groups[2].groupKey, "address");
    EXPECT_EQ(data.groups[3].groupKey, "carrier");
    EXPECT_EQ(data.groups[4].groupKey, "taxpayer");
    // The carrier flag is a real field, so a family-member carrier with no
    // other carrier data still emits the group.
    EXPECT_EQ(data.groups[3].fields.front().key, "carrier_family_member");
}

TEST(HealthDocumentData, DefaultConstruct)
{
    healthcard::HealthDocumentData d;
    EXPECT_TRUE(d.insurerName.empty());
    EXPECT_TRUE(d.personalNumber.empty());
    EXPECT_FALSE(d.permanentlyValid);
    EXPECT_FALSE(d.carrierFamilyMember);
}

TEST(HealthDocumentData, FieldAssignment)
{
    healthcard::HealthDocumentData d;
    d.insurerName = "RFZO";
    d.cardId = "1234567890";
    d.dateOfBirth = "01.01.1990";
    d.permanentlyValid = true;
    d.carrierFamilyMember = true;

    EXPECT_EQ(d.insurerName, "RFZO");
    EXPECT_EQ(d.cardId, "1234567890");
    EXPECT_EQ(d.dateOfBirth, "01.01.1990");
    EXPECT_TRUE(d.permanentlyValid);
    EXPECT_TRUE(d.carrierFamilyMember);
}

// --- Protocol constants ---

TEST(HealthProtocol, AidServszkShape)
{
    EXPECT_EQ(healthcard::protocol::AID_SERVSZK.size(), 13u);
    EXPECT_EQ(healthcard::protocol::AID_SERVSZK[0], 0xF3);
    EXPECT_EQ(healthcard::protocol::AID_SERVSZK[5], 'S');
    EXPECT_EQ(healthcard::protocol::AID_SERVSZK[6], 'E');
    EXPECT_EQ(healthcard::protocol::AID_SERVSZK[7], 'R');
}

TEST(HealthProtocol, FileIdsCanonicalLayout)
{
    using namespace healthcard::protocol;
    EXPECT_EQ(FILE_DOCUMENT, (std::vector<uint8_t>{0x0D, 0x01}));
    EXPECT_EQ(FILE_FIXED_PERSONAL, (std::vector<uint8_t>{0x0D, 0x02}));
    EXPECT_EQ(FILE_VARIABLE_PERSONAL, (std::vector<uint8_t>{0x0D, 0x03}));
    EXPECT_EQ(FILE_VARIABLE_ADMIN, (std::vector<uint8_t>{0x0D, 0x04}));
}

TEST(HealthProtocol, HeaderAndChunkSizes)
{
    EXPECT_EQ(healthcard::protocol::FILE_HEADER_SIZE, 4);
    EXPECT_EQ(healthcard::protocol::READ_CHUNK_SIZE, 0xFF);
}

// --- Probe path ---

TEST(HealthCardProbe, ProbeReturnsTrueOnSuccessfulAidSelect)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-health");

    conn.setTransmitFilter([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04 && cmd.data == healthcard::protocol::AID_SERVSZK) {
            return ok();
        }
        return err(0x6A, 0x82);
    });

    EXPECT_TRUE(healthcard::HealthCard::probe(conn));
}

TEST(HealthCardProbe, ProbeReturnsFalseOnAidSelectFailure)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-health");
    conn.setTransmitFilter([&](const APDUCommand&) -> APDUResponse { return err(0x6A, 0x82); });

    EXPECT_FALSE(healthcard::HealthCard::probe(conn));
}

// --- Construction + readDocumentData round-trip ---

TEST(HealthCardCtor, ThrowsIfInitCardFails)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-health");
    conn.setTransmitFilter([&](const APDUCommand&) -> APDUResponse { return err(0x6A, 0x82); });

    EXPECT_THROW({ healthcard::HealthCard card(conn); }, std::runtime_error);
}

TEST(HealthCardReadDocumentData, ParsesUtf16LeAndDateFormatting)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-health");

    // Build payloads for each of the 4 files. The reader stores parseTLV
    // results into HealthDocumentData; we exercise the UTF-16-LE decoder,
    // the DDMMYYYY → DD.MM.YYYY formatter, and the boolean ("01") path.

    // Document file: cardId (ASCII), dateOfIssue (DDMMYYYY), insurerName (UTF-16 LE).
    std::vector<uint8_t> docBody;
    appendTlv(docBody, healthcard::protocol::TAG_INSURER_NAME, ascii16Le("RFZO"));
    appendTlv(docBody, healthcard::protocol::TAG_CARD_ID, asciiBytes("1234567890"));
    appendTlv(docBody, healthcard::protocol::TAG_DATE_OF_ISSUE, asciiBytes("15012020"));

    // Fixed personal: insurantNumber + dateOfBirth.
    std::vector<uint8_t> fixedBody;
    appendTlv(fixedBody, healthcard::protocol::TAG_INSURANT_NUMBER, asciiBytes("999888777"));
    appendTlv(fixedBody, healthcard::protocol::TAG_DATE_OF_BIRTH, asciiBytes("01011990"));
    appendTlv(fixedBody, healthcard::protocol::TAG_GIVEN_NAME_LAT, ascii16Le("Marko"));

    // Variable personal: permanentlyValid "01" → true.
    std::vector<uint8_t> varPersBody;
    appendTlv(varPersBody, healthcard::protocol::TAG_PERMANENTLY_VALID, asciiBytes("01"));

    // Variable admin: gender = "01" → Мушко (server-mapped UTF-8).
    std::vector<uint8_t> varAdminBody;
    appendTlv(varAdminBody, healthcard::protocol::TAG_GENDER, asciiBytes("01"));
    appendTlv(varAdminBody, healthcard::protocol::TAG_PERSONAL_NUMBER, asciiBytes("0101990123456"));

    int callIdx = 0;
    std::vector<std::vector<uint8_t>> bodies = {docBody, fixedBody, varPersBody, varAdminBody};
    size_t fileIdx = 0;
    std::vector<uint8_t> currentBody;
    auto* currentBodyPtr = &currentBody;
    *currentBodyPtr = bodies[fileIdx];
    auto currentHeader = healthHeader(static_cast<uint16_t>(currentBodyPtr->size()));

    conn.setTransmitFilter([&](const APDUCommand& cmd) -> APDUResponse {
        ++callIdx;
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) {
            // AID SELECT — initCard
            return ok();
        }
        if (cmd.ins == 0xA4 && cmd.p1 == 0x00) {
            // SELECT FILE by ID — start of next file
            *currentBodyPtr = bodies[fileIdx];
            currentHeader = healthHeader(static_cast<uint16_t>(currentBodyPtr->size()));
            ++fileIdx;
            return ok();
        }
        if (cmd.ins == 0xB0) {
            // READ BINARY: header first (offset 0, len 4), then body chunks
            const uint16_t offset = static_cast<uint16_t>((static_cast<uint16_t>(cmd.p1) << 8) | cmd.p2);
            if (offset == 0 && cmd.le == 4) {
                return ok(currentHeader);
            }
            // body chunk starting at offset 4
            if (offset == 4) {
                const size_t take = std::min(static_cast<size_t>(cmd.le), currentBodyPtr->size());
                return ok(std::vector<uint8_t>(currentBodyPtr->begin(), currentBodyPtr->begin() + take));
            }
        }
        return ok();
    });

    healthcard::HealthCard card(conn);
    auto data = card.readDocumentData();

    EXPECT_EQ(data.cardId, "1234567890");
    EXPECT_EQ(data.dateOfIssue, "15.01.2020");
    EXPECT_EQ(data.insurerName, "RFZO");
    EXPECT_EQ(data.insurantNumber, "999888777");
    EXPECT_EQ(data.dateOfBirth, "01.01.1990");
    EXPECT_EQ(data.givenNameLatin, "Marko");
    EXPECT_TRUE(data.permanentlyValid);
    EXPECT_EQ(data.personalNumber, "0101990123456");
    // gender "01" — mapped to Cyrillic UTF-8 "Мушко"
    EXPECT_EQ(data.gender, "\xD0\x9C\xD1\x83\xD1\x88\xD0\xBA\xD0\xBE");
}

TEST(HealthCardReadDocumentData, GenderCode02MappedToZhensko)
{
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "fake-health");

    std::vector<uint8_t> docBody, fixedBody, varPersBody, varAdminBody;
    appendTlv(varAdminBody, healthcard::protocol::TAG_GENDER, asciiBytes("02"));

    std::vector<std::vector<uint8_t>> bodies = {docBody, fixedBody, varPersBody, varAdminBody};
    size_t fileIdx = 0;
    std::vector<uint8_t> currentBody;
    auto currentHeader = healthHeader(0);

    conn.setTransmitFilter([&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && cmd.p1 == 0x04)
            return ok();
        if (cmd.ins == 0xA4 && cmd.p1 == 0x00) {
            currentBody = bodies[fileIdx];
            currentHeader = healthHeader(static_cast<uint16_t>(currentBody.size()));
            ++fileIdx;
            return ok();
        }
        if (cmd.ins == 0xB0) {
            const uint16_t offset = static_cast<uint16_t>((static_cast<uint16_t>(cmd.p1) << 8) | cmd.p2);
            if (offset == 0)
                return ok(currentHeader);
            if (offset == 4 && !currentBody.empty()) {
                const size_t take = std::min(static_cast<size_t>(cmd.le), currentBody.size());
                return ok(std::vector<uint8_t>(currentBody.begin(), currentBody.begin() + take));
            }
            return ok();
        }
        return ok();
    });

    healthcard::HealthCard card(conn);
    auto data = card.readDocumentData();
    // "02" → "Женско"
    EXPECT_EQ(data.gender, "\xD0\x96\xD0\xB5\xD0\xBD\xD1\x81\xD0\xBA\xD0\xBE");
}
