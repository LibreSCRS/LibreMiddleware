// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/asic_module.h"
#include "native/pkcs11_module_manager.h"
#include "native/pkcs11_token.h"
#include "native/zip_records.h"
#include "signing_test_support/mock_tsa_server.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"

// miniz declarations for ZIP reading in tests (implementation in LibreSign via miniz.c)
#include "miniz.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace libresign;

// ---------------------------------------------------------------------------
// ZIP64 record writer / reader (native/zip_records.h)
//
// The ZIP64 branches only engage once a field outgrows its 32-bit slot, which
// on the ASiC-E path means a container past 4 GiB. Materialising one would
// cost more memory than the test host has, so the records are written and read
// by pure functions over caller-supplied sizes and offsets, and the tests
// drive them with synthetic values instead.
// ---------------------------------------------------------------------------

namespace {

bool containsSignature(std::span<const uint8_t> buf, uint32_t signature)
{
    if (buf.size() < 4)
        return false;
    for (size_t i = 0; i + 4 <= buf.size(); ++i) {
        if (zip::readLE32(buf, i) == signature)
            return true;
    }
    return false;
}

bool hasZip64Records(std::span<const uint8_t> buf)
{
    return containsSignature(buf, zip::kZip64EocdSignature) || containsSignature(buf, zip::kZip64EocdLocatorSignature);
}

std::vector<uint8_t> makeCentralDirEntry(uint32_t compressedSize, uint32_t uncompressedSize, uint32_t localOffset,
                                         std::string_view name, std::span<const uint8_t> extra)
{
    std::vector<uint8_t> entry;
    zip::appendLE32(entry, zip::kCentralDirEntrySignature);
    zip::appendLE16(entry, 45); // version made by
    zip::appendLE16(entry, 45); // version needed to extract
    zip::appendLE16(entry, 0);  // flags
    zip::appendLE16(entry, 0);  // method: STORED
    zip::appendLE16(entry, 0);  // mod time
    zip::appendLE16(entry, 0);  // mod date
    zip::appendLE32(entry, 0);  // crc
    zip::appendLE32(entry, compressedSize);
    zip::appendLE32(entry, uncompressedSize);
    zip::appendLE16(entry, static_cast<uint16_t>(name.size()));
    zip::appendLE16(entry, static_cast<uint16_t>(extra.size()));
    zip::appendLE16(entry, 0); // comment length
    zip::appendLE16(entry, 0); // disk number start
    zip::appendLE16(entry, 0); // internal attributes
    zip::appendLE32(entry, 0); // external attributes
    zip::appendLE32(entry, localOffset);
    entry.insert(entry.end(), name.begin(), name.end());
    entry.insert(entry.end(), extra.begin(), extra.end());
    return entry;
}

std::vector<uint8_t> makeZip64ExtraField(std::span<const uint64_t> members)
{
    std::vector<uint8_t> extra;
    zip::appendLE16(extra, zip::kZip64ExtraFieldId);
    zip::appendLE16(extra, static_cast<uint16_t>(members.size() * 8));
    for (uint64_t m : members)
        zip::appendLE64(extra, m);
    return extra;
}

// Offset of the ZIP64 extra field's first value in an entry built by
// makeCentralDirEntry with a 7-character name: 46 fixed bytes + name + the
// 4-byte extra-field header.
constexpr size_t kZip64ValuesOffset = zip::kCentralDirEntryFixedSize + 7 + 4;

} // namespace

TEST(ZipRecordsTest, BelowThresholdEmitsThePlainEocdOnly)
{
    std::vector<uint8_t> out;
    zip::appendEndOfCentralDirectory(out, 0x1234, 0x5678, 7);

    ASSERT_EQ(out.size(), zip::kEocdSize);
    EXPECT_EQ(zip::readLE32(out, 0), zip::kEocdSignature);
    EXPECT_EQ(zip::readLE16(out, 4), 0u);  // number of this disk
    EXPECT_EQ(zip::readLE16(out, 6), 0u);  // disk holding the central directory
    EXPECT_EQ(zip::readLE16(out, 8), 7u);  // entries on this disk
    EXPECT_EQ(zip::readLE16(out, 10), 7u); // entries total
    EXPECT_EQ(zip::readLE32(out, 12), 0x5678u);
    EXPECT_EQ(zip::readLE32(out, 16), 0x1234u);
    EXPECT_EQ(zip::readLE16(out, 20), 0u); // comment length

    // A ZIP64 record here would break every reader that predates ZIP64.
    EXPECT_FALSE(hasZip64Records(out));
}

TEST(ZipRecordsTest, CentralDirectoryOffsetPastFourGiBEmitsZip64Records)
{
    const uint64_t cdOffset = 5ULL << 30; // 5 GiB
    const uint64_t cdSize = 0x400;
    std::vector<uint8_t> out;
    zip::appendEndOfCentralDirectory(out, cdOffset, cdSize, 9);

    ASSERT_EQ(out.size(), zip::kZip64EocdSize + zip::kZip64EocdLocatorSize + zip::kEocdSize);

    // ZIP64 End of Central Directory Record — APPNOTE.TXT §4.3.14.
    EXPECT_EQ(zip::readLE32(out, 0), zip::kZip64EocdSignature);
    EXPECT_EQ(zip::readLE64(out, 4), zip::kZip64EocdSize - 12);
    EXPECT_EQ(zip::readLE16(out, 12), 45u); // version made by
    EXPECT_EQ(zip::readLE16(out, 14), 45u); // version needed to extract
    EXPECT_EQ(zip::readLE32(out, 16), 0u);  // number of this disk
    EXPECT_EQ(zip::readLE32(out, 20), 0u);  // disk holding the central directory
    EXPECT_EQ(zip::readLE64(out, 24), 9u);  // entries on this disk
    EXPECT_EQ(zip::readLE64(out, 32), 9u);  // entries total
    EXPECT_EQ(zip::readLE64(out, 40), cdSize);
    EXPECT_EQ(zip::readLE64(out, 48), cdOffset);

    // ZIP64 End of Central Directory Locator — APPNOTE.TXT §4.3.15.
    const size_t locator = zip::kZip64EocdSize;
    EXPECT_EQ(zip::readLE32(out, locator), zip::kZip64EocdLocatorSignature);
    EXPECT_EQ(zip::readLE32(out, locator + 4), 0u);
    EXPECT_EQ(zip::readLE64(out, locator + 8), cdOffset + cdSize);
    EXPECT_EQ(zip::readLE32(out, locator + 16), 1u);

    // End of Central Directory record — APPNOTE.TXT §4.3.16. Only the field
    // that overflowed carries the sentinel; the rest stay authoritative.
    const size_t eocd = zip::kZip64EocdSize + zip::kZip64EocdLocatorSize;
    EXPECT_EQ(zip::readLE32(out, eocd), zip::kEocdSignature);
    EXPECT_EQ(zip::readLE16(out, eocd + 10), 9u);
    EXPECT_EQ(zip::readLE32(out, eocd + 12), static_cast<uint32_t>(cdSize));
    EXPECT_EQ(zip::readLE32(out, eocd + 16), zip::kSentinel32);
}

TEST(ZipRecordsTest, CentralDirectorySizePastFourGiBEmitsZip64Records)
{
    const uint64_t cdOffset = 0x2000;
    const uint64_t cdSize = 5ULL << 30; // 5 GiB
    std::vector<uint8_t> out;
    zip::appendEndOfCentralDirectory(out, cdOffset, cdSize, 4);

    ASSERT_EQ(out.size(), zip::kZip64EocdSize + zip::kZip64EocdLocatorSize + zip::kEocdSize);
    EXPECT_EQ(zip::readLE64(out, 40), cdSize);
    EXPECT_EQ(zip::readLE64(out, 48), cdOffset);

    const size_t eocd = zip::kZip64EocdSize + zip::kZip64EocdLocatorSize;
    EXPECT_EQ(zip::readLE32(out, eocd + 12), zip::kSentinel32);
    EXPECT_EQ(zip::readLE32(out, eocd + 16), static_cast<uint32_t>(cdOffset));
}

TEST(ZipRecordsTest, EntryCountPastSixteenBitsEmitsZip64Records)
{
    const uint64_t entries = 70000;
    std::vector<uint8_t> out;
    zip::appendEndOfCentralDirectory(out, 0x100, 0x200, entries);

    ASSERT_EQ(out.size(), zip::kZip64EocdSize + zip::kZip64EocdLocatorSize + zip::kEocdSize);
    EXPECT_EQ(zip::readLE64(out, 24), entries);
    EXPECT_EQ(zip::readLE64(out, 32), entries);

    const size_t eocd = zip::kZip64EocdSize + zip::kZip64EocdLocatorSize;
    EXPECT_EQ(zip::readLE16(out, eocd + 8), zip::kSentinel16);
    EXPECT_EQ(zip::readLE16(out, eocd + 10), zip::kSentinel16);
    EXPECT_EQ(zip::readLE32(out, eocd + 12), 0x200u);
    EXPECT_EQ(zip::readLE32(out, eocd + 16), 0x100u);
}

TEST(ZipRecordsTest, ReaderRoundTripsThePlainEocd)
{
    std::vector<uint8_t> archive(200, 0);
    zip::appendEndOfCentralDirectory(archive, 128, 64, 6);

    const auto parsed = zip::readEndOfCentralDirectory(archive);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->centralDirOffset, 128u);
    EXPECT_EQ(parsed->centralDirSize, 64u);
    EXPECT_EQ(parsed->entryCount, 6u);
}

// The entry-count overflow reaches the same ZIP64 records as a 4 GiB archive
// but leaves the offsets small enough for the bytes to actually exist, so the
// locator can be followed to a record that is physically present.
TEST(ZipRecordsTest, ReaderFollowsTheLocatorToTheZip64Record)
{
    const uint64_t cdOffset = 128;
    const uint64_t cdSize = 64;
    const uint64_t entries = 70000;
    std::vector<uint8_t> archive(cdOffset + cdSize, 0);
    zip::appendEndOfCentralDirectory(archive, cdOffset, cdSize, entries);
    ASSERT_TRUE(hasZip64Records(archive));

    const auto parsed = zip::readEndOfCentralDirectory(archive);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->entryCount, entries);
    EXPECT_EQ(parsed->centralDirOffset, cdOffset);
    EXPECT_EQ(parsed->centralDirSize, cdSize);
}

TEST(ZipRecordsTest, ReaderTakesSixtyFourBitValuesFromTheZip64Record)
{
    const uint64_t bigOffset = 6ULL << 30;
    const uint64_t bigSize = 5ULL << 30;

    // The ZIP64 record sits at offset 0 here; a real archive would place it
    // past its central directory, but the reader only follows the locator.
    std::vector<uint8_t> archive;
    zip::appendLE32(archive, zip::kZip64EocdSignature);
    zip::appendLE64(archive, zip::kZip64EocdSize - 12);
    zip::appendLE16(archive, 45);
    zip::appendLE16(archive, 45);
    zip::appendLE32(archive, 0);
    zip::appendLE32(archive, 0);
    zip::appendLE64(archive, 3);
    zip::appendLE64(archive, 3);
    zip::appendLE64(archive, bigSize);
    zip::appendLE64(archive, bigOffset);
    ASSERT_EQ(archive.size(), zip::kZip64EocdSize);
    zip::appendLE32(archive, zip::kZip64EocdLocatorSignature);
    zip::appendLE32(archive, 0);
    zip::appendLE64(archive, 0); // the record starts at offset 0
    zip::appendLE32(archive, 1);
    zip::appendLE32(archive, zip::kEocdSignature);
    zip::appendLE16(archive, 0);
    zip::appendLE16(archive, 0);
    zip::appendLE16(archive, 3);
    zip::appendLE16(archive, 3);
    zip::appendLE32(archive, zip::kSentinel32);
    zip::appendLE32(archive, zip::kSentinel32);
    zip::appendLE16(archive, 0);

    const auto parsed = zip::readEndOfCentralDirectory(archive);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->centralDirOffset, bigOffset);
    EXPECT_EQ(parsed->centralDirSize, bigSize);
    EXPECT_EQ(parsed->entryCount, 3u);
}

TEST(ZipRecordsTest, ReaderRejectsASentinelWithNoZip64RecordBehindIt)
{
    std::vector<uint8_t> archive(64, 0);
    zip::appendLE32(archive, zip::kEocdSignature);
    zip::appendLE16(archive, 0);
    zip::appendLE16(archive, 0);
    zip::appendLE16(archive, 2);
    zip::appendLE16(archive, 2);
    zip::appendLE32(archive, zip::kSentinel32);
    zip::appendLE32(archive, zip::kSentinel32);
    zip::appendLE16(archive, 0);

    // A truncated 32-bit value must never stand in for the missing record.
    EXPECT_FALSE(zip::readEndOfCentralDirectory(archive).has_value());
}

// Exactly 65535 entries fills the 16-bit field with the value that doubles as
// the sentinel, and a writer that stopped there owes no ZIP64 record: the
// count is already exact, unlike a truncated 32-bit offset.
TEST(ZipRecordsTest, ReaderKeepsAnEntryCountSentinelWithNoZip64Record)
{
    std::vector<uint8_t> archive(64, 0);
    zip::appendLE32(archive, zip::kEocdSignature);
    zip::appendLE16(archive, 0);
    zip::appendLE16(archive, 0);
    zip::appendLE16(archive, zip::kSentinel16);
    zip::appendLE16(archive, zip::kSentinel16);
    zip::appendLE32(archive, 32);
    zip::appendLE32(archive, 16);
    zip::appendLE16(archive, 0);

    const auto parsed = zip::readEndOfCentralDirectory(archive);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->entryCount, 65535u);
    EXPECT_EQ(parsed->centralDirSize, 32u);
    EXPECT_EQ(parsed->centralDirOffset, 16u);
}

TEST(ZipRecordsTest, ReaderRejectsABufferWithNoEocd)
{
    const std::vector<uint8_t> archive(64, 0);
    EXPECT_FALSE(zip::readEndOfCentralDirectory(archive).has_value());
}

TEST(ZipRecordsTest, ShiftMovesAThirtyTwoBitOffsetInPlace)
{
    auto entry = makeCentralDirEntry(10, 10, 1000, "doc.txt", {});
    const size_t sizeBefore = entry.size();

    ASSERT_TRUE(zip::shiftLocalHeaderOffset(entry, 69));
    EXPECT_EQ(entry.size(), sizeBefore);
    EXPECT_EQ(zip::readLE32(entry, 42), 1069u);
    EXPECT_EQ(zip::readLE16(entry, 30), 0u); // no extra field was grown
}

TEST(ZipRecordsTest, ShiftMovesASixtyFourBitOffsetInsideTheZip64ExtraField)
{
    const uint64_t offset = 5ULL << 30;
    const std::vector<uint64_t> members{offset};
    const auto extra = makeZip64ExtraField(members);
    auto entry = makeCentralDirEntry(10, 10, zip::kSentinel32, "doc.txt", extra);
    const size_t sizeBefore = entry.size();

    ASSERT_TRUE(zip::shiftLocalHeaderOffset(entry, 69));
    EXPECT_EQ(entry.size(), sizeBefore);
    EXPECT_EQ(zip::readLE32(entry, 42), zip::kSentinel32);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset), offset + 69);
}

// The offset slot's position depends on which size members precede it, so a
// hardcoded slot index would pass the single-member case above and corrupt a
// size here. Both sizes present puts the offset last.
TEST(ZipRecordsTest, ShiftFindsTheOffsetBehindBothSizeMembers)
{
    const uint64_t uncompressed = 6ULL << 30;
    const uint64_t compressed = 5ULL << 30;
    const uint64_t offset = 7ULL << 30;
    const std::vector<uint64_t> members{uncompressed, compressed, offset};
    const auto extra = makeZip64ExtraField(members);
    auto entry = makeCentralDirEntry(zip::kSentinel32, zip::kSentinel32, zip::kSentinel32, "doc.txt", extra);

    ASSERT_TRUE(zip::shiftLocalHeaderOffset(entry, 69));
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset), uncompressed);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset + 8), compressed);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset + 16), offset + 69);
}

// Only the compressed size is a sentinel here, so the offset sits one member
// in — not zero and not two.
TEST(ZipRecordsTest, ShiftFindsTheOffsetBehindASingleSizeMember)
{
    const uint64_t compressed = 5ULL << 30;
    const uint64_t offset = 7ULL << 30;
    const std::vector<uint64_t> members{compressed, offset};
    const auto extra = makeZip64ExtraField(members);
    auto entry = makeCentralDirEntry(zip::kSentinel32, 10, zip::kSentinel32, "doc.txt", extra);

    ASSERT_TRUE(zip::shiftLocalHeaderOffset(entry, 69));
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset), compressed);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset + 8), offset + 69);
}

TEST(ZipRecordsTest, ShiftPromotesAnOffsetThatOutgrowsThirtyTwoBits)
{
    const uint32_t offset = zip::kSentinel32 - 10;
    auto entry = makeCentralDirEntry(10, 10, offset, "doc.txt", {});
    const size_t sizeBefore = entry.size();

    ASSERT_TRUE(zip::shiftLocalHeaderOffset(entry, 69));
    EXPECT_EQ(entry.size(), sizeBefore + 12); // a fresh ZIP64 extra field
    EXPECT_EQ(zip::readLE32(entry, 42), zip::kSentinel32);
    EXPECT_EQ(zip::readLE16(entry, 30), 12u); // extra field length

    const size_t extraStart = zip::kCentralDirEntryFixedSize + 7;
    EXPECT_EQ(zip::readLE16(entry, extraStart), zip::kZip64ExtraFieldId);
    EXPECT_EQ(zip::readLE16(entry, extraStart + 2), 8u);
    EXPECT_EQ(zip::readLE64(entry, extraStart + 4), static_cast<uint64_t>(offset) + 69);
}

TEST(ZipRecordsTest, ShiftPromotesIntoAnExistingZip64ExtraField)
{
    const uint64_t uncompressed = 6ULL << 30;
    const uint64_t compressed = 5ULL << 30;
    const uint32_t offset = zip::kSentinel32 - 10;
    const std::vector<uint64_t> members{uncompressed, compressed};
    const auto extra = makeZip64ExtraField(members);
    auto entry = makeCentralDirEntry(zip::kSentinel32, zip::kSentinel32, offset, "doc.txt", extra);
    const size_t sizeBefore = entry.size();

    ASSERT_TRUE(zip::shiftLocalHeaderOffset(entry, 69));
    EXPECT_EQ(entry.size(), sizeBefore + 8); // one more member, no new header
    EXPECT_EQ(zip::readLE32(entry, 42), zip::kSentinel32);
    EXPECT_EQ(zip::readLE16(entry, 30), static_cast<uint16_t>(extra.size() + 8));

    const size_t extraStart = zip::kCentralDirEntryFixedSize + 7;
    EXPECT_EQ(zip::readLE16(entry, extraStart + 2), 24u); // member bytes
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset), uncompressed);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset + 8), compressed);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset + 16), static_cast<uint64_t>(offset) + 69);
}

// miniz gates the ZIP64 *compressed* size member on the UNCOMPRESSED size
// (miniz.c, all four mz_zip_writer_create_zip64_extra_data call sites) while
// leaving the fixed compressed-size field at its real value. An entry whose
// uncompressed size passes 4 GiB but compresses below it therefore carries one
// member more than its fixed fields advertise. Counting members off the fixed
// fields alone lands the shift on the compressed size and leaves the offset
// where it was — a silently unreadable archive.
TEST(ZipRecordsTest, ShiftHandlesTheExtraSizeMemberMinizEmits)
{
    const uint64_t uncompressed = 6ULL << 30;
    const uint64_t compressed = 2ULL << 30; // fits 32 bits, so its fixed field is real
    const uint64_t offset = 7ULL << 30;
    const std::vector<uint64_t> members{uncompressed, compressed, offset};
    const auto extra = makeZip64ExtraField(members);
    auto entry =
        makeCentralDirEntry(static_cast<uint32_t>(compressed), zip::kSentinel32, zip::kSentinel32, "doc.txt", extra);

    ASSERT_TRUE(zip::shiftLocalHeaderOffset(entry, 69));
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset), uncompressed);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset + 8), compressed);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset + 16), offset + 69);
}

// The same miniz shape on the promotion path: the offset member must land
// behind both size members, not between them.
TEST(ZipRecordsTest, ShiftPromotesBehindTheExtraSizeMemberMinizEmits)
{
    const uint64_t uncompressed = 6ULL << 30;
    const uint64_t compressed = 2ULL << 30;
    const uint32_t offset = zip::kSentinel32 - 10;
    const std::vector<uint64_t> members{uncompressed, compressed};
    const auto extra = makeZip64ExtraField(members);
    auto entry = makeCentralDirEntry(static_cast<uint32_t>(compressed), zip::kSentinel32, offset, "doc.txt", extra);
    const size_t sizeBefore = entry.size();

    ASSERT_TRUE(zip::shiftLocalHeaderOffset(entry, 69));
    EXPECT_EQ(entry.size(), sizeBefore + 8);
    EXPECT_EQ(zip::readLE32(entry, 42), zip::kSentinel32);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset), uncompressed);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset + 8), compressed);
    EXPECT_EQ(zip::readLE64(entry, kZip64ValuesOffset + 16), static_cast<uint64_t>(offset) + 69);
}

// A length that fits neither the standard nor the miniz layout leaves the slot
// unknowable, and a guessed slot writes an archive no reader can open.
TEST(ZipRecordsTest, ShiftRejectsAZip64FieldOfUnrecognisedLength)
{
    const std::vector<uint64_t> members{1, 2, 3, 4};
    const auto tooMany = makeZip64ExtraField(members); // four members, offset claimed at the third
    auto entry = makeCentralDirEntry(10, 10, zip::kSentinel32, "doc.txt", tooMany);
    EXPECT_FALSE(zip::shiftLocalHeaderOffset(entry, 69));

    // Not a whole number of members either.
    std::vector<uint8_t> ragged;
    zip::appendLE16(ragged, zip::kZip64ExtraFieldId);
    zip::appendLE16(ragged, 12);
    for (int i = 0; i < 12; ++i)
        ragged.push_back(0);
    auto raggedEntry = makeCentralDirEntry(10, 10, zip::kSentinel32, "doc.txt", ragged);
    EXPECT_FALSE(zip::shiftLocalHeaderOffset(raggedEntry, 69));
}

TEST(ZipRecordsTest, ShiftRejectsASentinelOffsetWithNoZip64ExtraField)
{
    auto entry = makeCentralDirEntry(10, 10, zip::kSentinel32, "doc.txt", {});
    EXPECT_FALSE(zip::shiftLocalHeaderOffset(entry, 69));
}

TEST(ZipRecordsTest, ShiftRejectsAMalformedEntry)
{
    auto truncated = makeCentralDirEntry(10, 10, 1000, "doc.txt", {});
    truncated.resize(zip::kCentralDirEntryFixedSize - 1);
    EXPECT_FALSE(zip::shiftLocalHeaderOffset(truncated, 69));

    auto badSignature = makeCentralDirEntry(10, 10, 1000, "doc.txt", {});
    badSignature[0] = 0x00;
    EXPECT_FALSE(zip::shiftLocalHeaderOffset(badSignature, 69));

    // Declared lengths that do not add up to the buffer.
    auto lying = makeCentralDirEntry(10, 10, 1000, "doc.txt", {});
    zip::writeLE16(lying, 30, 32); // extra field length that is not there
    EXPECT_FALSE(zip::shiftLocalHeaderOffset(lying, 69));
}

// The ASiC-E writer splices its hand-built mimetype entry in front of a
// miniz-produced archive, which moves every local header. Run that same
// read / shift / re-close sequence over real miniz output and hand the result
// back to miniz's reader: below 4 GiB it must come out as a plain archive with
// every entry still reachable.
TEST(ZipRecordsTest, AShiftedMinizArchiveStaysReadable)
{
    const std::string payload = "ASiC-E payload";
    std::vector<uint8_t> produced;
    {
        mz_zip_archive writer;
        std::memset(&writer, 0, sizeof(writer));
        ASSERT_TRUE(mz_zip_writer_init_heap(&writer, 0, 0));
        ASSERT_TRUE(mz_zip_writer_add_mem(&writer, "doc.txt", payload.data(), payload.size(), MZ_DEFAULT_COMPRESSION));
        ASSERT_TRUE(mz_zip_writer_add_mem(&writer, "META-INF/signature001.p7s", payload.data(), payload.size(),
                                          MZ_DEFAULT_COMPRESSION));
        void* buf = nullptr;
        size_t bufSize = 0;
        ASSERT_TRUE(mz_zip_writer_finalize_heap_archive(&writer, &buf, &bufSize));
        produced.assign(static_cast<uint8_t*>(buf), static_cast<uint8_t*>(buf) + bufSize);
        mz_free(buf);
        mz_zip_writer_end(&writer);
    }

    const auto eocd = zip::readEndOfCentralDirectory(produced);
    ASSERT_TRUE(eocd.has_value());
    const auto cdOffset = static_cast<size_t>(eocd->centralDirOffset);
    const auto cdSize = static_cast<size_t>(eocd->centralDirSize);

    // A stand-in for the mimetype local entry the writer puts up front.
    constexpr uint32_t kPrefix = 69;
    std::vector<uint8_t> shifted(kPrefix, 0);
    shifted.insert(shifted.end(), produced.begin(), produced.begin() + static_cast<ptrdiff_t>(cdOffset));

    // The same walk the writer runs — driving a transcribed copy here would
    // leave the shipped loop free to drift while this test stayed green.
    const uint64_t newCdOffset = shifted.size();
    ASSERT_TRUE(zip::appendShiftedCentralDirectory(shifted, std::span(produced).subspan(cdOffset, cdSize), kPrefix));
    zip::appendEndOfCentralDirectory(shifted, newCdOffset, shifted.size() - newCdOffset, eocd->entryCount);
    EXPECT_FALSE(hasZip64Records(shifted));

    mz_zip_archive reader;
    std::memset(&reader, 0, sizeof(reader));
    ASSERT_TRUE(mz_zip_reader_init_mem(&reader, shifted.data(), shifted.size(), 0))
        << mz_zip_get_error_string(mz_zip_get_last_error(&reader));
    EXPECT_EQ(mz_zip_reader_get_num_files(&reader), 2u);
    const int index = mz_zip_reader_locate_file(&reader, "doc.txt", nullptr, 0);
    ASSERT_GE(index, 0);
    size_t extractedSize = 0;
    void* extracted = mz_zip_reader_extract_to_heap(&reader, static_cast<mz_uint>(index), &extractedSize, 0);
    ASSERT_NE(extracted, nullptr);
    EXPECT_EQ(std::string(static_cast<char*>(extracted), extractedSize), payload);
    mz_free(extracted);
    mz_zip_reader_end(&reader);
}

// An independent parser has to accept the records: miniz's reader follows the
// locator to the ZIP64 record and takes the entry count and central-directory
// offset from it. Reaching that path through the entry count rather than a
// 4 GiB central directory keeps the archive at a few megabytes.
TEST(ZipRecordsTest, MinizReadsAnArchiveClosedByTheZip64Records)
{
    constexpr uint32_t kEntries = 65535; // the 16-bit EOCD field's sentinel
    std::vector<uint8_t> archive;
    std::vector<uint32_t> localOffsets;
    localOffsets.reserve(kEntries);

    for (uint32_t i = 0; i < kEntries; ++i) {
        char name[9];
        std::snprintf(name, sizeof(name), "e%07u", i);
        localOffsets.push_back(static_cast<uint32_t>(archive.size()));
        zip::appendLE32(archive, 0x04034b50); // local file header
        zip::appendLE16(archive, 20);         // version needed
        zip::appendLE16(archive, 0);          // flags
        zip::appendLE16(archive, 0);          // method: STORED
        zip::appendLE16(archive, 0);          // mod time
        zip::appendLE16(archive, 0);          // mod date
        zip::appendLE32(archive, 0);          // crc of an empty file
        zip::appendLE32(archive, 0);          // compressed size
        zip::appendLE32(archive, 0);          // uncompressed size
        zip::appendLE16(archive, 8);          // file name length
        zip::appendLE16(archive, 0);          // extra field length
        archive.insert(archive.end(), name, name + 8);
    }

    const uint64_t cdOffset = archive.size();
    for (uint32_t i = 0; i < kEntries; ++i) {
        char name[9];
        std::snprintf(name, sizeof(name), "e%07u", i);
        const auto entry = makeCentralDirEntry(0, 0, localOffsets[i], std::string_view(name, 8), {});
        archive.insert(archive.end(), entry.begin(), entry.end());
    }
    const uint64_t cdSize = archive.size() - cdOffset;

    zip::appendEndOfCentralDirectory(archive, cdOffset, cdSize, kEntries);
    ASSERT_TRUE(hasZip64Records(archive));

    mz_zip_archive reader;
    std::memset(&reader, 0, sizeof(reader));
    ASSERT_TRUE(mz_zip_reader_init_mem(&reader, archive.data(), archive.size(), 0))
        << mz_zip_get_error_string(mz_zip_get_last_error(&reader));
    EXPECT_EQ(mz_zip_reader_get_num_files(&reader), kEntries);

    // Reading an entry in the middle proves the central-directory offset the
    // reader took from the ZIP64 record actually lands on the directory.
    char filename[16] = {};
    mz_zip_reader_get_filename(&reader, kEntries / 2, filename, sizeof(filename));
    char expected[9];
    std::snprintf(expected, sizeof(expected), "e%07u", kEntries / 2);
    EXPECT_STREQ(filename, expected);
    mz_zip_reader_end(&reader);
}

class ASiCModuleSoftHSMTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
        auto slot = libresign::test::findSoftHsmTestSlot(manager.acquire(softHsmPath));
        if (!slot)
            GTEST_SKIP() << "SoftHSM2 token '" << libresign::test::kSoftHsmTokenLabel << "' not initialised";
        testSlot = *slot;
    }
    const char* softHsmPath = nullptr;
    libresign::Pkcs11ModuleManager manager;
    unsigned long testSlot = 0;
};

TEST_F(ASiCModuleSoftHSMTest, SignWithCAdES_ProducesValidZip)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    ASiCModule asic;

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    auto result = asic.signWithCAdES(data, "test.txt", token, SignatureLevel::B_B, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.signedDocument.empty());

    // Verify ZIP magic bytes (PK\x03\x04)
    ASSERT_GE(result.signedDocument.size(), 4u);
    EXPECT_EQ(result.signedDocument[0], 'P');
    EXPECT_EQ(result.signedDocument[1], 'K');

    // A container this far below 4 GiB must close with the plain End of
    // Central Directory record: emitting the ZIP64 records unconditionally
    // would lock out every reader that predates ZIP64.
    EXPECT_FALSE(hasZip64Records(result.signedDocument));

    // Parse ZIP and verify ASiC-E structure
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    ASSERT_TRUE(mz_zip_reader_init_mem(&zip, result.signedDocument.data(), result.signedDocument.size(), 0));

    int numFiles = static_cast<int>(mz_zip_reader_get_num_files(&zip));
    EXPECT_GE(numFiles, 4); // mimetype, document, manifest, signature

    // First entry must be "mimetype"
    char filename[256];
    mz_zip_reader_get_filename(&zip, 0, filename, sizeof(filename));
    EXPECT_STREQ(filename, "mimetype");

    // Verify mimetype is stored uncompressed (method 0)
    mz_zip_archive_file_stat stat;
    ASSERT_TRUE(mz_zip_reader_file_stat(&zip, 0, &stat));
    EXPECT_EQ(stat.m_method, 0u);

    // Extract and verify mimetype content
    size_t mimetypeSize = 0;
    void* mimetypeData = mz_zip_reader_extract_to_heap(&zip, 0, &mimetypeSize, 0);
    ASSERT_NE(mimetypeData, nullptr);
    std::string mimetypeStr(static_cast<char*>(mimetypeData), mimetypeSize);
    EXPECT_EQ(mimetypeStr, "application/vnd.etsi.asic-e+zip");
    free(mimetypeData); // NOLINT

    // Verify all expected entries exist
    EXPECT_GE(mz_zip_reader_locate_file(&zip, "test.txt", nullptr, 0), 0);
    // ETSI EN 319 162-1 names the per-signature manifest ASiCManifest<nnn>.xml
    // and pairs it with the signature entry carrying the same suffix.
    EXPECT_GE(mz_zip_reader_locate_file(&zip, "META-INF/ASiCManifest001.xml", nullptr, 0), 0);
    EXPECT_GE(mz_zip_reader_locate_file(&zip, "META-INF/signature001.p7s", nullptr, 0), 0);

    // Verify document content round-trips
    int docIdx = mz_zip_reader_locate_file(&zip, "test.txt", nullptr, 0);
    ASSERT_GE(docIdx, 0);
    size_t docSize = 0;
    void* docData = mz_zip_reader_extract_to_heap(&zip, static_cast<mz_uint>(docIdx), &docSize, 0);
    ASSERT_NE(docData, nullptr);
    std::vector<uint8_t> extracted(static_cast<uint8_t*>(docData), static_cast<uint8_t*>(docData) + docSize);
    EXPECT_EQ(extracted, data);
    free(docData); // NOLINT

    // Verify signature is valid DER (starts with SEQUENCE tag 0x30)
    int sigIdx = mz_zip_reader_locate_file(&zip, "META-INF/signature001.p7s", nullptr, 0);
    ASSERT_GE(sigIdx, 0);
    size_t sigSize = 0;
    void* sigData = mz_zip_reader_extract_to_heap(&zip, static_cast<mz_uint>(sigIdx), &sigSize, 0);
    ASSERT_NE(sigData, nullptr);
    ASSERT_GT(sigSize, 0u);
    EXPECT_EQ(static_cast<uint8_t*>(sigData)[0], 0x30);
    free(sigData); // NOLINT

    mz_zip_reader_end(&zip);
}

// The long-term revocation gate is reached through appendSigner on the ASiC-E
// path too, by delegation: appendSigner re-enters signWithCAdES, which calls
// CAdESModule::sign, which runs the fail-closed check. Reaching it needs a
// working RFC 3161 step first — B-LT implies B-T, and CAdESModule::sign
// timestamps before it collects revocation material, so with no TSA the append
// fails at the timestamp and never gets to the gate. With one supplied, the
// SoftHSM token's single self-signed leaf is a chain of length one: no
// Trusted-List anchor completed it and no issuer hop reaches a verified root,
// so the tail is unprovable and the gate must fail closed rather than emit a
// long-term signature with no verifiable revocation evidence.
TEST_F(ASiCModuleSoftHSMTest, AppendSignerAtLongTermRejectsUnterminatedChain)
{
    libresign::test::MockTsaServer tsaServer;
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    ASiCModule asic;

    std::vector<uint8_t> data = {'A', 'S', 'i', 'C'};
    auto prior = asic.signWithCAdES(data, "test.txt", token, SignatureLevel::B_B, {});
    ASSERT_TRUE(prior.success) << prior.errorMessage;

    TSAConfig tsa;
    tsa.url = tsaServer.url();
    auto appended = asic.appendSigner(prior.signedDocument, {}, token, SignatureLevel::B_LT, tsa);
    EXPECT_FALSE(appended.success);
    ASSERT_TRUE(appended.failureKind.has_value()) << appended.errorMessage;
    EXPECT_EQ(*appended.failureKind, SignFailureKind::CertificateChainIncomplete) << appended.errorMessage;
}

#else
TEST(ASiCModuleTest, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif
