// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace libresign::zip {

// ZIP structural records shared by the ASiC-E writer: the End of Central
// Directory record, its ZIP64 counterparts, and the central-directory entry
// fields the writer has to rewrite when it splices its own hand-built
// mimetype entry in front of a miniz-produced archive.
//
// Everything here is a pure function over caller-supplied sizes and offsets.
// That is deliberate: the ZIP64 branches only engage past UINT32_MAX, and a
// test that had to materialise a 4 GiB archive to reach them would never be
// run. Passing synthetic offsets exercises the same code the writer runs.

inline constexpr uint32_t kEocdSignature = 0x06054b50;
inline constexpr uint32_t kZip64EocdSignature = 0x06064b50;
inline constexpr uint32_t kZip64EocdLocatorSignature = 0x07064b50;
inline constexpr uint32_t kCentralDirEntrySignature = 0x02014b50;

// APPNOTE.TXT §4.3.9.2 header ID of the ZIP64 Extended Information field.
inline constexpr uint16_t kZip64ExtraFieldId = 0x0001;

inline constexpr size_t kEocdSize = 22;
inline constexpr size_t kZip64EocdSize = 56;
inline constexpr size_t kZip64EocdLocatorSize = 20;
inline constexpr size_t kCentralDirEntryFixedSize = 46;

// A fixed field holding all-ones means "the real value lives in the ZIP64
// record" (APPNOTE.TXT §4.3.14, §4.4.1.4, §4.5.3). A value that happens to
// equal the sentinel is therefore indistinguishable from the marker, so the
// writer promotes to ZIP64 *at* the sentinel rather than past it.
inline constexpr uint16_t kSentinel16 = 0xFFFF;
inline constexpr uint32_t kSentinel32 = 0xFFFFFFFF;

// Version 4.5 — the ZIP feature level that introduced ZIP64.
inline constexpr uint16_t kZip64VersionNeeded = 45;

inline void appendLE16(std::vector<uint8_t>& v, uint16_t val)
{
    v.push_back(static_cast<uint8_t>(val & 0xFF));
    v.push_back(static_cast<uint8_t>(val >> 8));
}

inline void appendLE32(std::vector<uint8_t>& v, uint32_t val)
{
    v.push_back(static_cast<uint8_t>(val & 0xFF));
    v.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>(val >> 24));
}

inline void appendLE64(std::vector<uint8_t>& v, uint64_t val)
{
    for (int shift = 0; shift < 64; shift += 8)
        v.push_back(static_cast<uint8_t>((val >> shift) & 0xFF));
}

inline uint16_t readLE16(std::span<const uint8_t> buf, size_t pos)
{
    return static_cast<uint16_t>(static_cast<uint16_t>(buf[pos]) | static_cast<uint16_t>(buf[pos + 1] << 8));
}

inline uint32_t readLE32(std::span<const uint8_t> buf, size_t pos)
{
    return static_cast<uint32_t>(buf[pos]) | (static_cast<uint32_t>(buf[pos + 1]) << 8) |
           (static_cast<uint32_t>(buf[pos + 2]) << 16) | (static_cast<uint32_t>(buf[pos + 3]) << 24);
}

inline uint64_t readLE64(std::span<const uint8_t> buf, size_t pos)
{
    uint64_t val = 0;
    for (int i = 7; i >= 0; --i)
        val = (val << 8) | buf[pos + static_cast<size_t>(i)];
    return val;
}

inline void writeLE16(std::span<uint8_t> buf, size_t pos, uint16_t val)
{
    buf[pos] = static_cast<uint8_t>(val & 0xFF);
    buf[pos + 1] = static_cast<uint8_t>(val >> 8);
}

inline void writeLE32(std::span<uint8_t> buf, size_t pos, uint32_t val)
{
    buf[pos] = static_cast<uint8_t>(val & 0xFF);
    buf[pos + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    buf[pos + 2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[pos + 3] = static_cast<uint8_t>(val >> 24);
}

inline void writeLE64(std::span<uint8_t> buf, size_t pos, uint64_t val)
{
    for (size_t i = 0; i < 8; ++i)
        buf[pos + i] = static_cast<uint8_t>((val >> (8 * i)) & 0xFF);
}

/// Where the central directory sits and how much of it there is.
struct EndOfCentralDirectory
{
    uint64_t centralDirOffset = 0;
    uint64_t centralDirSize = 0;
    uint64_t entryCount = 0;
};

/// True when at least one End of Central Directory field cannot hold its
/// value and the archive therefore needs the ZIP64 records.
[[nodiscard]] inline bool needsZip64(uint64_t centralDirOffset, uint64_t centralDirSize, uint64_t entryCount)
{
    return centralDirOffset >= kSentinel32 || centralDirSize >= kSentinel32 || entryCount >= kSentinel16;
}

/// Append the End of Central Directory record for an archive whose central
/// directory starts at @p centralDirOffset, spans @p centralDirSize bytes and
/// holds @p entryCount entries.
///
/// When any of the three outgrows its End of Central Directory field, the
/// record is preceded by a ZIP64 End of Central Directory Record
/// (APPNOTE.TXT §4.3.14) and a ZIP64 End of Central Directory Locator
/// (§4.3.15); the overflowing End of Central Directory fields then carry the
/// all-ones sentinel (§4.3.16) and the real 64-bit values live in the ZIP64
/// record. Fields that still fit keep their real values — a reader that
/// consults the ZIP64 record only for sentinel fields must still find the
/// truth in the classic record.
///
/// @p out must already hold the archive up to the end of the central
/// directory. The ZIP64 record's own position is derived from
/// @p centralDirOffset + @p centralDirSize rather than from `out.size()`, so
/// the overflow branches can be driven with synthetic offsets without
/// materialising an archive of that size.
inline void appendEndOfCentralDirectory(std::vector<uint8_t>& out, uint64_t centralDirOffset, uint64_t centralDirSize,
                                        uint64_t entryCount)
{
    if (needsZip64(centralDirOffset, centralDirSize, entryCount)) {
        // The ZIP64 record begins immediately after the central directory.
        const uint64_t zip64EocdOffset = centralDirOffset + centralDirSize;

        // ZIP64 End of Central Directory Record — APPNOTE.TXT §4.3.14.
        appendLE32(out, kZip64EocdSignature);
        // Size of this record counted from the first byte after this field.
        appendLE64(out, kZip64EocdSize - 12);
        appendLE16(out, kZip64VersionNeeded); // version made by
        appendLE16(out, kZip64VersionNeeded); // version needed to extract
        appendLE32(out, 0);                   // number of this disk
        appendLE32(out, 0);                   // disk holding the central directory
        appendLE64(out, entryCount);          // entries in the central directory on this disk
        appendLE64(out, entryCount);          // entries in the central directory
        appendLE64(out, centralDirSize);
        appendLE64(out, centralDirOffset);

        // ZIP64 End of Central Directory Locator — APPNOTE.TXT §4.3.15.
        appendLE32(out, kZip64EocdLocatorSignature);
        appendLE32(out, 0); // disk holding the ZIP64 record
        appendLE64(out, zip64EocdOffset);
        appendLE32(out, 1); // total number of disks
    }

    // End of Central Directory record — APPNOTE.TXT §4.3.16.
    const auto entries16 = static_cast<uint16_t>(std::min<uint64_t>(entryCount, kSentinel16));
    appendLE32(out, kEocdSignature);
    appendLE16(out, 0); // number of this disk
    appendLE16(out, 0); // disk holding the central directory
    appendLE16(out, entries16);
    appendLE16(out, entries16);
    appendLE32(out, static_cast<uint32_t>(std::min<uint64_t>(centralDirSize, kSentinel32)));
    appendLE32(out, static_cast<uint32_t>(std::min<uint64_t>(centralDirOffset, kSentinel32)));
    appendLE16(out, 0); // comment length
}

/// Locate and decode the End of Central Directory record at the tail of
/// @p archive, following the ZIP64 End of Central Directory Locator for any
/// field that carries the all-ones sentinel (APPNOTE.TXT §4.3.15–§4.3.16).
///
/// Returns `nullopt` when no End of Central Directory record is present, or
/// when a sentinel field has no well-formed ZIP64 record behind it — a
/// truncated 32-bit value is never returned in its place.
[[nodiscard]] inline std::optional<EndOfCentralDirectory> readEndOfCentralDirectory(std::span<const uint8_t> archive)
{
    if (archive.size() < kEocdSize)
        return std::nullopt;

    // The End of Central Directory record is last (the writer emits no
    // archive comment). Scan backwards for its signature; a signed loop
    // avoids size_t underflow at index 0.
    size_t eocdOff = 0;
    bool found = false;
    for (auto i = static_cast<ptrdiff_t>(archive.size() - kEocdSize); i >= 0; --i) {
        if (readLE32(archive, static_cast<size_t>(i)) == kEocdSignature) {
            eocdOff = static_cast<size_t>(i);
            found = true;
            break;
        }
    }
    if (!found)
        return std::nullopt;

    const uint16_t entries16 = readLE16(archive, eocdOff + 10);
    const uint32_t cdSize32 = readLE32(archive, eocdOff + 12);
    const uint32_t cdOff32 = readLE32(archive, eocdOff + 16);

    EndOfCentralDirectory eocd;
    eocd.entryCount = entries16;
    eocd.centralDirSize = cdSize32;
    eocd.centralDirOffset = cdOff32;

    const bool sentinelEntries = entries16 == kSentinel16;
    const bool sentinelSize = cdSize32 == kSentinel32;
    const bool sentinelOffset = cdOff32 == kSentinel32;
    if (!sentinelEntries && !sentinelSize && !sentinelOffset)
        return eocd;

    // A sentinel points at the ZIP64 record; the locator sits immediately
    // before the End of Central Directory record.
    const auto zip64Start = [&]() -> std::optional<size_t> {
        if (eocdOff < kZip64EocdLocatorSize)
            return std::nullopt;
        const size_t locatorOff = eocdOff - kZip64EocdLocatorSize;
        if (readLE32(archive, locatorOff) != kZip64EocdLocatorSignature)
            return std::nullopt;
        const uint64_t recordOff = readLE64(archive, locatorOff + 8);
        if (recordOff > locatorOff || locatorOff - recordOff < kZip64EocdSize)
            return std::nullopt;
        const auto start = static_cast<size_t>(recordOff);
        if (readLE32(archive, start) != kZip64EocdSignature)
            return std::nullopt;
        return start;
    }();

    if (!zip64Start) {
        // A 32-bit sentinel with no record behind it leaves the central
        // directory unaddressable, so refuse rather than hand back a
        // truncated offset. A 16-bit one only ever means "exactly 65535",
        // which the classic field already carries.
        if (sentinelSize || sentinelOffset)
            return std::nullopt;
        return eocd;
    }

    // Only the sentinel fields are read from the ZIP64 record; a field that
    // still fits its classic slot stays authoritative there.
    if (sentinelEntries)
        eocd.entryCount = readLE64(archive, *zip64Start + 32);
    if (sentinelSize)
        eocd.centralDirSize = readLE64(archive, *zip64Start + 40);
    if (sentinelOffset)
        eocd.centralDirOffset = readLE64(archive, *zip64Start + 48);
    return eocd;
}

/// Add @p delta to the "relative offset of local header" of a single
/// central-directory entry held in @p entry, promoting the field to ZIP64
/// when the shifted offset no longer fits 32 bits.
///
/// APPNOTE.TXT §4.5.3: an offset too large for the fixed field is stored in
/// the ZIP64 Extended Information extra field and the fixed field carries the
/// all-ones sentinel. The extra field packs its members in a fixed order —
/// uncompressed size, compressed size, local header offset, disk start — so
/// where the offset lives depends on how many members precede it. That count
/// is read off the field's own length rather than off the fixed fields,
/// because the two disagree in practice: see the comment on the derivation
/// below.
///
/// @p entry may grow: promoting an offset that had no ZIP64 slot appends one
/// (and its extra-field header, when the entry had no ZIP64 field at all).
///
/// @return false when the entry is malformed, when the ZIP64 field a sentinel
///         promises is missing, when its length matches no recognised member
///         layout, or when the extra field cannot grow without overflowing
///         its own 16-bit length.
[[nodiscard]] inline bool shiftLocalHeaderOffset(std::vector<uint8_t>& entry, uint64_t delta)
{
    if (entry.size() < kCentralDirEntryFixedSize)
        return false;
    if (readLE32(entry, 0) != kCentralDirEntrySignature)
        return false;

    const uint32_t compressedSize = readLE32(entry, 20);
    const uint32_t uncompressedSize = readLE32(entry, 24);
    const uint16_t fileNameLen = readLE16(entry, 28);
    const uint16_t extraLen = readLE16(entry, 30);
    const uint16_t commentLen = readLE16(entry, 32);
    if (entry.size() != kCentralDirEntryFixedSize + fileNameLen + extraLen + commentLen)
        return false;

    const size_t extraStart = kCentralDirEntryFixedSize + fileNameLen;
    const size_t extraEnd = extraStart + extraLen;

    // Walk the extra-field chain for the ZIP64 Extended Information record.
    size_t zip64Start = 0;
    uint16_t zip64Size = 0;
    bool hasZip64 = false;
    for (size_t p = extraStart; p + 4 <= extraEnd;) {
        const uint16_t id = readLE16(entry, p);
        const uint16_t size = readLE16(entry, p + 2);
        if (p + 4 + size > extraEnd)
            return false; // extra field runs past the entry
        if (id == kZip64ExtraFieldId) {
            zip64Start = p;
            zip64Size = size;
            hasZip64 = true;
            break;
        }
        p += 4 + size;
    }

    const uint32_t fixedOffset = readLE32(entry, 42);
    const bool offsetInZip64 = fixedOffset == kSentinel32;

    // Where the offset member sits inside the ZIP64 field.
    //
    // APPNOTE.TXT §4.5.3 fixes the member order and says a member appears
    // only when its own fixed field is a sentinel. miniz, the writer feeding
    // this path, does not follow that rule: all four of its
    // mz_zip_writer_create_zip64_extra_data call sites gate the *compressed*
    // size member on `uncomp_size >= MZ_UINT32_MAX`, while the fixed
    // compressed-size field keeps `MZ_MIN(comp_size, MZ_UINT32_MAX)`. An
    // entry whose uncompressed size passes 4 GiB but compresses below it
    // therefore carries [uncompressed, compressed] with only the
    // *uncompressed* fixed field set to the sentinel — one member more than
    // the fixed fields advertise.
    //
    // Counting members off the fixed fields alone would then put the shift on
    // the compressed size and leave the offset untouched, so the count comes
    // from the field's own length. A length matching neither the standard nor
    // the miniz shape is refused rather than guessed at: a wrong slot writes
    // a plausible-looking archive that no reader can open.
    size_t offsetSlot = 0;
    if (hasZip64) {
        const bool diskInZip64 = readLE16(entry, 34) == kSentinel16;
        const size_t trailing = (offsetInZip64 ? 8u : 0u) + (diskInZip64 ? 4u : 0u);
        if (zip64Size < trailing || (zip64Size - trailing) % 8 != 0)
            return false;
        const size_t sizeMembers = (zip64Size - trailing) / 8;
        const size_t perStandard =
            (uncompressedSize == kSentinel32 ? 1u : 0u) + (compressedSize == kSentinel32 ? 1u : 0u);
        const size_t perMiniz = uncompressedSize == kSentinel32 ? 2u : perStandard;
        if (sizeMembers != perStandard && sizeMembers != perMiniz)
            return false;
        // zip64Size == sizeMembers * 8 + trailing, so the slot and the eight
        // bytes behind it are inside the field by construction.
        offsetSlot = sizeMembers * 8;
    }

    if (offsetInZip64) {
        if (!hasZip64)
            return false;
        const size_t slotPos = zip64Start + 4 + offsetSlot;
        const uint64_t current = readLE64(entry, slotPos);
        if (current > UINT64_MAX - delta)
            return false;
        writeLE64(entry, slotPos, current + delta);
        return true;
    }

    const uint64_t shifted = static_cast<uint64_t>(fixedOffset) + delta;
    if (shifted < kSentinel32) {
        writeLE32(entry, 42, static_cast<uint32_t>(shifted));
        return true;
    }

    // Promote: the shifted offset no longer fits the fixed field.
    if (hasZip64) {
        if (extraLen > kSentinel16 - 8)
            return false;
        const size_t slotPos = zip64Start + 4 + offsetSlot;
        entry.insert(entry.begin() + static_cast<ptrdiff_t>(slotPos), 8, 0);
        writeLE64(entry, slotPos, shifted);
        writeLE16(entry, zip64Start + 2, static_cast<uint16_t>(zip64Size + 8));
        writeLE16(entry, 30, static_cast<uint16_t>(extraLen + 8));
    } else {
        if (extraLen > kSentinel16 - 12)
            return false;
        entry.insert(entry.begin() + static_cast<ptrdiff_t>(extraStart), 12, 0);
        writeLE16(entry, extraStart, kZip64ExtraFieldId);
        writeLE16(entry, extraStart + 2, 8);
        writeLE64(entry, extraStart + 4, shifted);
        writeLE16(entry, 30, static_cast<uint16_t>(extraLen + 12));
    }
    writeLE32(entry, 42, kSentinel32);
    return true;
}

/// Copy every entry of @p centralDirectory into @p out with each entry's local
/// header offset shifted by @p delta.
///
/// Splicing anything in front of a ZIP's local file entries moves all of them,
/// and each central-directory entry has to be told by how much. Production and
/// tests drive the walk through this one function so a test cannot silently
/// diverge from the loop that ships.
///
/// The walk stops early on an entry whose declared lengths run past the end of
/// @p centralDirectory, emitting whatever was already copied. miniz generates
/// the input, so that cannot happen in practice, but a malformed buffer must
/// not be read past its end.
///
/// @return false when an entry is present but cannot be shifted; @p out then
///         holds a partial copy that the caller must discard.
[[nodiscard]] inline bool appendShiftedCentralDirectory(std::vector<uint8_t>& out,
                                                        std::span<const uint8_t> centralDirectory, uint64_t delta)
{
    const size_t size = centralDirectory.size();
    for (size_t i = 0; i < size;) {
        if (i + kCentralDirEntryFixedSize > size)
            break;
        // File name, extra field and comment lengths give the entry's size.
        const uint16_t fileNameLen = readLE16(centralDirectory, i + 28);
        const uint16_t extraLen = readLE16(centralDirectory, i + 30);
        const uint16_t commentLen = readLE16(centralDirectory, i + 32);
        const size_t entrySize = kCentralDirEntryFixedSize + fileNameLen + extraLen + commentLen;
        if (i + entrySize > size)
            break;

        std::vector<uint8_t> entry(centralDirectory.begin() + static_cast<ptrdiff_t>(i),
                                   centralDirectory.begin() + static_cast<ptrdiff_t>(i + entrySize));
        if (!shiftLocalHeaderOffset(entry, delta))
            return false;
        out.insert(out.end(), entry.begin(), entry.end());

        i += entrySize;
    }
    return true;
}

} // namespace libresign::zip
