// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "rs_document_profile.h"

#include "rs_container.h"

#include <date_format.h>
#include <text_encoding.h>
#include <tlv.h>

#include <algorithm>
#include <set>

namespace LibreSCRS::RsEId::Core {
namespace {

namespace SC = LibreSCRS::SmartCard::Internal;

constexpr std::size_t kPhotoHeaderSize = 2 * kContainerHeaderSize; // container, then the inner TLV

[[nodiscard]] bool onSurface(const FieldSpec& f, Surface surface) noexcept
{
    return (f.surfaces & static_cast<std::uint8_t>(surface)) != 0;
}

[[nodiscard]] ReadMode modeOf(const DocumentProfile& profile, std::uint16_t fid) noexcept
{
    for (const auto& f : profile.files) {
        if (f.fid == fid) {
            return f.mode;
        }
    }
    return ReadMode::Header;
}

[[nodiscard]] std::vector<SC::TLVField> parseFile(std::span<const std::uint8_t> file)
{
    const auto container = leadingTlv(file);
    if (!container) {
        return {};
    }
    const auto body = container->subspan(kContainerHeaderSize);
    return SC::parseTLV(body.data(), body.size());
}

[[nodiscard]] std::string decode(const SC::TLVField& field, const FieldSpec& spec, Surface surface)
{
    std::string text = spec.encoding == TextEncoding::Utf16Le ? SC::decodeUtf16Le(field.value) : field.asString();
    if (spec.format == FieldFormat::Date && surface == Surface::CardEdge) {
        text = SC::formatDateDMY(text);
    }
    return text;
}

} // namespace

std::vector<std::uint16_t> groupFiles(const DocumentProfile& profile, std::string_view groupKey, Surface surface)
{
    std::set<std::uint16_t> fids;
    for (const auto& f : profile.fields) {
        if (f.group == groupKey && onSurface(f, surface)) {
            fids.insert(f.fid);
        }
    }
    return {fids.begin(), fids.end()};
}

std::optional<ProfileGroup> buildGroup(const DocumentProfile& profile, std::string_view groupKey, const RawFiles& files,
                                       Surface surface)
{
    const auto spec = std::find_if(profile.groups.begin(), profile.groups.end(),
                                   [&](const GroupSpec& g) { return g.key == groupKey; });
    if (spec == profile.groups.end()) {
        return std::nullopt;
    }

    std::vector<const FieldSpec*> rows;
    for (const auto& f : profile.fields) {
        if (f.group == groupKey && onSurface(f, surface)) {
            rows.push_back(&f);
        }
    }
    std::stable_sort(rows.begin(), rows.end(), [](const FieldSpec* a, const FieldSpec* b) { return a->fid < b->fid; });

    ProfileGroup group{std::string{spec->key}, std::string{spec->label}, {}};
    std::map<std::uint16_t, std::vector<SC::TLVField>> parsed;
    for (const FieldSpec* row : rows) {
        auto it = parsed.find(row->fid);
        if (it == parsed.end()) {
            const auto file = files.find(row->fid);
            const bool readable = file != files.end() && modeOf(profile, row->fid) == ReadMode::Header;
            it = parsed.emplace(row->fid, readable ? parseFile(file->second) : std::vector<SC::TLVField>{}).first;
        }
        const auto field = std::find_if(it->second.begin(), it->second.end(),
                                        [&](const SC::TLVField& t) { return t.tag == row->tag; });
        if (field == it->second.end()) {
            continue;
        }
        auto value = decode(*field, *row, surface);
        if (!value.empty()) {
            group.fields.push_back({std::string{row->key}, std::string{row->label}, std::move(value)});
        }
    }

    if (group.fields.empty()) {
        return std::nullopt;
    }
    return group;
}

std::vector<ProfileGroup> buildGroups(const DocumentProfile& profile, const RawFiles& files, Surface surface)
{
    std::vector<ProfileGroup> out;
    for (const auto& g : profile.groups) {
        if (auto group = buildGroup(profile, g.key, files, surface)) {
            out.push_back(std::move(*group));
        }
    }
    return out;
}

std::vector<std::uint8_t> extractPhoto(std::span<const std::uint8_t> photoFile)
{
    if (photoFile.size() < kPhotoHeaderSize + 2 || photoFile[kPhotoHeaderSize] != 0xFF ||
        photoFile[kPhotoHeaderSize + 1] != 0xD8) {
        return {};
    }
    // Stop at the declared end: the allocation behind it is padding.
    const auto container = leadingTlv(photoFile);
    const auto end = container ? container->size() : photoFile.size();
    if (end <= kPhotoHeaderSize) {
        return {};
    }
    return {photoFile.begin() + kPhotoHeaderSize, photoFile.begin() + static_cast<std::ptrdiff_t>(end)};
}

std::vector<std::uint8_t> sodBlock(const FileSpec& spec, std::span<const std::uint8_t> file)
{
    if (spec.mode == ReadMode::Allocation) {
        return {file.begin(), file.end()};
    }
    const auto tlv = leadingTlv(file);
    if (!tlv) {
        return {};
    }
    return {tlv->begin(), tlv->end()};
}

std::vector<std::size_t> measuredSlotCounts()
{
    std::set<std::size_t> counts;
    for (const auto& p : documentProfiles()) {
        for (const auto& sod : p.sods) {
            counts.insert(sod.slots.size());
        }
    }
    return {counts.begin(), counts.end()};
}

} // namespace LibreSCRS::RsEId::Core
