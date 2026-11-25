// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "rs_container.h"

#include "rs_tags.h"

#include <tlv.h>

namespace LibreSCRS::RsEId::Core {
namespace {

[[nodiscard]] std::uint16_t le16(std::span<const std::uint8_t> b, std::size_t i) noexcept
{
    return static_cast<std::uint16_t>(b[i] | (b[i + 1] << 8));
}

// An inner TLV tag may itself start with 0x30 (0x0830 on the one-slot signed
// object of the official ID), so the first byte alone does not say "SEQUENCE".
// A real CMS is indefinite-length, or its definite length spans the content.
// Two known limits, both failing closed: a bare definite-length CMS followed by
// trailing bytes is taken for a wrapper and stripped (the parse then fails), and
// a wrapper tag 0x8030 reads as an indefinite CMS (d2i then rejects it).
[[nodiscard]] bool startsWithCms(std::span<const std::uint8_t> content) noexcept
{
    if (content.size() < 2 || content[0] != 0x30) {
        return false;
    }
    if (content[1] == 0x80) {
        return true;
    }
    if (content[1] < 0x80) {
        return content.size() == 2u + content[1];
    }
    const std::size_t octets = content[1] & 0x7Fu;
    if (octets > 4 || content.size() < 2 + octets) {
        return false;
    }
    std::size_t length = 0;
    for (std::size_t i = 0; i < octets; ++i) {
        length = (length << 8) | content[2 + i];
    }
    return content.size() == 2 + octets + length;
}

} // namespace

std::optional<std::uint16_t> outerTag(std::span<const std::uint8_t> file) noexcept
{
    if (file.size() < kContainerHeaderSize) {
        return std::nullopt;
    }
    return le16(file, 0);
}

std::optional<std::span<const std::uint8_t>> leadingTlv(std::span<const std::uint8_t> file) noexcept
{
    if (file.size() < kContainerHeaderSize) {
        return std::nullopt;
    }
    const std::size_t total = kContainerHeaderSize + le16(file, 2);
    if (total > file.size()) {
        return std::nullopt;
    }
    return file.first(total);
}

std::span<const std::uint8_t> innerTlvPayload(std::span<const std::uint8_t> content) noexcept
{
    if (content.size() <= kContainerHeaderSize || startsWithCms(content)) {
        return content;
    }
    return content.subspan(kContainerHeaderSize);
}

std::vector<std::uint16_t> parseManifest(std::span<const std::uint8_t> manifestFile)
{
    std::vector<std::uint16_t> ids;

    const auto tlv = leadingTlv(manifestFile);
    if (!tlv) {
        return ids;
    }

    const auto body = tlv->subspan(kContainerHeaderSize);
    const auto fields = LibreSCRS::SmartCard::Internal::parseTLV(body.data(), body.size());
    const auto listed = LibreSCRS::SmartCard::Internal::findBytes(fields, tags::kAnnexManifestFileList);

    ids.reserve(listed.size() / 2);
    for (std::size_t i = 0; i + 1 < listed.size(); i += 2) {
        ids.push_back(static_cast<std::uint16_t>(listed[i] | (listed[i + 1] << 8)));
    }
    return ids;
}

AnnexCoverage annexCoverage(std::span<const std::uint16_t> manifestIds)
{
    AnnexCoverage cov;

    // The manifest never lists itself, yet the fixed object covers it first.
    cov.fixed.push_back(tags::kFidManifest);

    for (const std::uint16_t id : manifestIds) {
        if (id == tags::kFidSodFixed || id == tags::kFidSodVariable) {
            continue; // a signed object does not cover itself
        }
        if (id == tags::kFidVariableData) {
            cov.variable.push_back(id);
            continue;
        }
        cov.fixed.push_back(id);
    }
    return cov;
}

} // namespace LibreSCRS::RsEId::Core
