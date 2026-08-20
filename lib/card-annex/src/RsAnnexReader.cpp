// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "RsAnnexReader.h"

#include <LibreSCRS/Plugin/SecurityCheck.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include <apdu.h>
#include <smartcard/i_connection.h>
#include <rs_container.h>
#include <rs_digest_binding.h>
#include <rs_signed_object.h>
#include <rs_tags.h>
#include <smartcard/chunked_read.h>
#include <tlv.h>

#include <algorithm>
#include <map>

namespace LibreSCRS::Annex {
namespace {

namespace Core = LibreSCRS::RsEId::Core;
namespace SC = LibreSCRS::SmartCard::Internal;

// The applet identifier this issuer advertises today. Matching is only an
// invitation -- the manifest confirms -- because the identifier has moved once
// already (the previous generation was two bytes shorter).
constexpr std::array<std::uint8_t, 13> kAnnexAid{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45,
                                                 0x52, 0x4F, 0x44, 0x49, 0x44, 0x01};
constexpr std::uint8_t kMasterFileHi = 0x3F;
constexpr std::uint8_t kMasterFileLo = 0x00;

[[nodiscard]] SC::APDUResponse dispatch(const AnnexContext& ctx, const SC::APDUCommand& cmd)
{
    if (ctx.channel != nullptr && ctx.channel->state() == LibreSCRS::SecureChannel::ChannelState::Open) {
        return ctx.channel->transmit(cmd, ctx.token);
    }
    return ctx.conn->transmit(cmd);
}

/// SELECT the file at @p dfPath + @p fid, then read its container whole.
/// Returns empty on any refusal: the caller turns that into "no annex".
[[nodiscard]] std::vector<std::uint8_t> readAnnexFile(const AnnexContext& ctx, std::span<const std::uint8_t> dfPath,
                                                      std::uint16_t fid)
{
    std::vector<std::uint8_t> path(dfPath.begin(), dfPath.end());
    path.push_back(static_cast<std::uint8_t>(fid >> 8));
    path.push_back(static_cast<std::uint8_t>(fid & 0xFF));

    SC::APDUCommand select{.cla = 0x00, .ins = 0xA4, .p1 = 0x08, .p2 = 0x0C, .data = path, .le = 0, .hasLe = false};
    const auto sel = dispatch(ctx, select);
    if (sel.sw1 != 0x90 && sel.sw1 != 0x61) {
        return {};
    }

    // The shared reader fetches the header straight off the connection while
    // routing the body through readChunk, which would split the two across a
    // secure channel. Supplying the header keeps both on one path.
    const auto head = dispatch(ctx, SC::readBinary(0, Core::kContainerHeaderSize));
    if (!head.isSuccess() || head.data.size() < Core::kContainerHeaderSize) {
        return {};
    }

    SC::ChunkedReadOptions opts;
    opts.headerSpec.maxContentLength = 64 * 1024;
    opts.includeHeaderInResult = true; // the digest covers tag and length too
    opts.errorPrefix = "annex";
    opts.headerOverride = head.data;
    opts.readChunk = [&ctx](std::uint16_t offset, std::uint8_t length) {
        return dispatch(ctx, SC::readBinary(offset, length));
    };
    return SC::readChunkedFile(*ctx.conn, opts);
}

/// Digest input for one covered file: the container exactly as signed.
[[nodiscard]] Core::BlockCandidates blockOf(const std::vector<std::uint8_t>& file)
{
    return Core::BlockCandidates{file};
}

/// CMS bytes inside a signed object: container body, then the inner wrapper.
[[nodiscard]] std::vector<std::uint8_t> cmsOf(const std::vector<std::uint8_t>& sodFile)
{
    const auto container = Core::leadingTlv(sodFile);
    if (!container || container->size() <= Core::kContainerHeaderSize) {
        return {};
    }
    const auto body = container->subspan(Core::kContainerHeaderSize);
    const auto cms = Core::innerTlvPayload(body);
    return {cms.begin(), cms.end()};
}

struct FieldSpec
{
    std::uint16_t tag;
    const char* key;
    const char* label;
};

// Only tags whose meaning is confirmed. Six more appear on the card carrying
// filler values; naming a personal field wrongly is worse than not showing it.
constexpr std::array kKnownFields{
    FieldSpec{Core::tags::kDocumentSerialNo, "document_serial", "Document Number"},
    FieldSpec{Core::tags::kParentGivenName, "parent_given_name", "Parent Given Name"},
    FieldSpec{Core::tags::kCommunityOfBirth, "community_of_birth", "Community of Birth"},
    FieldSpec{Core::tags::kStateOfBirth, "state_of_birth", "State of Birth"},
    FieldSpec{Core::tags::kState, "state", "State"},
    FieldSpec{Core::tags::kCommunity, "community", "Community"},
    FieldSpec{Core::tags::kPlace, "place", "Place"},
    FieldSpec{Core::tags::kStreet, "street", "Street"},
    FieldSpec{Core::tags::kHouseNumber, "house_number", "House Number"},
    FieldSpec{Core::tags::kHouseLetter, "house_letter", "House Letter"},
    FieldSpec{Core::tags::kEntrance, "entrance", "Entrance"},
    FieldSpec{Core::tags::kFloor, "floor", "Floor"},
    FieldSpec{Core::tags::kApartmentNumber, "apartment_number", "Apartment"},
    FieldSpec{Core::tags::kAddressDate, "address_date", "Address Date"},
    FieldSpec{Core::tags::kAddressLabel, "address_label", "Address Label"},
};

void appendFields(LibreSCRS::Plugin::CardFieldGroup& g, const std::vector<std::uint8_t>& file)
{
    const auto container = Core::leadingTlv(file);
    if (!container || container->size() <= Core::kContainerHeaderSize) {
        return;
    }
    const auto body = container->subspan(Core::kContainerHeaderSize);
    const auto fields = SC::parseTLV(body.data(), body.size());

    for (const auto& spec : kKnownFields) {
        const auto value = SC::findString(fields, spec.tag);
        if (!value.empty()) {
            g.addText(spec.key, spec.label, value);
        }
    }
}

} // namespace

std::vector<std::uint8_t> annexDfPath(const EfDirEntry& entry)
{
    std::vector<std::uint8_t> path = entry.path;
    if (path.size() > 2 && path[0] == kMasterFileHi && path[1] == kMasterFileLo) {
        path.erase(path.begin(), path.begin() + 2);
    }
    return path;
}

bool RsAnnexReader::handles(const EfDirEntry& entry) const
{
    if (entry.aid.size() == kAnnexAid.size() && std::equal(entry.aid.begin(), entry.aid.end(), kAnnexAid.begin())) {
        return true;
    }
    // The identifier may move; the path is the other half of the invitation.
    const auto path = annexDfPath(entry);
    return path.size() == 2 && path[0] == static_cast<std::uint8_t>(Core::tags::kFidAnnexDf >> 8) &&
           path[1] == static_cast<std::uint8_t>(Core::tags::kFidAnnexDf & 0xFF);
}

std::vector<LibreSCRS::Plugin::CardFieldGroup> RsAnnexReader::read(const EfDirEntry& entry,
                                                                   const AnnexContext& ctx) const
{
    if (ctx.conn == nullptr) {
        return {};
    }
    const auto dfPath = annexDfPath(entry);

    const auto manifestFile = readAnnexFile(ctx, dfPath, Core::tags::kFidManifest);
    if (Core::outerTag(manifestFile) != Core::tags::kFidManifest) {
        return {}; // not this format after all -- withdraw rather than guess
    }

    const auto coverage = Core::annexCoverage(Core::parseManifest(manifestFile));

    std::map<std::uint16_t, std::vector<std::uint8_t>> files;
    for (const auto fid : coverage.fixed) {
        auto file = (fid == Core::tags::kFidManifest) ? manifestFile : readAnnexFile(ctx, dfPath, fid);
        if (Core::outerTag(file) != fid) {
            return {}; // a container read from the wrong place is not usable
        }
        files.emplace(fid, std::move(file));
    }
    for (const auto fid : coverage.variable) {
        auto file = readAnnexFile(ctx, dfPath, fid);
        if (Core::outerTag(file) != fid) {
            return {};
        }
        files.emplace(fid, std::move(file));
    }

    const Core::TrustStore trust; // anchors are a later concern; binding is not
    bool bound = true;

    const auto verify = [&](std::uint16_t sodFid, const std::vector<std::uint16_t>& covered) {
        if (covered.empty()) {
            return true;
        }
        const auto cms = cmsOf(readAnnexFile(ctx, dfPath, sodFid));
        if (cms.empty()) {
            return false;
        }
        std::vector<Core::BlockCandidates> blocks;
        blocks.reserve(covered.size());
        for (const auto fid : covered) {
            blocks.push_back(blockOf(files.at(fid)));
        }
        const auto report = Core::verifySignedObject(cms, blocks, Core::DigestBinding::Positional, trust);
        // The primitive tolerates a short block list; this caller must not, or
        // files the object covered would go unexamined.
        return report.digestsBound && report.slotCount == blocks.size();
    };

    bound = verify(Core::tags::kFidSodFixed, coverage.fixed) && verify(Core::tags::kFidSodVariable, coverage.variable);
    if (!bound) {
        // Nothing is shown rather than shown-and-flagged. These are personal
        // details that could not be attributed to the issuer, and a reader who
        // sees them has already read them whatever a badge next to them says.
        return {};
    }

    LibreSCRS::Plugin::CardFieldGroup personal;
    personal.groupKey = annexGroupKey(annexId(), "personal");
    personal.groupLabel = "Additional Data";
    for (const auto& [fid, file] : files) {
        if (fid != Core::tags::kFidManifest) {
            appendFields(personal, file);
        }
    }
    if (personal.fields.empty()) {
        return {};
    }

    LibreSCRS::Plugin::CardFieldGroup security;
    security.groupKey = annexGroupKey(annexId(), "security");
    security.groupLabel = "Additional Data Verification";
    // Say what was checked and what was not. The digests bind and the object's
    // signature verifies, but no anchor was offered, so the signer is unproven --
    // reporting integrity alone would read as more than it is.
    security.addText("annex_integrity", "Data Integrity",
                     std::string{LibreSCRS::Plugin::statusToString(LibreSCRS::Plugin::SecurityCheck::Status::Passed)});
    security.addText(
        "annex_authenticity", "Data Authenticity",
        std::string{LibreSCRS::Plugin::statusToString(LibreSCRS::Plugin::SecurityCheck::Status::NotPerformed)});

    return {std::move(personal), std::move(security)};
}

} // namespace LibreSCRS::Annex
