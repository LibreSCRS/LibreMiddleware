// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Regression test for the rs-eid plugin's verification-field emission: the
// three verification fields (card_verification, fixed_verification,
// variable_verification) must appear exactly once in the CardData returned
// by readCard(), in the "verification" group -- never duplicated into "meta".
//
// Drives the real, dlopen'd rs-eid-plugin.so through CardPluginService,
// against a detached PCSCConnection scripted as a SERID card by
// CardEdgeFileRig. Each of the data files (document, personal, address) is a
// single-tag TLV blob carrying that group's first field non-empty --
// CardFieldGroup::addText() throws if its very first call is both empty AND
// the group has no field yet, so an all-empty fixture cannot reach the
// verification block this test targets. The portrait is a minimal synthetic
// JPEG stub: a missing file would send the Gemalto reader down its reconnect
// retry, which a detached connection cannot do. No TrustStore is
// injected, so verifyCard/verifyFixedData/verifyVariableData resolve to
// "unknown" without any further APDU.

#include <gtest/gtest.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <session_access.h>
#include <pcsc_connection.h>

#include "card_protocol.h"
#include "cardedge_file_rig.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;

namespace {

std::filesystem::path pluginDir()
{
    return std::filesystem::path(PLUGIN_DIR);
}

std::shared_ptr<LibreSCRS::Plugin::CardPlugin> findRsEid(LibreSCRS::Plugin::CardPluginService& registry)
{
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "rs-eid")
            return p;
    }
    return nullptr;
}

// Gemalto-family ATR (3B FF 94 ...), the shape the SERID chip presents.
std::vector<std::uint8_t> serIdAtr()
{
    return {0x3B, 0xFF, 0x94, 0x00, 0x00, 0x81, 0x31, 0x80, 0x43};
}

// Little-endian 16-bit tag + little-endian 16-bit length + value, matching
// the custom TLV format lib/smartcard/src/tlv.cpp parses.
std::vector<std::uint8_t> encodeSingleFieldTlv(std::uint16_t tag, std::string_view value)
{
    std::vector<std::uint8_t> out;
    out.push_back(static_cast<std::uint8_t>(tag & 0xFF));
    out.push_back(static_cast<std::uint8_t>((tag >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value.size() & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value.size() >> 8) & 0xFF));
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

// A CardEdge file as stored: 4-byte header (two arbitrary bytes, LE u16
// content length) followed by the content.
std::vector<std::uint8_t> withHeader(const std::vector<std::uint8_t>& content)
{
    std::vector<std::uint8_t> out{0x00, 0x00, static_cast<std::uint8_t>(content.size() & 0xFF),
                                  static_cast<std::uint8_t>((content.size() >> 8) & 0xFF)};
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

std::uint16_t fid(std::uint8_t hi, std::uint8_t lo)
{
    return static_cast<std::uint16_t>((hi << 8) | lo);
}

// Counts every occurrence of @p key across all groups in @p data, returning
// the (possibly repeated) groupKey each occurrence was found in.
std::vector<std::string> findAllOccurrences(const LibreSCRS::Plugin::CardData& data, const std::string& key)
{
    std::vector<std::string> foundIn;
    for (const auto& group : data.groups) {
        for (const auto& field : group.fields) {
            if (field.key == key)
                foundIn.push_back(group.groupKey);
        }
    }
    return foundIn;
}

} // namespace

TEST(RsEidPluginVerificationTest, VerificationFieldsAppearExactlyOnceInVerificationGroup)
{
    LibreSCRS::Plugin::CardPluginService registry{pluginDir()};
    auto plugin = findRsEid(registry);
    ASSERT_NE(plugin, nullptr) << "rs-eid-plugin.so did not load from " << pluginDir();

    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("Scripted SERID Reader");
    ASSERT_NE(session, nullptr);

    auto& conn = LibreSCRS::SmartCard::Internal::connectionOf(*session);
    // The plugin reads the ATR the session recorded when it opened.
    LibreSCRS::SmartCard::Testing::SessionAccess::setAtr(*session, serIdAtr());

    using namespace eidcard::protocol;
    LibreSCRS::RsEId::Test::CardEdgeFileRig rig;
    rig.acceptAid(AID_SERID);
    // Each file carries exactly the group builder's first field, non-empty --
    // enough to satisfy CardFieldGroup::addText()'s empty-value guard; every
    // later field in that group is empty and no-ops safely once the group is
    // non-empty.
    rig.addFile(fid(FILE_PERSONAL_DATA_H, FILE_PERSONAL_DATA_L),
                withHeader(encodeSingleFieldTlv(TAG_PERSONAL_NUMBER, "0101990710000")));
    rig.addFile(fid(FILE_VARIABLE_DATA_H, FILE_VARIABLE_DATA_L), withHeader(encodeSingleFieldTlv(TAG_STATE, "Serbia")));
    rig.addFile(fid(FILE_DOCUMENT_DATA_H, FILE_DOCUMENT_DATA_L),
                withHeader(encodeSingleFieldTlv(TAG_DOC_REG_NO, "000000000")));
    // Portrait: 4-byte TLV header the reader trims, then a JPEG stub.
    rig.addFile(fid(FILE_PORTRAIT_H, FILE_PORTRAIT_L), withHeader({0x00, 0x00, 0x02, 0x00, 0xFF, 0xD8}));
    conn.setTransmitFilter([&rig](const APDUCommand& cmd) { return rig(cmd); });

    auto rr = plugin->readCard(*session);
    ASSERT_EQ(rr.status, LibreSCRS::Plugin::ReadResult::Status::Ok) << rr.diagnosticDetail.value_or("<no diag>");
    ASSERT_TRUE(rr.data.has_value());
    const auto& data = *rr.data;

    for (const std::string key : {"card_verification", "fixed_verification", "variable_verification"}) {
        auto foundIn = findAllOccurrences(data, key);
        EXPECT_EQ(foundIn.size(), 1u) << key << " appeared " << foundIn.size() << " time(s) in the returned CardData";
        if (foundIn.size() == 1) {
            EXPECT_EQ(foundIn.front(), "verification")
                << key << " must live in the 'verification' group, found in '" << foundIn.front() << "' instead";
        }
    }

    // The historical bug appended the same three fields into "meta" (already
    // emitted earlier in the read) on top of the dedicated "verification"
    // group. Confirm "meta" carries only its own card_type field.
    const auto meta = std::ranges::find(data.groups, "meta", &LibreSCRS::Plugin::CardFieldGroup::groupKey);
    ASSERT_NE(meta, data.groups.end());
    EXPECT_EQ(meta->fields.size(), 1u) << "meta group must not carry verification fields alongside card_type";
}
