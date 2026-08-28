// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Regression test for the rs-eid plugin's verification-field emission: the
// three verification fields (card_verification, fixed_verification,
// variable_verification) must appear exactly once in the CardData returned
// by readCard(), in the "verification" group — never duplicated into "meta".
//
// Drives the real, dlopen'd rs-eid-plugin.so through CardPluginService,
// against a detached PCSCConnection scripted to answer as an Apollo-family
// card. Apollo card-type detection is ATR-only (no APDU), so only the ATR
// needs to be faked (via the test-only PCSCConnection::setDetachedAtr seam).
// Each of the four data files (document, personal, address, portrait) is
// read through the same Apollo protocol: SELECT by file id, then a 6-byte
// header READ BINARY, then (unless the header's empty-file marker short-
// circuits it) a body READ BINARY. The rig below answers each file with a
// single-tag TLV blob carrying that group's first field non-empty --
// CardFieldGroup::addText() throws if its very first call is both empty AND
// the group has no field yet, so an all-empty fixture cannot reach the
// verification block this test targets. The portrait file is left
// unregistered (empty-file marker), which readPortrait() tolerates directly.
// No TrustStore is injected, so verifyCard/verifyFixedData/verifyVariableData
// resolve to "unknown" without any further APDU.

#include <gtest/gtest.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/Unwrap.h>
#include <pcsc_connection.h>

#include "card_protocol.h"

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

// 3B B9 18 00 ... — Apollo 2008 ATR shape (matches protocol_test.cpp's
// EidProtocolATR.ApolloMatchesExpectedPrefix fixture). Apollo detection
// (eidcard::EIdCard::detectCardType) is ATR-only, no APDU involved.
std::vector<std::uint8_t> apolloAtr()
{
    return {0x3B, 0xB9, 0x18, 0x00, 0x81, 0x31};
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

// Plays the Apollo file-read protocol (card_reader_apollo.cpp) for whichever
// of the four rs-eid data files is currently SELECTed: SELECT by file id
// (INS=0xA4) always succeeds; a 6-byte header READ BINARY (INS=0xB0,
// offset=0, Le=6) reports either the Apollo empty-file marker (registered
// file has no content, or no file registered at all -- covers the portrait
// file this rig never registers) or the little-endian content length;
// any further READ BINARY serves the matching slice of the registered
// content.
class ApolloFileRig
{
public:
    void addFile(std::uint8_t fileId1, std::uint8_t fileId2, std::vector<std::uint8_t> content)
    {
        files[key(fileId1, fileId2)] = std::move(content);
    }

    APDUResponse operator()(const APDUCommand& cmd)
    {
        APDUResponse r;
        if (cmd.ins == 0xA4) { // SELECT by file id
            if (cmd.data.size() == 2)
                current = key(cmd.data[0], cmd.data[1]);
            r.sw1 = 0x90;
            r.sw2 = 0x00;
            return r;
        }
        if (cmd.ins == 0xB0) { // READ BINARY
            auto it = files.find(current);
            const std::vector<std::uint8_t>* content = (it != files.end()) ? &it->second : nullptr;
            const bool headerProbe = (cmd.p1 == 0x00 && cmd.p2 == 0x00 && cmd.hasLe && cmd.le == 6);
            r.sw1 = 0x90;
            r.sw2 = 0x00;
            if (headerProbe) {
                if (!content || content->empty()) {
                    r.data = {0x00, 0x00, 0x00, 0x00, 0xFF, 0x00}; // empty-file marker
                } else {
                    const auto len = static_cast<std::uint16_t>(content->size());
                    r.data = {0x00,
                              0x00,
                              0x00,
                              0x00,
                              static_cast<std::uint8_t>(len & 0xFF),
                              static_cast<std::uint8_t>((len >> 8) & 0xFF)};
                }
                return r;
            }
            // Body read: dataOffset is always headerSize (6) on this protocol.
            const auto fileOffset = static_cast<std::uint16_t>((cmd.p1 & 0x7F) << 8 | cmd.p2);
            const std::uint16_t bodyOffset = fileOffset >= 6 ? static_cast<std::uint16_t>(fileOffset - 6) : 0;
            if (content && bodyOffset < content->size()) {
                const std::size_t n = std::min<std::size_t>(cmd.le, content->size() - bodyOffset);
                r.data.assign(content->begin() + bodyOffset, content->begin() + bodyOffset + static_cast<long>(n));
            }
            return r;
        }
        // No other instruction is expected: no TrustStore is injected, so
        // verifyCard/verifyFixedData/verifyVariableData stay APDU-free.
        r.sw1 = 0x6A;
        r.sw2 = 0x82;
        return r;
    }

private:
    static int key(std::uint8_t a, std::uint8_t b)
    {
        return (static_cast<int>(a) << 8) | b;
    }

    std::map<int, std::vector<std::uint8_t>> files;
    int current = -1;
};

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

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Scripted Apollo Reader");
    ASSERT_NE(session, nullptr);

    auto& conn = LibreSCRS::SmartCard::detail::unwrap(*session);
    conn.setDetachedAtr(apolloAtr());

    using namespace eidcard::protocol;
    ApolloFileRig rig;
    // Each file carries exactly the group builder's first field, non-empty --
    // enough to satisfy CardFieldGroup::addText()'s empty-value guard; every
    // later field in that group is empty and no-ops safely once the group is
    // non-empty. The portrait file is left unregistered (empty-file marker).
    rig.addFile(FILE_PERSONAL_DATA_H, FILE_PERSONAL_DATA_L, encodeSingleFieldTlv(TAG_PERSONAL_NUMBER, "0101990710000"));
    rig.addFile(FILE_VARIABLE_DATA_H, FILE_VARIABLE_DATA_L, encodeSingleFieldTlv(TAG_STATE, "Serbia"));
    rig.addFile(FILE_DOCUMENT_DATA_H, FILE_DOCUMENT_DATA_L, encodeSingleFieldTlv(TAG_DOC_REG_NO, "000000000"));
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
    auto metaIdx = data.findGroup("meta");
    ASSERT_TRUE(metaIdx.has_value());
    EXPECT_EQ(data.groupAt(*metaIdx).fields.size(), 1u)
        << "meta group must not carry verification fields alongside card_type";
}
