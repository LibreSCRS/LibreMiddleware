// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginExport.h>

#include <array>

namespace {
// A1 (4.0 hardening): the mock matches a 4-byte test ATR `0xDE 0xAD .. ..`
// with the trailing two bytes wildcarded. The previous canHandle was a
// 2-byte-prefix match over arbitrary length; the integration test exercises
// the 4-byte form (`{0xDE, 0xAD, 0xBE, 0xEF}`).
inline const std::array<LibreSCRS::Plugin::Atr, 1> kMockAtrs{
    LibreSCRS::Plugin::Atr{{0xDE, 0xAD, 0x00, 0x00}, std::vector<std::uint8_t>{0xFF, 0xFF, 0x00, 0x00}},
};
} // namespace

class MockCardPlugin : public LibreSCRS::Plugin::CardPlugin
{
public:
    MockCardPlugin()
    {
        setIdentity("mock", "Mock Card", /*priority=*/500);
    }

    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::IdentityData;
    }

    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return kMockAtrs;
    }

    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        LibreSCRS::Plugin::CardData data;
        data.cardType = "mock";
        LibreSCRS::Plugin::CardFieldGroup group;
        group.groupKey = "test";
        group.groupLabel = "Test Data";
        group.fields.push_back({"name", "Name", LibreSCRS::Plugin::FieldType::Text, {'M', 'o', 'c', 'k'}});
        data.groups.push_back(std::move(group));
        return LibreSCRS::Plugin::ReadResult::ok(std::move(data));
    }

    LibreSCRS::Auth::PreReadAuthMethod preReadAuth(LibreSCRS::SmartCard::CardSession&) const override
    {
        return LibreSCRS::Auth::PreReadAuthMethod::None;
    }
};

LIBRESCRS_DECLARE_CARD_PLUGIN(MockCardPlugin, LibreSCRS::Plugin::kCardPluginAbiVersion)
