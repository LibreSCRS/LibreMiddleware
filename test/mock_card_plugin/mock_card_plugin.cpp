// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <plugin/card_plugin.h>

class MockCardPlugin : public plugin::CardPlugin
{
public:
    std::string pluginId() const override
    {
        return "mock";
    }
    std::string displayName() const override
    {
        return "Mock Card";
    }
    int probePriority() const override
    {
        return 500;
    }

    bool canHandle(const std::vector<uint8_t>& atr) const override
    {
        return atr.size() >= 2 && atr[0] == 0xDE && atr[1] == 0xAD;
    }

    plugin::CardData readCard(smartcard::PCSCConnection& /*conn*/) const override
    {
        plugin::CardData data;
        data.cardType = "mock";
        plugin::CardFieldGroup group;
        group.groupKey = "test";
        group.groupLabel = "Test Data";
        group.fields.push_back({"name", "Name", plugin::FieldType::Text, {'M', 'o', 'c', 'k'}});
        data.groups.push_back(std::move(group));
        return data;
    }
};

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<MockCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
