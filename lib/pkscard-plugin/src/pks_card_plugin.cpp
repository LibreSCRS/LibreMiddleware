// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <pkscard/pkscard.h>
#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>

namespace {

class PksCardPlugin : public plugin::CardPlugin
{
public:
    std::string pluginId() const override
    {
        return "rs-pks";
    }
    std::string displayName() const override
    {
        return "Serbian PKS Qualified Signature";
    }
    int probePriority() const override
    {
        return 200;
    }

    bool canHandle(const std::vector<uint8_t>& atr) const override
    {
        // PKS ATR: 3B DE 97 ...
        return atr.size() >= 3 && atr[0] == 0x3B && atr[1] == 0xDE && atr[2] == 0x97;
    }

    bool canHandleConnection(smartcard::PCSCConnection& conn) const override
    {
        return pkscard::PKSCard::probe(conn);
    }

    plugin::CardData readCard(smartcard::PCSCConnection& conn) const override
    {
        plugin::CardData data;
        data.cardType = "rs-pks";

        plugin::CardFieldGroup meta;
        meta.groupKey = "meta";
        meta.groupLabel = "Card Metadata";
        meta.fields.push_back({"card_type", "Card Type", plugin::FieldType::Text, {'P', 'K', 'S'}});
        data.groups.push_back(std::move(meta));
        return data;
    }
};

} // namespace

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<PksCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
