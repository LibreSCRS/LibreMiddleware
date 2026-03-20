// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <pkscard/pkscard.h>
#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>

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
        pkscard::PKSCard card(conn);
        auto certs = card.readCertificates();

        plugin::CardData data;
        data.cardType = "rs-pks";

        plugin::CardFieldGroup pkiGroup;
        pkiGroup.groupKey = "pki";
        pkiGroup.groupLabel = "PKI";

        std::string certCount = std::to_string(certs.size());
        pkiGroup.fields.push_back(
            {"certificate_count", "Certificates", plugin::FieldType::Text, {certCount.begin(), certCount.end()}});

        for (const auto& cert : certs) {
            pkiGroup.fields.push_back(
                {"cert_label", cert.label, plugin::FieldType::Text, {cert.label.begin(), cert.label.end()}});
        }

        data.groups.push_back(std::move(pkiGroup));
        return data;
    }

    bool supportsPKI() const override
    {
        return true;
    }

    std::vector<plugin::CertificateData> readCertificates(smartcard::PCSCConnection& conn) const override
    {
        pkscard::PKSCard card(conn);
        auto certs = card.readCertificates();

        std::vector<plugin::CertificateData> result;
        for (const auto& cert : certs) {
            result.push_back({cert.label, cert.derBytes, cert.keyFID, cert.keySizeBits});
        }
        return result;
    }

    plugin::PINResult verifyPIN(smartcard::PCSCConnection& conn, const std::string& pin) const override
    {
        pkscard::PKSCard card(conn);
        auto r = card.verifyPIN(pin);
        return {r.success, r.retriesLeft, r.blocked};
    }

    plugin::PINResult changePIN(smartcard::PCSCConnection& conn, const std::string& oldPin,
                                const std::string& newPin) const override
    {
        pkscard::PKSCard card(conn);
        auto r = card.changePIN(oldPin, newPin);
        return {r.success, r.retriesLeft, r.blocked};
    }

    int getPINTriesLeft(smartcard::PCSCConnection& conn) const override
    {
        pkscard::PKSCard card(conn);
        return card.getPINTriesLeft().retriesLeft;
    }

    plugin::SignResult sign(smartcard::PCSCConnection& conn, uint16_t keyReference, std::span<const uint8_t> data,
                            plugin::SignMechanism /*mechanism*/) const override
    {
        pkscard::PKSCard card(conn);
        auto sig = card.signData(keyReference, {data.begin(), data.end()});
        return {!sig.empty(), std::move(sig)};
    }

    std::vector<std::pair<std::string, uint16_t>> discoverKeyReferences(smartcard::PCSCConnection& conn) const override
    {
        pkscard::PKSCard card(conn);
        return card.discoverKeyReferences();
    }
};

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<PksCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
