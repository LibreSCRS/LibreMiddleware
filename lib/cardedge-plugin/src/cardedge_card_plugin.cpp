// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <cardedge/cardedge.h>
#include <cardedge/pki_applet_guard.h>
#include <plugin/card_plugin.h>
#include <smartcard/apdu.h>
#include <smartcard/pcsc_connection.h>

namespace {

// PKCS#15 AID — same as cardedge::protocol::AID_PKCS15 (inlined to avoid private header dependency)
const std::vector<uint8_t> AID_PKCS15 = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};

class CardEdgePlugin : public plugin::CardPlugin
{
public:
    std::string pluginId() const override
    {
        return "cardedge";
    }

    std::string displayName() const override
    {
        return "CardEdge (Serbian PKI)";
    }

    int probePriority() const override
    {
        return 840;
    }

    bool canHandle(const std::vector<uint8_t>& /*atr*/) const override
    {
        return false;
    }

    bool canHandleConnection(smartcard::PCSCConnection& conn) const override
    {
        // Phase 1: SELECT PKCS#15 AID
        auto resp = conn.transmit(smartcard::selectByAID(AID_PKCS15));
        if (!resp.isSuccess())
            return false;

        // Phase 2: SELECT root dir 0x7000 (CardEdge-specific, not present on standard PKCS#15)
        resp = conn.transmit(smartcard::selectByFileId(0x70, 0x00));
        return resp.isSuccess();
    }

    plugin::CardData readCard(smartcard::PCSCConnection& /*conn*/) const override
    {
        plugin::CardData data;
        data.cardType = "cardedge";

        plugin::CardFieldGroup meta;
        meta.groupKey = "meta";
        meta.groupLabel = "Card Metadata";
        std::string name = "CardEdge (Serbian PKI)";
        meta.fields.push_back({"card_type", "Card Type", plugin::FieldType::Text, {name.begin(), name.end()}});
        data.groups.push_back(std::move(meta));

        return data;
    }

    bool supportsPKI() const override
    {
        return true;
    }

    std::vector<plugin::CertificateData> readCertificates(smartcard::PCSCConnection& conn) const override
    {
        cardedge::PkiAppletGuard guard(conn);
        auto certs = cardedge::readCertificates(conn);

        std::vector<plugin::CertificateData> result;
        for (const auto& cert : certs) {
            result.push_back({cert.label, cert.derBytes, cert.keyFID, cert.keySizeBits});
        }
        return result;
    }

    plugin::PINResult verifyPIN(smartcard::PCSCConnection& conn, const std::string& pin) const override
    {
        cardedge::PkiAppletGuard guard(conn);
        auto r = cardedge::verifyPIN(conn, pin);
        return {r.success, r.retriesLeft, r.blocked};
    }

    plugin::PINResult changePIN(smartcard::PCSCConnection& conn, const std::string& oldPin,
                                const std::string& newPin) const override
    {
        cardedge::PkiAppletGuard guard(conn);
        auto r = cardedge::changePIN(conn, oldPin, newPin);
        return {r.success, r.retriesLeft, r.blocked};
    }

    int getPINTriesLeft(smartcard::PCSCConnection& conn) const override
    {
        cardedge::PkiAppletGuard guard(conn);
        return cardedge::getPINTriesLeft(conn).retriesLeft;
    }

    plugin::SignResult sign(smartcard::PCSCConnection& conn, uint16_t keyReference, std::span<const uint8_t> data,
                            plugin::SignMechanism /*mechanism*/) const override
    {
        cardedge::PkiAppletGuard guard(conn);
        auto sig = cardedge::signData(conn, keyReference, {data.begin(), data.end()});
        return {!sig.empty(), std::move(sig)};
    }

    std::vector<std::pair<std::string, uint16_t>> discoverKeyReferences(smartcard::PCSCConnection& conn) const override
    {
        cardedge::PkiAppletGuard guard(conn);
        return cardedge::discoverKeyReferences(conn);
    }
};

} // namespace

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<CardEdgePlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
