// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <piv/piv_card.h>
#include <piv/piv_types.h>
#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>

#include <format>
#include <string>

namespace {

/// Convert a byte vector to a hex string (lowercase, no separators).
std::string toHex(const std::vector<uint8_t>& bytes)
{
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t b : bytes)
        result += std::format("{:02x}", b);
    return result;
}

/// Decode pinUsagePolicy bits into a human-readable string.
std::string decodePinPolicy(uint16_t policy)
{
    std::string result;
    // Bit 7 of first byte (0x80) = Application PIN required
    if (policy & 0x8000)
        result += "Application PIN";
    // Bit 6 of first byte (0x40) = Global PIN required
    if (policy & 0x4000) {
        if (!result.empty())
            result += ", ";
        result += "Global PIN";
    }
    // Bit 4 of first byte (0x10) = OCC (biometric on-card comparison)
    if (policy & 0x1000) {
        if (!result.empty())
            result += ", ";
        result += "OCC";
    }
    if (result.empty())
        result = "none";
    return result;
}

class PIVCardPlugin : public plugin::CardPlugin
{
public:
    std::string pluginId() const override
    {
        return "piv";
    }

    std::string displayName() const override
    {
        return "PIV (NIST SP 800-73)";
    }

    int probePriority() const override
    {
        return 700;
    }

    bool canHandle(const std::vector<uint8_t>& /*atr*/) const override
    {
        return false;
    }

    bool canHandleConnection(smartcard::PCSCConnection& conn) const override
    {
        try {
            piv::PIVCard card(conn);
            return card.probe();
        } catch (...) {
            return false;
        }
    }

    bool supportsPKI() const override
    {
        return true;
    }

    plugin::CardData readCard(smartcard::PCSCConnection& conn) const override
    {
        smartcard::CardTransaction tx(conn);
        piv::PIVCard card(conn);
        card.probe();
        auto pivData = card.readAll();

        plugin::CardData data;
        data.cardType = "piv";

        // CHUID group
        {
            plugin::CardFieldGroup group;
            group.groupKey = "chuid";
            group.groupLabel = "CHUID";
            plugin::addTextField(group, "guid", "GUID", toHex(pivData.chuid.guid));
            plugin::addTextField(group, "fascn", "FASC-N", toHex(pivData.chuid.fascn));
            plugin::addTextField(group, "expirationDate", "Expiration Date", pivData.chuid.expirationDate);
            data.groups.push_back(std::move(group));
        }

        // CCC group
        {
            plugin::CardFieldGroup group;
            group.groupKey = "ccc";
            group.groupLabel = "CCC";
            plugin::addTextField(group, "cardIdentifier", "Card Identifier", toHex(pivData.ccc.cardIdentifier));
            data.groups.push_back(std::move(group));
        }

        // Printed info group (optional)
        if (pivData.printedInfo) {
            const auto& pi = *pivData.printedInfo;
            plugin::CardFieldGroup group;
            group.groupKey = "printed";
            group.groupLabel = "Printed Information";
            plugin::addTextField(group, "name", "Name", pi.name);
            plugin::addTextField(group, "employeeAffiliation", "Employee Affiliation", pi.employeeAffiliation);
            plugin::addTextField(group, "org1", "Organization (Line 1)", pi.organizationAffiliation1);
            plugin::addTextField(group, "org2", "Organization (Line 2)", pi.organizationAffiliation2);
            plugin::addTextField(group, "expiry", "Expiration Date", pi.expirationDate);
            plugin::addTextField(group, "serialNumber", "Agency Serial Number", pi.agencyCardSerialNumber);
            plugin::addTextField(group, "issuerId", "Issuer Identification", pi.issuerIdentification);
            data.groups.push_back(std::move(group));
        }

        // Discovery group
        {
            plugin::CardFieldGroup group;
            group.groupKey = "discovery";
            group.groupLabel = "Discovery";
            plugin::addTextField(group, "pinPolicy", "PIN Policy", decodePinPolicy(pivData.discovery.pinUsagePolicy));
            data.groups.push_back(std::move(group));
        }

        // Key history group (optional)
        if (pivData.keyHistory) {
            const auto& kh = *pivData.keyHistory;
            plugin::CardFieldGroup group;
            group.groupKey = "keyHistory";
            group.groupLabel = "Key History";
            plugin::addTextField(group, "onCardCerts", "On-Card Certificates", std::to_string(kh.keysWithOnCardCerts));
            plugin::addTextField(group, "offCardCerts", "Off-Card Certificates",
                                 std::to_string(kh.keysWithOffCardCerts));
            plugin::addTextField(group, "offCardURL", "Off-Card URL", kh.offCardCertURL);
            data.groups.push_back(std::move(group));
        }

        // PKI group (if certificates present)
        if (!pivData.certificates.empty()) {
            plugin::CardFieldGroup group;
            group.groupKey = "pki";
            group.groupLabel = "PKI";
            plugin::addTextField(group, "certificateCount", "Certificate Count",
                                 std::to_string(pivData.certificates.size()));
            data.groups.push_back(std::move(group));
        }

        return data;
    }

    std::vector<plugin::CertificateData> readCertificates(smartcard::PCSCConnection& conn) const override
    {
        smartcard::CardTransaction tx(conn);
        piv::PIVCard card(conn);
        card.probe();
        auto certs = card.readCertificates();

        std::vector<plugin::CertificateData> result;
        result.reserve(certs.size());
        for (auto& cert : certs) {
            plugin::CertificateData cd;
            cd.label = cert.slotName;
            cd.derBytes = std::move(cert.certBytes);
            cd.keyFID = cert.keyReference;
            result.push_back(std::move(cd));
        }
        return result;
    }

    std::vector<plugin::PinStatusEntry> getPINList(smartcard::PCSCConnection& conn) const override
    {
        smartcard::CardTransaction tx(conn);
        piv::PIVCard card(conn);
        card.probe();
        auto pins = card.discoverPINs();

        std::vector<plugin::PinStatusEntry> result;
        for (const auto& pin : pins) {
            plugin::PinStatusEntry entry;
            entry.label = pin.label;
            entry.reference = pin.keyReference;
            entry.initialized = true;

            try {
                entry.triesLeft = card.getPINTriesLeft(pin.keyReference);
                entry.blocked = (entry.triesLeft == 0);
            } catch (...) {
                entry.triesLeft = -1;
            }

            entry.minLength = 6;
            entry.maxLength = 8;
            entry.canChange = false;
            result.push_back(std::move(entry));
        }
        return result;
    }

    plugin::PINResult verifyPIN(smartcard::PCSCConnection& conn, const std::string& pin) const override
    {
        smartcard::CardTransaction tx(conn);
        piv::PIVCard card(conn);
        card.probe();

        auto pins = card.discoverPINs();
        if (pins.empty())
            return {};

        return card.verifyPIN(pins.front().keyReference, pin);
    }

    int getPINTriesLeft(smartcard::PCSCConnection& conn) const override
    {
        smartcard::CardTransaction tx(conn);
        piv::PIVCard card(conn);
        card.probe();

        auto pins = card.discoverPINs();
        if (pins.empty())
            return -1;

        return card.getPINTriesLeft(pins.front().keyReference);
    }

    std::vector<std::pair<std::string, uint16_t>> discoverKeyReferences(smartcard::PCSCConnection& conn) const override
    {
        smartcard::CardTransaction tx(conn);
        piv::PIVCard card(conn);
        card.probe();
        return card.discoverKeys();
    }
};

} // namespace

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<PIVCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
