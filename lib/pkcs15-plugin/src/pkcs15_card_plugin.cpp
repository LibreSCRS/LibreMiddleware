// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <pkcs15/pkcs15_card.h>
#include <pkcs15/pkcs15_types.h>
#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>

#include <algorithm>
#include <string>

namespace {

class PKCS15CardPlugin : public plugin::CardPlugin
{
public:
    std::string pluginId() const override
    {
        return "pkcs15";
    }

    std::string displayName() const override
    {
        return "PKCS#15 (generic PKI)";
    }

    int probePriority() const override
    {
        return 850;
    }

    bool canHandle(const std::vector<uint8_t>& /*atr*/) const override
    {
        return false; // Never match by ATR alone
    }

    bool canHandleConnection(smartcard::PCSCConnection& conn) const override
    {
        try {
            pkcs15::PKCS15Card card(conn);
            return card.probe();
        } catch (...) {
            return false;
        }
    }

    plugin::CardData readCard(smartcard::PCSCConnection& conn) const override
    {
        pkcs15::PKCS15Card card(conn);
        auto profile = card.readProfile();

        plugin::CardData data;
        data.cardType = "pkcs15";

        // Token info group
        {
            plugin::CardFieldGroup group;
            group.groupKey = "token";
            group.groupLabel = "Token Info";
            plugin::addTextField(group, "label", "Label", profile.tokenInfo.label);
            plugin::addTextField(group, "serial_number", "Serial Number", profile.tokenInfo.serialNumber);
            plugin::addTextField(group, "manufacturer", "Manufacturer", profile.tokenInfo.manufacturer);
            data.groups.push_back(std::move(group));
        }

        // Certificates group
        if (!profile.certificates.empty()) {
            plugin::CardFieldGroup group;
            group.groupKey = "certificates";
            group.groupLabel = "Certificates";
            for (const auto& cert : profile.certificates) {
                plugin::addTextField(group, "cert_" + cert.label, cert.label, cert.label);
            }
            data.groups.push_back(std::move(group));
        }

        // PINs group
        if (!profile.pins.empty()) {
            plugin::CardFieldGroup group;
            group.groupKey = "pins";
            group.groupLabel = "PINs";
            for (const auto& pin : profile.pins) {
                int tries = card.getPINTriesLeft(pin);
                std::string triesStr = (tries >= 0) ? std::to_string(tries) : "unknown";
                plugin::addTextField(group, "pin_" + pin.label, pin.label, "tries left: " + triesStr);
            }
            data.groups.push_back(std::move(group));
        }

        return data;
    }

    bool supportsPKI() const override
    {
        return true;
    }

    std::vector<plugin::CertificateData> readCertificates(smartcard::PCSCConnection& conn) const override
    {
        pkcs15::PKCS15Card card(conn);
        auto profile = card.readProfile();

        std::vector<plugin::CertificateData> result;
        for (const auto& cert : profile.certificates) {
            auto der = card.readCertificate(cert);
            if (der.empty())
                continue;

            plugin::CertificateData cd;
            cd.label = cert.label;
            cd.derBytes = std::move(der);

            // Find matching private key by id
            for (const auto& key : profile.privateKeys) {
                if (key.id == cert.id) {
                    // keyFID = last 2 bytes of key path
                    if (key.path.size() >= 2) {
                        cd.keyFID =
                            static_cast<uint16_t>((key.path[key.path.size() - 2] << 8) | key.path[key.path.size() - 1]);
                    }
                    cd.keySizeBits = key.keySizeBits;
                    break;
                }
            }

            result.push_back(std::move(cd));
        }

        {
            std::lock_guard<std::mutex> lock(cacheMtx);
            cachedProfile = profile;
        }

        return result;
    }

    std::vector<plugin::PinStatusEntry> getPINList(smartcard::PCSCConnection& conn) const override
    {
        pkcs15::PKCS15Card card(conn);
        pkcs15::PKCS15Profile profile;
        {
            std::lock_guard<std::mutex> lock(cacheMtx);
            profile = cachedProfile;
        }
        if (profile.pins.empty())
            profile = card.readProfile();

        std::vector<plugin::PinStatusEntry> result;
        for (const auto& pin : profile.pins) {
            plugin::PinStatusEntry entry;
            entry.label = pin.label;
            entry.reference = pin.pinReference;
            entry.initialized = pin.initialized;

            if (pin.initialized) {
                try {
                    entry.triesLeft = card.getPINTriesLeft(pin);
                    entry.blocked = (entry.triesLeft == 0);
                } catch (...) {
                    entry.triesLeft = -1;
                }
            }

            result.push_back(std::move(entry));
        }
        return result;
    }

    plugin::PINResult changePIN(smartcard::PCSCConnection& conn, uint8_t pinReference, const std::string& oldPin,
                                const std::string& newPin) const override
    {
        pkcs15::PKCS15Card card(conn);
        pkcs15::PKCS15Profile profile;
        {
            std::lock_guard<std::mutex> lock(cacheMtx);
            profile = cachedProfile;
        }
        if (profile.pins.empty())
            profile = card.readProfile();

        for (const auto& pin : profile.pins) {
            if (pin.pinReference == pinReference) {
                auto r = card.changePIN(pin, oldPin, newPin);
                return {r.success, r.retriesLeft, r.blocked};
            }
        }
        return {};
    }

    plugin::PINResult changePIN(smartcard::PCSCConnection& conn, const std::string& oldPin,
                                const std::string& newPin) const override
    {
        pkcs15::PKCS15Card card(conn);
        pkcs15::PKCS15Profile profile;
        {
            std::lock_guard<std::mutex> lock(cacheMtx);
            profile = cachedProfile;
        }
        if (profile.pins.empty())
            profile = card.readProfile();
        auto* pinInfo = findUserPin(profile);
        if (!pinInfo)
            return {};

        auto r = card.changePIN(*pinInfo, oldPin, newPin);
        return {r.success, r.retriesLeft, r.blocked};
    }

    int getPINTriesLeft(smartcard::PCSCConnection& conn) const override
    {
        pkcs15::PKCS15Card card(conn);
        pkcs15::PKCS15Profile profile;
        {
            std::lock_guard<std::mutex> lock(cacheMtx);
            profile = cachedProfile;
        }
        if (profile.pins.empty())
            profile = card.readProfile();
        auto* pin = findUserPin(profile);
        if (!pin)
            return -1;

        return card.getPINTriesLeft(*pin);
    }

    plugin::PINResult verifyPIN(smartcard::PCSCConnection& conn, const std::string& pin) const override
    {
        pkcs15::PKCS15Card card(conn);
        pkcs15::PKCS15Profile profile;
        {
            std::lock_guard<std::mutex> lock(cacheMtx);
            profile = cachedProfile;
        }
        if (profile.pins.empty())
            profile = card.readProfile();
        auto* pinInfo = findUserPin(profile);
        if (!pinInfo)
            return {};

        auto r = card.verifyPIN(*pinInfo, pin);
        return {r.success, r.retriesLeft, r.blocked};
    }

private:
    mutable std::mutex cacheMtx;
    mutable pkcs15::PKCS15Profile cachedProfile;

    static const pkcs15::PinInfo* findUserPin(const pkcs15::PKCS15Profile& profile)
    {
        // Find first local + initialized PIN (User PIN)
        for (const auto& pin : profile.pins) {
            if (pin.local && pin.initialized)
                return &pin;
        }
        // Fallback: first initialized PIN
        for (const auto& pin : profile.pins) {
            if (pin.initialized)
                return &pin;
        }
        return nullptr;
    }
};

} // namespace

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<PKCS15CardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
