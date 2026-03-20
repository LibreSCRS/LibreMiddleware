// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <plugin/card_plugin.h>
#include <smartcard/pcsc_connection.h>

#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

#include <openssl/x509.h>

namespace {

std::string extractSubjectCN(const uint8_t* der, size_t len)
{
    const uint8_t* p = der;
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(len));
    if (!cert)
        return "(unreadable)";

    X509_NAME* subject = X509_get_subject_name(cert);
    char buf[256] = {};
    X509_NAME_get_text_by_NID(subject, NID_commonName, buf, sizeof(buf));

    std::string cn(buf);
    X509_free(cert);
    return cn.empty() ? "(no CN)" : cn;
}

class OpenSCCardPlugin : public plugin::CardPlugin
{
public:
    ~OpenSCCardPlugin() override
    {
        teardown();
    }

    std::string pluginId() const override
    {
        return "opensc";
    }
    std::string displayName() const override
    {
        return "OpenSC (generic)";
    }
    int probePriority() const override
    {
        return 900;
    }

    bool canHandle(const std::vector<uint8_t>& /*atr*/) const override
    {
        return false;
    }

    bool canHandleConnection(smartcard::PCSCConnection& conn) const override
    {
        teardown(); // Clean up any previous session (re-entrancy safety)

        readerName = conn.readerName();

        int rc = sc_establish_context(&ctx, "librescrs");
        if (rc < 0)
            return false;

        sc_reader_t* reader = sc_ctx_get_reader_by_name(ctx, readerName.c_str());
        if (!reader) {
            teardown();
            return false;
        }

        rc = sc_connect_card(reader, &card);
        if (rc < 0) {
            teardown();
            return false;
        }

        rc = sc_pkcs15_bind(card, nullptr, &p15card);
        if (rc < 0) {
            teardown();
            return false;
        }

        // Check for PKI objects to set supportsPKI flag
        sc_pkcs15_object_t* pinObjs[8];
        int pinCount = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, pinObjs, 8);

        sc_pkcs15_object_t* keyObjs[8];
        int keyCount = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY_RSA, keyObjs, 8);

        hasPKI = (pinCount > 0 || keyCount > 0);

        return true;
    }

    plugin::CardData readCard(smartcard::PCSCConnection& /*conn*/) const override
    {
        plugin::CardData data;
        data.cardType = "opensc";

        if (!p15card)
            return data;

        // Token info group
        plugin::CardFieldGroup tokenGroup;
        tokenGroup.groupKey = "token";
        tokenGroup.groupLabel = "Token Info";

        auto* ti = p15card->tokeninfo;
        if (ti) {
            auto addField = [&](const std::string& key, const std::string& label, const char* val) {
                if (val && val[0] != '\0') {
                    std::string s(val);
                    tokenGroup.fields.push_back({key, label, plugin::FieldType::Text, {s.begin(), s.end()}});
                }
            };
            addField("label", "Label", ti->label);
            addField("manufacturer", "Manufacturer", ti->manufacturer_id);
            addField("serial", "Serial Number", ti->serial_number);

            // Decode flags to human-readable string
            std::string flagStr;
            if (ti->flags & SC_PKCS15_TOKEN_PRN_GENERATION)
                flagStr += "PRN ";
            if (ti->flags & SC_PKCS15_TOKEN_LOGIN_REQUIRED)
                flagStr += "Login required ";
            if (!flagStr.empty()) {
                flagStr.pop_back(); // remove trailing space
                tokenGroup.fields.push_back(
                    {"flags", "Flags", plugin::FieldType::Text, {flagStr.begin(), flagStr.end()}});
            }
        }
        data.groups.push_back(std::move(tokenGroup));

        // Certificates summary group
        sc_pkcs15_object_t* certObjs[16];
        int certCount = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, certObjs, 16);

        if (certCount > 0) {
            plugin::CardFieldGroup certGroup;
            certGroup.groupKey = "certificates";
            certGroup.groupLabel = "Certificates";

            for (int i = 0; i < certCount; ++i) {
                auto* certInfo = static_cast<sc_pkcs15_cert_info_t*>(certObjs[i]->data);
                sc_pkcs15_cert_t* cert = nullptr;
                int rc = sc_pkcs15_read_certificate(p15card, certInfo, 0, &cert);

                std::string cn = "(unreadable)";
                if (rc == 0 && cert) {
                    cn = extractSubjectCN(cert->data.value, cert->data.len);
                    sc_pkcs15_free_certificate(cert);
                }

                std::string key = "cert_" + std::to_string(i);
                std::string label = certObjs[i]->label[0] ? certObjs[i]->label : ("Certificate " + std::to_string(i));
                certGroup.fields.push_back({key, label, plugin::FieldType::Text, {cn.begin(), cn.end()}});
            }
            data.groups.push_back(std::move(certGroup));
        }

        return data;
    }

    bool supportsPKI() const override
    {
        return hasPKI;
    }

    std::vector<plugin::CertificateData> readCertificates(smartcard::PCSCConnection& /*conn*/) const override
    {
        std::vector<plugin::CertificateData> result;
        if (!p15card)
            return result;

        sc_pkcs15_object_t* certObjs[16];
        int certCount = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, certObjs, 16);

        for (int i = 0; i < certCount; ++i) {
            auto* certInfo = static_cast<sc_pkcs15_cert_info_t*>(certObjs[i]->data);
            sc_pkcs15_cert_t* cert = nullptr;
            int rc = sc_pkcs15_read_certificate(p15card, certInfo, 0, &cert);
            if (rc < 0 || !cert)
                continue;

            plugin::CertificateData cd;
            cd.label = certObjs[i]->label;
            cd.derBytes.assign(cert->data.value, cert->data.value + cert->data.len);

            // Try to find associated private key for FID and key size
            sc_pkcs15_object_t* keyObj = nullptr;
            rc = sc_pkcs15_find_prkey_by_id(p15card, &certInfo->id, &keyObj);
            if (rc == 0 && keyObj) {
                auto* keyInfo = static_cast<sc_pkcs15_prkey_info_t*>(keyObj->data);
                cd.keyFID = static_cast<uint16_t>(keyInfo->key_reference);
                cd.keySizeBits = static_cast<uint16_t>(keyInfo->modulus_length);
            }

            sc_pkcs15_free_certificate(cert);
            result.push_back(std::move(cd));
        }

        return result;
    }

    plugin::PINResult verifyPIN(smartcard::PCSCConnection& /*conn*/, const std::string& pin) const override
    {
        if (!p15card)
            return {};

        sc_pkcs15_object_t* pinObjs[4];
        int count = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, pinObjs, 4);
        if (count <= 0)
            return {};

        int rc = sc_pkcs15_verify_pin(p15card, pinObjs[0], reinterpret_cast<const uint8_t*>(pin.data()), pin.size());

        // Refresh tries_left from card (verify may not update auth_info on all drivers)
        sc_pkcs15_get_pin_info(p15card, pinObjs[0]);
        auto* authInfo = static_cast<sc_pkcs15_auth_info_t*>(pinObjs[0]->data);
        return {rc == 0, authInfo->tries_left, authInfo->tries_left == 0};
    }

    plugin::PINResult changePIN(smartcard::PCSCConnection& /*conn*/, const std::string& oldPin,
                                const std::string& newPin) const override
    {
        if (!p15card)
            return {};

        sc_pkcs15_object_t* pinObjs[4];
        int count = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, pinObjs, 4);
        if (count <= 0)
            return {};

        int rc = sc_pkcs15_change_pin(p15card, pinObjs[0], reinterpret_cast<const uint8_t*>(oldPin.data()),
                                      oldPin.size(), reinterpret_cast<const uint8_t*>(newPin.data()), newPin.size());

        // Refresh tries_left from card
        sc_pkcs15_get_pin_info(p15card, pinObjs[0]);
        auto* authInfo = static_cast<sc_pkcs15_auth_info_t*>(pinObjs[0]->data);
        return {rc == 0, authInfo->tries_left, authInfo->tries_left == 0};
    }

    int getPINTriesLeft(smartcard::PCSCConnection& /*conn*/) const override
    {
        if (!p15card)
            return -1;

        sc_pkcs15_object_t* pinObjs[4];
        int count = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, pinObjs, 4);
        if (count <= 0)
            return -1;

        int rc = sc_pkcs15_get_pin_info(p15card, pinObjs[0]);
        if (rc < 0)
            return -1;
        auto* authInfo = static_cast<sc_pkcs15_auth_info_t*>(pinObjs[0]->data);
        return authInfo->tries_left;
    }

    plugin::SignResult sign(smartcard::PCSCConnection& /*conn*/, uint16_t keyReference, std::span<const uint8_t> data,
                            plugin::SignMechanism /*mechanism*/) const override
    {
        if (!p15card)
            return {};

        // Find private key by reference
        sc_pkcs15_object_t* keyObjs[8];
        int keyCount = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY_RSA, keyObjs, 8);

        sc_pkcs15_object_t* targetKey = nullptr;
        for (int i = 0; i < keyCount; ++i) {
            auto* keyInfo = static_cast<sc_pkcs15_prkey_info_t*>(keyObjs[i]->data);
            if (static_cast<uint16_t>(keyInfo->key_reference) == keyReference) {
                targetKey = keyObjs[i];
                break;
            }
        }
        if (!targetKey)
            return {};

        auto* keyInfo = static_cast<sc_pkcs15_prkey_info_t*>(targetKey->data);
        size_t sigLen = keyInfo->modulus_length / 8; // RSA signature length in bytes
        std::vector<uint8_t> sig(sigLen);

        int rc = sc_pkcs15_compute_signature(p15card, targetKey, SC_ALGORITHM_RSA_PAD_PKCS1, data.data(), data.size(),
                                             sig.data(), sig.size(), nullptr);

        if (rc < 0)
            return {};
        sig.resize(static_cast<size_t>(rc));
        return {true, std::move(sig)};
    }

    std::vector<std::pair<std::string, uint16_t>>
    discoverKeyReferences(smartcard::PCSCConnection& /*conn*/) const override
    {
        std::vector<std::pair<std::string, uint16_t>> result;
        if (!p15card)
            return result;

        sc_pkcs15_object_t* keyObjs[8];
        int keyCount = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY_RSA, keyObjs, 8);

        for (int i = 0; i < keyCount; ++i) {
            auto* keyInfo = static_cast<sc_pkcs15_prkey_info_t*>(keyObjs[i]->data);
            result.emplace_back(keyObjs[i]->label, static_cast<uint16_t>(keyInfo->key_reference));
        }

        return result;
    }

private:
    void teardown() const
    {
        if (p15card) {
            sc_pkcs15_unbind(p15card);
            p15card = nullptr;
        }
        if (card) {
            sc_disconnect_card(card);
            card = nullptr;
        }
        if (ctx) {
            sc_release_context(ctx);
            ctx = nullptr;
        }
        hasPKI = false;
    }

    mutable sc_context_t* ctx = nullptr;
    mutable sc_card_t* card = nullptr;
    mutable sc_pkcs15_card_t* p15card = nullptr;
    mutable std::string readerName;
    mutable bool hasPKI = false;
};

} // namespace

extern "C" std::unique_ptr<plugin::CardPlugin> create_card_plugin()
{
    return std::make_unique<OpenSCCardPlugin>();
}

extern "C" uint32_t card_plugin_abi_version()
{
    return plugin::LIBRESCRS_PLUGIN_ABI_VERSION;
}
