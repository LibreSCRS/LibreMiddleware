// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_signing_key.h"

#include "native/plugin_signing_key.h"
#include "signing_test_support.h"

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <span>
#include <utility>
#include <vector>

namespace libresign::test {

namespace {

// The plugin key together with the registry its plugin was loaded from: the
// registry unloads the plugin's shared object when it goes, so it outlives
// the key that calls into it.
class CardSigningKey final : public SigningKey
{
public:
    CardSigningKey(std::unique_ptr<LibreSCRS::Plugin::CardPluginService> plugins, std::unique_ptr<PluginSigningKey> key)
        : plugins(std::move(plugins)), key(std::move(key))
    {}

    std::vector<std::uint8_t> sign(std::span<const std::uint8_t> hash, const std::string& algorithm,
                                   std::span<const std::uint8_t> rawData) override
    {
        return key->sign(hash, algorithm, rawData);
    }
    std::vector<std::uint8_t> certificate() const override
    {
        return key->certificate();
    }
    std::vector<std::vector<std::uint8_t>> certificateChain() const override
    {
        return key->certificateChain();
    }
    void setResolvedChain(std::vector<std::vector<std::uint8_t>> chain, ChainTermination termination) override
    {
        key->setResolvedChain(std::move(chain), termination);
    }
    ChainTermination chainTermination() const override
    {
        return key->chainTermination();
    }

private:
    std::unique_ptr<LibreSCRS::Plugin::CardPluginService> plugins;
    std::unique_ptr<PluginSigningKey> key;
};

} // namespace

std::unique_ptr<SigningKey> openCardSigningKey(const TestConfig& config, std::string& skipReason)
{
    auto opened = LibreSCRS::SmartCard::CardSession::open(config.readerName);
    if (!opened) {
        skipReason = "no card session on reader '" + config.readerName + "'";
        return nullptr;
    }
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
    if (const char* can = std::getenv("LIBRESCRS_TEST_CAN"); can != nullptr && *can != '\0')
        session->setPaceSecret(LibreSCRS::Auth::PaceSecretKind::Can, LibreSCRS::Secure::String{can});

    auto plugins = std::make_unique<LibreSCRS::Plugin::CardPluginService>(std::filesystem::path(PLUGIN_DIR));
    for (const auto& plugin : plugins->findAllCandidates(session->atr(), *session)) {
        if (!LibreSCRS::Plugin::hasCapability(plugin->capabilities(), LibreSCRS::Plugin::CardCapabilities::PKI))
            continue;
        const auto certs = plugin->readCertificates(*session);
        std::vector<std::vector<std::uint8_t>> chain;
        for (const auto& c : certs) {
            if (!c.derBytes.empty())
                chain.push_back(c.derBytes);
        }
        for (const auto& c : certs) {
            if (!c.keyFID || (!config.keyAlias.empty() && c.label != config.keyAlias))
                continue;
            const LibreSCRS::Secure::Buffer pin(config.pin);
            auto key = std::make_unique<PluginSigningKey>(plugin, session, c, pin, chain,
                                                          std::span<const std::uint8_t>{}, LibreSCRS::CancelToken{});
            return std::make_unique<CardSigningKey>(std::move(plugins), std::move(key));
        }
    }
    skipReason = "no plugin reads a signing key" +
                 (config.keyAlias.empty() ? std::string{} : " labelled '" + config.keyAlias + "'") +
                 " from the card on '" + config.readerName + "'";
    return nullptr;
}

} // namespace libresign::test
