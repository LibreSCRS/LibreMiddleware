// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <plugin/card_data.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

// Forward declare to avoid smartcard header dependency in interface
namespace smartcard {
class PCSCConnection;
}

namespace plugin {

constexpr uint32_t LIBRESCRS_PLUGIN_ABI_VERSION = 2;

struct PINResult
{
    bool success = false;
    int retriesLeft = -1;
    bool blocked = false;
};

struct CertificateData
{
    std::string label;
    std::vector<uint8_t> derBytes;
    uint16_t keyFID = 0;
    uint16_t keySizeBits = 0;
};

enum class SignMechanism { RSA_PKCS };

struct SignResult
{
    bool success = false;
    std::vector<uint8_t> signature;
};

class CardPlugin
{
public:
    virtual ~CardPlugin() = default;

    // Identification
    virtual std::string pluginId() const = 0;
    virtual std::string displayName() const = 0;
    virtual int probePriority() const = 0;

    // Two-phase probe:
    // Phase 1 (fast, no I/O): match by ATR bytes only.
    virtual bool canHandle(const std::vector<uint8_t>& atr) const = 0;
    // Phase 2 (slow, requires card I/O): try AID selection on live connection.
    // Called only if canHandle(atr) returned false for ALL plugins.
    virtual bool canHandleConnection(smartcard::PCSCConnection& /*conn*/) const
    {
        return false;
    }

    // Data reading
    virtual CardData readCard(smartcard::PCSCConnection& conn) const = 0;

    // Callback for progressive group delivery during card reading.
    // First argument is the plugin's pluginId() so the GUI can look up
    // the correct widget plugin before cardDataReady fires.
    using GroupCallback = std::function<void(const std::string& cardType, const CardFieldGroup&)>;

    // Progressive version of readCard — calls onGroup for each group as it
    // becomes available. Default delegates to readCard() (backward compatible).
    virtual CardData readCardStreaming(smartcard::PCSCConnection& conn, GroupCallback onGroup) const
    {
        return readCard(conn);
    }

    // Optional: PKI operations
    virtual bool supportsPKI() const
    {
        return false;
    }
    virtual std::vector<CertificateData> readCertificates(smartcard::PCSCConnection& /*conn*/) const
    {
        return {};
    }
    virtual PINResult verifyPIN(smartcard::PCSCConnection& /*conn*/, const std::string& /*pin*/) const
    {
        return {};
    }
    virtual PINResult changePIN(smartcard::PCSCConnection& /*conn*/, const std::string& /*oldPin*/,
                                const std::string& /*newPin*/) const
    {
        return {};
    }
    virtual int getPINTriesLeft(smartcard::PCSCConnection& /*conn*/) const
    {
        return -1;
    }
    virtual SignResult sign(smartcard::PCSCConnection& /*conn*/, uint16_t /*keyReference*/,
                            std::span<const uint8_t> /*data*/, SignMechanism /*mechanism*/) const
    {
        return {};
    }
    virtual std::vector<std::pair<std::string, uint16_t>>
    discoverKeyReferences(smartcard::PCSCConnection& /*conn*/) const
    {
        return {};
    }

    // Optional: credential passing for two-phase authentication (e.g. eMRTD PACE/BAC).
    // Keys are plugin-specific. Default is no-op.
    virtual void setCredentials(const std::string& /*key*/, const std::string& /*value*/) const {}
};

// Every plugin .so must export these two functions with C linkage:
//   extern "C" std::unique_ptr<CardPlugin> create_card_plugin();
//   extern "C" uint32_t card_plugin_abi_version();
//
// ABI constraint: Plugins MUST be built with the same compiler and C++ standard
// library (libstdc++/libc++) as the host application. The ABI version check
// (LIBRESCRS_PLUGIN_ABI_VERSION) catches interface changes but cannot detect
// compiler or standard library mismatches.
//
// Plugin methods are const with respect to plugin identity and configuration.
// Session state (mutable) may be cached across calls for performance — e.g.,
// the OpenSC fallback plugin keeps sc_pkcs15_card_t* alive to avoid expensive
// re-binding. Callers should batch related operations when possible.

} // namespace plugin
