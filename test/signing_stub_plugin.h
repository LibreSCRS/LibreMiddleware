// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>

#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::TestSupport {

/// A PKI card plugin that never touches a card. It records what a host asks of
/// it -- every credential deposit and every sign, in order -- and answers
/// sign from @ref respond (NotImplemented when unset). Tests that only need a
/// plugin object to hand to the signing service use it as it is.
class SigningStubPlugin : public LibreSCRS::Plugin::CardPlugin
{
public:
    struct SignCall
    {
        std::uint16_t keyReference = 0;
        LibreSCRS::Plugin::SignMechanism mechanism = LibreSCRS::Plugin::SignMechanism::RSA_PKCS;
        std::vector<std::uint8_t> data;
    };

    explicit SigningStubPlugin(
        LibreSCRS::Plugin::CardCapabilities capabilities = LibreSCRS::Plugin::CardCapabilities::PKI)
        : caps(capabilities)
    {
        setIdentity("stub-pki", "Stub PKI", /*priority=*/1000);
    }

    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return caps;
    }

    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        static constexpr std::array<LibreSCRS::Plugin::Atr, 0> kAtrs{};
        return kAtrs;
    }

    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::ok(LibreSCRS::Plugin::CardData{});
    }

    LibreSCRS::Plugin::CredentialCounters readCounters(LibreSCRS::SmartCard::CardSession&,
                                                       std::string_view) const override
    {
        // No APDU traffic: the session is never touched.
        return {};
    }

    void setCredentials(LibreSCRS::SmartCard::CardSession&, std::string_view key,
                        const LibreSCRS::Secure::String& value) override
    {
        const bool erase = value.view().empty();
        events.push_back(std::string(key) + (erase ? ":erase" : ":deposit"));
        if (key == "pin")
            depositedPin = std::string(value.view());
    }

    /// The answer to each sign; may throw, as a card's transport can.
    std::function<LibreSCRS::Plugin::SignResult(const SignCall&)> respond;

    /// In order: "pin:deposit", "pin:erase", "sign".
    mutable std::vector<std::string> events;
    mutable std::vector<SignCall> signCalls;
    /// The PIN currently deposited; empty after an erase.
    std::string depositedPin;

    [[nodiscard]] int count(std::string_view event) const
    {
        int n = 0;
        for (const auto& e : events)
            n += (e == event) ? 1 : 0;
        return n;
    }

protected:
    LibreSCRS::Plugin::SignResult doSign(LibreSCRS::SmartCard::CardSession&, std::uint16_t keyReference,
                                         std::span<const std::uint8_t> data,
                                         LibreSCRS::Plugin::SignMechanism mechanism) const override
    {
        events.emplace_back("sign");
        signCalls.push_back(SignCall{keyReference, mechanism, std::vector<std::uint8_t>(data.begin(), data.end())});
        if (respond)
            return respond(signCalls.back());
        LibreSCRS::Plugin::SignResult r;
        r.outcome = LibreSCRS::Plugin::SignResultOutcome::NotImplemented;
        return r;
    }

private:
    LibreSCRS::Plugin::CardCapabilities caps;
};

} // namespace LibreSCRS::TestSupport
