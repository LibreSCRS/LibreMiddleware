// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "rsa_test_key.h"
#include "signing_stub_plugin.h"

#include <cstdint>
#include <vector>

namespace LibreSCRS::TestSupport {

/// A PKI card plugin whose one key lives in memory: readCertificates reports
/// its self-signed certificate, and sign answers with a real RSA PKCS#1 v1.5
/// signature -- over the raw message for RSA_SHA256, over the given DigestInfo
/// for RSA_PKCS -- so a document the signing engine produces through it
/// verifies with that certificate. Every call is still recorded.
class SoftKeyPlugin : public SigningStubPlugin
{
    RsaTestKey key; // first: certDer is copied from it

public:
    static constexpr std::uint16_t kKeyHandle = 0x4410;

    SoftKeyPlugin() : key(makeRsaTestKey("Soft Key Signer")), certDer(key.certDer)
    {
        respond = [this](const SignCall& call) { return signWithTheKey(call); };
    }

    std::vector<LibreSCRS::Plugin::CertificateData> readCertificates(LibreSCRS::SmartCard::CardSession&) const override
    {
        LibreSCRS::Plugin::CertificateData c;
        c.label = "Soft Key Signer";
        c.derBytes = certDer;
        c.keyFID = kKeyHandle;
        c.ckaId = {0x45};
        return {c};
    }

    std::vector<std::uint8_t> certDer;

private:
    LibreSCRS::Plugin::SignResult signWithTheKey(const SignCall& call) const
    {
        LibreSCRS::Plugin::SignResult r;
        r.outcome = LibreSCRS::Plugin::SignResultOutcome::NotImplemented;
        if (call.keyReference != kKeyHandle) {
            r.outcome = LibreSCRS::Plugin::SignResultOutcome::PluginError;
            return r;
        }
        if (call.mechanism == LibreSCRS::Plugin::SignMechanism::RSA_SHA256)
            r.signature = key.signPkcs1(EVP_sha256(), call.data);
        else if (call.mechanism == LibreSCRS::Plugin::SignMechanism::RSA_PKCS)
            r.signature = key.signPkcs1(nullptr, call.data);
        else
            return r;
        r.outcome = r.signature.empty() ? LibreSCRS::Plugin::SignResultOutcome::PluginError
                                        : LibreSCRS::Plugin::SignResultOutcome::Ok;
        return r;
    }
};

} // namespace LibreSCRS::TestSupport
