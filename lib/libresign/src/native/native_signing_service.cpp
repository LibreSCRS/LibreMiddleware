// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/native/native_signing_service.h"
#include "libresign/native/pkcs11_token.h"
#include "libresign/native/cades_module.h"
#include "libresign/native/pades_module.h"
#include "libresign/native/xades_module.h"
#include "libresign/native/jades_module.h"
#include "libresign/native/asic_module.h"
#include "native_utils.h" // parseCert (X509Ptr RAII) — avoids manual d2i_X509 / X509_free

#include <openssl/x509.h>

namespace libresign {

bool NativeSigningService::configure(const TrustConfig& config)
{
    trustConfig = config;
    return true;
}

bool NativeSigningService::isAvailable() const
{
    return true;
}

SigningResult NativeSigningService::sign(const SigningRequest& request,
                                         const std::string& pkcs11ModulePath,
                                         std::span<const uint8_t> pin,
                                         const std::string& keyAlias,
                                         const std::string& tokenLabel)
{
    try {
        auto makeToken = [&]() -> Pkcs11Token {
            if (tokenLabel.empty())
                return Pkcs11Token(pkcs11ModulePath, pin, keyAlias, -1);
            return Pkcs11Token(pkcs11ModulePath, pin, keyAlias, tokenLabel);
        };
        auto token = makeToken();

        // Certificate expiry enforcement. The native backend's CMS path
        // does not intrinsically reject expired signers — add an explicit
        // check so `allowExpiredCertificate=false` (the default) behaves
        // consistently with the DSS backend. The flag is the test-build
        // opt-in used by LibreCelik when the user accepts the
        // expired-cert warning at the signing page.
        {
            auto certDer = token.certificate();
            if (!certDer.empty()) {
                auto x509 = native_utils::parseCert(certDer);
                if (x509) {
                    const int cmp = X509_cmp_current_time(X509_get0_notAfter(x509.get()));
                    const bool expired = (cmp <= 0); // -1 past, 0 malformed — treat both as expired
                    if (expired && !request.allowExpiredCertificate)
                        return {false, {}, "Signing certificate has expired"};
                }
            }
        }

        // Wire trust config to TSA/revocation parameters
        auto tsa = request.tsa;
        tsa.crlEnabled = trustConfig.crlEnabled;
        tsa.ocspEnabled = trustConfig.ocspEnabled;

        switch (request.format) {
        case SignatureFormat::CAdES: {
            CAdESModule cades;
            return cades.sign(request.document, token, request.level, tsa);
        }
        case SignatureFormat::PAdES: {
            PAdESModule pades;
            return pades.sign(request.document, token, request.level, tsa, request.visual);
        }
        case SignatureFormat::XAdES: {
            XAdESModule xades;
            return xades.sign(request.document, request.fileName, token, request.level, request.packaging, tsa);
        }

        case SignatureFormat::JAdES: {
            JAdESModule jades;
            return jades.sign(request.document, request.fileName, token, request.level, request.packaging, tsa);
        }

        case SignatureFormat::ASiC_E: {
            ASiCModule asic;
            return asic.signWithCAdES(request.document, request.fileName, token, request.level, tsa);
        }
        default:
            return {false, {}, "Unsupported signature format"};
        }
    } catch (const std::exception& e) {
        return {false, {}, std::string("Native signing error: ") + e.what()};
    }
}

} // namespace libresign
