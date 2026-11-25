// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_verifier.h"
#include "card_protocol.h"
#include "card_reader_base.h"
#include <rs_container.h>
#include <rs_digest_binding.h>
#include <rs_signed_object.h>
#include <apdu.h>
#include <smartcard/card_connection.h>

#include <LibreSCRS/Logging.h>
#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace eidcard {

namespace Core = LibreSCRS::RsEId::Core;

using LibreSCRS::Internal::Crypto::Pkcs7Ptr;
using LibreSCRS::Internal::Crypto::X509StackBorrowedPtr;
using LibreSCRS::Internal::Crypto::X509StoreCtxPtr;

CardVerifier::CardVerifier(const std::string& certificateFolderPath)
{
    trust.loadFromFolder(certificateFolderPath);
}

void CardVerifier::addCertificate(const std::vector<uint8_t>& derCert)
{
    trust.addCertificate(derCert);
}

CardVerifier::~CardVerifier() = default;

// --- High-level dispatch ---

VerificationResult CardVerifier::verifyCard(LibreSCRS::SmartCard::CardConnection& conn, CardReaderBase& reader,
                                            CardType cardType)
{
    try {
        switch (cardType) {
        case CardType::Gemalto2014:
        case CardType::ForeignerIF2020:
            return verifyGemaltoCardCert(conn, reader);
        default:
            return VerificationResult::Unknown;
        }
    } catch (const std::exception& e) {
        LibreSCRS::log::tracef(LibreSCRS::log::TraceChannel::Sign, "[CardVerifier] verifyCard exception: {}", e.what());
        return VerificationResult::Unknown;
    } catch (...) {
        LibreSCRS::log::trace(LibreSCRS::log::TraceChannel::Sign, "[CardVerifier] verifyCard unknown exception");
        return VerificationResult::Unknown;
    }
}

VerificationResult CardVerifier::verifyFixedData(LibreSCRS::SmartCard::CardConnection& conn, CardReaderBase& reader,
                                                 CardType cardType)
{
    try {
        switch (cardType) {
        case CardType::Gemalto2014:
        case CardType::ForeignerIF2020:
            return verifyGemaltoSOD(conn, reader, protocol::FILE_SOD_FX_H, protocol::FILE_SOD_FX_L,
                                    {{protocol::FILE_DOCUMENT_DATA_H, protocol::FILE_DOCUMENT_DATA_L},
                                     {protocol::FILE_PERSONAL_DATA_H, protocol::FILE_PERSONAL_DATA_L},
                                     {protocol::FILE_PORTRAIT_H, protocol::FILE_PORTRAIT_L}});
        default:
            return VerificationResult::Unknown;
        }
    } catch (const std::exception& e) {
        LibreSCRS::log::tracef(LibreSCRS::log::TraceChannel::Sign, "[CardVerifier] verifyFixedData exception: {}",
                               e.what());
        return VerificationResult::Unknown;
    } catch (...) {
        LibreSCRS::log::trace(LibreSCRS::log::TraceChannel::Sign, "[CardVerifier] verifyFixedData unknown exception");
        return VerificationResult::Unknown;
    }
}

VerificationResult CardVerifier::verifyVariableData(LibreSCRS::SmartCard::CardConnection& conn, CardReaderBase& reader,
                                                    CardType cardType)
{
    try {
        switch (cardType) {
        case CardType::Gemalto2014:
        case CardType::ForeignerIF2020:
            return verifyGemaltoSOD(conn, reader, protocol::FILE_SOD_VX_H, protocol::FILE_SOD_VX_L,
                                    {{protocol::FILE_VARIABLE_DATA_H, protocol::FILE_VARIABLE_DATA_L}});
        default:
            return VerificationResult::Unknown;
        }
    } catch (const std::exception& e) {
        LibreSCRS::log::tracef(LibreSCRS::log::TraceChannel::Sign, "[CardVerifier] verifyVariableData exception: {}",
                               e.what());
        return VerificationResult::Unknown;
    } catch (...) {
        LibreSCRS::log::trace(LibreSCRS::log::TraceChannel::Sign,
                              "[CardVerifier] verifyVariableData unknown exception");
        return VerificationResult::Unknown;
    }
}

// --- Gemalto card-level certificate verification ---

VerificationResult CardVerifier::verifyGemaltoCardCert(LibreSCRS::SmartCard::CardConnection& conn,
                                                       CardReaderBase& reader)
{
    // Read SOD FX block to extract the signer certificate
    auto sodRaw = reader.readFile(conn, protocol::FILE_SOD_FX_H, protocol::FILE_SOD_FX_L);
    if (sodRaw.empty())
        return VerificationResult::Invalid;

    // Strip inner TLV header to get pure PKCS#7 DER
    const auto sodData = Core::innerTlvPayload(sodRaw);

    // Parse PKCS#7 to extract signer certificate. Pkcs7Ptr / X509StackBorrowedPtr /
    // X509StoreCtxPtr keep their handles alive across every throwable line
    // below. With raw owning pointers any C++ exception between
    // d2i_PKCS7 and the manual *_free calls leaked the PKCS7 + signer
    // stack. Mirrors the rewrite of the sibling
    // verifyPKCS7Signature() in this file. X509StackBorrowedPtr's deleter is
    // sk_X509_free (not sk_X509_pop_free) because PKCS7_get0_signers
    // returns borrowed certs owned by the parent PKCS7.
    const uint8_t* p = sodData.data();
    Pkcs7Ptr pkcs7(d2i_PKCS7(nullptr, &p, static_cast<long>(sodData.size())));
    if (!pkcs7) {
        return VerificationResult::Invalid;
    }

    // Verify PKCS#7 signature — PKCS7_NOVERIFY skips cert chain validation
    // (chain is verified separately below), but the CMS signature itself IS checked.
    int rc = PKCS7_verify(pkcs7.get(), nullptr, nullptr, nullptr, nullptr, PKCS7_NOVERIFY);
    if (rc != 1) {
        return VerificationResult::Invalid;
    }

    // Extract the single signer and route through the shared chain + domain-pin decision.
    X509StackBorrowedPtr signerCerts(PKCS7_get0_signers(pkcs7.get(), nullptr, 0));
    if (!signerCerts || sk_X509_num(signerCerts.get()) != 1) {
        return VerificationResult::Invalid;
    }
    X509* signerCert = sk_X509_value(signerCerts.get(), 0);

    return Core::verifySignerTrust(trust, signerCert);
}

// --- Gemalto SOD (PKCS#7) verification ---

VerificationResult CardVerifier::verifyGemaltoSOD(LibreSCRS::SmartCard::CardConnection& conn, CardReaderBase& reader,
                                                  uint8_t sodFileH, uint8_t sodFileL,
                                                  const std::vector<std::pair<uint8_t, uint8_t>>& dataFileIds)
{
    // 1. Read SOD block from card

    auto sodRaw = reader.readFile(conn, sodFileH, sodFileL);
    if (sodRaw.empty())
        return VerificationResult::Invalid;

    // Strip inner TLV header to get pure PKCS#7 DER
    const auto sodData = Core::innerTlvPayload(sodRaw);

    // Legacy binding: this generation's on-card slot order was never measured, so
    // a digest is still accepted in any slot. Item 140 tracks tightening it once an
    // old card can be measured. Both candidate encodings are offered because which
    // one the issuer hashed was never established either.
    std::vector<Core::BlockCandidates> blocks;
    blocks.reserve(dataFileIds.size());
    for (const auto& [fh, fl] : dataFileIds) {
        blocks.push_back({reader.readFileRaw(conn, fh, fl), reader.readFile(conn, fh, fl)});
    }

    const auto report = Core::verifySignedObject(sodData, blocks, Core::DigestBinding::AnywhereLegacy, trust);
    if (report.signer != VerificationResult::Valid) {
        return report.signer;
    }
    return report.digestsBound ? VerificationResult::Valid : VerificationResult::Invalid;
}

} // namespace eidcard
