// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_verifier.h"
#include "card_protocol.h"
#include "card_reader_base.h"
#include <rs_container.h>
#include <rs_digest_binding.h>
#include <rs_signed_object.h>
#include <pcsc_connection.h>

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <iomanip>
#include <iostream>

namespace eidcard {

namespace Core = LibreSCRS::RsEId::Core;

using LibreSCRS::Internal::Crypto::EvpMdCtxPtr;
using LibreSCRS::Internal::Crypto::EvpPkeyPtr;
using LibreSCRS::Internal::Crypto::Pkcs7Ptr;
using LibreSCRS::Internal::Crypto::StackX509Ptr;
using LibreSCRS::Internal::Crypto::X509Ptr;
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

VerificationResult CardVerifier::verifyCard(LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                                            CardReaderBase& reader, CardType cardType)
{
    try {
        switch (cardType) {
        case CardType::Apollo2008:
            return verifyApolloCardCert(conn, reader);
        case CardType::Gemalto2014:
        case CardType::ForeignerIF2020:
            return verifyGemaltoCardCert(conn, reader);
        default:
            return VerificationResult::Unknown;
        }
    } catch (const std::exception& e) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] verifyCard exception: " << e.what() << std::endl;
#endif
        return VerificationResult::Unknown;
    } catch (...) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] verifyCard unknown exception" << std::endl;
#endif
        return VerificationResult::Unknown;
    }
}

VerificationResult CardVerifier::verifyFixedData(LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                                                 CardReaderBase& reader, CardType cardType)
{
    try {
        switch (cardType) {
        case CardType::Gemalto2014:
        case CardType::ForeignerIF2020:
            return verifyGemaltoSOD(conn, reader, protocol::FILE_SOD_FX_H, protocol::FILE_SOD_FX_L,
                                    {{protocol::FILE_DOCUMENT_DATA_H, protocol::FILE_DOCUMENT_DATA_L},
                                     {protocol::FILE_PERSONAL_DATA_H, protocol::FILE_PERSONAL_DATA_L},
                                     {protocol::FILE_PORTRAIT_H, protocol::FILE_PORTRAIT_L}});
        case CardType::Apollo2008:
            return verifyApolloSignature(conn, reader, protocol::FILE_SIGN_FX_H, protocol::FILE_SIGN_FX_L,
                                         protocol::FILE_CERT_FX_H, protocol::FILE_CERT_FX_L,
                                         {{protocol::FILE_DOCUMENT_DATA_H, protocol::FILE_DOCUMENT_DATA_L},
                                          {protocol::FILE_PERSONAL_DATA_H, protocol::FILE_PERSONAL_DATA_L}});
        default:
            return VerificationResult::Unknown;
        }
    } catch (const std::exception& e) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] verifyFixedData exception: " << e.what() << std::endl;
#endif
        return VerificationResult::Unknown;
    } catch (...) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] verifyFixedData unknown exception" << std::endl;
#endif
        return VerificationResult::Unknown;
    }
}

VerificationResult CardVerifier::verifyVariableData(LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                                                    CardReaderBase& reader, CardType cardType)
{
    try {
        switch (cardType) {
        case CardType::Gemalto2014:
        case CardType::ForeignerIF2020:
            return verifyGemaltoSOD(conn, reader, protocol::FILE_SOD_VX_H, protocol::FILE_SOD_VX_L,
                                    {{protocol::FILE_VARIABLE_DATA_H, protocol::FILE_VARIABLE_DATA_L}});
        case CardType::Apollo2008:
            return verifyApolloSignature(conn, reader, protocol::FILE_SIGN_VX_H, protocol::FILE_SIGN_VX_L,
                                         protocol::FILE_CERT_VX_H, protocol::FILE_CERT_VX_L,
                                         {{protocol::FILE_VARIABLE_DATA_H, protocol::FILE_VARIABLE_DATA_L}});
        default:
            return VerificationResult::Unknown;
        }
    } catch (const std::exception& e) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] verifyVariableData exception: " << e.what() << std::endl;
#endif
        return VerificationResult::Unknown;
    } catch (...) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] verifyVariableData unknown exception" << std::endl;
#endif
        return VerificationResult::Unknown;
    }
}

// --- Gemalto card-level certificate verification ---

VerificationResult CardVerifier::verifyGemaltoCardCert(LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                                                       CardReaderBase& reader)
{
    // Read SOD FX block to extract the signer certificate
    auto sodRaw = reader.readFile(conn, protocol::FILE_SOD_FX_H, protocol::FILE_SOD_FX_L);
#ifndef NDEBUG
    std::cerr << "[CardVerifier] Gemalto card cert: SOD FX size: " << sodRaw.size() << " bytes" << std::endl;
#endif
    if (sodRaw.empty())
        return VerificationResult::Invalid;

    // Strip inner TLV header to get pure PKCS#7 DER
    const auto sodData = Core::innerTlvPayload(sodRaw);
#ifndef NDEBUG
    std::cerr << "[CardVerifier] Gemalto card cert: PKCS#7 size after strip: " << sodData.size() << " bytes"
              << std::endl;
#endif

    // Parse PKCS#7 to extract signer certificate. Pkcs7Ptr / StackX509Ptr /
    // X509StoreCtxPtr keep their handles alive across every throwable line
    // below — most importantly the std::cerr stream operations
    // (which can throw under std::ios_base::failure with fail-on-throw
    // exception masks) and the X509_NAME_oneline path that allocates an
    // OpenSSL string. With raw owning pointers any C++ exception between
    // d2i_PKCS7 and the manual *_free calls leaked the PKCS7 + signer
    // stack. Mirrors the Wave 4 rewrite of the sibling
    // verifyPKCS7Signature() in this file. StackX509Ptr's deleter is
    // sk_X509_free (not sk_X509_pop_free) because PKCS7_get0_signers
    // returns borrowed certs owned by the parent PKCS7.
    const uint8_t* p = sodData.data();
    Pkcs7Ptr pkcs7(d2i_PKCS7(nullptr, &p, static_cast<long>(sodData.size())));
    if (!pkcs7) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Gemalto card cert: failed to parse PKCS#7" << std::endl;
#endif
        return VerificationResult::Invalid;
    }

    // Verify PKCS#7 signature — PKCS7_NOVERIFY skips cert chain validation
    // (chain is verified separately below), but the CMS signature itself IS checked.
    int rc = PKCS7_verify(pkcs7.get(), nullptr, nullptr, nullptr, nullptr, PKCS7_NOVERIFY);
    if (rc != 1) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Gemalto card cert: PKCS#7 structure invalid" << std::endl;
#endif
        return VerificationResult::Invalid;
    }

    // Extract the single signer and route through the shared chain + domain-pin decision.
    StackX509Ptr signerCerts(PKCS7_get0_signers(pkcs7.get(), nullptr, 0));
    if (!signerCerts || sk_X509_num(signerCerts.get()) != 1) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Gemalto card cert: expected exactly one signer, got "
                  << (signerCerts ? sk_X509_num(signerCerts.get()) : 0) << std::endl;
#endif
        return VerificationResult::Invalid;
    }
    X509* signerCert = sk_X509_value(signerCerts.get(), 0);

#ifndef NDEBUG
    char* subject = X509_NAME_oneline(X509_get_subject_name(signerCert), nullptr, 0);
    if (subject) {
        std::cerr << "[CardVerifier] Gemalto card signer: " << subject << std::endl;
        OPENSSL_free(subject);
    }
#endif

    return Core::verifySignerTrust(trust, signerCert);
}

// --- Gemalto SOD (PKCS#7) verification ---

VerificationResult CardVerifier::verifyGemaltoSOD(LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                                                  CardReaderBase& reader, uint8_t sodFileH, uint8_t sodFileL,
                                                  const std::vector<std::pair<uint8_t, uint8_t>>& dataFileIds)
{
    // 1. Read SOD block from card
#ifndef NDEBUG
    std::cerr << "[CardVerifier] Reading SOD file 0x" << std::hex << (int)sodFileH << std::setfill('0') << std::setw(2)
              << (int)sodFileL << std::dec << std::endl;
#endif

    auto sodRaw = reader.readFile(conn, sodFileH, sodFileL);
#ifndef NDEBUG
    std::cerr << "[CardVerifier] SOD data size: " << sodRaw.size() << " bytes" << std::endl;
#endif
    if (sodRaw.empty())
        return VerificationResult::Invalid;

    // Strip inner TLV header to get pure PKCS#7 DER
    const auto sodData = Core::innerTlvPayload(sodRaw);
#ifndef NDEBUG
    std::cerr << "[CardVerifier] PKCS#7 size after strip: " << sodData.size() << " bytes" << std::endl;
#endif

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

// --- Apollo card certificate verification ---

VerificationResult CardVerifier::verifyApolloCardCert(LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                                                      CardReaderBase& reader)
{
    auto userCertData = reader.readFile(conn, protocol::FILE_USER_CERT1_H, protocol::FILE_USER_CERT1_L);
#ifndef NDEBUG
    std::cerr << "[CardVerifier] Apollo user cert size: " << userCertData.size() << " bytes" << std::endl;
#endif
    if (userCertData.empty())
        return VerificationResult::Invalid;

    if (verifyCertificateChain(userCertData)) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Apollo cert chain: VALID" << std::endl;
#endif
        return VerificationResult::Valid;
    }

#ifndef NDEBUG
    std::cerr << "[CardVerifier] Apollo cert chain: INVALID" << std::endl;
#endif
    return VerificationResult::Invalid;
}

// --- Apollo signature verification ---

VerificationResult CardVerifier::verifyApolloSignature(LibreSCRS::SmartCard::Internal::PCSCConnection& conn,
                                                       CardReaderBase& reader, uint8_t sigFileH, uint8_t sigFileL,
                                                       uint8_t certFileH, uint8_t certFileL,
                                                       const std::vector<std::pair<uint8_t, uint8_t>>& dataFileIds)
{
    // 1. Read the signing certificate from card
    auto certData = reader.readFile(conn, certFileH, certFileL);
#ifndef NDEBUG
    std::cerr << "[CardVerifier] Apollo signing cert size: " << certData.size() << " bytes" << std::endl;
#endif
    if (certData.empty())
        return VerificationResult::Invalid;

    // 2. Verify the signing certificate chain against trusted CAs
    if (!verifyCertificateChain(certData)) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Apollo signing cert chain: INVALID" << std::endl;
#endif
        return VerificationResult::Invalid;
    }
#ifndef NDEBUG
    std::cerr << "[CardVerifier] Apollo signing cert chain: VALID" << std::endl;
#endif

    // 3. Read the signature from card
    auto signature = reader.readFile(conn, sigFileH, sigFileL);
#ifndef NDEBUG
    std::cerr << "[CardVerifier] Apollo signature size: " << signature.size() << " bytes" << std::endl;
#endif
    if (signature.empty())
        return VerificationResult::Invalid;

    // 4. Read and concatenate all data blocks
    std::vector<uint8_t> allData;
    for (const auto& [fh, fl] : dataFileIds) {
        auto blockData = reader.readFile(conn, fh, fl);
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Apollo data block (0x" << std::hex << (int)fh << std::setfill('0') << std::setw(2)
                  << (int)fl << std::dec << ") size: " << blockData.size() << " bytes" << std::endl;
#endif
        allData.insert(allData.end(), blockData.begin(), blockData.end());
    }

    // 5. Verify RSA signature over data using public key from signing cert
    if (verifyRSASignature(certData, allData, signature)) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Apollo RSA signature: VALID" << std::endl;
#endif
        return VerificationResult::Valid;
    }

#ifndef NDEBUG
    std::cerr << "[CardVerifier] Apollo RSA signature: INVALID" << std::endl;
#endif
    return VerificationResult::Invalid;
}

// --- OpenSSL helpers ---

bool CardVerifier::verifyCertificateChain(const std::vector<uint8_t>& certDER)
{
    if (!trust.native())
        return false;

    const uint8_t* p = certDER.data();
    X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(certDER.size())));
    if (!cert) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Failed to parse DER certificate (" << certDER.size() << " bytes)" << std::endl;
#endif
        return false;
    }

    X509StoreCtxPtr ctx(X509_STORE_CTX_new());
    if (!ctx) {
        return false;
    }

    int rc = X509_STORE_CTX_init(ctx.get(), trust.native(), cert.get(), nullptr);
    bool valid = false;
    if (rc == 1) {
        valid = (X509_verify_cert(ctx.get()) == 1);
#ifndef NDEBUG
        if (!valid) {
            int err = X509_STORE_CTX_get_error(ctx.get());
            std::cerr << "[CardVerifier] X509_verify_cert error: " << X509_verify_cert_error_string(err) << " (" << err
                      << ")" << std::endl;
        }
#endif
    }

    return valid;
}

bool CardVerifier::verifyRSASignature(const std::vector<uint8_t>& certDER, const std::vector<uint8_t>& data,
                                      const std::vector<uint8_t>& signature)
{
    // Parse certificate to extract public key
    const uint8_t* p = certDER.data();
    X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(certDER.size())));
    if (!cert)
        return false;

    EvpPkeyPtr pkey(X509_get_pubkey(cert.get()));
    if (!pkey)
        return false;

    EvpMdCtxPtr mdctx(EVP_MD_CTX_new());
    if (!mdctx) {
        return false;
    }

    bool valid = false;

    // Try SHA-256 first (newer cards)
    if (EVP_DigestVerifyInit(mdctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) == 1 &&
        EVP_DigestVerifyUpdate(mdctx.get(), data.data(), data.size()) == 1 &&
        EVP_DigestVerifyFinal(mdctx.get(), signature.data(), signature.size()) == 1) {
        valid = true;
    }

    // If SHA-256 fails, try SHA-1 (some older Apollo cards may use it)
    if (!valid) {
        EVP_MD_CTX_reset(mdctx.get());
        if (EVP_DigestVerifyInit(mdctx.get(), nullptr, EVP_sha1(), nullptr, pkey.get()) == 1 &&
            EVP_DigestVerifyUpdate(mdctx.get(), data.data(), data.size()) == 1 &&
            EVP_DigestVerifyFinal(mdctx.get(), signature.data(), signature.size()) == 1) {
            valid = true;
        }
    }

    return valid;
}

} // namespace eidcard
