// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_verifier.h"
#include "card_protocol.h"
#include "card_reader_base.h"
#include "smartcard/pcsc_connection.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/x509_vfy.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>

namespace eidcard {

// The card file data returned by readFile() has the outer 4-byte TLV header
// (2-byte file ID + 2-byte LE length) already stripped (readFile reads from offset 4).
// But an inner TLV wrapper (2-byte tag + 2-byte LE length) still wraps the actual
// PKCS#7 DER content. This helper strips that inner header.
static std::vector<uint8_t> stripInnerTlvHeader(const std::vector<uint8_t>& data)
{
    if (data.size() <= 4)
        return data;

#ifndef NDEBUG
    // Log first bytes for debugging
    std::cerr << "[CardVerifier] Raw data first 16 bytes:";
    for (size_t i = 0; i < std::min(data.size(), size_t(16)); i++)
        std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    std::cerr << std::dec << std::endl;
#endif

    // If data already starts with ASN.1 SEQUENCE (0x30), it's already pure DER
    if (data[0] == 0x30)
        return data;

#ifndef NDEBUG
    // Otherwise strip the 4-byte inner TLV header (2-byte tag + 2-byte LE length)
    std::cerr << "[CardVerifier] Stripping 4-byte inner TLV header (tag=0x" << std::hex << std::setfill('0')
              << std::setw(2) << (int)data[0] << std::setw(2) << (int)data[1] << ", len=" << std::dec
              << (static_cast<uint16_t>(data[2]) | (static_cast<uint16_t>(data[3]) << 8)) << ")" << std::endl;
#endif

    return std::vector<uint8_t>(data.begin() + 4, data.end());
}

// PIMPL implementation for OpenSSL types
struct CardVerifier::CertStore
{
    X509_STORE* store = nullptr;
    int certCount = 0;

    CertStore()
    {
        store = X509_STORE_new();
    }

    ~CertStore()
    {
        if (store) {
            X509_STORE_free(store);
        }
    }
};

CardVerifier::CardVerifier(const std::string& certificateFolderPath)
    : certStore(std::make_unique<CertStore>()), certFolderPath(certificateFolderPath)
{
    if (!certFolderPath.empty())
        loadTrustedCertificates();
#ifndef NDEBUG
    std::cerr << "[CardVerifier] Loaded " << certStore->certCount
              << " trusted certificates from: " << (certFolderPath.empty() ? "(individual certs)" : certFolderPath)
              << std::endl;
#endif
}

void CardVerifier::addCertificate(const std::vector<uint8_t>& derCert)
{
    if (!certStore || !certStore->store || derCert.empty())
        return;

    const uint8_t* p = derCert.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(derCert.size()));
    if (cert) {
        X509_STORE_add_cert(certStore->store, cert);
        X509_free(cert);
        certStore->certCount++;
    }
}

CardVerifier::~CardVerifier() = default;

void CardVerifier::loadTrustedCertificates()
{
    if (!certStore || !certStore->store)
        return;

    // Match CelikAPI behavior: don't check certificate validity times
    X509_STORE_set_flags(certStore->store, X509_V_FLAG_NO_CHECK_TIME);

    if (!std::filesystem::exists(certFolderPath)) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Certificate folder does not exist: " << certFolderPath << std::endl;
#endif
        return;
    }

    for (const auto& entry : std::filesystem::directory_iterator(certFolderPath)) {
        if (!entry.is_regular_file())
            continue;

        auto ext = entry.path().extension().string();
        if (ext != ".cer" && ext != ".crt" && ext != ".pem")
            continue;

        std::ifstream ifs(entry.path(), std::ios::binary);
        if (!ifs)
            continue;

        std::vector<uint8_t> data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        if (data.empty())
            continue;

        // Try DER format first (the .cer files are DER-encoded)
        const uint8_t* p = data.data();
        X509* cert = d2i_X509(nullptr, &p, static_cast<long>(data.size()));

        if (!cert) {
            // Try PEM as fallback
            BIO* bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
            if (bio) {
                cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);
            }
        }

        if (cert) {
            X509_STORE_add_cert(certStore->store, cert);
            X509_free(cert); // X509_STORE_add_cert increments refcount
            certStore->certCount++;
        }
    }
}

// --- High-level dispatch ---

VerificationResult CardVerifier::verifyCard(smartcard::PCSCConnection& conn, CardReaderBase& reader, CardType cardType)
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

VerificationResult CardVerifier::verifyFixedData(smartcard::PCSCConnection& conn, CardReaderBase& reader,
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

VerificationResult CardVerifier::verifyVariableData(smartcard::PCSCConnection& conn, CardReaderBase& reader,
                                                    CardType cardType)
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

VerificationResult CardVerifier::verifyGemaltoCardCert(smartcard::PCSCConnection& conn, CardReaderBase& reader)
{
    // Read SOD FX block to extract the signer certificate
    auto sodRaw = reader.readFile(conn, protocol::FILE_SOD_FX_H, protocol::FILE_SOD_FX_L);
#ifndef NDEBUG
    std::cerr << "[CardVerifier] Gemalto card cert: SOD FX size: " << sodRaw.size() << " bytes" << std::endl;
#endif
    if (sodRaw.empty())
        return VerificationResult::Invalid;

    // Strip inner TLV header to get pure PKCS#7 DER
    auto sodData = stripInnerTlvHeader(sodRaw);
#ifndef NDEBUG
    std::cerr << "[CardVerifier] Gemalto card cert: PKCS#7 size after strip: " << sodData.size() << " bytes"
              << std::endl;
#endif

    // Parse PKCS#7 to extract signer certificate
    const uint8_t* p = sodData.data();
    PKCS7* pkcs7 = d2i_PKCS7(nullptr, &p, static_cast<long>(sodData.size()));
    if (!pkcs7) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Gemalto card cert: failed to parse PKCS#7" << std::endl;
#endif
        return VerificationResult::Invalid;
    }

    // Verify PKCS#7 signature integrity
    int rc = PKCS7_verify(pkcs7, nullptr, nullptr, nullptr, nullptr, PKCS7_NOVERIFY | PKCS7_NOSIGS);
    if (rc != 1) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Gemalto card cert: PKCS#7 structure invalid" << std::endl;
#endif
        PKCS7_free(pkcs7);
        return VerificationResult::Invalid;
    }

    // Extract signer certificate and verify chain
    STACK_OF(X509)* signerCerts = PKCS7_get0_signers(pkcs7, nullptr, 0);
    bool chainValid = false;

    if (signerCerts && sk_X509_num(signerCerts) > 0) {
        X509* signerCert = sk_X509_value(signerCerts, 0);

#ifndef NDEBUG
        char* subject = X509_NAME_oneline(X509_get_subject_name(signerCert), nullptr, 0);
        if (subject) {
            std::cerr << "[CardVerifier] Gemalto card signer: " << subject << std::endl;
            OPENSSL_free(subject);
        }
#endif

        X509_STORE_CTX* ctx = X509_STORE_CTX_new();
        if (ctx) {
            rc = X509_STORE_CTX_init(ctx, certStore->store, signerCert, nullptr);
            if (rc == 1) {
                chainValid = (X509_verify_cert(ctx) == 1);
#ifndef NDEBUG
                if (!chainValid) {
                    int err = X509_STORE_CTX_get_error(ctx);
                    std::cerr << "[CardVerifier] Gemalto card cert chain error: " << X509_verify_cert_error_string(err)
                              << " (" << err << ")" << std::endl;
                }
#endif
            }
            X509_STORE_CTX_free(ctx);
        }
    } else {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Gemalto card cert: no signer certificates found" << std::endl;
#endif
    }

    if (signerCerts)
        sk_X509_free(signerCerts);
    PKCS7_free(pkcs7);

#ifndef NDEBUG
    std::cerr << "[CardVerifier] Gemalto card cert chain: " << (chainValid ? "VALID" : "INVALID") << std::endl;
#endif
    return chainValid ? VerificationResult::Valid : VerificationResult::Invalid;
}

// --- Gemalto SOD (PKCS#7) verification ---

VerificationResult CardVerifier::verifyGemaltoSOD(smartcard::PCSCConnection& conn, CardReaderBase& reader,
                                                  uint8_t sodFileH, uint8_t sodFileL,
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
    auto sodData = stripInnerTlvHeader(sodRaw);
#ifndef NDEBUG
    std::cerr << "[CardVerifier] PKCS#7 size after strip: " << sodData.size() << " bytes" << std::endl;
#endif

    // 2. Verify PKCS#7 signature and extract signed content (hash array)
    std::vector<uint8_t> signedContent;
    if (!verifyPKCS7Signature(sodData, signedContent)) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] PKCS#7 signature verification FAILED" << std::endl;
#endif
        return VerificationResult::Invalid;
    }
#ifndef NDEBUG
    std::cerr << "[CardVerifier] PKCS#7 signature OK, signed content size: " << signedContent.size() << " bytes"
              << std::endl;

    // Dump first 64 bytes of signed content for format analysis
    std::cerr << "[CardVerifier] Signed content first bytes:";
    for (size_t i = 0; i < std::min(signedContent.size(), size_t(64)); i++)
        std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << (int)signedContent[i];
    std::cerr << std::dec << std::endl;
#endif

    // 3. Compare hashes of data blocks against the SOD content.
    // The signed content contains concatenated SHA-256 hashes (32 bytes each),
    // covering ALL data groups registered for this SOD (not just the ones we read).
    // CelikAPI hashes the full file data including the 4-byte TLV header
    // (2-byte file ID + 2-byte LE length) that our readFile() strips.
    // Since we don't know the exact block ordering, we search for each
    // computed hash anywhere within the signed content.
    constexpr size_t SHA256_SIZE = 32;

    if (signedContent.size() < SHA256_SIZE) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Signed content too small: " << signedContent.size() << std::endl;
#endif
        return VerificationResult::Invalid;
    }

    size_t totalHashes = signedContent.size() / SHA256_SIZE;
#ifndef NDEBUG
    std::cerr << "[CardVerifier] SOD contains " << totalHashes << " hash slots" << std::endl;
#endif

    for (size_t i = 0; i < dataFileIds.size(); i++) {
        auto fh = dataFileIds[i].first;
        auto fl = dataFileIds[i].second;

        // Read full file including TLV header for hashing (CelikAPI behavior)
        auto rawBlock = reader.readFileRaw(conn, fh, fl);
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Block " << i << " (0x" << std::hex << (int)fh << std::setfill('0') << std::setw(2)
                  << (int)fl << std::dec << ") raw size: " << rawBlock.size() << " bytes" << std::endl;

        // Log first 8 bytes to verify header format
        std::cerr << "[CardVerifier] Block " << i << " first 8 bytes:";
        for (size_t b = 0; b < std::min(rawBlock.size(), size_t(8)); b++)
            std::cerr << " " << std::hex << std::setfill('0') << std::setw(2) << (int)rawBlock[b];
        std::cerr << std::dec << std::endl;
#endif

        auto hashRaw = computeSHA256(rawBlock);

        // Also compute hash without header as fallback
        auto blockData = reader.readFile(conn, fh, fl);
        auto hashNoHeader = computeSHA256(blockData);

        // Search for hash in any position within the signed content
        bool found = false;
        for (size_t slot = 0; slot < totalHashes && !found; slot++) {
            const uint8_t* slotPtr = signedContent.data() + slot * SHA256_SIZE;
            if (CRYPTO_memcmp(hashRaw.data(), slotPtr, SHA256_SIZE) == 0) {
#ifndef NDEBUG
                std::cerr << "[CardVerifier] Block " << i << " hash matches at slot " << slot << " (raw with header)"
                          << std::endl;
#endif
                found = true;
            } else if (CRYPTO_memcmp(hashNoHeader.data(), slotPtr, SHA256_SIZE) == 0) {
#ifndef NDEBUG
                std::cerr << "[CardVerifier] Block " << i << " hash matches at slot " << slot << " (without header)"
                          << std::endl;
#endif
                found = true;
            }
        }

        if (!found) {
#ifndef NDEBUG
            std::cerr << "[CardVerifier] Hash MISMATCH for block " << i << std::endl;
            std::cerr << "  Raw (with hdr): ";
            for (size_t j = 0; j < SHA256_SIZE; j++)
                std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int)hashRaw[j];
            std::cerr << std::endl << "  Without header: ";
            for (size_t j = 0; j < SHA256_SIZE; j++)
                std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int)hashNoHeader[j];
            std::cerr << std::dec << std::endl;

            // Dump all hash slots for comparison
            for (size_t slot = 0; slot < totalHashes; slot++) {
                std::cerr << "  Slot " << slot << ":         ";
                for (size_t j = 0; j < SHA256_SIZE; j++)
                    std::cerr << std::hex << std::setfill('0') << std::setw(2)
                              << (int)signedContent[slot * SHA256_SIZE + j];
                std::cerr << std::dec << std::endl;
            }
#endif
            return VerificationResult::Invalid;
        }
    }

    return VerificationResult::Valid;
}

// --- Apollo card certificate verification ---

VerificationResult CardVerifier::verifyApolloCardCert(smartcard::PCSCConnection& conn, CardReaderBase& reader)
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

VerificationResult CardVerifier::verifyApolloSignature(smartcard::PCSCConnection& conn, CardReaderBase& reader,
                                                       uint8_t sigFileH, uint8_t sigFileL, uint8_t certFileH,
                                                       uint8_t certFileL,
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
    if (!certStore || !certStore->store)
        return false;

    const uint8_t* p = certDER.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(certDER.size()));
    if (!cert) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Failed to parse DER certificate (" << certDER.size() << " bytes)" << std::endl;
#endif
        return false;
    }

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_free(cert);
        return false;
    }

    int rc = X509_STORE_CTX_init(ctx, certStore->store, cert, nullptr);
    bool valid = false;
    if (rc == 1) {
        valid = (X509_verify_cert(ctx) == 1);
#ifndef NDEBUG
        if (!valid) {
            int err = X509_STORE_CTX_get_error(ctx);
            std::cerr << "[CardVerifier] X509_verify_cert error: " << X509_verify_cert_error_string(err) << " (" << err
                      << ")" << std::endl;
        }
#endif
    }

    X509_STORE_CTX_free(ctx);
    X509_free(cert);
    return valid;
}

bool CardVerifier::verifyPKCS7Signature(const std::vector<uint8_t>& pkcs7DER, std::vector<uint8_t>& extractedContent)
{
    if (!certStore || !certStore->store)
        return false;

    // Parse PKCS#7 structure
    const uint8_t* p = pkcs7DER.data();
    PKCS7* pkcs7 = d2i_PKCS7(nullptr, &p, static_cast<long>(pkcs7DER.size()));
    if (!pkcs7) {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] Failed to parse PKCS#7 data (" << pkcs7DER.size() << " bytes)" << std::endl;
        unsigned long err = ERR_get_error();
        if (err)
            std::cerr << "[CardVerifier] OpenSSL error: " << ERR_error_string(err, nullptr) << std::endl;
#endif
        return false;
    }

    // Create output BIO for extracted content
    BIO* contentBio = BIO_new(BIO_s_mem());
    if (!contentBio) {
        PKCS7_free(pkcs7);
        return false;
    }

    // Step 1: Verify the PKCS#7 signature (PKCS7_NOVERIFY = don't check cert chain yet)
    int rc = PKCS7_verify(pkcs7, nullptr, nullptr, nullptr, contentBio, PKCS7_NOVERIFY);
    if (rc != 1) {
#ifndef NDEBUG
        unsigned long err = ERR_get_error();
        std::cerr << "[CardVerifier] PKCS7_verify failed: " << (err ? ERR_error_string(err, nullptr) : "unknown error")
                  << std::endl;
#endif
        BIO_free(contentBio);
        PKCS7_free(pkcs7);
        return false;
    }

    // Extract the signed content
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(contentBio, &bptr);
    if (bptr && bptr->length > 0) {
        extractedContent.assign(reinterpret_cast<const uint8_t*>(bptr->data),
                                reinterpret_cast<const uint8_t*>(bptr->data) + bptr->length);
    }
    BIO_free(contentBio);

#ifndef NDEBUG
    std::cerr << "[CardVerifier] PKCS7 signature verified, extracted content: " << extractedContent.size() << " bytes"
              << std::endl;
#endif

    // Step 2: Verify the signer certificate chain against our trusted CAs
    STACK_OF(X509)* signerCerts = PKCS7_get0_signers(pkcs7, nullptr, 0);
    bool chainValid = false;

    if (signerCerts && sk_X509_num(signerCerts) > 0) {
        X509* signerCert = sk_X509_value(signerCerts, 0);

#ifndef NDEBUG
        // Print signer cert subject for debugging
        char* subject = X509_NAME_oneline(X509_get_subject_name(signerCert), nullptr, 0);
        if (subject) {
            std::cerr << "[CardVerifier] Signer cert subject: " << subject << std::endl;
            OPENSSL_free(subject);
        }
#endif

        X509_STORE_CTX* ctx = X509_STORE_CTX_new();
        if (ctx) {
            rc = X509_STORE_CTX_init(ctx, certStore->store, signerCert, nullptr);
            if (rc == 1) {
                chainValid = (X509_verify_cert(ctx) == 1);
#ifndef NDEBUG
                if (!chainValid) {
                    int err = X509_STORE_CTX_get_error(ctx);
                    std::cerr << "[CardVerifier] Signer cert chain error: " << X509_verify_cert_error_string(err)
                              << " (" << err << ")" << std::endl;
                }
#endif
            }
            X509_STORE_CTX_free(ctx);
        }
    } else {
#ifndef NDEBUG
        std::cerr << "[CardVerifier] No signer certificates found in PKCS#7" << std::endl;
#endif
    }

    if (signerCerts)
        sk_X509_free(signerCerts);
    PKCS7_free(pkcs7);

#ifndef NDEBUG
    std::cerr << "[CardVerifier] Signer cert chain: " << (chainValid ? "VALID" : "INVALID") << std::endl;
#endif
    return chainValid;
}

bool CardVerifier::verifyRSASignature(const std::vector<uint8_t>& certDER, const std::vector<uint8_t>& data,
                                      const std::vector<uint8_t>& signature)
{
    // Parse certificate to extract public key
    const uint8_t* p = certDER.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(certDER.size()));
    if (!cert)
        return false;

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    X509_free(cert);
    if (!pkey)
        return false;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    bool valid = false;

    // Try SHA-256 first (newer cards)
    if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
        EVP_DigestVerifyUpdate(mdctx, data.data(), data.size()) == 1 &&
        EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size()) == 1) {
        valid = true;
    }

    // If SHA-256 fails, try SHA-1 (some older Apollo cards may use it)
    if (!valid) {
        EVP_MD_CTX_reset(mdctx);
        if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha1(), nullptr, pkey) == 1 &&
            EVP_DigestVerifyUpdate(mdctx, data.data(), data.size()) == 1 &&
            EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size()) == 1) {
            valid = true;
        }
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return valid;
}

std::vector<uint8_t> CardVerifier::computeSHA256(const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> hash(EVP_MD_size(EVP_sha256()));

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return {};

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 || EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    EVP_MD_CTX_free(ctx);
    hash.resize(len);
    return hash;
}

} // namespace eidcard
