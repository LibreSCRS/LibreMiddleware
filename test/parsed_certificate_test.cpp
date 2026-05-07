// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Certificate/DistinguishedName.h>
#include <LibreSCRS/Certificate/ObjectIdentifier.h>
#include <LibreSCRS/Certificate/ParsedCertificate.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifndef LIBREMIDDLEWARE_TEST_DATA_DIR
#error "LIBREMIDDLEWARE_TEST_DATA_DIR must be defined by the build system"
#endif

namespace {

using LibreSCRS::Certificate::DistinguishedName;
using LibreSCRS::Certificate::DistinguishedNameComponent;
using LibreSCRS::Certificate::Extension;
using LibreSCRS::Certificate::KeyUsageBit;
using LibreSCRS::Certificate::ObjectIdentifier;
using LibreSCRS::Certificate::ParsedCertificate;
using LibreSCRS::Certificate::PublicKeyAlgorithm;

std::vector<std::uint8_t> readFile(const std::string& relPath)
{
    std::filesystem::path p = std::filesystem::path(LIBREMIDDLEWARE_TEST_DATA_DIR) / relPath;
    std::ifstream f(p, std::ios::binary);
    if (!f)
        return {};
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

} // namespace

// -----------------------------------------------------------------------------
// ObjectIdentifier
// -----------------------------------------------------------------------------

TEST(ObjectIdentifier, FriendlyNameLookup)
{
    EXPECT_EQ(ObjectIdentifier{"2.5.4.3"}.friendlyName(), "commonName");
    EXPECT_EQ(ObjectIdentifier{"1.3.6.1.5.5.7.3.1"}.friendlyName(), "TLS Web Server Authentication");
    EXPECT_TRUE(ObjectIdentifier{"1.999.888.777"}.friendlyName().empty());
}

TEST(ObjectIdentifier, EqualityAndOrdering)
{
    EXPECT_EQ(ObjectIdentifier{"2.5.4.3"}, ObjectIdentifier{"2.5.4.3"});
    EXPECT_NE(ObjectIdentifier{"2.5.4.3"}, ObjectIdentifier{"2.5.4.10"});
    // Default operator<=> is lexicographic on dottedDecimal — well-defined,
    // but not numeric. Use single-digit components for a robust ordering check.
    EXPECT_LT(ObjectIdentifier{"2.5.4.3"}, ObjectIdentifier{"2.5.4.5"});
}

// -----------------------------------------------------------------------------
// DistinguishedName
// -----------------------------------------------------------------------------

TEST(DistinguishedName, ConvenienceAccessorsResolve)
{
    DistinguishedName dn;
    dn.components.push_back({ObjectIdentifier{"2.5.4.3"}, "Test CN"});
    dn.components.push_back({ObjectIdentifier{"2.5.4.10"}, "Test Org"});
    dn.components.push_back({ObjectIdentifier{"1.999.888"}, "Custom Value"});
    EXPECT_EQ(dn.commonName(), "Test CN");
    EXPECT_EQ(dn.organization(), "Test Org");
    EXPECT_EQ(dn.locality(), "");
    EXPECT_EQ(dn.components.size(), 3u);
}

// -----------------------------------------------------------------------------
// ParsedCertificate — fromDer error paths
// -----------------------------------------------------------------------------

TEST(ParsedCertificate, MalformedDerReturnsNullopt)
{
    std::vector<std::uint8_t> garbage{0x00, 0x01, 0x02, 0x03};
    auto result = ParsedCertificate::fromDer(garbage);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, ParsedCertificate::ParseError::Kind::Invalid);
    EXPECT_FALSE(result.error().userMessage.key.empty()); // 4.0: userMessage mandatory
    EXPECT_TRUE(result.error().diagnosticDetail.has_value());
}

TEST(ParsedCertificate, EmptyInputReturnsNullopt)
{
    auto emptyResult = ParsedCertificate::fromDer(std::span<const std::uint8_t>{});
    ASSERT_FALSE(emptyResult.has_value());
    EXPECT_EQ(emptyResult.error().userMessage.key, "librescrs.error.cert.derInvalid");
}

// -----------------------------------------------------------------------------
// ParsedCertificate — identity, validity, signature
// -----------------------------------------------------------------------------

TEST(ParsedCertificate, ParsesValidDer)
{
    auto certDer = readFile("cert/serbian-rs-eid-issuer.der");
    ASSERT_FALSE(certDer.empty());
    auto cert = ParsedCertificate::fromDer(certDer);
    ASSERT_TRUE(cert.has_value());
    EXPECT_EQ(cert->subject().country(), "RS");
    EXPECT_FALSE(cert->subject().commonName().empty());
}

TEST(ParsedCertificate, ValidityDatesParsable)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/serbian-rs-eid-issuer.der"));
    ASSERT_TRUE(cert.has_value());
    EXPECT_LT(cert->notBefore(), cert->notAfter());
    EXPECT_LT(cert->notBefore(), std::chrono::system_clock::now());
}

TEST(ParsedCertificate, SerialNumberIsNonEmpty)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/tls-cert.der"));
    ASSERT_TRUE(cert.has_value());
    EXPECT_FALSE(cert->serialNumber().empty());
}

TEST(ParsedCertificate, SignatureAlgorithmDescription)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/tls-cert.der"));
    ASSERT_TRUE(cert.has_value());
    EXPECT_FALSE(cert->signatureAlgorithmDescription().empty());
    EXPECT_FALSE(cert->signatureValue().empty());
}

TEST(ParsedCertificate, DerBytesRoundTrip)
{
    auto bytes = readFile("cert/tls-cert.der");
    auto cert = ParsedCertificate::fromDer(bytes);
    ASSERT_TRUE(cert.has_value());
    auto der = cert->derBytes();
    ASSERT_EQ(der.size(), bytes.size());
    EXPECT_TRUE(std::equal(der.begin(), der.end(), bytes.begin()));
}

// -----------------------------------------------------------------------------
// ParsedCertificate — public key
// -----------------------------------------------------------------------------

TEST(ParsedCertificate, PublicKeyInfoForRsa)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/rsa-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto pk = cert->publicKey();
    EXPECT_EQ(pk.algorithm, PublicKeyAlgorithm::RSA);
    EXPECT_GE(pk.bitLength, 2048);
    EXPECT_TRUE(pk.algorithmDescription.starts_with("RSA"));
}

TEST(ParsedCertificate, PublicKeyInfoForEcdsa)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/ecdsa-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto pk = cert->publicKey();
    EXPECT_EQ(pk.algorithm, PublicKeyAlgorithm::ECDSA);
    EXPECT_FALSE(pk.curveOid.empty());
}

// -----------------------------------------------------------------------------
// ParsedCertificate — typed extensions
// -----------------------------------------------------------------------------

TEST(ParsedCertificate, KeyUsageReflectsExtension)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/signing-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto usage = cert->keyUsage();
    ASSERT_TRUE(usage.has_value());
    EXPECT_NE(std::find(usage->begin(), usage->end(), KeyUsageBit::DigitalSignature), usage->end());
    EXPECT_NE(std::find(usage->begin(), usage->end(), KeyUsageBit::NonRepudiation), usage->end());
}

TEST(ParsedCertificate, ExtendedKeyUsageReturnsOidsWithFriendlyNamesWhenKnown)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/tls-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto eku = cert->extendedKeyUsage();
    ASSERT_TRUE(eku.has_value());
    auto serverAuthIt = std::find_if(eku->begin(), eku->end(),
                                     [](const auto& oid) { return oid.dottedDecimal == "1.3.6.1.5.5.7.3.1"; });
    ASSERT_NE(serverAuthIt, eku->end());
    // LibreSCRS OID DB normalises EKU OIDs to their long-form name.
    EXPECT_EQ(serverAuthIt->friendlyName(), "TLS Web Server Authentication");
}

TEST(ParsedCertificate, BasicConstraintsCaTrue)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/ca-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto bc = cert->basicConstraints();
    ASSERT_TRUE(bc.has_value());
    EXPECT_TRUE(bc->isCa);
}

TEST(ParsedCertificate, SubjectAlternativeNamesParsed)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/tls-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto san = cert->subjectAlternativeNames();
    ASSERT_TRUE(san.has_value());
    bool hasDns = std::any_of(san->begin(), san->end(), [](const auto& gn) { return gn.value == "test.example.com"; });
    EXPECT_TRUE(hasDns);
}

TEST(ParsedCertificate, SubjectKeyIdentifierPresent)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/tls-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto ski = cert->subjectKeyIdentifier();
    ASSERT_TRUE(ski.has_value());
    EXPECT_FALSE(ski->empty());
}

TEST(ParsedCertificate, CrlDistributionPointsExtractedAsUrls)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/cert-with-crl-dp.der"));
    ASSERT_TRUE(cert.has_value());
    auto crls = cert->crlDistributionPoints();
    ASSERT_TRUE(crls.has_value());
    EXPECT_FALSE(crls->empty());
    EXPECT_TRUE(crls->front().starts_with("http"));
}

TEST(ParsedCertificate, OcspResponderUrlExtracted)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/tls-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto ocsp = cert->ocspResponderUrls();
    ASSERT_TRUE(ocsp.has_value());
    ASSERT_FALSE(ocsp->empty());
    EXPECT_EQ(ocsp->front(), "http://ocsp.example.com");
}

TEST(ParsedCertificate, CaIssuersUrlExtracted)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/tls-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto caUrls = cert->caIssuersUrls();
    ASSERT_TRUE(caUrls.has_value());
    ASSERT_FALSE(caUrls->empty());
    EXPECT_EQ(caUrls->front(), "http://ca.example.com/ca.crt");
}

TEST(ParsedCertificate, CertificatePoliciesPresent)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/tls-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto pols = cert->certificatePolicies();
    ASSERT_TRUE(pols.has_value());
    EXPECT_FALSE(pols->empty());
}

// -----------------------------------------------------------------------------
// ParsedCertificate — generic extensions
// -----------------------------------------------------------------------------

TEST(ParsedCertificate, ExtensionsEnumeratesAllIncludingUnknown)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/cert-with-custom-ext.der"));
    ASSERT_TRUE(cert.has_value());
    auto exts = cert->extensions();
    EXPECT_FALSE(exts.empty());
    bool hasUnknown = std::any_of(exts.begin(), exts.end(), [](const auto& e) { return e.oid.friendlyName().empty(); });
    EXPECT_TRUE(hasUnknown);
}

TEST(ParsedCertificate, FindExtensionByOid)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/tls-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto keyUsage = cert->findExtension(ObjectIdentifier{"2.5.29.15"});
    ASSERT_TRUE(keyUsage.has_value());
    EXPECT_EQ(keyUsage->oid.dottedDecimal, "2.5.29.15");
    EXPECT_FALSE(keyUsage->value.empty());
    EXPECT_TRUE(keyUsage->critical);
}

TEST(ParsedCertificate, FindExtensionMissingReturnsNullopt)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/rsa-cert.der"));
    ASSERT_TRUE(cert.has_value());
    auto missing = cert->findExtension(ObjectIdentifier{"1.3.6.1.4.1.99999.42.42"});
    EXPECT_FALSE(missing.has_value());
}

TEST(ParsedCertificate, AbsentTypedExtensionReturnsNullopt)
{
    // rsa-cert.der is a minimal self-signed cert without KU/EKU/SAN.
    auto cert = ParsedCertificate::fromDer(readFile("cert/rsa-cert.der"));
    ASSERT_TRUE(cert.has_value());
    EXPECT_FALSE(cert->extendedKeyUsage().has_value());
    EXPECT_FALSE(cert->subjectAlternativeNames().has_value());
    EXPECT_FALSE(cert->crlDistributionPoints().has_value());
}

// -----------------------------------------------------------------------------
// ParsedCertificate — move semantics
// -----------------------------------------------------------------------------

TEST(ParsedCertificate, MoveConstructorPreservesState)
{
    auto cert = ParsedCertificate::fromDer(readFile("cert/tls-cert.der"));
    ASSERT_TRUE(cert.has_value());
    ParsedCertificate moved(std::move(*cert));
    EXPECT_TRUE(static_cast<bool>(moved));
    EXPECT_FALSE(moved.subject().commonName().empty());
}
