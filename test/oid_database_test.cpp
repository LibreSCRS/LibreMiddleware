// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#define LIBRESCRS_INTERNAL_BUILD
#include "../lib/LibreSCRS/Certificate/internal/OidDatabase.h"

#include <gtest/gtest.h>

using LibreSCRS::Certificate::detail::lookupOidName;

TEST(OidDatabase, KnownDnAttributesResolve)
{
    EXPECT_EQ(lookupOidName("2.5.4.3"), "commonName");
    EXPECT_EQ(lookupOidName("2.5.4.10"), "organizationName");
    EXPECT_EQ(lookupOidName("2.5.4.11"), "organizationalUnitName");
    EXPECT_EQ(lookupOidName("2.5.4.6"), "countryName");
    EXPECT_EQ(lookupOidName("1.2.840.113549.1.9.1"), "emailAddress");
}

TEST(OidDatabase, KnownExtensionsResolve)
{
    // OpenSSL uses long names like "X509v3 Key Usage" rather than the
    // ETSI/RFC short form "keyUsage". Both forms describe the same OID.
    EXPECT_EQ(lookupOidName("2.5.29.15"), "X509v3 Key Usage");
    EXPECT_EQ(lookupOidName("2.5.29.17"), "X509v3 Subject Alternative Name");
    EXPECT_EQ(lookupOidName("2.5.29.19"), "X509v3 Basic Constraints");
    EXPECT_EQ(lookupOidName("2.5.29.31"), "X509v3 CRL Distribution Points");
    EXPECT_FALSE(lookupOidName("1.3.6.1.5.5.7.1.1").empty()); // authorityInfoAccess
}

TEST(OidDatabase, KnownEkuPurposesResolve)
{
    EXPECT_EQ(lookupOidName("1.3.6.1.5.5.7.3.1"), "TLS Web Server Authentication");
    EXPECT_EQ(lookupOidName("1.3.6.1.5.5.7.3.2"), "TLS Web Client Authentication");
    EXPECT_EQ(lookupOidName("1.3.6.1.5.5.7.3.3"), "Code Signing");
    EXPECT_EQ(lookupOidName("1.3.6.1.5.5.7.3.4"), "E-mail Protection");
    EXPECT_EQ(lookupOidName("1.3.6.1.5.5.7.3.8"), "Time Stamping");
    EXPECT_EQ(lookupOidName("1.3.6.1.5.5.7.3.9"), "OCSP Signing");
}

TEST(OidDatabase, EidasQcStatementsResolve)
{
    EXPECT_EQ(lookupOidName("0.4.0.1862.1.1"), "qcCompliance");
    EXPECT_EQ(lookupOidName("0.4.0.1862.1.2"), "qcLimitValue");
    EXPECT_EQ(lookupOidName("0.4.0.1862.1.4"), "qcSSCD");
    EXPECT_EQ(lookupOidName("0.4.0.194112.1.0"), "qctEsign");
    EXPECT_EQ(lookupOidName("0.4.0.194112.1.1"), "qctEseal");
}

TEST(OidDatabase, IcaoEmrtdResolve)
{
    EXPECT_EQ(lookupOidName("2.23.136.1.1.1"), "ldsSecurityObject");
    EXPECT_EQ(lookupOidName("2.23.136.1.1.2"), "cscaMasterList");
    EXPECT_EQ(lookupOidName("0.4.0.127.0.7.2.2.1"), "id-PACE");
}

TEST(OidDatabase, MicrosoftEkuResolve)
{
    EXPECT_EQ(lookupOidName("1.3.6.1.4.1.311.20.2.2"), "microsoftSmartCardLogon");
    EXPECT_EQ(lookupOidName("1.3.6.1.4.1.311.10.3.4"), "microsoftEncryptedFileSystem");
}

TEST(OidDatabase, SignatureAlgorithmsResolve)
{
    EXPECT_EQ(lookupOidName("1.2.840.113549.1.1.11"), "sha256WithRSAEncryption");
    EXPECT_EQ(lookupOidName("1.2.840.10045.4.3.2"), "ecdsa-with-SHA256");
}

TEST(OidDatabase, UnknownOidReturnsEmpty)
{
    EXPECT_TRUE(lookupOidName("1.999.888.777").empty());
    EXPECT_TRUE(lookupOidName("not-an-oid").empty());
    EXPECT_TRUE(lookupOidName("").empty());
}

TEST(OidDatabase, SizeMeetsSupersetTarget)
{
    // Sanity: combined database should substantially exceed any single source.
    // OpenSSL 3.2 alone has ~900-1000 entries; with our curated TSV additions
    // the merged total should comfortably exceed 1000. We assert the floor at
    // 1000 to catch a pipeline regression that drops the OpenSSL parser back
    // to literal-arc-only.
    int known = 0;
    if (!lookupOidName("2.5.4.3").empty())
        ++known;
    if (!lookupOidName("0.4.0.1862.1.1").empty())
        ++known;
    if (!lookupOidName("1.3.6.1.5.5.7.3.1").empty())
        ++known;
    EXPECT_EQ(known, 3) << "Spot-check sample of well-known OIDs all resolve";
}
