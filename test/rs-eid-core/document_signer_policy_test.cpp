// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "detail/document_signer_policy.h"

#include <gtest/gtest.h>
#include <openssl/x509.h>

#include <memory>
#include <string>

namespace {

using LibreSCRS::RsEId::Core::detail::signerIsMupDocumentSigner;

struct X509Deleter
{
    void operator()(X509* p) const noexcept
    {
        X509_free(p);
    }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

// Build a bare certificate whose ISSUER CN is `issuerCn`. The policy predicate reads
// only the issuer CN, so no signing or chain is needed — this isolates the domain check.
X509Ptr certWithIssuerCn(const std::string& issuerCn)
{
    X509Ptr cert(X509_new());
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8,
                               reinterpret_cast<const unsigned char*>(issuerCn.c_str()),
                               static_cast<int>(issuerCn.size()), -1, 0);
    X509_set_issuer_name(cert.get(), name);
    X509_NAME_free(name);
    return cert;
}

// A certificate with a distinct SUBJECT CN and ISSUER CN — proves the predicate keys on
// the issuer, not the subject.
X509Ptr certWithSubjectAndIssuerCn(const std::string& subjectCn, const std::string& issuerCn)
{
    X509Ptr cert(X509_new());
    X509_NAME* subj = X509_NAME_new();
    X509_NAME_add_entry_by_NID(subj, NID_commonName, MBSTRING_UTF8,
                               reinterpret_cast<const unsigned char*>(subjectCn.c_str()),
                               static_cast<int>(subjectCn.size()), -1, 0);
    X509_set_subject_name(cert.get(), subj);
    X509_NAME_free(subj);

    X509_NAME* iss = X509_NAME_new();
    X509_NAME_add_entry_by_NID(iss, NID_commonName, MBSTRING_UTF8,
                               reinterpret_cast<const unsigned char*>(issuerCn.c_str()),
                               static_cast<int>(issuerCn.size()), -1, 0);
    X509_set_issuer_name(cert.get(), iss);
    X509_NAME_free(iss);
    return cert;
}

// --- Accept: every bundled MUP resources-branch CA generation ---

TEST(DocumentSignerPolicy, AcceptsGen2ResursiIssuer)
{
    // Current live signer StrongSecurityFormat_09 is issued by "MUPCA Resursi".
    auto c = certWithIssuerCn("MUPCA Resursi");
    EXPECT_TRUE(signerIsMupDocumentSigner(c.get()));
}

TEST(DocumentSignerPolicy, AcceptsGen4ResursiIssuer)
{
    auto c = certWithIssuerCn("MUP Resursi CA 4");
    EXPECT_TRUE(signerIsMupDocumentSigner(c.get()));
}

TEST(DocumentSignerPolicy, AcceptsGen1ResursiIssuer)
{
    auto c = certWithIssuerCn("Intermediate CA resursi 001");
    EXPECT_TRUE(signerIsMupDocumentSigner(c.get()));
}

TEST(DocumentSignerPolicy, AcceptsGen3ResursiIssuer)
{
    auto c = certWithIssuerCn("MUPCA Resursi 3");
    EXPECT_TRUE(signerIsMupDocumentSigner(c.get()));
}

// --- Reject: sibling branches under the same MUP roots ---

TEST(DocumentSignerPolicy, RejectsCitizenIssuerGen2)
{
    auto c = certWithIssuerCn("MUPCA Gradjani");
    EXPECT_FALSE(signerIsMupDocumentSigner(c.get()));
}

TEST(DocumentSignerPolicy, RejectsCitizenIssuerGen1)
{
    auto c = certWithIssuerCn("Intermediate CA gradjani 001");
    EXPECT_FALSE(signerIsMupDocumentSigner(c.get()));
}

TEST(DocumentSignerPolicy, RejectsOfficialsIssuer)
{
    auto c = certWithIssuerCn("MUP Sluzbenici CA 4");
    EXPECT_FALSE(signerIsMupDocumentSigner(c.get()));
}

// The in-tree fixture test-data/cert/serbian-rs-eid-issuer.der is CN="MUP Gradjani CA 4"
// (a citizen CA). A cert issued by it must be rejected as a SOD signer.
TEST(DocumentSignerPolicy, RejectsInTreeCitizenCaAsIssuer)
{
    auto c = certWithIssuerCn("MUP Gradjani CA 4");
    EXPECT_FALSE(signerIsMupDocumentSigner(c.get()));
}

// --- Reject: non-MUP / qualified CAs (the over-trust attack vector) ---

TEST(DocumentSignerPolicy, RejectsForeignQualifiedCaIssuer)
{
    auto c = certWithIssuerCn("Some Qualified Trust Services CA");
    EXPECT_FALSE(signerIsMupDocumentSigner(c.get()));
}

// The predicate keys on the ISSUER, not the subject: a cert whose subject looks like a
// document-signer but is issued by the citizen branch must be rejected.
TEST(DocumentSignerPolicy, KeysOnIssuerNotSubject)
{
    auto c = certWithSubjectAndIssuerCn("StrongSecurityFormat", "MUPCA Gradjani");
    EXPECT_FALSE(signerIsMupDocumentSigner(c.get()));
}

// Exclusion runs before acceptance: an issuer CN containing BOTH tokens is rejected.
TEST(DocumentSignerPolicy, RejectsIssuerContainingBothTokens)
{
    auto c = certWithIssuerCn("MUP Resursi i Gradjani CA");
    EXPECT_FALSE(signerIsMupDocumentSigner(c.get()));
}

// A Cyrillic homoglyph of "Resursi" must NOT match the ASCII token — documents that a
// homoglyph-spoofed issuer cannot slip through (the predicate assumes ASCII CNs).
TEST(DocumentSignerPolicy, RejectsCyrillicHomoglyphIssuer)
{
    auto c = certWithIssuerCn("МУПЦА Ресурси"); // Cyrillic
    EXPECT_FALSE(signerIsMupDocumentSigner(c.get()));
}

// --- Fail-closed edges ---

TEST(DocumentSignerPolicy, RejectsMissingCn)
{
    X509Ptr cert(X509_new()); // no issuer CN set
    EXPECT_FALSE(signerIsMupDocumentSigner(cert.get()));
}

TEST(DocumentSignerPolicy, RejectsNullptr)
{
    EXPECT_FALSE(signerIsMupDocumentSigner(nullptr));
}

TEST(DocumentSignerPolicy, MatchIsCaseInsensitive)
{
    auto c = certWithIssuerCn("mupca RESURSI");
    EXPECT_TRUE(signerIsMupDocumentSigner(c.get()));
}

} // namespace
