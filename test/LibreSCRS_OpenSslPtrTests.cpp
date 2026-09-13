// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The two X509-stack pointers, and the distinction no compiler used to be able
// to check.
//
// Two structures with the SAME name lived in this tree, in two namespaces, and
// did opposite things to the same argument: one popped and freed every
// certificate in the stack, the other freed only the stack. A line moved
// between the two files was a double free or a leak, with no diagnostic
// anywhere and no test that could tell.
//
// What can be asserted here, and what cannot, stated plainly. That the OWNING
// deleter running over borrowed certificates is a double free is not observable
// from inside the process without a sanitizer, and this repository configures
// none -- there is no -fsanitize leg in its CMake or in its CI. So the pin is
// two-part: the types are DIFFERENT types, so a call site cannot take the wrong
// one by copy-paste and still compile; and both ownership shapes are driven
// here end to end, so a sanitizer leg added later inherits the coverage without
// anyone having to write these cases again.

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <gtest/gtest.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <type_traits>
#include <vector>

using LibreSCRS::Internal::Crypto::BnPtr;
using LibreSCRS::Internal::Crypto::EvpPkeyPtr;
using LibreSCRS::Internal::Crypto::X509StackBorrowedDeleter;
using LibreSCRS::Internal::Crypto::X509StackBorrowedPtr;
using LibreSCRS::Internal::Crypto::X509StackOwningDeleter;
using LibreSCRS::Internal::Crypto::X509StackOwningPtr;

namespace {

/// A self-signed certificate, minted so the ownership cases have something real
/// to hold. Nothing here depends on its contents.
LibreSCRS::Internal::Crypto::X509Ptr mintCert()
{
    EvpPkeyPtr key(EVP_RSA_gen(2048));
    if (!key) {
        return {};
    }
    LibreSCRS::Internal::Crypto::X509Ptr cert(X509_new());
    if (!cert) {
        return {};
    }
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
    X509_set_pubkey(cert.get(), key.get());
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("owning-vs-borrowed"),
                               -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) {
        return {};
    }
    return cert;
}

} // namespace

// The mechanism. Neither pointer is called what either of the two originals was
// called, and they are not the same type, so the migration could not be done by
// leaving the name alone -- every call site had to be read once and answered.
TEST(OpenSslStackPtr, OwningAndBorrowedAreDistinctTypes)
{
    static_assert(!std::is_same_v<X509StackOwningDeleter, X509StackBorrowedDeleter>,
                  "the two deleters must not collapse into one type");
    static_assert(!std::is_same_v<X509StackOwningPtr, X509StackBorrowedPtr>,
                  "the two pointers must not collapse into one type");
    static_assert(!std::is_assignable_v<X509StackOwningPtr&, X509StackBorrowedPtr&&>,
                  "a borrowed stack must not be assignable into an owning one");
    static_assert(!std::is_assignable_v<X509StackBorrowedPtr&, X509StackOwningPtr&&>,
                  "an owning stack must not be assignable into a borrowed one");
    SUCCEED();
}

// The owning shape: a stack this code built and holds the only reference to.
TEST(OpenSslStackPtr, OwningFreesTheMembersItWasHandedOwnershipOf)
{
    auto cert = mintCert();
    ASSERT_TRUE(cert);
    {
        X509StackOwningPtr stack(sk_X509_new_null());
        ASSERT_TRUE(stack);
        // The stack takes over the reference this scope holds.
        ASSERT_GT(sk_X509_push(stack.get(), cert.release()), 0);
        EXPECT_EQ(sk_X509_num(stack.get()), 1);
    }
    // Nothing to assert about the certificate afterwards -- it is gone, which
    // is the contract. The case exists so the owning path is exercised at all.
    SUCCEED();
}

// The borrowed shape: exactly what PKCS7_get0_signers hands back. The
// certificates belong to the parent structure, and after the stack dies they
// must still be readable through it.
TEST(OpenSslStackPtr, BorrowedLeavesItsMembersToTheirOwner)
{
    auto owner = mintCert();
    ASSERT_TRUE(owner);
    {
        X509StackBorrowedPtr stack(sk_X509_new_null());
        ASSERT_TRUE(stack);
        // No reference transferred: the scope above still owns the certificate.
        ASSERT_GT(sk_X509_push(stack.get(), owner.get()), 0);
        EXPECT_EQ(sk_X509_num(stack.get()), 1);
    }
    // Still usable: had the owning deleter run here, this read would be a use
    // after free -- silent today, loud under a sanitizer leg.
    X509_NAME* subject = X509_get_subject_name(owner.get());
    ASSERT_NE(subject, nullptr);
    char buf[128] = {};
    EXPECT_NE(X509_NAME_get_text_by_NID(subject, NID_commonName, buf, sizeof(buf)), -1);
    EXPECT_STREQ(buf, "owning-vs-borrowed");
}

// The call this whole distinction exists for, driven for real: PKCS7_get0_signers
// returns a stack whose certificates are owned by the PKCS7 structure.
TEST(OpenSslStackPtr, Pkcs7SignersAreBorrowedFromTheirParent)
{
    auto cert = mintCert();
    ASSERT_TRUE(cert);

    LibreSCRS::Internal::Crypto::Pkcs7Ptr p7(PKCS7_new());
    ASSERT_TRUE(p7);
    ASSERT_EQ(PKCS7_set_type(p7.get(), NID_pkcs7_signed), 1);
    ASSERT_EQ(PKCS7_content_new(p7.get(), NID_pkcs7_data), 1);
    ASSERT_EQ(PKCS7_add_certificate(p7.get(), cert.get()), 1);

    {
        // get0: borrowed. The stack is ours to free; its contents are not.
        X509StackBorrowedPtr signers(PKCS7_get0_signers(p7.get(), nullptr, PKCS7_NOVERIFY));
        // Whether any signer is found depends on the structure; what matters is
        // that the stack is released without touching the parent's certificates.
    }

    // The parent still holds its certificate.
    STACK_OF(X509)* held = p7->d.sign != nullptr ? p7->d.sign->cert : nullptr;
    ASSERT_NE(held, nullptr);
    EXPECT_EQ(sk_X509_num(held), 1);
    EXPECT_NE(X509_get_subject_name(sk_X509_value(held, 0)), nullptr);
}

namespace {

constexpr int kProbeBytes = 64;
constexpr int kWordBytes = 8;
constexpr int kProbeWords = kProbeBytes / kWordBytes;
constexpr unsigned char kPattern = 0xAB;

// Builds a BIGNUM out of a known pattern, releases it through `release`, then
// immediately asks the allocator for the same number of bytes and counts how
// many whole words of the pattern are still readable there.
//
// This is a probe, not a proof: whether the allocator hands back the same chunk
// is its business. The control leg below is what makes the probe honest -- if
// plain BN_free leaves nothing either, the probe could not observe anything on
// this platform and the case skips instead of passing.
//
// Whole words rather than bytes, because the allocator writes its own
// bookkeeping into the head of a freed chunk and on glibc part of that is a
// per-process random key. Counted a byte at a time, one byte of that key can
// equal the pattern by chance and score as a survivor, turning a deleter that
// wiped everything red at random. A random eight-byte word equal to the pattern
// has no such chance, and the words the bookkeeping overwrites are lost alike.
template <class Release>
int survivingPatternWords(Release release)
{
    std::vector<unsigned char> pattern(kProbeBytes, kPattern);
    BIGNUM* bn = BN_bin2bn(pattern.data(), kProbeBytes, nullptr);
    if (bn == nullptr) {
        return -1;
    }
    release(bn);

    auto* reused = static_cast<unsigned char*>(OPENSSL_malloc(kProbeBytes));
    if (reused == nullptr) {
        return -1;
    }
    int surviving = 0;
    for (int w = 0; w < kProbeWords; ++w) {
        bool intact = true;
        for (int i = 0; i < kWordBytes; ++i) {
            intact = intact && reused[w * kWordBytes + i] == kPattern;
        }
        if (intact) {
            ++surviving;
        }
    }
    OPENSSL_free(reused);
    return surviving;
}

} // namespace

// PACE holds three secrets that exist ONLY as a BIGNUM -- the ephemeral private
// keys skMap/skAgree, the x-coordinate of the ECDH shared secret K, and the
// decrypted nonce s. CleanseGuard cannot reach any of them: it wipes
// std::vector, and the ephemeral private key has no vector copy at all.
//
// So the deleter is the only thing standing between those bytes and a core
// dump, a swap page, or the next allocation of the same size. This case drives
// exactly that, against a control that proves the probe can see anything here.
TEST(OpenSslBnPtr, DeleterZeroesTheLimbBufferBeforeReleasingIt)
{
    const int control = survivingPatternWords([](BIGNUM* p) { BN_free(p); });
    ASSERT_GE(control, 0) << "allocation failed; nothing was measured";
    if (control == 0) {
        GTEST_SKIP() << "this allocator did not return the freed chunk, so the "
                        "probe cannot observe cleansing either way";
    }

    const int throughDeleter = survivingPatternWords([](BIGNUM* p) { BnPtr guard(p); });
    ASSERT_GE(throughDeleter, 0) << "allocation failed; nothing was measured";

    EXPECT_EQ(throughDeleter, 0) << throughDeleter << " of " << kProbeWords
                                 << " words of the secret stayed readable in the released heap after "
                                    "BnPtr ran its deleter (plain BN_free left "
                                 << control
                                 << "). PACE ephemeral "
                                    "private keys are freed through this deleter and nothing else wipes "
                                    "them.";
}
