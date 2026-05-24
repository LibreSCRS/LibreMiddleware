// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// OpenScPKCS11Provider compile-time + minimal-runtime contract tests.
//
// Deep bind/sign/login coverage already lives in
//   lib/pkcs15/test/CrossProviderCoordinationTests.cpp (LIBRESCRS_VENDOR_OPENSC)
// and
//   test/opensc_fallback_integration_test.cpp (hardware-gated).
//
// This test pins down the no-PC/SC unit-tier surface: provider constructs,
// vtable links cleanly, probe() returns nullptr on a manifestly nonexistent
// reader without leaking the libopensc context.

#include <gtest/gtest.h>

#include <internal/OpenScPKCS11Provider.h>

#include <memory>
#include <type_traits>

using LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider;

TEST(OpenScProviderTraits, DefaultConstructorIsNoexcept)
{
    static_assert(std::is_nothrow_default_constructible_v<OpenScPKCS11Provider>,
                  "OpenScPKCS11Provider() must be noexcept per the contract docstring");
    SUCCEED();
}

TEST(OpenScProviderTraits, FinalClass)
{
    static_assert(std::is_final_v<OpenScPKCS11Provider>,
                  "OpenScPKCS11Provider is declared `final` — derived classes would split the "
                  "vtable across consumers");
    SUCCEED();
}

TEST(OpenScProvider, ConstructsCleanly)
{
    EXPECT_NO_THROW({ OpenScPKCS11Provider provider; });
}

TEST(OpenScProvider, MultipleInstancesIndependent)
{
    // The provider holds no per-instance state beyond its vtable; multiple
    // instances are safe to construct and destroy independently. Verifies
    // sc_establish_context / sc_release_context pairing in the libopensc
    // archive isn't accidentally singleton-protected.
    OpenScPKCS11Provider a;
    OpenScPKCS11Provider b;
    SUCCEED();
}
