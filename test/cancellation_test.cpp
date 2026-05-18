// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "signing_test_support/pkcs11_token_mock.h"

// Signing cancellation / disconnect / concurrency tests.
//
// These bodies are placeholders that GTEST_SKIP() with a structured reason.
// Each one captures the exact assertion contract the production fix must
// deliver. They become live tests once @c IPkcs11Token from
// @c pkcs11_token_mock.h is wired into the signing modules and a
// @c LibreSCRS::CancelToken handle is plumbed through @c SigningService::sign.
//
// The placeholders are intentionally checked in (rather than left as TODOs)
// so the gtest discovery output continues to remind every contributor that
// these axes are NOT yet covered by automation.

namespace {
constexpr const char* kSkipReason = "Pkcs11Token concrete class — IPkcs11Token mock + CancelToken integration "
                                    "in SigningService::sign required before this scenario can run "
                                    "(see test/signing_test_support/pkcs11_token_mock.h)";
} // namespace

TEST(SigningCancellation, CancelBeforeSign_DoesNotConsumePinAttempt)
{
    // Contract once mockable:
    //   1. Construct a CancelToken in the cancelled state.
    //   2. Hand SigningService::sign a request + the cancelled token.
    //   3. Expect Status::UserCancelled (failureKind == UserCancelled).
    //   4. Mock token observes ZERO C_Login + ZERO C_Sign invocations
    //      (no PIN attempt consumed on the card).
    GTEST_SKIP() << kSkipReason;
    [[maybe_unused]] libresign::test::MockPkcs11Token mock;
}

TEST(SigningCancellation, CardDisconnectDuringSign)
{
    // Contract once mockable:
    //   1. Mock token's sign() throws "PKCS#11 error: 0x82" (CKR_TOKEN_REMOVED).
    //   2. SigningService::sign surfaces success=false +
    //      failureKind == SignFailureKind::CardError.
    //   3. No resource leak (mock destructor invoked exactly once).
    GTEST_SKIP() << kSkipReason;
    [[maybe_unused]] libresign::test::MockPkcs11Token mock;
    mock.errorOnSign = 0x82; // CKR_TOKEN_REMOVED
}

TEST(SigningCancellation, ConcurrentSignsOnSameCard_SerializeViaScopedLock)
{
    // Contract once mockable:
    //   1. Two threads concurrently call SigningService::sign with the same
    //      reader name + module.
    //   2. Inside the mock's sign(), record entry timestamps and sleep 50 ms
    //      before returning a value.
    //   3. Assert the two recorded intervals do NOT overlap — the per-reader
    //      scoped lock (LibreSCRS::SmartCard) serialises them on the same
    //      physical card.
    GTEST_SKIP() << kSkipReason;
}
