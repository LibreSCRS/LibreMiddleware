// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include <LibreSCRS/Signing/SigningResult.h>

#include "detail/ErrorClassifier.h"
#include <types.h>

namespace {

using libresign::SignFailureKind;

/// Canonical source-of-truth list of every @ref libresign::SignFailureKind
/// value. The bridge mapping switches (in @ref ErrorClassifier.h) close on
/// the enum under @c -Wswitch-enum, so adding a new kind already breaks the
/// build at the bridge. This array additionally locks the cardinality at
/// the test layer: a new kind without a matching entry here fails
/// @c kAllListsEveryKind at runtime.
constexpr SignFailureKind kAll[] = {
    SignFailureKind::TsaUnreachable,
    SignFailureKind::RevocationFetchFailed,
    SignFailureKind::CardError,
    SignFailureKind::PinFailed,
    SignFailureKind::UserCancelled,
    SignFailureKind::InvalidInput,
    SignFailureKind::PdfPreparationError,
    SignFailureKind::XmlSerializationError,
    SignFailureKind::JsonSerializationError,
    SignFailureKind::ZipBuildError,
    SignFailureKind::OpensslError,
    SignFailureKind::PolicyViolation,
    SignFailureKind::EngineError,
    SignFailureKind::KeyAmbiguous,
};

TEST(SignFailureKindTest, ArrayLocksCardinality)
{
    EXPECT_EQ(sizeof(kAll) / sizeof(kAll[0]), 14u);
}

TEST(SignFailureKindTest, EveryKindMapsToNonEmptyUserMessage)
{
    for (auto k : kAll) {
        auto msg = LibreSCRS::Signing::detail::kindToUserMessage(k);
        EXPECT_FALSE(msg.key.empty()) << "SignFailureKind value " << static_cast<int>(k)
                                      << " mapped to LocalizedText with empty key";
        EXPECT_FALSE(msg.defaultText.empty())
            << "SignFailureKind value " << static_cast<int>(k) << " mapped to LocalizedText with empty defaultText";
    }
}

TEST(SignFailureKindTest, EveryKindMapsToNonOkStatus)
{
    using S = LibreSCRS::Signing::SigningResult::Status;
    for (auto k : kAll) {
        libresign::SigningResult r;
        r.success = false;
        r.failureKind = k;
        EXPECT_NE(LibreSCRS::Signing::detail::classifyLibresignError(r), S::Ok)
            << "SignFailureKind value " << static_cast<int>(k) << " unexpectedly classified as Status::Ok";
    }
}

} // namespace
