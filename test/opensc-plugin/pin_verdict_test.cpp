// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// How the OpenSC plugin reads sc_pkcs15_verify_pin's answer: a verdict on the
// PIN (wrong, blocked) is told apart from every failure the PIN did not cause,
// because a refused one-shot PIN must never be presented a second time.

#include <gtest/gtest.h>

#include "opensc_pin_verdict.h"

#include <libopensc/errors.h>

namespace {

using LibreSCRS::OpenSc::PinVerdict;
using LibreSCRS::OpenSc::pinVerdictFromVerifyRc;

// A wrong PIN stays Incorrect whatever the retry counter says: drivers that
// bypass the ISO PIN command leave that counter at 0, so it cannot mean
// "blocked".
TEST(OpenScPinVerdict, VerifyAnswerMapsToAVerdict)
{
    EXPECT_EQ(pinVerdictFromVerifyRc(SC_SUCCESS), PinVerdict::Accepted);
    EXPECT_EQ(pinVerdictFromVerifyRc(SC_ERROR_PIN_CODE_INCORRECT), PinVerdict::Incorrect); // 63Cx
    EXPECT_EQ(pinVerdictFromVerifyRc(SC_ERROR_AUTH_METHOD_BLOCKED), PinVerdict::Blocked);  // 6983
}

TEST(OpenScPinVerdict, OnlyAnAnswerOnThePinIsAVerdict)
{
    // Not a verdict on the PIN: a reset and one retry may cure it.
    EXPECT_EQ(pinVerdictFromVerifyRc(SC_ERROR_CARD_RESET), PinVerdict::NotAVerdict);
    EXPECT_EQ(pinVerdictFromVerifyRc(SC_ERROR_SECURITY_STATUS_NOT_SATISFIED), PinVerdict::NotAVerdict);
    EXPECT_EQ(pinVerdictFromVerifyRc(SC_ERROR_CARD_REMOVED), PinVerdict::NotAVerdict);
    EXPECT_EQ(pinVerdictFromVerifyRc(SC_ERROR_TRANSMIT_FAILED), PinVerdict::NotAVerdict);
    // Refused by OpenSC before any APDU, so no card verdict either.
    EXPECT_EQ(pinVerdictFromVerifyRc(SC_ERROR_INVALID_PIN_LENGTH), PinVerdict::NotAVerdict);
}

} // namespace
