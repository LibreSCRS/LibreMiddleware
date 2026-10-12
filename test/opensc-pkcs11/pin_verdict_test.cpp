// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// How the OpenSC slot reads sc_pkcs15_verify_pin's answer: a verdict on the
// PIN (wrong, blocked) is told apart from every failure the PIN did not cause,
// because a refused one-shot PIN must never be presented a second time.

#include <gtest/gtest.h>

#include "opensc_pin_verdict.h"

#include <internal/Crv.h>

#include <libopensc/errors.h>

namespace {

namespace Crv = LibreSCRS::Pkcs11::Internal::Crv;
using LibreSCRS::OpenSc::Pkcs11::crvFromVerifyRc;
using LibreSCRS::OpenSc::Pkcs11::refusalFromVerifyRc;

// OpenSC's own PKCS#11 mapping of the same answers. A wrong PIN stays
// PinIncorrect whatever the retry counter says: drivers that bypass the ISO
// PIN command leave that counter at 0, so it cannot mean "blocked".
TEST(OpenScPinVerdict, VerifyAnswerMapsToTheLoginReturnCode)
{
    EXPECT_EQ(crvFromVerifyRc(SC_SUCCESS), Crv::Ok);
    EXPECT_EQ(crvFromVerifyRc(SC_ERROR_PIN_CODE_INCORRECT), Crv::PinIncorrect); // 63Cx
    EXPECT_EQ(crvFromVerifyRc(SC_ERROR_AUTH_METHOD_BLOCKED), Crv::PinLocked);   // 6983
    EXPECT_EQ(crvFromVerifyRc(SC_ERROR_INVALID_PIN_LENGTH), Crv::PinLenRange);
    EXPECT_EQ(crvFromVerifyRc(SC_ERROR_CARD_REMOVED), Crv::DeviceError);
    EXPECT_EQ(crvFromVerifyRc(SC_ERROR_TRANSMIT_FAILED), Crv::DeviceError);
}

TEST(OpenScPinVerdict, OnlyAVerdictOnThePinIsARefusal)
{
    EXPECT_EQ(refusalFromVerifyRc(SC_ERROR_PIN_CODE_INCORRECT), Crv::PinIncorrect);
    EXPECT_EQ(refusalFromVerifyRc(SC_ERROR_AUTH_METHOD_BLOCKED), Crv::PinLocked);
    // Not a verdict on the PIN: a reset and one retry may cure it.
    EXPECT_EQ(refusalFromVerifyRc(SC_ERROR_CARD_RESET), Crv::DeviceError);
    EXPECT_EQ(refusalFromVerifyRc(SC_ERROR_SECURITY_STATUS_NOT_SATISFIED), Crv::DeviceError);
    // Refused by OpenSC before any APDU, so no card verdict either.
    EXPECT_EQ(refusalFromVerifyRc(SC_ERROR_INVALID_PIN_LENGTH), Crv::DeviceError);
}

} // namespace
