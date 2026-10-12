// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// OpenScSlot::verifyContextPin decides what it may VERIFY before it touches the
// card: a key the card does not flag user_consent is refused as a bad argument,
// so a context login can never spend a try of the PIN for an ordinary key.
// Driven with an unbound OpenScCard -- no reader, no PC/SC. What happens after
// the gate (sc_pkcs15_verify_pin, the signature in the same transaction) needs
// a bound sc_pkcs15_card_t and is left to the hardware tests.

#include <gtest/gtest.h>

#include "opensc_card.h"
#include "opensc_slot.h"

#include <internal/Crv.h>

#include <libopensc/pkcs15.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace {

namespace Crv = LibreSCRS::Pkcs11::Internal::Crv;
using LibreSCRS::OpenSc::Pkcs11::OpenScCard;
using LibreSCRS::OpenSc::Pkcs11::OpenScSlot;

struct KeyObject
{
    explicit KeyObject(std::uint8_t id, bool perOperation)
    {
        info.id.value[0] = id;
        info.id.len = 1;
        object.type = SC_PKCS15_TYPE_PRKEY_RSA;
        object.data = &info;
        object.user_consent = perOperation ? 1 : 0;
    }
    sc_pkcs15_prkey_info_t info{};
    sc_pkcs15_object_t object{};
};

class OpenScContextPinGate : public ::testing::Test
{
protected:
    std::unique_ptr<OpenScSlot> slotOver(std::weak_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> parent)
    {
        return std::make_unique<OpenScSlot>(std::move(parent), std::vector<std::uint8_t>{0x01}, "PIN", &pinObject,
                                            std::vector<sc_pkcs15_object_t*>{&ordinary.object, &perOperation.object},
                                            std::vector<sc_pkcs15_object_t*>{},
                                            LibreSCRS::Pkcs11::Internal::PKCS11TokenInfo{}, 1UL);
    }

    sc_pkcs15_object_t pinObject{};
    KeyObject ordinary{0x01, false};
    KeyObject perOperation{0x02, true};
    const std::vector<std::uint8_t> pin{'1', '2', '3', '4'};
};

TEST_F(OpenScContextPinGate, OrdinaryOrUnknownKeyIsABadArgument)
{
    auto card = std::make_shared<OpenScCard>();
    auto slot = slotOver(card);
    EXPECT_EQ(slot->verifyContextPin(std::vector<std::uint8_t>{0x01}, pin), Crv::ArgumentsBad)
        << "a key without user_consent takes no context login";
    EXPECT_EQ(slot->verifyContextPin(std::vector<std::uint8_t>{0x7F}, pin), Crv::ArgumentsBad);
}

TEST_F(OpenScContextPinGate, PerOperationKeyNeedsABoundCard)
{
    auto card = std::make_shared<OpenScCard>();
    auto slot = slotOver(card);
    EXPECT_EQ(slot->verifyContextPin(std::vector<std::uint8_t>{0x02}, pin), Crv::DeviceError)
        << "past the gate, an unbound card has nothing to VERIFY with";

    std::weak_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> gone;
    {
        auto transient = std::make_shared<OpenScCard>();
        gone = transient;
    }
    EXPECT_EQ(slotOver(gone)->verifyContextPin(std::vector<std::uint8_t>{0x02}, pin), Crv::DeviceError);
}

} // namespace
