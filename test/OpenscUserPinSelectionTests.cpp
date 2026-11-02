// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief User-PIN selection tests for the opensc-plugin change seam (no
///        hardware).
///
/// Contract under test: the empty-selector change path must address the
/// AODF's user PIN, never pinObjs[0] —
/// on a card whose AODF lists its unblocking (PUK) PIN before the user's,
/// addressing index 0 spends the PUK's retry counter on a user credential
/// attempt instead.

#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>

#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdlib>
#include <string_view>
#include <vector>

// Internal seams defined in lib/opensc-plugin/src/opensc_card_plugin.cpp
// (compiled into this test binary). Alias underlying types must match the
// definition exactly — drift fails loudly at link time.
namespace LibreSCRS::OpenSc {
sc_pkcs15_object_t* resolveChangePinTarget(sc_pkcs15_object_t* const* pinObjs, int pinCount, std::string_view pinLabel);
} // namespace LibreSCRS::OpenSc

namespace {

sc_pkcs15_auth_info makeAuthInfo(int reference, int triesLeft, unsigned long flags)
{
    sc_pkcs15_auth_info info{};
    info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
    info.attrs.pin.flags = flags | SC_PKCS15_PIN_FLAG_INITIALIZED;
    info.attrs.pin.reference = reference;
    info.tries_left = triesLeft;
    info.max_tries = 3;
    return info;
}
sc_pkcs15_object makeAuthObject(sc_pkcs15_auth_info& info)
{
    sc_pkcs15_object obj{};
    obj.type = SC_PKCS15_TYPE_AUTH_PIN;
    obj.data = &info;
    return obj;
}

// [0] PUK (unblocking) -- [1] user PIN -- [2] SO PIN.
struct ThreeObjectAodf
{
    sc_pkcs15_auth_info pukInfo = makeAuthInfo(0x01, 3, SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN);
    sc_pkcs15_auth_info userInfo = makeAuthInfo(0x02, 3, 0);
    sc_pkcs15_auth_info soInfo = makeAuthInfo(0x03, 3, SC_PKCS15_PIN_FLAG_SO_PIN);
    sc_pkcs15_object puk = makeAuthObject(pukInfo);
    sc_pkcs15_object user = makeAuthObject(userInfo);
    sc_pkcs15_object so = makeAuthObject(soInfo);
    sc_pkcs15_object* objs[3] = {&puk, &user, &so};
};

} // namespace

TEST(OpenscUserPinSelection, EmptySelectorChangeAddressesTheUserPin)
{
    ThreeObjectAodf aodf;
    EXPECT_EQ(LibreSCRS::OpenSc::resolveChangePinTarget(aodf.objs, 3, {}), &aodf.user);
}

// The case a naive fix would miss: an AODF with no user PIN at all must
// address NOTHING, never fall back to index 0 (the PUK).
TEST(OpenscUserPinSelection, AllAuxiliaryAodfAddressesNothing)
{
    sc_pkcs15_auth_info pukInfo = makeAuthInfo(0x01, 3, SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN);
    sc_pkcs15_auth_info soInfo = makeAuthInfo(0x02, 3, SC_PKCS15_PIN_FLAG_SO_PIN);
    sc_pkcs15_object puk = makeAuthObject(pukInfo);
    sc_pkcs15_object so = makeAuthObject(soInfo);
    sc_pkcs15_object* objs[2] = {&puk, &so};

    EXPECT_EQ(LibreSCRS::OpenSc::resolveChangePinTarget(objs, 2, {}), nullptr)
        << "no user PIN in the AODF must address no PIN";
}

namespace LibreSCRS::OpenSc {
std::vector<sc_pkcs15_object_t*> allObjectsOfType(sc_pkcs15_card_t* p15card, unsigned int type);
} // namespace LibreSCRS::OpenSc

// Every object of a type is enumerated: a card with more keys than a fixed
// array held lost the rest, and a key that is not enumerated cannot be signed
// with.
TEST(OpenscObjectEnumeration, EveryKeyOfTheProfileIsEnumerated)
{
    sc_pkcs15_card_t* p15card = sc_pkcs15_card_new();
    ASSERT_NE(p15card, nullptr);
    constexpr int kKeys = 20;
    for (int i = 0; i < kKeys; ++i) {
        auto* obj = static_cast<sc_pkcs15_object_t*>(calloc(1, sizeof(sc_pkcs15_object_t)));
        ASSERT_NE(obj, nullptr);
        obj->type = SC_PKCS15_TYPE_PRKEY_RSA;
        ASSERT_EQ(sc_pkcs15_add_object(p15card, obj), SC_SUCCESS);
    }

    const auto keys = LibreSCRS::OpenSc::allObjectsOfType(p15card, SC_PKCS15_TYPE_PRKEY);
    EXPECT_EQ(keys.size(), static_cast<std::size_t>(kKeys));

    sc_pkcs15_card_free(p15card);
}
