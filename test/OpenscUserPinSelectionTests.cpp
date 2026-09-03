// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief User-PIN selection tests for the opensc-plugin verify/change/counter
///        seams (no hardware).
///
/// Contract under test: verify, the empty-selector change path, and the
/// counter read must all address the AODF's user PIN, never pinObjs[0] —
/// on a card whose AODF lists its unblocking (PUK) PIN before the user's,
/// addressing index 0 spends the PUK's retry counter on a user credential
/// attempt instead.

#include <LibreSCRS/Plugin/CredentialCounters.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>

#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

#include <gtest/gtest.h>

#include <cstddef>
#include <string_view>
#include <vector>

// Internal seams defined in lib/opensc-plugin/src/opensc_card_plugin.cpp
// (compiled into this test binary). Alias underlying types must match the
// definition exactly — drift fails loudly at link time.
namespace LibreSCRS::OpenSc {
using VerifyPinFn = int (*)(sc_pkcs15_card_t*, sc_pkcs15_object_t*, const unsigned char*, std::size_t);
using RefreshPinInfoFn = int (*)(sc_pkcs15_card_t*, sc_pkcs15_object_t*);
LibreSCRS::Plugin::PINResult verifyPinOnUserObject(sc_pkcs15_card_t* p15card, sc_pkcs15_object_t* const* pinObjs,
                                                   int pinCount, const LibreSCRS::Secure::String& pin,
                                                   VerifyPinFn verifyFn, RefreshPinInfoFn refreshFn);
LibreSCRS::Plugin::CredentialCounters readCountersFromUserPin(sc_pkcs15_card_t* p15card,
                                                              sc_pkcs15_object_t* const* pinObjs, int pinCount,
                                                              RefreshPinInfoFn refreshFn);
sc_pkcs15_object_t* resolveChangePinTarget(sc_pkcs15_object_t* const* pinObjs, int pinCount, std::string_view pinLabel);
} // namespace LibreSCRS::OpenSc

namespace {

struct DriverLog
{
    std::vector<sc_pkcs15_object_t*> verifyTargets;
    std::vector<sc_pkcs15_object_t*> changeTargets;
    int refreshCalls = 0;
};
DriverLog driverLog;

int fakeVerifyPin(sc_pkcs15_card_t*, sc_pkcs15_object_t* obj, const unsigned char*, std::size_t)
{
    driverLog.verifyTargets.push_back(obj);
    return 0; // SC_SUCCESS
}
int fakeRefreshPinInfo(sc_pkcs15_card_t*, sc_pkcs15_object_t*)
{
    ++driverLog.refreshCalls;
    return 0;
}

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

TEST(OpenscUserPinSelection, VerifyAddressesTheUserPinNotTheFirstObject)
{
    ThreeObjectAodf aodf;
    driverLog = {};
    const LibreSCRS::Secure::String pin{"1234"};
    LibreSCRS::OpenSc::verifyPinOnUserObject(nullptr, aodf.objs, 3, pin, &fakeVerifyPin, &fakeRefreshPinInfo);
    ASSERT_EQ(driverLog.verifyTargets.size(), 1u);
    EXPECT_EQ(driverLog.verifyTargets[0], &aodf.user);
}

TEST(OpenscUserPinSelection, EmptySelectorChangeAddressesTheUserPin)
{
    ThreeObjectAodf aodf;
    EXPECT_EQ(LibreSCRS::OpenSc::resolveChangePinTarget(aodf.objs, 3, {}), &aodf.user);
}

// The case a naive fix would miss: an AODF with no user PIN at all must
// dispatch NOTHING, never fall back to index 0 (the PUK).
TEST(OpenscUserPinSelection, AllAuxiliaryAodfDispatchesNothing)
{
    sc_pkcs15_auth_info pukInfo = makeAuthInfo(0x01, 3, SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN);
    sc_pkcs15_auth_info soInfo = makeAuthInfo(0x02, 3, SC_PKCS15_PIN_FLAG_SO_PIN);
    sc_pkcs15_object puk = makeAuthObject(pukInfo);
    sc_pkcs15_object so = makeAuthObject(soInfo);
    sc_pkcs15_object* objs[2] = {&puk, &so};

    driverLog = {};
    const LibreSCRS::Secure::String pin{"1234"};
    LibreSCRS::OpenSc::verifyPinOnUserObject(nullptr, objs, 2, pin, &fakeVerifyPin, &fakeRefreshPinInfo);
    EXPECT_TRUE(driverLog.verifyTargets.empty()) << "no user PIN in the AODF must dispatch zero APDUs";
}

TEST(OpenscUserPinSelection, CountersComeFromTheUserPin)
{
    ThreeObjectAodf aodf;
    aodf.userInfo.tries_left = 2;
    aodf.pukInfo.tries_left = 1; // if this leaked through, the test would see 1
    const auto counters = LibreSCRS::OpenSc::readCountersFromUserPin(nullptr, aodf.objs, 3, &fakeRefreshPinInfo);
    ASSERT_TRUE(counters.retriesLeft.has_value());
    EXPECT_EQ(*counters.retriesLeft, 2);
}
