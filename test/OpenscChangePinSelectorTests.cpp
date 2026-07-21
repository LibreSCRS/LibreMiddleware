// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Selector-correctness tests for the opensc-plugin changePIN path.
///
/// Drives the plugin's change-dispatch seam with synthetic sc_pkcs15
/// auth objects and injected driver entry points — pure struct input, no
/// card I/O (the OpenscPinLifecycleTests harness pattern: the test target
/// compiles the plugin translation unit directly, so the seam needs no
/// symbol export from the plugin shared object).
///
/// Contract under test: a NON-EMPTY selector must mutate exactly the
/// addressed PIN object (matched by label or by the documented
/// "pin_<reference>" form) and a selector that matches nothing must be
/// refused as PluginError with ZERO driver dispatch; an EMPTY selector
/// keeps the legacy default-PIN behaviour (first enumerated object).

#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>

#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

// Internal seam defined in lib/opensc-plugin/src/opensc_card_plugin.cpp
// (compiled into this test binary). Alias underlying types must match the
// definition exactly — drift fails loudly at link time.
namespace LibreSCRS::OpenSc {
using ChangePinFn = int (*)(sc_pkcs15_card_t*, sc_pkcs15_object_t*, const unsigned char*, std::size_t,
                            const unsigned char*, std::size_t);
using RefreshPinInfoFn = int (*)(sc_pkcs15_card_t*, sc_pkcs15_object_t*);
LibreSCRS::Plugin::PINResult changePinWithSelector(sc_pkcs15_card_t* p15card, sc_pkcs15_object_t* const* pinObjs,
                                                   int pinCount, std::string_view pinLabel,
                                                   const LibreSCRS::Secure::String& oldPin,
                                                   const LibreSCRS::Secure::String& newPin, ChangePinFn changeFn,
                                                   RefreshPinInfoFn refreshFn);
std::vector<LibreSCRS::Plugin::PinStatusEntry> buildPinStatusEntries(sc_pkcs15_object_t* const* pinObjs, int pinCount,
                                                                     const char* driverShortName);
} // namespace LibreSCRS::OpenSc

using LibreSCRS::Plugin::PINResultOutcome;

namespace {

/// Everything the fake driver observed. Records the addressed object and
/// the credential LENGTHS only (never the bytes).
struct DriverLog
{
    std::vector<sc_pkcs15_object_t*> changeTargets;
    std::vector<std::size_t> oldLens;
    std::vector<std::size_t> newLens;
    int refreshCalls = 0;
};

DriverLog driverLog;

int fakeChangePin(sc_pkcs15_card_t* /*p15card*/, sc_pkcs15_object_t* pinObj, const unsigned char* /*oldPin*/,
                  std::size_t oldLen, const unsigned char* /*newPin*/, std::size_t newLen)
{
    driverLog.changeTargets.push_back(pinObj);
    driverLog.oldLens.push_back(oldLen);
    driverLog.newLens.push_back(newLen);
    return 0; // SC_SUCCESS
}

int fakeRefreshPinInfo(sc_pkcs15_card_t* /*p15card*/, sc_pkcs15_object_t* /*pinObj*/)
{
    ++driverLog.refreshCalls;
    return 0;
}

/// Builds a zeroed AUTH_PIN object wired to @p info (which must outlive
/// the returned object).
sc_pkcs15_object makeAuthObject(const char* label, sc_pkcs15_auth_info& info)
{
    sc_pkcs15_object obj{};
    obj.type = SC_PKCS15_TYPE_AUTH_PIN;
    std::strncpy(obj.label, label, sizeof(obj.label) - 1);
    obj.data = &info;
    return obj;
}

sc_pkcs15_auth_info makeAuthInfo(int reference, int triesLeft)
{
    sc_pkcs15_auth_info info{};
    info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED;
    info.attrs.pin.reference = reference;
    info.tries_left = triesLeft;
    return info;
}

/// Two-PIN fake card shared by every test: "pin-1-label" (ref 0x01) and
/// "pin-2-label" (ref 0x02).
struct TwoPinCard
{
    sc_pkcs15_auth_info firstInfo = makeAuthInfo(0x01, 3);
    sc_pkcs15_auth_info secondInfo = makeAuthInfo(0x02, 3);
    sc_pkcs15_object first = makeAuthObject("pin-1-label", firstInfo);
    sc_pkcs15_object second = makeAuthObject("pin-2-label", secondInfo);
    sc_pkcs15_object* objs[2] = {&first, &second};
};

LibreSCRS::Plugin::PINResult callChangePinOn(sc_pkcs15_object_t* const* objs, int count, std::string_view pinLabel)
{
    const LibreSCRS::Secure::String oldPin{"1234"};
    const LibreSCRS::Secure::String newPin{"56789"};
    return LibreSCRS::OpenSc::changePinWithSelector(nullptr, objs, count, pinLabel, oldPin, newPin, &fakeChangePin,
                                                    &fakeRefreshPinInfo);
}

LibreSCRS::Plugin::PINResult callChangePin(TwoPinCard& card, std::string_view pinLabel)
{
    return callChangePinOn(card.objs, 2, pinLabel);
}

} // namespace

// A selector naming the SECOND enumerated PIN object must dispatch the
// change to THAT object — never to the first one. Both documented selector
// forms (the object label and "pin_<reference>") address the same object.
TEST(OpenscChangePinSelector, SelectorTargetsAddressedObject)
{
    TwoPinCard card;

    driverLog = {};
    const auto byLabel = callChangePin(card, "pin-2-label");
    EXPECT_EQ(byLabel.outcome, PINResultOutcome::Ok);
    EXPECT_EQ(byLabel.retriesLeft, std::optional<int>{3});
    EXPECT_FALSE(byLabel.blocked);
    ASSERT_EQ(driverLog.changeTargets.size(), 1u);
    EXPECT_EQ(driverLog.changeTargets[0], &card.second);
    EXPECT_EQ(driverLog.oldLens[0], 4u);
    EXPECT_EQ(driverLog.newLens[0], 5u);

    driverLog = {};
    const auto byReference = callChangePin(card, "pin_2");
    EXPECT_EQ(byReference.outcome, PINResultOutcome::Ok);
    ASSERT_EQ(driverLog.changeTargets.size(), 1u);
    EXPECT_EQ(driverLog.changeTargets[0], &card.second);
}

// A non-empty selector that matches no PIN object is a refusal, not a
// fallback: PluginError with retriesLeft unset, not blocked, and ZERO
// driver dispatch (nothing reached the card).
TEST(OpenscChangePinSelector, UnknownSelectorRefusesWithoutCardMutation)
{
    TwoPinCard card;

    driverLog = {};
    const auto result = callChangePin(card, "no-such-pin");
    EXPECT_EQ(result.outcome, PINResultOutcome::PluginError);
    EXPECT_EQ(result.retriesLeft, std::nullopt);
    EXPECT_FALSE(result.blocked);
    EXPECT_TRUE(driverLog.changeTargets.empty());
    EXPECT_EQ(driverLog.refreshCalls, 0);
}

// Both directions of the selector contract: every label getPINList
// advertises — including the "pin_<reference>" substitute published for
// an empty AODF label — must resolve to exactly the object it was
// advertised for. An empty label may never surface as "" (which the
// contract reserves for the legacy default-PIN fallback and would alias
// this record onto a DIFFERENT credential).
TEST(OpenscChangePinSelector, AdvertisedLabelsResolveToTheirObjects)
{
    sc_pkcs15_auth_info labeledInfo = makeAuthInfo(0x01, 3);
    sc_pkcs15_auth_info unlabeledInfo = makeAuthInfo(0x02, 3);
    sc_pkcs15_object labeled = makeAuthObject("pin-1-label", labeledInfo);
    sc_pkcs15_object unlabeled = makeAuthObject("", unlabeledInfo);
    sc_pkcs15_object* objs[] = {&labeled, &unlabeled};

    const auto entries = LibreSCRS::OpenSc::buildPinStatusEntries(objs, 2, nullptr);
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].label, "pin-1-label");
    EXPECT_EQ(entries[1].label, "pin_2");

    for (std::size_t i = 0; i < entries.size(); ++i) {
        driverLog = {};
        const auto result = callChangePinOn(objs, 2, entries[i].label);
        EXPECT_EQ(result.outcome, PINResultOutcome::Ok) << "selector: " << entries[i].label;
        ASSERT_EQ(driverLog.changeTargets.size(), 1u) << "selector: " << entries[i].label;
        EXPECT_EQ(driverLog.changeTargets[0], objs[i]) << "selector: " << entries[i].label;
    }
}

// Regression guard for the legacy host path: an EMPTY selector keeps
// today's default-PIN behaviour — the FIRST enumerated object is changed.
TEST(OpenscChangePinSelector, EmptySelectorKeepsDefaultPinBehaviour)
{
    TwoPinCard card;

    driverLog = {};
    const auto result = callChangePin(card, "");
    EXPECT_EQ(result.outcome, PINResultOutcome::Ok);
    EXPECT_EQ(result.retriesLeft, std::optional<int>{3});
    EXPECT_FALSE(result.blocked);
    ASSERT_EQ(driverLog.changeTargets.size(), 1u);
    EXPECT_EQ(driverLog.changeTargets[0], &card.first);
    EXPECT_EQ(driverLog.refreshCalls, 1);
}
