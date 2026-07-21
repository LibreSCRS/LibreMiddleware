// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Lifecycle classification tests for the opensc-plugin PIN path.
///
/// Drives the plugin's evidence-building seam with synthetic sc_pkcs15
/// auth objects — pure struct construction, no card I/O, mirroring the
/// getPINList non-consumption invariant. The test target compiles the
/// plugin translation unit directly (same pattern OpenScBridgeTests uses
/// for the reader bridge), so the seam needs no symbol export from the
/// plugin shared object.

#include <LibreSCRS/Plugin/PinStatusEntry.h>

#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

// Internal seam defined in lib/opensc-plugin/src/opensc_card_plugin.cpp
// (compiled into this test binary).
namespace LibreSCRS::OpenSc {
std::vector<LibreSCRS::Plugin::PinStatusEntry> buildPinStatusEntries(sc_pkcs15_object_t* const* pinObjs, int pinCount,
                                                                     const char* driverShortName);
} // namespace LibreSCRS::OpenSc

using LibreSCRS::Plugin::PinKind;
using LibreSCRS::Plugin::PinRecovery;
using LibreSCRS::Plugin::PinState;
using LibreSCRS::Plugin::UnblockStyle;

namespace {

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

} // namespace

TEST(OpenscPinLifecycle, NeedsChangePropagates)
{
    sc_pkcs15_auth_info info{};
    info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED;
    info.attrs.pin.reference = 0x01;
    info.tries_left = 3;
    // Drivers OR the needs-change bit onto the logged state (see the
    // vendored esteid2025 driver), so the signal is a bit test.
    info.logged_in = SC_PIN_STATE_LOGGED_OUT | SC_PIN_STATE_NEEDS_CHANGE;

    sc_pkcs15_object obj = makeAuthObject("PIN1", info);
    sc_pkcs15_object* objs[] = {&obj};

    const auto entries = LibreSCRS::OpenSc::buildPinStatusEntries(objs, 1, nullptr);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].state, PinState::NeedsChange);
    EXPECT_FALSE(entries[0].blocked);
    // No quirk row for this driver family, but the card demands a change
    // before use — the change action must be offered (a needs-change
    // state with no offered change verb would be a dead end).
    EXPECT_TRUE(entries[0].canChange);
}

TEST(OpenscPinLifecycle, QuirklessFamilyKeepsEvidenceOnlyChangeAdvertisement)
{
    // Families without a quirk row keep the evidence-only change
    // advertisement this plugin shipped before the derivation engine:
    // any non-PUK, non-SO object without the change-disabled flag.
    sc_pkcs15_auth_info info{};
    info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED;
    info.attrs.pin.reference = 0x01;
    info.tries_left = 3;

    sc_pkcs15_object obj = makeAuthObject("PIN1", info);
    sc_pkcs15_object* objs[] = {&obj};

    {
        const auto entries = LibreSCRS::OpenSc::buildPinStatusEntries(objs, 1, nullptr);
        ASSERT_EQ(entries.size(), 1u);
        EXPECT_TRUE(entries[0].canChange);
    }

    info.attrs.pin.flags |= SC_PKCS15_PIN_FLAG_CHANGE_DISABLED; // card veto
    const auto vetoed = LibreSCRS::OpenSc::buildPinStatusEntries(objs, 1, nullptr);
    ASSERT_EQ(vetoed.size(), 1u);
    EXPECT_FALSE(vetoed[0].canChange);
}

TEST(OpenscPinLifecycle, EmptyLabelAdvertisesReferenceSelector)
{
    // An empty AODF label must never be advertised verbatim: the
    // changePIN selector contract reserves the EMPTY selector for the
    // legacy default-PIN fallback, so "" would alias this record onto a
    // different credential. The documented "pin_<reference>" form is the
    // non-aliasing substitute — and a valid selector as advertised.
    sc_pkcs15_auth_info info{};
    info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED;
    info.attrs.pin.reference = 0x02;
    info.tries_left = 3;

    sc_pkcs15_object obj = makeAuthObject("", info);
    sc_pkcs15_object* objs[] = {&obj};

    const auto entries = LibreSCRS::OpenSc::buildPinStatusEntries(objs, 1, nullptr);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].label, "pin_2");
    EXPECT_EQ(entries[0].reference, 0x02);
}

TEST(OpenscPinLifecycle, TwoUnblockersResolvePerPinPuk)
{
    // Two PIN/PUK pairs (each PIN chained to its OWN unblocker via the
    // AODF authId): the unblock advertisement must evaluate the PUK the
    // chain names, never merely the first unblocker in enumeration
    // order. PUK B is exhausted, so only PIN A may advertise unblock.
    sc_pkcs15_auth_info pinAInfo{};
    pinAInfo.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED;
    pinAInfo.attrs.pin.reference = 0x80;
    pinAInfo.tries_left = 3;

    sc_pkcs15_auth_info pukAInfo{};
    pukAInfo.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN;
    pukAInfo.attrs.pin.reference = 0x81;
    pukAInfo.tries_left = 3; // presentable
    pukAInfo.auth_id.value[0] = 0x02;
    pukAInfo.auth_id.len = 1;

    sc_pkcs15_auth_info pinBInfo{};
    pinBInfo.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED;
    pinBInfo.attrs.pin.reference = 0x82;
    pinBInfo.tries_left = 3;

    sc_pkcs15_auth_info pukBInfo{};
    pukBInfo.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN;
    pukBInfo.attrs.pin.reference = 0x83;
    pukBInfo.tries_left = 0; // exhausted → NOT presentable
    pukBInfo.auth_id.value[0] = 0x04;
    pukBInfo.auth_id.len = 1;

    sc_pkcs15_object pinA = makeAuthObject("PIN A", pinAInfo);
    pinA.auth_id.value[0] = 0x02; // protected by PUK A
    pinA.auth_id.len = 1;
    sc_pkcs15_object pukA = makeAuthObject("PUK A", pukAInfo);
    sc_pkcs15_object pinB = makeAuthObject("PIN B", pinBInfo);
    pinB.auth_id.value[0] = 0x04; // protected by PUK B
    pinB.auth_id.len = 1;
    sc_pkcs15_object pukB = makeAuthObject("PUK B", pukBInfo);
    sc_pkcs15_object* objs[] = {&pinA, &pukA, &pinB, &pukB};

    // PIV row: the RRC command form is verified, so the chain outcome is
    // decided purely by the addressed PUK's presentability.
    const auto entries = LibreSCRS::OpenSc::buildPinStatusEntries(objs, 4, "PIV-II");
    ASSERT_EQ(entries.size(), 4u);

    EXPECT_TRUE(entries[0].unblockable);
    EXPECT_EQ(entries[0].recovery, PinRecovery::HolderViaPuk);

    EXPECT_FALSE(entries[2].unblockable);
    EXPECT_NE(entries[2].recovery, PinRecovery::HolderViaPuk);
}

TEST(OpenscPinLifecycle, UnblockingPinFlagYieldsPukKind)
{
    sc_pkcs15_auth_info info{};
    info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN;
    info.attrs.pin.reference = 0x81;
    info.tries_left = 3;

    sc_pkcs15_object obj = makeAuthObject("PUK", info);
    sc_pkcs15_object* objs[] = {&obj};

    const auto entries = LibreSCRS::OpenSc::buildPinStatusEntries(objs, 1, nullptr);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].kind, PinKind::Puk);
}

TEST(OpenscPinLifecycle, SrbeidFamilyCanChangeAndIssuerRecovery)
{
    // Current Serbian CardEdge applet (vendored srbeid driver, single-PIN
    // model): the holder can change the PIN; a blocked PIN is recovered
    // through the issuer process (with guidance), never via a PUK.
    sc_pkcs15_auth_info info{};
    info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED;
    info.attrs.pin.reference = 0x01;
    info.tries_left = 3;
    info.logged_in = SC_PIN_STATE_LOGGED_OUT;

    sc_pkcs15_object obj = makeAuthObject("PIN", info);
    sc_pkcs15_object* objs[] = {&obj};

    {
        const auto entries = LibreSCRS::OpenSc::buildPinStatusEntries(objs, 1, "srbeid");
        ASSERT_EQ(entries.size(), 1u);
        EXPECT_EQ(entries[0].kind, PinKind::UserPin);
        EXPECT_EQ(entries[0].state, PinState::Operational);
        EXPECT_TRUE(entries[0].canChange);
        EXPECT_TRUE(entries[0].probeSafe);
    }

    info.tries_left = 0; // exhausted → blocked, issuer recovery
    const auto blocked = LibreSCRS::OpenSc::buildPinStatusEntries(objs, 1, "srbeid");
    ASSERT_EQ(blocked.size(), 1u);
    EXPECT_EQ(blocked[0].state, PinState::Blocked);
    EXPECT_FALSE(blocked[0].unblockable);
    EXPECT_EQ(blocked[0].recovery, PinRecovery::IssuerProcess);
    EXPECT_TRUE(blocked[0].blockedGuidance.has_value());
}

TEST(OpenscPinLifecycle, PivFamilyGetsSetsNewPinStyle)
{
    // PIV application PIN (reference 0x80) protected/unblocked by the PUK
    // (reference 0x81). The chain is expressed AODF-style: the PIN
    // object's auth_id names the PUK auth object's own id, which the
    // caller resolves into the derivation engine's chain contract.
    sc_pkcs15_auth_info pinInfo{};
    pinInfo.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED;
    pinInfo.attrs.pin.reference = 0x80;
    pinInfo.tries_left = 3;
    pinInfo.logged_in = SC_PIN_STATE_LOGGED_OUT;

    sc_pkcs15_auth_info pukInfo{};
    pukInfo.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN;
    pukInfo.attrs.pin.reference = 0x81;
    pukInfo.tries_left = 3; // presentable (not blocked)
    pukInfo.auth_id.value[0] = 0x02;
    pukInfo.auth_id.len = 1;

    sc_pkcs15_object pin = makeAuthObject("PIV Card Application PIN", pinInfo);
    pin.auth_id.value[0] = 0x02; // protected by the PUK object
    pin.auth_id.len = 1;
    sc_pkcs15_object puk = makeAuthObject("PIN Unblocking Key", pukInfo);
    sc_pkcs15_object* objs[] = {&pin, &puk};

    const auto entries = LibreSCRS::OpenSc::buildPinStatusEntries(objs, 2, "PIV-II");
    ASSERT_EQ(entries.size(), 2u);

    // PIV family quirks applied on the UserPin entry: verified RRC form +
    // resolved presentable PUK + no veto → unblockable, SetsNewPin style.
    EXPECT_EQ(entries[0].kind, PinKind::UserPin);
    EXPECT_TRUE(entries[0].unblockable);
    EXPECT_EQ(entries[0].unblockStyle, UnblockStyle::SetsNewPin);
    EXPECT_EQ(entries[0].recovery, PinRecovery::HolderViaPuk);
    EXPECT_TRUE(entries[0].canChange);
    EXPECT_TRUE(entries[0].probeSafe);
    ASSERT_TRUE(entries[0].retriesLeft.has_value());
    EXPECT_EQ(*entries[0].retriesLeft, 3);

    EXPECT_EQ(entries[1].kind, PinKind::Puk);
}
