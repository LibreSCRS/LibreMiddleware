// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pin_family_quirks.h"

#include <LibreSCRS/LocalizedText.h>

namespace LibreSCRS::Plugin::Internal {

namespace {

constexpr std::size_t kindIndex(PinKind k) noexcept
{
    return static_cast<std::size_t>(k);
}

constexpr std::size_t unblockIndex(UnblockStyle s) noexcept
{
    return static_cast<std::size_t>(s);
}

/// ISO card-verb execution defaults shared by both applet-suite generations.
/// [HW-VERIFY]: placeholders pending a hardware campaign; AUTH key
/// life-cycle at creation is [HW-VERIFY] — do not assert active.
void applyIsoExecutionDefaults(FamilyQuirks& q) noexcept
{
    q.rrcP1[unblockIndex(UnblockStyle::Unknown)] = 0x00;
    q.rrcP1[unblockIndex(UnblockStyle::ResetOnly)] = 0x01;
    q.rrcP1[unblockIndex(UnblockStyle::SetsNewPin)] = 0x00;
    q.rrcP1[unblockIndex(UnblockStyle::UnblockAndChange)] = 0x00;
    q.transportChangeP1 = 0x00;
    q.keyActivate = {.ins = 0x44, .p1 = 0x00, .p2 = 0x00};
    q.secStateClear = FamilyQuirks::SecStateClear::ReselectApplet;
}

/// Conservative fallback for PinKind members beyond the table (PinKind is
/// append-only; the table is rebuilt when a kind gains real knowledge).
const FamilyKindQuirks& kindQuirksOrDefault(const std::array<FamilyKindQuirks, kPinKindCount>& kinds,
                                            PinKind k) noexcept
{
    static const FamilyKindQuirks kConservative{};
    const std::size_t i = kindIndex(k);
    return i < kinds.size() ? kinds[i] : kConservative;
}

// Guidance texts travel as message key + English fallback; clients own the
// translations (never showing the fallback when a translation exists). The
// Serbian (ćirilica) source strings for the client catalogs are kept next
// to each key as comments.

// sr (ћирилица): "Деблокаду обавља издавалац картице."
LocalizedText issuerUnblockGuidance()
{
    return LocalizedText{
        .key = "librescrs.pin.blocked.issuer",
        .defaultText = "Unblocking is done by the issuer.",
        .placeholders = {},
    };
}

// sr (ћирилица): "Активацију кључа за потписивање обавља издавалац."
LocalizedText issuerKeyActivationGuidance()
{
    return LocalizedText{
        .key = "librescrs.pin.keyActivation.issuer",
        .defaultText = "The signing key is activated by the issuer.",
        .placeholders = {},
    };
}

// Current Serbian eID applet (CardEdge): single-PIN model, no PUK on card.
// Counter reads are shipping behaviour (probeSafe). A blocked PIN is
// recovered only through the issuer's challenge/response process.
FamilyQuirks makeCurrentLkCardEdge()
{
    FamilyQuirks q;
    q.id = FamilyId::CurrentLkCardEdge;
    q.supportsTransportPin = false;
    q.probeSafe = true;
    auto& user = q.kinds[kindIndex(PinKind::UserPin)];
    user.canChange = true;
    user.blockedRecovery = PinRecovery::IssuerProcess;
    user.blockedGuidance = issuerUnblockGuidance();
    return q;
}

// Applet-suite generation 1: transport-born SIGN PIN model. Unblock authority
// is the PUK, but the RESET RETRY COUNTER variant is not hardware-verified yet,
// so no unblock form is advertised; recovery stays evidence-derived.
FamilyQuirks makeAppletSuiteGen1()
{
    FamilyQuirks q;
    q.id = FamilyId::AppletSuiteGen1;
    q.supportsTransportPin = true;
    q.probeSafe = true;
    q.usesPace = true; // PACE applet suite; carries a CAN (recognised on contact too)
    auto& user = q.kinds[kindIndex(PinKind::UserPin)];
    user.canChange = true;
    user.retriesMax = 3;
    auto& sign = q.kinds[kindIndex(PinKind::SignPin)];
    sign.canChange = true;
    sign.retriesMax = 3;
    q.kinds[kindIndex(PinKind::Puk)].retriesMax = 5;
    // Card-verb execution bytes: ISO defaults only, [HW-VERIFY]. AUTH key
    // life-cycle at creation is [HW-VERIFY] — do not assert active.
    applyIsoExecutionDefaults(q);
    return q;
}

// New Serbian eID applet suite (SRB-eID V2.00): same transport model as
// generation 1; every command-form fact — including counter-probe
// safety — is unverified until the dedicated driver track lands, so the
// probe gate stays shut (probeSafe=false) and nothing beyond the
// spec-published counters is advertised.
FamilyQuirks makeAppletSuiteGen2()
{
    FamilyQuirks q;
    q.id = FamilyId::AppletSuiteGen2;
    q.supportsTransportPin = true;
    q.probeSafe = false;
    // Same PACE applet-suite lineage — correct family metadata. Dormant until
    // an AppletSuiteGen2 token-label resolver marker exists (no card resolves
    // to AppletSuiteGen2 today); consistent with this row's other
    // currently-unreached facts.
    q.usesPace = true;
    auto& user = q.kinds[kindIndex(PinKind::UserPin)];
    user.canChange = true;
    user.retriesMax = 3;
    auto& sign = q.kinds[kindIndex(PinKind::SignPin)];
    sign.canChange = true;
    sign.retriesMax = 3;
    q.kinds[kindIndex(PinKind::Puk)].retriesMax = 5;
    // Card-verb execution bytes: same clean-room stance as generation 1 —
    // shared ISO defaults only, [HW-VERIFY]. No per-personalization value
    // (PIN refs, retry, budgets) belongs here; those are runtime AODF/DOCP
    // facts. AUTH key life-cycle at creation is [HW-VERIFY] — do not assert
    // active.
    applyIsoExecutionDefaults(q);
    return q;
}

// NIST PIV: PIN change and the PUK-based unblock form (which sets a new
// PIN) are public standard knowledge, so the unblock variant is verified
// by specification. An exhausted PUK is terminal — card replacement only.
FamilyQuirks makePiv()
{
    FamilyQuirks q;
    q.id = FamilyId::Piv;
    q.supportsTransportPin = false;
    q.probeSafe = true;
    auto& user = q.kinds[kindIndex(PinKind::UserPin)];
    user.canChange = true;
    user.rrcVariantKnown = true;
    user.unblockStyle = UnblockStyle::SetsNewPin;
    q.kinds[kindIndex(PinKind::Puk)].blockedRecovery = PinRecovery::None;
    return q;
}

// Postal CA card profile: counter safety unverified (probeSafe stays
// false). Key activation is issuer-tool-only; the derivation forwards
// the guidance text below (display-only) while keeping
// keyActivationPending/keyActivatable conservatively off — asserting a
// deactivated key needs key/certificate state evidence no plugin reads
// yet. The pkcs15 resolver maps this family from a hardware-captured
// EF.TokenInfo manufacturerID — never from the label, which is holder
// data on these cards. probeSafe stays false regardless: the
// no-decrement evidence on record was measured on an earlier applet
// generation, so it says nothing about the current one.
FamilyQuirks makeAetPosta()
{
    FamilyQuirks q;
    q.id = FamilyId::AetPosta;
    q.supportsTransportPin = false;
    q.probeSafe = false;
    q.keyActivationGuidance = issuerKeyActivationGuidance();
    return q;
}

const std::array<FamilyQuirks, 5>& familyRows()
{
    static const std::array<FamilyQuirks, 5> kRows{
        makeCurrentLkCardEdge(), makeAppletSuiteGen1(), makeAppletSuiteGen2(), makePiv(), makeAetPosta(),
    };
    return kRows;
}

} // namespace

bool FamilyQuirks::canChange(PinKind k) const noexcept
{
    return kindQuirksOrDefault(kinds, k).canChange;
}

bool FamilyQuirks::rrcVariantKnown(PinKind k) const noexcept
{
    return kindQuirksOrDefault(kinds, k).rrcVariantKnown;
}

UnblockStyle FamilyQuirks::unblockStyle(PinKind k) const noexcept
{
    return kindQuirksOrDefault(kinds, k).unblockStyle;
}

PinRecovery FamilyQuirks::blockedRecovery(PinKind k) const noexcept
{
    return kindQuirksOrDefault(kinds, k).blockedRecovery;
}

std::optional<LocalizedText> FamilyQuirks::blockedGuidance(PinKind k) const
{
    return kindQuirksOrDefault(kinds, k).blockedGuidance;
}

std::optional<int> FamilyQuirks::retriesMax(PinKind k) const noexcept
{
    return kindQuirksOrDefault(kinds, k).retriesMax;
}

const FamilyQuirks* findFamilyQuirks(FamilyId id) noexcept
try {
    if (id == FamilyId::Unknown)
        return nullptr;
    for (const FamilyQuirks& row : familyRows()) {
        if (row.id == id)
            return &row;
    }
    return nullptr;
} catch (...) {
    // bad_alloc while the static table was first built (guidance strings
    // allocate): degrade to "no family knowledge". The failed static
    // initialization retries on the next call.
    return nullptr;
}

} // namespace LibreSCRS::Plugin::Internal
