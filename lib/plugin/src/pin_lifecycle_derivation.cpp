// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Credential-lifecycle derivation, in rule order: kind → state →
// capabilities → counters/probe safety.

#include "pin_lifecycle_derivation.h"

#include "pin_family_quirks.h"

namespace LibreSCRS::Plugin::Internal {

namespace {

/// Resolves the protecting PUK for @p e per the chain-resolution contract
/// on PinEvidence: a present authIdChainTarget carries the protecting
/// object's FULL id bytes, and the chain target is the evidence entry
/// whose ownId equals them. Matching by identity — never "the first
/// unblocker" — keeps multi-unblocker profiles (one PUK per PIN) from
/// evaluating presentability against the wrong PUK.
/// Returns nullptr when no chain exists or the named entry is absent.
const PinEvidence* resolveChainPuk(const PinEvidence& e, const std::vector<PinEvidence>& allEvidence) noexcept
{
    if (!e.authIdChainTarget.has_value() || e.authIdChainTarget->empty())
        return nullptr;
    for (const PinEvidence& candidate : allEvidence) {
        if (&candidate != &e && candidate.ownId == *e.authIdChainTarget)
            return &candidate;
    }
    return nullptr;
}

} // namespace

PinStatusEntry derivePinStatus(const PinEvidence& e, const std::vector<PinEvidence>& allEvidence,
                               const FamilyQuirks* quirks)
{
    PinStatusEntry out;
    out.label = e.label;
    out.reference = e.reference;
    out.initialized = e.initialized;
    out.blocked = e.blocked;

    // ---- kind (evidence rules) ----
    // Note: "is the chain target of another PIN" is folded into
    // unblockingPinFlag by the CALLER (each plugin resolves authId → object
    // when filling PinEvidence and sets the flag on the resolved target).
    // The quirk table currently carries no kind knowledge, so evidence
    // rules stand alone; a kind-override step slots in here if a family
    // ever needs one.
    if (e.paceEvidence && !e.soPinFlag && !e.unblockingPinFlag) {
        // A CAN is a PACE password: never an SO PIN, never an unblocking
        // authority. Excluding those keeps a PUK/SO-PIN that happens to carry
        // the change+unblock-disabled shape from being captured as a CAN — the
        // PUK signal below then classifies it correctly.
        out.kind = PinKind::Can;
    } else if (e.unblockingPinFlag) { // primary PUK signal (soPin corroborates only)
        out.kind = PinKind::Puk;
    } else if (e.localScope && e.inQscdDf) {
        out.kind = PinKind::SignPin;
    } else if (!e.soPinFlag && e.reference != 0) {
        out.kind = PinKind::UserPin;
    } // soPin-only, non-unblocker → stays Unknown

    // ---- state (precedence: Blocked > NeedsChange > Transport > Operational) --
    const bool familyTransport = quirks && quirks->supportsTransportPin && out.kind == PinKind::SignPin;
    if (e.blocked) {
        out.state = PinState::Blocked;
    } else if (e.needsChangeSignal) { // driver-reported must-change-before-use
        out.state = PinState::NeedsChange;
    } else if (!e.initialized && familyTransport) {
        out.state = PinState::Transport;
    } else if (e.initialized) {
        out.state = PinState::Operational;
    } // else stays Unknown

    // ---- capabilities ----
    // Change: a family row governs when present; without one the
    // evidence-only advertisement applies (the shape every plugin shipped
    // before this engine): any non-PUK, non-SO, non-CAN credential. A
    // driver-reported must-change state always offers the change action —
    // the card itself demands it. The card's change-disabled veto wins
    // over everything.
    const bool familyChange =
        quirks ? quirks->canChange(out.kind) : (!e.unblockingPinFlag && !e.soPinFlag && out.kind != PinKind::Can);
    out.canChange = !e.changeDisabledFlag && (familyChange || out.state == PinState::NeedsChange);
    out.activatable = familyTransport && out.state == PinState::Transport;

    // unblockable: chain + known variant + no veto + presentable PUK.
    const PinEvidence* puk = resolveChainPuk(e, allEvidence);
    const bool pukPresentable = puk && !puk->blocked;
    if (puk && quirks && quirks->rrcVariantKnown(out.kind) && !e.unblockDisabledFlag && pukPresentable) {
        out.unblockable = true;
        out.unblockStyle = quirks->unblockStyle(out.kind);
        out.recovery = PinRecovery::HolderViaPuk;
    } else if (quirks) {
        out.recovery = quirks->blockedRecovery(out.kind);
        out.blockedGuidance = quirks->blockedGuidance(out.kind);
    }

    // ---- key activation (family knowledge; display-only this increment) --
    // keyActivationPending / keyActivatable keep their conservative false
    // defaults: asserting a deactivated signing key requires key or
    // certificate state evidence no plugin reads yet. The family's
    // guidance text IS forwarded — on credentials that could guard
    // signing, never on PUK/CAN records — so hosts can explain
    // issuer-tool-only activation once a pending state becomes
    // assertable.
    if (quirks && quirks->keyActivationGuidance.has_value() && out.kind != PinKind::Puk && out.kind != PinKind::Can) {
        out.keyActivationGuidance = quirks->keyActivationGuidance;
    }

    // ---- counters & probe safety ----
    out.probeSafe = quirks && quirks->probeSafe;
    if (quirks) {
        out.retriesMax = quirks->retriesMax(out.kind);
    }
    return out;
}

} // namespace LibreSCRS::Plugin::Internal
