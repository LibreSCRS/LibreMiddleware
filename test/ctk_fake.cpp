// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ctk_fake.h"

#include <algorithm>
#include <condition_variable>
#include <map>
#include <mutex>

namespace LibreSCRS::SmartCard::Internal::Ctk {

namespace {

struct SlotRecord
{
    Fake::Slot slot;
    Fake::Calls calls;
    // Bumped when the card leaves or another takes its place: a session opened
    // on an older card is gone with it.
    std::uint64_t cardGeneration = 0;
    // Bumped when the system ends the session while the card stays.
    std::uint64_t sessionGeneration = 0;
    SlotState settled = SlotState::Empty;
    std::uint32_t transitions = 0;
};

struct World
{
    std::mutex mtx;
    std::condition_variable changed;
    bool managerPresent = true;
    std::map<std::string, SlotRecord> slots;
    std::uint64_t generation = 0; // every change a watcher could see
    int slotsAcquires = 0;
    int slotsManagerLookups = 0;
};

World& world()
{
    static World w;
    return w;
}

} // namespace

struct CtkCard::Impl
{
    std::string slotName;
    std::uint64_t cardGeneration = 0;
    std::uint64_t sessionGeneration = 0;
    bool open = false;
    CtkProtocol protocol = CtkProtocol::T1;
    mutable std::mutex cardMtx; // one per card: two cards never wait for each other
};

namespace {

// Opens a session for @p impl under the world lock.
std::expected<void, CtkFailure> beginLocked(World& w, CtkCard::Impl& impl, std::chrono::milliseconds deadline)
{
    if (!w.managerPresent)
        return std::unexpected(CtkFailure{CtkStatus::NoManager, "no slot manager"});
    auto it = w.slots.find(impl.slotName);
    if (it == w.slots.end() || it->second.slot.state == SlotState::Missing)
        return std::unexpected(CtkFailure{CtkStatus::UnknownSlot, impl.slotName});
    auto& rec = it->second;
    ++rec.calls.opens;
    rec.calls.lastDeadline = deadline;
    if (rec.slot.state == SlotState::Empty)
        return std::unexpected(CtkFailure{CtkStatus::NoCard, impl.slotName});
    if (rec.slot.state == SlotState::MuteCard)
        return std::unexpected(CtkFailure{CtkStatus::Mute, impl.slotName});
    if (rec.slot.refuseOpenWith != CtkStatus::Ok)
        return std::unexpected(CtkFailure{rec.slot.refuseOpenWith, "refused by the script"});
    rec.calls.order.emplace_back("open");
    impl.cardGeneration = rec.cardGeneration;
    impl.sessionGeneration = rec.sessionGeneration;
    impl.protocol = rec.slot.protocol;
    impl.open = true;
    rec.calls.maxLiveSessions = std::max(rec.calls.maxLiveSessions, ++rec.calls.liveSessions);
    return {};
}

void endLocked(World& w, CtkCard::Impl& impl)
{
    if (!impl.open)
        return;
    impl.open = false;
    auto it = w.slots.find(impl.slotName);
    if (it == w.slots.end())
        return;
    ++it->second.calls.ends;
    --it->second.calls.liveSessions;
    it->second.calls.order.emplace_back("end");
}

// Whether @p impl's session is still the slot's, and if not, why.
CtkStatus stateLocked(World& w, const CtkCard::Impl& impl)
{
    auto it = w.slots.find(impl.slotName);
    if (it == w.slots.end() || it->second.slot.state != SlotState::ValidCard ||
        it->second.cardGeneration != impl.cardGeneration)
        return CtkStatus::CardGone;
    if (!impl.open || it->second.sessionGeneration != impl.sessionGeneration)
        return CtkStatus::SessionLost;
    return CtkStatus::Ok;
}

} // namespace

CtkCard::CtkCard(std::unique_ptr<Impl> i) noexcept : impl(std::move(i)) {}

std::expected<std::unique_ptr<CtkCard>, CtkFailure>
CtkCard::open(const std::string& slotName, std::chrono::milliseconds grantDeadline, const ManagerProvider& /*manager*/)
{
    auto i = std::make_unique<Impl>();
    i->slotName = slotName;
    auto& w = world();
    std::lock_guard lock(w.mtx);
    if (auto begun = beginLocked(w, *i, grantDeadline); !begun)
        return std::unexpected(begun.error());
    return std::make_unique<CtkCard>(std::move(i));
}

CtkCard::~CtkCard()
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    endLocked(w, *impl);
}

std::expected<std::vector<std::uint8_t>, CtkFailure> CtkCard::exchange(std::span<const std::uint8_t> command)
{
    std::lock_guard cardLock(impl->cardMtx);
    auto& w = world();
    std::function<std::expected<std::vector<std::uint8_t>, CtkStatus>(std::span<const std::uint8_t>)> responder;
    {
        std::lock_guard lock(w.mtx);
        const auto s = stateLocked(w, *impl);
        if (s == CtkStatus::SessionLost) {
            // The session ends while the command is out: the card got it, the
            // reply is lost. This is the case in which a resend spends a
            // second PIN try.
            w.slots.at(impl->slotName).calls.received.emplace_back(command.begin(), command.end());
        }
        if (s != CtkStatus::Ok)
            return std::unexpected(CtkFailure{s, "session not usable"});
        auto& rec = w.slots.at(impl->slotName);
        ++rec.calls.exchanges;
        rec.calls.received.emplace_back(command.begin(), command.end());
        responder = rec.slot.responder;
    }
    if (!responder)
        return std::vector<std::uint8_t>{0x90, 0x00};
    auto reply = responder(command);
    if (!reply)
        return std::unexpected(CtkFailure{reply.error(), "scripted failure"});
    return std::move(*reply);
}

std::expected<void, CtkFailure> CtkCard::reopen(std::chrono::milliseconds grantDeadline)
{
    std::lock_guard cardLock(impl->cardMtx);
    auto& w = world();
    std::lock_guard lock(w.mtx);
    // Begins on whatever card the slot holds now, swapped or not: the
    // connection's own "card left" check is what the tests judge.
    endLocked(w, *impl);
    return beginLocked(w, *impl, grantDeadline);
}

bool CtkCard::alive() const noexcept
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    return stateLocked(w, *impl) == CtkStatus::Ok;
}

CtkStatus CtkCard::lossKind() const noexcept
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    const auto s = stateLocked(w, *impl);
    return s == CtkStatus::CardGone ? CtkStatus::CardGone : CtkStatus::SessionLost;
}

CtkProtocol CtkCard::protocol() const noexcept
{
    return impl->protocol;
}

std::vector<std::uint8_t> CtkCard::atr() const
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    auto it = w.slots.find(impl->slotName);
    if (it == w.slots.end() || it->second.slot.state != SlotState::ValidCard)
        return {};
    return it->second.slot.atr;
}

std::vector<std::string> slotNames(const ManagerProvider& /*manager*/)
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    if (!w.managerPresent)
        return {};
    std::vector<std::string> names;
    for (const auto& [name, rec] : w.slots) {
        if (rec.slot.state != SlotState::Missing)
            names.push_back(name);
    }
    return names;
}

struct CtkSlots::Impl
{
    bool acquired = false;
    bool cancelled = false;
};

CtkSlots::CtkSlots(ManagerProvider /*manager*/) : impl(std::make_unique<Impl>()) {}

CtkSlots::~CtkSlots() = default;

CtkStatus CtkSlots::acquire()
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    ++w.slotsAcquires;
    ++w.slotsManagerLookups;
    impl->cancelled = false;
    if (!w.managerPresent)
        return CtkStatus::NoManager;
    impl->acquired = true;
    return CtkStatus::Ok;
}

std::vector<SlotSnapshot> CtkSlots::snapshot() const
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    std::vector<SlotSnapshot> out;
    if (!impl->acquired || !w.managerPresent)
        return out;
    for (const auto& [name, rec] : w.slots) {
        if (rec.slot.state == SlotState::Missing)
            continue;
        SlotSnapshot snap;
        snap.name = name;
        snap.state = rec.slot.state;
        if (rec.slot.state == SlotState::ValidCard)
            snap.atr = rec.slot.atr;
        snap.settled = rec.settled == SlotState::Probing ? SlotState::Empty : rec.settled;
        snap.transitions = rec.transitions;
        out.push_back(std::move(snap));
    }
    return out;
}

std::uint64_t CtkSlots::generation() const noexcept
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    return w.generation;
}

WaitResult CtkSlots::waitForChange(std::uint64_t seen, std::optional<std::chrono::milliseconds> timeout)
{
    auto& w = world();
    std::unique_lock lock(w.mtx);
    const auto ready = [&] { return impl->cancelled || w.generation != seen; };
    if (timeout) {
        if (!w.changed.wait_for(lock, *timeout, ready))
            return WaitResult::TimedOut;
    } else {
        w.changed.wait(lock, ready);
    }
    return impl->cancelled ? WaitResult::Cancelled : WaitResult::Changed;
}

void CtkSlots::cancel() noexcept
{
    auto& w = world();
    {
        std::lock_guard lock(w.mtx);
        impl->cancelled = true;
    }
    w.changed.notify_all();
}

namespace Fake {

void reset()
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    w.managerPresent = true;
    w.slots.clear();
    w.generation = 0;
    w.slotsAcquires = 0;
    w.slotsManagerLookups = 0;
}

void setManagerPresent(bool present)
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    w.managerPresent = present;
    ++w.generation;
    w.changed.notify_all();
}

Slot& slot(const std::string& name)
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    auto [it, created] = w.slots.try_emplace(name);
    if (created) {
        it->second.settled = it->second.slot.state;
        ++w.generation;
        w.changed.notify_all();
    }
    return it->second.slot;
}

void removeSlot(const std::string& name)
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    auto it = w.slots.find(name);
    if (it != w.slots.end()) {
        it->second.slot.state = SlotState::Missing;
        ++it->second.cardGeneration;
    }
    ++w.generation;
    w.changed.notify_all();
}

void loseSession(const std::string& name)
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    ++w.slots[name].sessionGeneration;
}

void removeCard(const std::string& name)
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    auto& rec = w.slots[name];
    rec.slot.state = SlotState::Empty;
    ++rec.cardGeneration;
    if (rec.settled != SlotState::Empty) {
        rec.settled = SlotState::Empty;
        ++rec.transitions;
    }
    ++w.generation;
    w.changed.notify_all();
}

void swapCard(const std::string& name, std::vector<std::uint8_t> atr)
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    auto& rec = w.slots[name];
    rec.slot.atr = std::move(atr);
    rec.slot.state = SlotState::ValidCard;
    ++rec.cardGeneration;
    rec.transitions += 2; // out and in again
    rec.settled = SlotState::ValidCard;
    ++w.generation;
    w.changed.notify_all();
}

void setSlotState(const std::string& name, SlotState state)
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    auto& rec = w.slots[name];
    rec.slot.state = state;
    if (state != SlotState::Probing && state != rec.settled) {
        rec.settled = state;
        ++rec.transitions;
        if (state != SlotState::ValidCard)
            ++rec.cardGeneration;
    }
    ++w.generation;
    w.changed.notify_all();
}

int slotsAcquires()
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    return w.slotsAcquires;
}

int slotsManagerLookups()
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    return w.slotsManagerLookups;
}

Calls calls(const std::string& name)
{
    auto& w = world();
    std::lock_guard lock(w.mtx);
    auto it = w.slots.find(name);
    return it == w.slots.end() ? Calls{} : it->second.calls;
}

} // namespace Fake

} // namespace LibreSCRS::SmartCard::Internal::Ctk
