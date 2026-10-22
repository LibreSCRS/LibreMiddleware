// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Hardware checks of MonitorService on macOS, whose reader and card events
// come from CryptoTokenKit's slots rather than PC/SC:
//   - a card inserted and removed by hand arrives as CardInserted and
//     CardRemoved, and the reader list then equals CryptoTokenKit's slots;
//   - a reader plugged in while the monitor runs arrives at once as
//     ReaderAdded, and its removal as ReaderRemoved;
//   - the reader name the monitor reports opens the test card.
//
// Every case skips unless LIBRESCRS_HW_MONITOR=1, so ctest reports them
// Skipped. No case skips after a failure: ctest reads any "[  SKIPPED ]" in the
// output as Skipped, which would hide the failure. They are meant to be run one
// at a time by the person at the readers:
//
//   LIBRESCRS_HW_MONITOR=1 ./MonitorCtkHardwareTests --gtest_filter=MonitorCtkHardware.<Case>
//
// A step that needs a person prints what to do and waits for the event, not
// for Enter, for at most LIBRESCRS_HW_MONITOR_WAIT_SECONDS (default 120); an
// event that does not arrive in time fails the case, so the binary never
// hangs. LIBRESCRS_HW_MONITOR_CYCLES (default 1) repeats the insert and remove
// steps; between two cycles a ctkd restart
// (launchctl kickstart -k gui/$UID/com.apple.ctkd) must leave the reader list
// right within five seconds and the next insertion must still arrive.
// The card goes into a reader that is empty and has had no card event the test
// did not ask for, so a contactless slot that drops and regains its card by
// itself cannot answer the step in the person's place.
//
// Card safety: no case sends an APDU. A session is opened only on a slot whose
// ATR, read without a session, starts with the contact test LK's prefix.
//
// Every event goes to stderr as one line starting with "MONHW ", stamped with
// the wall clock in milliseconds, to be lined up with the timestamps of a
// passive PC/SC observer running in another process.

#include "ctk_hw_cards.h"
#include "ctk_hw_probe.h"

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {

namespace CtkHw = LibreSCRS::Tests::CtkHw;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::MonitorEvent;
using LibreSCRS::SmartCard::MonitorService;
using Clock = std::chrono::steady_clock;

constexpr auto kSettle = std::chrono::seconds(2);
// How long the reader list may disagree with CryptoTokenKit's slots, ctkd
// restart included.
constexpr auto kListAgreement = std::chrono::seconds(5);

std::chrono::seconds waitLimit()
{
    return std::chrono::seconds(std::max(1L, CtkHw::envLong("LIBRESCRS_HW_MONITOR_WAIT_SECONDS", 120)));
}

long long wallMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void record(const std::string& line)
{
    std::fprintf(stderr, "MONHW wall_ms=%lld %s\n", wallMs(), line.c_str());
    std::fflush(stderr);
}

const char* kindName(MonitorEvent::Kind kind)
{
    switch (kind) {
    case MonitorEvent::Kind::ReaderAdded:
        return "ReaderAdded";
    case MonitorEvent::Kind::ReaderRemoved:
        return "ReaderRemoved";
    case MonitorEvent::Kind::CardInserted:
        return "CardInserted";
    case MonitorEvent::Kind::CardRemoved:
        return "CardRemoved";
    case MonitorEvent::Kind::Error:
        return "Error";
    default:
        return "unknown";
    }
}

void ownerPrompt(const std::string& instruction)
{
    std::fprintf(stderr, "\n>>> %s\n>>> Waiting up to %lld s for the event.\n", instruction.c_str(),
                 static_cast<long long>(waitLimit().count()));
    std::fflush(stderr);
    record("prompt \"" + instruction + "\"");
}

// Every event the monitor delivered, in order, with its arrival time.
class EventLog
{
public:
    struct Seen
    {
        MonitorEvent event;
        Clock::time_point at;
        std::size_t index = 0;
    };

    void push(const MonitorEvent& event)
    {
        std::string line = std::string("event kind=") + kindName(event.kind) + " reader=\"" + event.readerName + "\"";
        if (event.atr)
            line += " atr=" + CtkHw::hex(*event.atr);
        if (event.diagnosticDetail)
            line += " detail=\"" + *event.diagnosticDetail + "\"";
        record(line);
        std::lock_guard lock(mtx);
        seen.push_back({event, Clock::now(), seen.size()});
        cv.notify_all();
    }

    std::size_t size() const
    {
        std::lock_guard lock(mtx);
        return seen.size();
    }

    std::vector<Seen> snapshot() const
    {
        std::lock_guard lock(mtx);
        return seen;
    }

    /// The first event at index @p from or later that @p match accepts, or
    /// an Error event at any index (the monitor stops after one, so nothing
    /// else would come), waiting at most @p limit.
    std::optional<Seen> waitFor(std::size_t from, const std::function<bool(const MonitorEvent&)>& match,
                                std::chrono::seconds limit) const
    {
        std::unique_lock lock(mtx);
        std::optional<Seen> found;
        cv.wait_for(lock, limit, [&] {
            for (std::size_t i = 0; i < seen.size(); ++i)
                if (seen[i].event.kind == MonitorEvent::Kind::Error || (i >= from && match(seen[i].event))) {
                    found = seen[i];
                    return true;
                }
            return false;
        });
        return found;
    }

private:
    mutable std::mutex mtx;
    mutable std::condition_variable cv;
    std::vector<Seen> seen;
};

// A monitor with one subscription feeding @ref log; unsubscribes with Drain
// before the log goes away.
class Watch
{
public:
    Watch()
    {
        id = monitor.subscribe([this](const MonitorEvent& event) { log.push(event); });
        std::this_thread::sleep_for(kSettle); // the events of what is already there
    }
    ~Watch()
    {
        monitor.unsubscribe(id, MonitorService::DrainPolicy::Drain);
    }
    Watch(const Watch&) = delete;
    Watch& operator=(const Watch&) = delete;

    EventLog log;
    MonitorService monitor;

private:
    MonitorService::SubscriptionId id;
};

bool isCardEvent(const MonitorEvent& event)
{
    return event.kind == MonitorEvent::Kind::CardInserted || event.kind == MonitorEvent::Kind::CardRemoved;
}

// Readers CryptoTokenKit reports empty now and for which the monitor has
// reported no card event except the test's own (@p own, log indices). A slot
// that drops and regains a card without the person (a dual-interface card's
// contactless side, each time another process opens its contact side) would
// otherwise answer the person's step.
std::set<std::string> quietEmptyReaders(const EventLog& log, const std::set<std::size_t>& own)
{
    std::set<std::string> churned;
    for (const auto& seen : log.snapshot())
        if (isCardEvent(seen.event) && !own.contains(seen.index))
            churned.insert(seen.event.readerName);
    std::set<std::string> quiet;
    for (const auto& slot : CtkHw::passiveSlots())
        if (slot.state == CtkHw::SlotState::Empty && !churned.contains(slot.name))
            quiet.insert(slot.name);
    return quiet;
}

std::string quotedList(const std::set<std::string>& names)
{
    std::string out;
    for (const auto& name : names)
        out += (out.empty() ? "\"" : ", \"") + name + "\"";
    return out;
}

std::set<std::string> slotNames()
{
    std::set<std::string> names;
    for (const auto& slot : CtkHw::passiveSlots())
        names.insert(slot.name);
    return names;
}

// The monitor's reader list equals CryptoTokenKit's slot names within
// kListAgreement; the last pair seen otherwise.
::testing::AssertionResult readersMatchSlots(const MonitorService& monitor)
{
    const auto deadline = Clock::now() + kListAgreement;
    std::set<std::string> listed;
    std::set<std::string> slots;
    bool available = false;
    for (;;) {
        const auto readers = monitor.listReaders();
        available = readers.has_value();
        listed = available ? std::set<std::string>(readers->begin(), readers->end()) : std::set<std::string>{};
        slots = slotNames();
        if (available && listed == slots)
            return ::testing::AssertionSuccess();
        if (Clock::now() >= deadline)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!available)
        return ::testing::AssertionFailure() << "listReaders() is unavailable";
    return ::testing::AssertionFailure() << "reader list {" << quotedList(listed) << "} != CryptoTokenKit slots {"
                                         << quotedList(slots) << "}";
}

// The awaited event arrived, and it is not the monitor's Error.
::testing::AssertionResult arrived(const std::optional<EventLog::Seen>& seen, const std::string& what)
{
    if (!seen)
        return ::testing::AssertionFailure() << "no " << what << " within " << waitLimit().count() << " s";
    if (seen->event.kind == MonitorEvent::Kind::Error)
        return ::testing::AssertionFailure() << "the monitor reported an Error instead of " << what << ": "
                                             << seen->event.diagnosticDetail.value_or("no detail");
    return ::testing::AssertionSuccess();
}

std::size_t errorCount(const EventLog& log)
{
    const auto all = log.snapshot();
    return static_cast<std::size_t>(
        std::count_if(all.begin(), all.end(), [](const auto& s) { return s.event.kind == MonitorEvent::Kind::Error; }));
}

double msBetween(Clock::time_point from, Clock::time_point to)
{
    return std::chrono::duration<double, std::milli>(to - from).count();
}

} // namespace

// ---------------------------------------------------------------------------------------

class MonitorCtkHardware : public ::testing::Test
{
protected:
    void SetUp() override
    {
        if (CtkHw::envOpt("LIBRESCRS_HW_MONITOR").value_or("") != "1")
            GTEST_SKIP() << "hardware check: set LIBRESCRS_HW_MONITOR=1 and follow the prompts at the readers";
        for (const auto& slot : CtkHw::passiveSlots())
            record("slot name=\"" + slot.name + "\" state=" + std::to_string(static_cast<long>(slot.state)) +
                   " atr=" + CtkHw::hex(slot.atr));
    }
};

TEST_F(MonitorCtkHardware, InsertAndRemoveArrive)
{
    Watch watch;
    const long cycles = std::max(1L, CtkHw::envLong("LIBRESCRS_HW_MONITOR_CYCLES", 1));
    std::set<std::size_t> own;
    for (long cycle = 1; cycle <= cycles; ++cycle) {
        const auto eligible = quietEmptyReaders(watch.log, own);
        ASSERT_FALSE(eligible.empty()) << "no empty reader without card events of its own: start with an empty "
                                          "reader and keep contactless cards away";
        std::size_t mark = watch.log.size();
        ownerPrompt("Cycle " + std::to_string(cycle) + "/" + std::to_string(cycles) +
                    (cycle > 1 ? ": to check a ctkd restart, run `launchctl kickstart -k gui/$UID/com.apple.ctkd` "
                                 "first. Then insert"
                               : ": insert") +
                    " a contact card into one of " + quotedList(eligible) + ".");
        auto start = Clock::now();
        const auto inserted = watch.log.waitFor(
            mark,
            [&](const MonitorEvent& e) {
                return e.kind == MonitorEvent::Kind::CardInserted && eligible.contains(e.readerName);
            },
            waitLimit());
        ASSERT_TRUE(arrived(inserted, "CardInserted into " + quotedList(eligible)));
        own.insert(inserted->index);
        const auto reader = inserted->event.readerName;
        record("arrived kind=CardInserted reader=\"" + reader +
               "\" ms_after_prompt=" + std::to_string(msBetween(start, inserted->at)));
        ASSERT_TRUE(inserted->event.atr.has_value());
        EXPECT_FALSE(inserted->event.atr->empty());
        EXPECT_TRUE(readersMatchSlots(watch.monitor));

        mark = watch.log.size();
        ownerPrompt("Remove the card from \"" + reader + "\".");
        start = Clock::now();
        const auto removed = watch.log.waitFor(
            mark,
            [&](const MonitorEvent& e) { return e.kind == MonitorEvent::Kind::CardRemoved && e.readerName == reader; },
            waitLimit());
        ASSERT_TRUE(arrived(removed, "CardRemoved for \"" + reader + "\""));
        own.insert(removed->index);
        record("arrived kind=CardRemoved reader=\"" + reader +
               "\" ms_after_prompt=" + std::to_string(msBetween(start, removed->at)));
        EXPECT_TRUE(readersMatchSlots(watch.monitor));
    }
    EXPECT_EQ(errorCount(watch.log), 0u) << "the monitor reported an Error event (it stops after one)";
}

TEST_F(MonitorCtkHardware, SecondReaderHotPlugArrives)
{
    Watch watch;
    const auto initial = watch.monitor.listReaders();
    ASSERT_TRUE(initial.has_value()) << "listReaders() is unavailable";
    record("initial readers=" + std::to_string(initial->size()));

    std::size_t mark = watch.log.size();
    ownerPrompt("Plug in a reader that is not plugged in now (keep the others where they are).");
    auto start = Clock::now();
    const auto added = watch.log.waitFor(
        mark,
        [&](const MonitorEvent& e) {
            return e.kind == MonitorEvent::Kind::ReaderAdded &&
                   std::find(initial->begin(), initial->end(), e.readerName) == initial->end();
        },
        waitLimit());
    ASSERT_TRUE(arrived(added, "ReaderAdded for a new reader"));
    const auto reader = added->event.readerName;
    record("arrived kind=ReaderAdded reader=\"" + reader +
           "\" ms_after_prompt=" + std::to_string(msBetween(start, added->at)));
    EXPECT_TRUE(readersMatchSlots(watch.monitor));

    mark = watch.log.size();
    ownerPrompt("Unplug \"" + reader + "\".");
    start = Clock::now();
    const auto removed = watch.log.waitFor(
        mark,
        [&](const MonitorEvent& e) { return e.kind == MonitorEvent::Kind::ReaderRemoved && e.readerName == reader; },
        waitLimit());
    ASSERT_TRUE(arrived(removed, "ReaderRemoved for \"" + reader + "\""));
    record("arrived kind=ReaderRemoved reader=\"" + reader +
           "\" ms_after_prompt=" + std::to_string(msBetween(start, removed->at)));
    EXPECT_TRUE(readersMatchSlots(watch.monitor));
    EXPECT_EQ(errorCount(watch.log), 0u) << "the monitor reported an Error event (it stops after one)";
}

TEST_F(MonitorCtkHardware, ReportedNameOpensTheTestCard)
{
    const auto slot = CtkHw::slotWithAtrPrefix(CtkHw::kLkContact);
    if (!slot)
        GTEST_SKIP() << "no contact test LK (by ATR prefix) in any reader";

    Watch watch;
    // The name as the monitor reports it: from the card's own event if the
    // monitor announced the card already present, from its reader list if not.
    std::optional<std::string> reported;
    for (const auto& seen : watch.log.snapshot())
        if (seen.event.kind == MonitorEvent::Kind::CardInserted && seen.event.atr &&
            CtkHw::atrHasPrefix(*seen.event.atr, CtkHw::kLkContact))
            reported = seen.event.readerName;
    const char* source = "event";
    if (!reported) {
        source = "listReaders";
        const auto readers = watch.monitor.listReaders();
        ASSERT_TRUE(readers.has_value()) << "listReaders() is unavailable";
        if (std::find(readers->begin(), readers->end(), *slot) != readers->end())
            reported = *slot;
    }
    ASSERT_TRUE(reported.has_value()) << "the monitor does not report the reader holding the test LK (\"" << *slot
                                      << "\")";
    record(std::string("reported reader=\"") + *reported + "\" from=" + source);
    EXPECT_EQ(*reported, *slot);

    const auto start = Clock::now();
    {
        auto opened = CardSession::open(*reported);
        ASSERT_TRUE(opened.has_value()) << "CardSession::open(\"" << *reported
                                        << "\") failed: " << opened.error().diagnosticDetail.value_or("no detail");
        record("open reader=\"" + *reported + "\" ms=" + std::to_string(msBetween(start, Clock::now())));
    } // the session ends here, before any command reached the card
    EXPECT_EQ(errorCount(watch.log), 0u) << "the monitor reported an Error event (it stops after one)";
}
