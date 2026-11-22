// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "ipcsc_scan_provider.h"
#include <smartcard/monitor_event.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace LibreSCRS::SmartCard::detail {
class MonitorFactory;
} // namespace LibreSCRS::SmartCard::detail

namespace LibreSCRS::SmartCard::Internal {

using MonitorCallback = std::function<void(const MonitorEvent&)>;
using ReaderListCallback = std::function<void(const std::vector<std::string>&)>;

class Monitor
{
public:
    explicit Monitor(std::unique_ptr<IPCSCScanProvider> provider);
    ~Monitor();

    Monitor(const Monitor&) = delete;
    Monitor& operator=(const Monitor&) = delete;

    using SubscriptionId = uint64_t;
    SubscriptionId subscribe(MonitorCallback onEvent, ReaderListCallback onReaders = nullptr);
    void unsubscribe(SubscriptionId id);

private:
    // The test seams drive a MonitorService's dispatch by invoking the
    // callbacks it registered here, exactly as the poll thread does; the
    // dispatch functions themselves are hidden in the shared library.
    friend class ::LibreSCRS::SmartCard::detail::MonitorFactory;

    struct Subscriber
    {
        MonitorCallback onEvent;
        ReaderListCallback onReaders;
    };

    // IfIdle: stop only if the monitor still has no subscriber once the
    // thread state is held, so a first subscriber that arrived after the
    // last unsubscribe keeps its thread.
    enum class Stop {
        Always,
        IfIdle,
    };

    void startThread();
    void stopThread(Stop when);
    void cancelAndJoin();
    void run();

    LONG establishContext();
    void setContext(SCARDCONTEXT ctx);
    void reEstablishContext();
    bool checkPnPSupport();
    std::vector<std::string> enumerateReaders();
    void waitForFirstReader(bool pnp);
    bool processEvents(std::vector<SCARD_READERSTATE>& states, int readerCount, bool pnp);

    void notifyEvent(const MonitorEvent& event);
    void notifyReaders(const std::vector<std::string>& readers);

    std::unique_ptr<IPCSCScanProvider> pcsc;

    mutable std::mutex contextMtx;
    SCARDCONTEXT hContext = 0;

    std::map<std::string, DWORD> previousReaderStates;
    // The PnP entry as last reported, passed back as its current state. A
    // source that keeps the reader count in the upper 16 bits (CryptoTokenKit)
    // reports every UNAWARE look as a change, so the loop would never wait.
    DWORD pnpState = SCARD_STATE_UNAWARE;
    // Last ATR announced for each reader that currently holds a card. A moved
    // PC/SC event counter says the reader's state changed, NOT that the card
    // did -- a contactless reader re-establishes the RF field constantly and the
    // counter moves with it. The ATR is what tells one card from another, so it
    // is what decides whether a still-present card is a new card.
    std::map<std::string, std::vector<std::uint8_t>> lastSeenAtr;
    std::atomic<bool> stopRequested{false};

    mutable std::mutex subscribersMtx;
    std::map<SubscriptionId, Subscriber> subscribers;
    SubscriptionId nextId = 1;

    // Serializes startThread/stopThread against each other so rapid
    // last-unsubscribe → first-subscribe cycles cannot land a still-joinable
    // monitorThread into startThread's `monitorThread = std::thread(...)`
    // assignment (which would call std::terminate).
    mutable std::mutex threadMtx;
    std::thread monitorThread;

    // Set when run() has returned; lets cancelAndJoin() stop repeating the cancel.
    std::mutex exitMtx;
    std::condition_variable exitCv;
    bool runReturned = false;
};

} // namespace LibreSCRS::SmartCard::Internal
