// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#pragma once

#include "ipcsc_scan_provider.h"
#include "monitor_event.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace smartcard {

using MonitorCallback = std::function<void(const MonitorEvent&)>;
using ReaderListCallback = std::function<void(const std::vector<std::string>&)>;

class Monitor
{
public:
    explicit Monitor(std::unique_ptr<IPCSCScanProvider> provider = nullptr);
    ~Monitor();

    Monitor(const Monitor&) = delete;
    Monitor& operator=(const Monitor&) = delete;

    using SubscriptionId = uint64_t;
    SubscriptionId subscribe(MonitorCallback onEvent, ReaderListCallback onReaders = nullptr);
    void unsubscribe(SubscriptionId id);

    bool isRunning() const;

private:
    struct Subscriber
    {
        MonitorCallback onEvent;
        ReaderListCallback onReaders;
    };

    void startThread();
    void stopThread();
    void run();

    void establishContext();
    bool checkPnPSupport();
    std::vector<std::string> enumerateReaders();
    void waitForFirstReader(bool pnp);
    bool processEvents(std::vector<SCARD_READERSTATE>& states, int readerCount, bool pnp);

    void notifyEvent(const MonitorEvent& event);
    void notifyReaders(const std::vector<std::string>& readers);

    std::unique_ptr<IPCSCScanProvider> pcsc;
    std::atomic<SCARDCONTEXT> hContext{0};
    std::map<std::string, DWORD> previousReaderStates;
    std::atomic<bool> stopRequested{false};

    mutable std::mutex subscribersMtx;
    std::map<SubscriptionId, Subscriber> subscribers;
    SubscriptionId nextId = 1;

    std::thread monitorThread;
};

} // namespace smartcard
