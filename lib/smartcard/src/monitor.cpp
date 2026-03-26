// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#include "smartcard/monitor.h"
#include "smartcard/pcsc_scan_provider.h"

#include <chrono>
#include <cstring>
#include <stdexcept>

namespace smartcard {

static constexpr DWORD SCAN_TIMEOUT = 3600 * 1000; // 1 hour
static constexpr const char* PNP_READER = "\\\\?PnP?\\Notification";

Monitor::Monitor(std::unique_ptr<IPCSCScanProvider> provider)
    : pcsc(provider ? std::move(provider) : std::make_unique<PCSCScanProvider>())
{}

Monitor::~Monitor()
{
    stopThread();
}

Monitor::SubscriptionId Monitor::subscribe(MonitorCallback onEvent, ReaderListCallback onReaders)
{
    std::lock_guard lock(subscribersMtx);
    auto id = nextId++;
    subscribers[id] = {std::move(onEvent), std::move(onReaders)};
    if (subscribers.size() == 1) {
        startThread();
    }
    return id;
}

void Monitor::unsubscribe(SubscriptionId id)
{
    bool shouldStop = false;
    {
        std::lock_guard lock(subscribersMtx);
        subscribers.erase(id);
        shouldStop = subscribers.empty();
    }
    if (shouldStop) {
        stopThread();
    }
}

bool Monitor::isRunning() const
{
    return monitorThread.joinable() && !stopRequested.load();
}

void Monitor::startThread()
{
    previousReaderStates.clear();
    stopRequested = false;
    monitorThread = std::thread(&Monitor::run, this);
}

void Monitor::stopThread()
{
    if (!monitorThread.joinable()) {
        return;
    }
    stopRequested = true;
    // Note: hContext.load() may race with the monitor thread replacing hContext
    // in enumerateReaders(). SCardCancel on a stale context returns an error
    // but does not crash — the monitor thread will see stopRequested and exit.
    pcsc->cancel(hContext.load());
    monitorThread.join();
}

void Monitor::run()
{
    while (!stopRequested.load()) {
        try {
            establishContext();
            break;
        } catch (...) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    if (stopRequested.load())
        return;

    try {
        bool pnp = checkPnPSupport();

        while (!stopRequested.load()) {
            auto readers = enumerateReaders();

            if (readers.empty()) {
                notifyReaders({});
                waitForFirstReader(pnp);
                continue;
            }

            int readerCount = static_cast<int>(readers.size());
            int stateCount = pnp ? readerCount + 1 : readerCount;
            std::vector<SCARD_READERSTATE> states(stateCount, SCARD_READERSTATE{});

            std::vector<std::string> readerList;
            for (int i = 0; i < readerCount; i++) {
                readerList.push_back(readers[i]);
                states[i].szReader = readers[i].c_str();
                states[i].cbAtr = sizeof(states[i].rgbAtr);

                auto it = previousReaderStates.find(readers[i]);
                if (it != previousReaderStates.end()) {
                    states[i].dwCurrentState = it->second;
                } else {
                    states[i].dwCurrentState = SCARD_STATE_UNAWARE;
                }
            }

            if (pnp) {
                states[readerCount].szReader = PNP_READER;
                states[readerCount].dwCurrentState = SCARD_STATE_UNAWARE;
            }

            notifyReaders(readerList);

            if (!processEvents(states, readerCount, pnp)) {
                break; // cancelled
            }

            // Save current reader states for the next enumeration cycle
            previousReaderStates.clear();
            for (int i = 0; i < readerCount; i++) {
                previousReaderStates[readers[i]] = states[i].dwCurrentState;
            }
        }

        pcsc->releaseContext(hContext);
    } catch (...) {
        pcsc->releaseContext(hContext);
    }
}

void Monitor::establishContext()
{
    SCARDCONTEXT ctx = 0;
    LONG rv = pcsc->establishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
    if (rv != SCARD_S_SUCCESS) {
        throw std::runtime_error("Cannot establish context in Monitor");
    }
    hContext = ctx;
}

bool Monitor::checkPnPSupport()
{
    SCARD_READERSTATE state{};
    state.szReader = PNP_READER;
    state.dwCurrentState = SCARD_STATE_UNAWARE;

    pcsc->getStatusChange(hContext, 0, &state, 1);
    if (state.dwEventState & SCARD_STATE_UNKNOWN) {
        return false;
    }
    return true;
}

std::vector<std::string> Monitor::enumerateReaders()
{
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD dwReaders = 0;
        LONG rv = pcsc->listReaders(hContext, nullptr, nullptr, &dwReaders);

        if (rv == SCARD_E_NO_READERS_AVAILABLE || dwReaders == 0) {
            return {};
        }

        if (rv != SCARD_S_SUCCESS) {
            pcsc->releaseContext(hContext);
            SCARDCONTEXT ctx = 0;
            rv = pcsc->establishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
            if (rv != SCARD_S_SUCCESS) {
                throw std::runtime_error("Cannot re-establish context in Monitor");
            }
            hContext = ctx;
            return {};
        }

        std::vector<char> buffer(dwReaders);
        buffer[0] = '\0';
        rv = pcsc->listReaders(hContext, nullptr, buffer.data(), &dwReaders);

        if (rv == SCARD_E_INSUFFICIENT_BUFFER)
            continue; // retry

        if (rv == SCARD_E_NO_READERS_AVAILABLE) {
            return {};
        }
        if (rv != SCARD_S_SUCCESS) {
            return {};
        }

        std::vector<std::string> readers;
        const char* ptr = buffer.data();
        while (ptr < buffer.data() + dwReaders && *ptr != '\0') {
            readers.emplace_back(ptr);
            ptr += readers.back().size() + 1;
        }
        return readers;
    }
    return {};
}

void Monitor::waitForFirstReader(bool pnp)
{
    if (pnp) {
        SCARD_READERSTATE state{};
        state.szReader = PNP_READER;
        state.dwCurrentState = SCARD_STATE_UNAWARE;

        LONG rv;
        do {
            rv = pcsc->getStatusChange(hContext, SCAN_TIMEOUT, &state, 1);
        } while (rv == SCARD_E_TIMEOUT && !stopRequested.load());

        if (rv != SCARD_S_SUCCESS) {
            pcsc->releaseContext(hContext);
            SCARDCONTEXT ctx = 0;
            LONG rv2 = pcsc->establishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
            if (rv2 != SCARD_S_SUCCESS) {
                throw std::runtime_error("Cannot re-establish context in Monitor");
            }
            hContext = ctx;
        }
    } else {
        DWORD dwReaders = 0;
        DWORD dwReadersOld = 0;
        pcsc->listReaders(hContext, nullptr, nullptr, &dwReadersOld);
        dwReaders = dwReadersOld;

        LONG rv = SCARD_S_SUCCESS;
        while ((rv == SCARD_S_SUCCESS) && (dwReaders == dwReadersOld)) {
            rv = pcsc->listReaders(hContext, nullptr, nullptr, &dwReaders);
            if (rv == SCARD_E_NO_READERS_AVAILABLE) {
                rv = SCARD_S_SUCCESS;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (stopRequested.load()) {
                return;
            }
        }
    }
}

bool Monitor::processEvents(std::vector<SCARD_READERSTATE>& states, int readerCount, bool pnp)
{
    int totalStates = pnp ? readerCount + 1 : readerCount;

    // Non-blocking probe to capture initial card state
    LONG rv = pcsc->getStatusChange(hContext, 0, states.data(), totalStates);

    while ((rv == SCARD_S_SUCCESS) || (rv == SCARD_E_TIMEOUT)) {
        if (pnp) {
            if (states[readerCount].dwEventState & SCARD_STATE_CHANGED) {
                return true; // re-enumerate
            }
        } else {
            DWORD dwReaders = 0;
            DWORD dwReadersOld = 0;
            for (int i = 0; i < readerCount; i++) {
                dwReadersOld += strlen(states[i].szReader) + 1;
            }
            dwReadersOld += 1; // trailing null
            if ((pcsc->listReaders(hContext, nullptr, nullptr, &dwReaders) == SCARD_S_SUCCESS) &&
                (dwReaders != dwReadersOld)) {
                return true; // re-enumerate
            }
        }

        bool needReEnumeration = false;
        for (int i = 0; i < readerCount; i++) {
            DWORD dwPrevState = states[i].dwCurrentState;
            if (states[i].dwEventState & SCARD_STATE_CHANGED) {
                states[i].dwCurrentState = states[i].dwEventState & ~SCARD_STATE_CHANGED;
            } else {
                continue;
            }

            if (states[i].dwEventState & SCARD_STATE_UNKNOWN) {
                notifyEvent({MonitorEvent::Type::CardRemoved, states[i].szReader, {}});
                needReEnumeration = true;
                break;
            }

            bool shouldEmit = false;
            MonitorEvent::Type eventType = MonitorEvent::Type::CardRemoved;
            std::vector<uint8_t> atr;

            if (states[i].dwEventState & SCARD_STATE_EMPTY) {
                shouldEmit = true;
                eventType = MonitorEvent::Type::CardRemoved;
            }

            if (states[i].dwEventState & SCARD_STATE_PRESENT) {
                if (states[i].dwEventState & SCARD_STATE_EXCLUSIVE) {
                    continue;
                } else if (states[i].dwEventState & SCARD_STATE_MUTE) {
                    continue;
                } else if (dwPrevState & SCARD_STATE_PRESENT) {
                    if ((dwPrevState >> 16) == (states[i].dwEventState >> 16)) {
                        // Same event counter — INUSE toggle, skip
                        continue;
                    }
                    // Card swapped — emit remove for old card
                    notifyEvent({MonitorEvent::Type::CardRemoved, states[i].szReader, {}});
                    shouldEmit = true;
                    eventType = MonitorEvent::Type::CardInserted;
                    atr.assign(states[i].rgbAtr, states[i].rgbAtr + states[i].cbAtr);
                } else {
                    shouldEmit = true;
                    eventType = MonitorEvent::Type::CardInserted;
                    atr.assign(states[i].rgbAtr, states[i].rgbAtr + states[i].cbAtr);
                }
            }

            if (shouldEmit) {
                notifyEvent({eventType, states[i].szReader, std::move(atr)});
            }
        }

        if (needReEnumeration) {
            return true;
        }

        if (stopRequested.load())
            break;

        rv = pcsc->getStatusChange(hContext, SCAN_TIMEOUT, states.data(), totalStates);
    }

    // Post-loop error handling
    if (rv == SCARD_E_NO_SERVICE) {
        // Emit CardRemoved only for readers that had a card present
        for (int i = 0; i < readerCount; i++) {
            if (states[i].dwCurrentState & SCARD_STATE_PRESENT) {
                notifyEvent({MonitorEvent::Type::CardRemoved, states[i].szReader, {}});
            }
        }

        // Re-establish context
        pcsc->releaseContext(hContext);
        SCARDCONTEXT ctx = 0;
        LONG rv2 = pcsc->establishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
        if (rv2 != SCARD_S_SUCCESS) {
            throw std::runtime_error("Cannot re-establish context in Monitor");
        }
        hContext = ctx;
        return true;
    }

    if (rv == SCARD_E_UNKNOWN_READER) {
        return true; // re-enumerate
    }

    if (rv == SCARD_E_CANCELLED) {
        return false; // stop
    }

    // Other error — re-establish context
    if (rv != SCARD_S_SUCCESS) {
        pcsc->releaseContext(hContext);
        SCARDCONTEXT ctx = 0;
        LONG rv2 = pcsc->establishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
        if (rv2 != SCARD_S_SUCCESS) {
            throw std::runtime_error("Cannot re-establish context in Monitor");
        }
        hContext = ctx;
    }
    return true;
}

void Monitor::notifyEvent(const MonitorEvent& event)
{
    std::vector<MonitorCallback> callbacks;
    {
        std::lock_guard lock(subscribersMtx);
        callbacks.reserve(subscribers.size());
        for (const auto& [id, sub] : subscribers) {
            if (sub.onEvent)
                callbacks.push_back(sub.onEvent);
        }
    }
    for (const auto& cb : callbacks) {
        try {
            cb(event);
        } catch (...) {
        }
    }
}

void Monitor::notifyReaders(const std::vector<std::string>& readers)
{
    std::vector<ReaderListCallback> callbacks;
    {
        std::lock_guard lock(subscribersMtx);
        callbacks.reserve(subscribers.size());
        for (const auto& [id, sub] : subscribers) {
            if (sub.onReaders)
                callbacks.push_back(sub.onReaders);
        }
    }
    for (const auto& cb : callbacks) {
        try {
            cb(readers);
        } catch (...) {
        }
    }
}

} // namespace smartcard
