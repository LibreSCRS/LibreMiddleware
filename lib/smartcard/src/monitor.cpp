// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#include "monitor.h"
#include "pcsc_scan_provider.h"

#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>

namespace LibreSCRS::SmartCard::Internal {

static constexpr DWORD SCAN_TIMEOUT = 3600 * 1000; // 1 hour
static constexpr const char* PNP_READER = "\\\\?PnP?\\Notification";

// SCARD_* constants are defined by the PCSC headers as unsigned (DWORD)
// literals, but SCardXxx() functions return signed LONG. Comparing the two
// directly triggers -Wsign-compare. Re-declare the ones we use as typed LONG
// constants so every comparison below is sign-homogeneous.
static constexpr LONG kScSuccess = static_cast<LONG>(SCARD_S_SUCCESS);
static constexpr LONG kScNoReadersAvailable = static_cast<LONG>(SCARD_E_NO_READERS_AVAILABLE);
static constexpr LONG kScInsufficientBuffer = static_cast<LONG>(SCARD_E_INSUFFICIENT_BUFFER);
static constexpr LONG kScTimeout = static_cast<LONG>(SCARD_E_TIMEOUT);
static constexpr LONG kScNoService = static_cast<LONG>(SCARD_E_NO_SERVICE);
static constexpr LONG kScUnknownReader = static_cast<LONG>(SCARD_E_UNKNOWN_READER);
static constexpr LONG kScCancelled = static_cast<LONG>(SCARD_E_CANCELLED);

Monitor::Monitor(std::unique_ptr<IPCSCScanProvider> provider)
    : pcsc(provider ? std::move(provider) : std::make_unique<PCSCScanProvider>())
{}

Monitor::~Monitor()
{
    stopThread();
}

Monitor::SubscriptionId Monitor::subscribe(MonitorCallback onEvent, ReaderListCallback onReaders)
{
    bool needsStart = false;
    SubscriptionId id;
    {
        std::lock_guard lock(subscribersMtx);
        id = nextId++;
        assert(subscribers.find(id) == subscribers.end()); // overflow guard
        subscribers[id] = {std::move(onEvent), std::move(onReaders)};
        // Capture the first-subscriber flag under subscribersMtx, but call
        // startThread() outside the lock. startThread() acquires threadMtx
        // and may join a prior poll thread that is blocked in notifyReaders/
        // notifyEvent trying to acquire subscribersMtx — holding both
        // subscribersMtx and waiting for threadMtx (which stopThread holds
        // while joining that same poll thread) forms an ABBA deadlock.
        needsStart = (subscribers.size() == 1);
    }
    if (needsStart) {
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
    // Take threadMtx: startThread/stopThread mutate monitorThread under this
    // lock, so reading monitorThread.joinable() without it is a data race.
    // isRunning is never called from a threadMtx-holding path (only by
    // MonitorService and tests), so there is no self-deadlock.
    std::lock_guard<std::mutex> lock(threadMtx);
    return monitorThread.joinable() && !stopRequested.load();
}

void Monitor::startThread()
{
    std::lock_guard lock(threadMtx);
    if (monitorThread.joinable()) {
        // A prior stopThread() on another thread has not yet completed the
        // join. Two cases:
        //
        // (a) Normal: stopThread already set stopRequested=true and
        //     cancelled, but the OS hasn't scheduled the poll thread to
        //     exit yet. Just join and let it finish.
        //
        // (b) Race: startThread acquired threadMtx BEFORE a concurrent
        //     stopThread (i.e. subscribe/startThread raced unsubscribe/
        //     stopThread for threadMtx and won). The poll thread is still
        //     running with stopRequested=false; if we join now we block
        //     forever because the concurrent stopThread — which would have
        //     set stopRequested=true and cancelled — cannot acquire
        //     threadMtx while we hold it. Detect this by checking
        //     stopRequested and set it + cancel ourselves so the join
        //     can complete.
        if (!stopRequested.load()) {
            stopRequested = true;
            SCARDCONTEXT ctx;
            {
                std::lock_guard ctxLock(contextMtx);
                ctx = hContext;
            }
            if (ctx)
                pcsc->cancel(ctx);
        }
        monitorThread.join();
    }
    previousReaderStates.clear();
    stopRequested = false;
    // Spawn via a local lambda so the std::thread::_State_impl<...> template
    // instantiation parameterises over the anonymous closure (local linkage)
    // rather than over the internal Monitor type, which the *LibreSCRS::*
    // export glob would otherwise promote to a global SHARED-build symbol.
    // Mirrors the coalesceFlusher spawn in lib/LibreSCRS/SmartCard/MonitorService.cpp.
    monitorThread = std::thread([this] { run(); });
}

void Monitor::stopThread()
{
    std::lock_guard lock(threadMtx);
    if (!monitorThread.joinable()) {
        return;
    }
    stopRequested = true;

    SCARDCONTEXT ctx;
    {
        std::lock_guard ctxLock(contextMtx);
        ctx = hContext;
    }
    if (ctx)
        pcsc->cancel(ctx);

    monitorThread.join();
}

void Monitor::run()
{
    bool contextEstablished = false;
    while (!stopRequested.load()) {
        try {
            establishContext();
            contextEstablished = true;
            break;
        } catch (...) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    if (stopRequested.load()) {
        // stopThread() (or startThread() fixing the startThread/stopThread
        // race) set stopRequested between establishContext() returning and
        // the break, or before the loop ran at all. If this invocation
        // established a context, release it now — otherwise
        // establishContextCount and releaseContextCount are permanently
        // unbalanced by one per occurrence. See monitor.cpp TOCTOU note.
        if (contextEstablished) {
            SCARDCONTEXT ctx;
            {
                std::lock_guard<std::mutex> ctxLock(contextMtx);
                ctx = hContext;
                hContext = 0;
            }
            if (ctx) {
                pcsc->releaseContext(ctx);
            }
        }
        return;
    }

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

        // Zero hContext under contextMtx before releasing so a concurrent
        // stopThread() cannot read the handle and SCardCancel a context this
        // path has already released (undefined behaviour). Mirrors the
        // early-stop path above.
        {
            SCARDCONTEXT ctx;
            {
                std::lock_guard<std::mutex> ctxLock(contextMtx);
                ctx = hContext;
                hContext = 0;
            }
            if (ctx) {
                pcsc->releaseContext(ctx);
            }
        }
    } catch (...) {
        // Same teardown discipline on the exception path: zero under
        // contextMtx before release so a concurrent stopThread() cannot
        // SCardCancel a released context.
        {
            SCARDCONTEXT ctx;
            {
                std::lock_guard<std::mutex> ctxLock(contextMtx);
                ctx = hContext;
                hContext = 0;
            }
            if (ctx) {
                pcsc->releaseContext(ctx);
            }
        }
    }
}

void Monitor::setContext(SCARDCONTEXT ctx)
{
    std::lock_guard lock(contextMtx);
    hContext = ctx;
}

void Monitor::reEstablishContext()
{
    // Snapshot and zero hContext under contextMtx before releasing, so a
    // concurrent stopThread() cannot read and SCardCancel the released
    // handle, and so a throw from the re-establish below cannot leave a
    // stale released handle visible to a concurrent reader.
    SCARDCONTEXT old;
    {
        std::lock_guard<std::mutex> ctxLock(contextMtx);
        old = hContext;
        hContext = 0;
    }
    if (old) {
        pcsc->releaseContext(old);
    }

    SCARDCONTEXT ctx = 0;
    LONG rv = pcsc->establishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
    if (rv != kScSuccess) {
        throw std::runtime_error("Cannot re-establish context in Monitor");
    }
    setContext(ctx);
}

void Monitor::establishContext()
{
    SCARDCONTEXT ctx = 0;
    LONG rv = pcsc->establishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
    if (rv != kScSuccess) {
        throw std::runtime_error("Cannot establish context in Monitor");
    }
    setContext(ctx);
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

        if (rv == kScNoReadersAvailable || dwReaders == 0) {
            return {};
        }

        if (rv != kScSuccess) {
            reEstablishContext();
            return {};
        }

        std::vector<char> buffer(dwReaders);
        buffer[0] = '\0';
        rv = pcsc->listReaders(hContext, nullptr, buffer.data(), &dwReaders);

        if (rv == kScInsufficientBuffer)
            continue; // retry

        if (rv == kScNoReadersAvailable) {
            return {};
        }
        if (rv != kScSuccess) {
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
        } while (rv == kScTimeout && !stopRequested.load());

        if (rv != kScSuccess) {
            reEstablishContext();
        }
    } else {
        auto readersBefore = enumerateReaders();
        while (!stopRequested.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto readersNow = enumerateReaders();
            if (readersNow != readersBefore)
                break;
        }
    }
}

bool Monitor::processEvents(std::vector<SCARD_READERSTATE>& states, int readerCount, bool pnp)
{
    int totalStates = pnp ? readerCount + 1 : readerCount;

    // Non-blocking probe to capture initial card state
    LONG rv = pcsc->getStatusChange(hContext, 0, states.data(), totalStates);

    while ((rv == kScSuccess) || (rv == kScTimeout)) {
        if (pnp) {
            if (states[readerCount].dwEventState & SCARD_STATE_CHANGED) {
                return true; // re-enumerate
            }
        } else {
            auto currentReaders = enumerateReaders();
            std::vector<std::string> knownReaders;
            knownReaders.reserve(readerCount);
            for (int i = 0; i < readerCount; i++) {
                knownReaders.emplace_back(states[i].szReader);
            }
            if (currentReaders != knownReaders) {
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
                } else if ((dwPrevState & SCARD_STATE_PRESENT) &&
                           (dwPrevState & (SCARD_STATE_MUTE | SCARD_STATE_EXCLUSIVE))) {
                    // Card was PRESENT but suppressed (MUTE/EXCLUSIVE) — now usable.
                    // Emit CardInserted that we deferred earlier.
                    shouldEmit = true;
                    eventType = MonitorEvent::Type::CardInserted;
                    atr.assign(states[i].rgbAtr, states[i].rgbAtr + states[i].cbAtr);
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
    if (rv == kScNoService) {
        // Emit CardRemoved only for readers that had a card present
        for (int i = 0; i < readerCount; i++) {
            if (states[i].dwCurrentState & SCARD_STATE_PRESENT) {
                notifyEvent({MonitorEvent::Type::CardRemoved, states[i].szReader, {}});
            }
        }

        reEstablishContext();
        return true;
    }

    if (rv == kScUnknownReader) {
        return true; // re-enumerate
    }

    if (rv == kScCancelled) {
        return false; // stop
    }

    // Other error — re-establish context
    if (rv != kScSuccess) {
        reEstablishContext();
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
        } catch (const std::exception& ex) {
            std::cerr << "Monitor: event callback threw: " << ex.what() << "\n";
        } catch (...) {
            std::cerr << "Monitor: event callback threw unknown exception\n";
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
        } catch (const std::exception& ex) {
            std::cerr << "Monitor: reader-list callback threw: " << ex.what() << "\n";
        } catch (...) {
            std::cerr << "Monitor: reader-list callback threw unknown exception\n";
        }
    }
}

} // namespace LibreSCRS::SmartCard::Internal
