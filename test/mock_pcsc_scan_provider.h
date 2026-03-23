// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#ifndef SMARTCARD_MOCK_PCSC_SCAN_PROVIDER_H
#define SMARTCARD_MOCK_PCSC_SCAN_PROVIDER_H

#include <smartcard/ipcsc_scan_provider.h>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace smartcard {

struct MockCounters
{
    std::atomic<int> establishContextCount{0};
    std::atomic<int> releaseContextCount{0};
    std::atomic<int> listReadersCount{0};
    std::atomic<int> getStatusChangeCount{0};
    std::atomic<int> cancelCount{0};
};

class MockPCSCScanProvider : public IPCSCScanProvider
{
public:
    explicit MockPCSCScanProvider(std::shared_ptr<MockCounters> c) : counters(std::move(c)) {}

    struct StatusChangeAction
    {
        LONG returnValue = SCARD_S_SUCCESS;
        std::vector<DWORD> eventStates = {};
        bool blocking = false;
        std::optional<std::vector<std::string>> newReaders = {};
        // ATR data to set on reader states (index -> ATR bytes)
        std::vector<std::vector<uint8_t>> atrData = {};
    };

    void setReaders(std::vector<std::string> names)
    {
        std::lock_guard<std::mutex> lock(mtx);
        readerNames = std::move(names);
    }

    void setListReadersReturn(LONG rv)
    {
        std::lock_guard<std::mutex> lock(mtx);
        listReadersRv = rv;
    }

    void pushStatusChange(StatusChangeAction action)
    {
        std::lock_guard<std::mutex> lock(mtx);
        statusChangeQueue.push_back(std::move(action));
    }

    LONG establishContext(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT phContext) override
    {
        *phContext = 42;
        counters->establishContextCount++;
        return SCARD_S_SUCCESS;
    }

    LONG releaseContext(SCARDCONTEXT) override
    {
        counters->releaseContextCount++;
        return SCARD_S_SUCCESS;
    }

    LONG listReaders(SCARDCONTEXT, LPCSTR, LPSTR mszReaders, LPDWORD pcchReaders) override
    {
        std::lock_guard<std::mutex> lock(mtx);
        counters->listReadersCount++;

        if (listReadersRv != SCARD_S_SUCCESS) {
            return listReadersRv;
        }

        if (readerNames.empty()) {
            *pcchReaders = 0;
            return SCARD_E_NO_READERS_AVAILABLE;
        }

        DWORD needed = 1; // trailing null
        for (const auto& name : readerNames) {
            needed += name.size() + 1;
        }

        if (mszReaders == nullptr) {
            *pcchReaders = needed;
            return SCARD_S_SUCCESS;
        }

        char* ptr = mszReaders;
        for (const auto& name : readerNames) {
            std::memcpy(ptr, name.c_str(), name.size() + 1);
            ptr += name.size() + 1;
        }
        *ptr = '\0';
        *pcchReaders = needed;
        return SCARD_S_SUCCESS;
    }

    LONG getStatusChange(SCARDCONTEXT, DWORD, SCARD_READERSTATE* rgReaderStates, DWORD cReaders) override
    {
        StatusChangeAction action;
        {
            std::lock_guard<std::mutex> lock(mtx);
            counters->getStatusChangeCount++;

            if (cancelled) {
                cancelled = false;
                return SCARD_E_CANCELLED;
            }

            if (statusChangeQueue.empty()) {
                return SCARD_E_CANCELLED;
            }

            action = statusChangeQueue.front();
            statusChangeQueue.erase(statusChangeQueue.begin());

            if (action.newReaders) {
                readerNames = std::move(*action.newReaders);
            }
        }

        if (action.blocking) {
            std::unique_lock<std::mutex> lock(blockMtx);
            blocked = true;
            blockCv.wait(lock, [this] { return !blocked; });

            std::lock_guard<std::mutex> lock2(mtx);
            if (cancelled) {
                cancelled = false;
                return SCARD_E_CANCELLED;
            }
        }

        for (DWORD i = 0; i < cReaders && i < action.eventStates.size(); i++) {
            rgReaderStates[i].dwEventState = action.eventStates[i];
        }

        for (DWORD i = 0; i < cReaders && i < action.atrData.size(); i++) {
            if (!action.atrData[i].empty()) {
                std::memcpy(rgReaderStates[i].rgbAtr, action.atrData[i].data(), action.atrData[i].size());
                rgReaderStates[i].cbAtr = static_cast<DWORD>(action.atrData[i].size());
            }
        }

        return action.returnValue;
    }

    LONG cancel(SCARDCONTEXT) override
    {
        {
            std::lock_guard<std::mutex> lock(mtx);
            cancelled = true;
            counters->cancelCount++;
        }
        {
            std::lock_guard<std::mutex> lock(blockMtx);
            blocked = false;
            blockCv.notify_all();
        }
        return SCARD_S_SUCCESS;
    }

private:
    std::shared_ptr<MockCounters> counters;

    std::mutex mtx;
    std::vector<std::string> readerNames;
    LONG listReadersRv = SCARD_S_SUCCESS;
    std::vector<StatusChangeAction> statusChangeQueue;

    std::mutex blockMtx;
    std::condition_variable blockCv;
    bool blocked = false;
    bool cancelled = false;
};

} // namespace smartcard

#endif // SMARTCARD_MOCK_PCSC_SCAN_PROVIDER_H
