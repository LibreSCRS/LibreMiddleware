// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#include <plugin/auto_reader.h>
#include <plugin/card_plugin_registry.h>
#include <smartcard/pcsc_connection.h>

#include <chrono>
#include <mutex>
#include <thread>

namespace plugin {

AutoReader::AutoReader(smartcard::Monitor& monitor, CardPluginRegistry& registry, CardDataCallback onData,
                       ErrorCallback onError)
    : monitor(monitor), registry(registry), onData(std::move(onData)), onError(std::move(onError))
{
    subscriptionId = monitor.subscribe([this](const smartcard::MonitorEvent& e) { onMonitorEvent(e); });
}

AutoReader::~AutoReader()
{
    monitor.unsubscribe(subscriptionId);

    std::map<std::string, PendingRead> pending;
    {
        std::lock_guard lock(pendingMtx);
        pending = std::move(pendingByReader);
    }
    for (auto& [name, pr] : pending) {
        pr.cancelled->store(true);
        if (pr.future.valid())
            pr.future.wait();
    }
}

void AutoReader::onMonitorEvent(const smartcard::MonitorEvent& event)
{
    if (event.type == smartcard::MonitorEvent::Type::CardRemoved) {
        std::lock_guard lock(pendingMtx);
        auto it = pendingByReader.find(event.readerName);
        if (it != pendingByReader.end()) {
            it->second.cancelled->store(true);
        }
        return;
    }

    if (event.type != smartcard::MonitorEvent::Type::CardInserted)
        return;

    auto readerName = event.readerName;
    auto atr = event.atr;

    auto cancelFlag = std::make_shared<std::atomic<bool>>(false);

    auto future =
        std::async(std::launch::async, [this, readerName = std::move(readerName), atr = std::move(atr), cancelFlag]() {
            constexpr int maxAttempts = 2;
            constexpr auto retryDelay = std::chrono::milliseconds(300);

            for (int attempt = 0; attempt < maxAttempts; ++attempt) {
                if (cancelFlag->load())
                    return;

                try {
                    smartcard::PCSCConnection conn(readerName);
                    auto candidates = registry.findAllCandidates(atr, conn);

                    if (candidates.empty()) {
                        if (onError)
                            onError(readerName, "No compatible plugin found");
                        return;
                    }

                    // Note: onData/onError callbacks are invoked from this background thread.
                    // Callers must ensure thread safety (e.g., use QMetaObject::invokeMethod).
                    for (auto* plugin : candidates) {
                        if (cancelFlag->load())
                            return;
                        try {
                            auto data = plugin->readCard(conn);
                            if (onData)
                                onData(readerName, data);
                            return;
                        } catch (...) {
                            // Try next plugin
                        }
                    }

                    if (onError)
                        onError(readerName, "All plugins failed to read card");
                    return;

                } catch (const std::exception& ex) {
                    if (attempt + 1 < maxAttempts)
                        std::this_thread::sleep_for(retryDelay);
                    else if (onError)
                        onError(readerName, std::string("Card connection failed: ") + ex.what());
                } catch (...) {
                    if (attempt + 1 < maxAttempts)
                        std::this_thread::sleep_for(retryDelay);
                    else if (onError)
                        onError(readerName, "Card connection failed");
                }
            }
        });

    std::lock_guard lock(pendingMtx);

    // If there's already a running task for this reader, cancel it
    auto it = pendingByReader.find(event.readerName);
    if (it != pendingByReader.end()) {
        it->second.cancelled->store(true);
    }

    pendingByReader[event.readerName] = {std::move(future), cancelFlag};
}

} // namespace plugin
