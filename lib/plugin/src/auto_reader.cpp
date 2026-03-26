// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#include <plugin/auto_reader.h>
#include <plugin/card_plugin_registry.h>
#include <smartcard/pcsc_connection.h>

#include <chrono>
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

    std::vector<std::future<void>> pending;
    {
        std::lock_guard lock(pendingMtx);
        pending = std::move(pendingReads);
    }
    for (auto& f : pending) {
        if (f.valid())
            f.wait();
    }
}

void AutoReader::onMonitorEvent(const smartcard::MonitorEvent& event)
{
    if (event.type != smartcard::MonitorEvent::Type::CardInserted)
        return;

    auto readerName = event.readerName;
    auto atr = event.atr;

    auto future = std::async(std::launch::async, [this, readerName = std::move(readerName), atr = std::move(atr)]() {
        constexpr int maxAttempts = 2;
        constexpr auto retryDelay = std::chrono::milliseconds(300);

        for (int attempt = 0; attempt < maxAttempts; ++attempt) {
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

    // Clean up completed futures
    pendingReads.erase(std::remove_if(pendingReads.begin(), pendingReads.end(),
                                      [](const std::future<void>& f) {
                                          return f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                                      }),
                       pendingReads.end());

    pendingReads.push_back(std::move(future));
}

} // namespace plugin
