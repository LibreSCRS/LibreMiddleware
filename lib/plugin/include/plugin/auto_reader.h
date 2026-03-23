// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#pragma once

#include <plugin/card_data.h>
#include <smartcard/monitor.h>

#include <functional>
#include <future>
#include <mutex>
#include <string>
#include <vector>

namespace plugin {

class CardPluginRegistry;

using CardDataCallback = std::function<void(const std::string& readerName, const CardData& data)>;
using ErrorCallback = std::function<void(const std::string& readerName, const std::string& error)>;

class AutoReader
{
public:
    AutoReader(smartcard::Monitor& monitor, CardPluginRegistry& registry, CardDataCallback onData,
               ErrorCallback onError = nullptr);
    ~AutoReader();

    AutoReader(const AutoReader&) = delete;
    AutoReader& operator=(const AutoReader&) = delete;

private:
    void onMonitorEvent(const smartcard::MonitorEvent& event);

    smartcard::Monitor& monitor;
    CardPluginRegistry& registry;
    CardDataCallback onData;
    ErrorCallback onError;
    smartcard::Monitor::SubscriptionId subscriptionId;

    std::mutex pendingMtx;
    std::vector<std::future<void>> pendingReads;
};

} // namespace plugin
