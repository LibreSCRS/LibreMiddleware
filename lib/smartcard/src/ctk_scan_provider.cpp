// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ctk_scan_provider.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

namespace {

constexpr LONG kSuccess = static_cast<LONG>(SCARD_S_SUCCESS);
// Any non-zero value: the context is the CtkSlots, held by the provider.
constexpr SCARDCONTEXT kContext = 1;

DWORD flagsOf(Ctk::SlotState state)
{
    switch (state) {
    case Ctk::SlotState::ValidCard:
        return SCARD_STATE_PRESENT;
    case Ctk::SlotState::MuteCard:
        return SCARD_STATE_PRESENT | SCARD_STATE_MUTE;
    case Ctk::SlotState::Missing:
        return SCARD_STATE_UNKNOWN | SCARD_STATE_UNAVAILABLE;
    case Ctk::SlotState::Empty:
    case Ctk::SlotState::Probing:
        break;
    }
    return SCARD_STATE_EMPTY;
}

// Fills one reader state from the snapshot; true when it changed.
bool fill(SCARD_READERSTATE& state, const std::vector<Ctk::SlotSnapshot>& slots)
{
    const DWORD current = state.dwCurrentState & ~static_cast<DWORD>(SCARD_STATE_CHANGED);
    DWORD event = 0;
    if (state.szReader != nullptr && std::strcmp(state.szReader, kPnpReaderName) == 0) {
        event = static_cast<DWORD>(slots.size() & 0xFFFF) << 16;
        // Only the count is compared: UNAWARE with no readers waits for one.
        if ((current >> 16) == (event >> 16)) {
            state.dwEventState = event;
            return false;
        }
        state.dwEventState = event | SCARD_STATE_CHANGED;
        return true;
    }

    const auto it = std::find_if(slots.begin(), slots.end(), [&](const Ctk::SlotSnapshot& slot) {
        return state.szReader != nullptr && slot.name == state.szReader;
    });
    if (it == slots.end()) {
        state.dwEventState = SCARD_STATE_UNKNOWN | SCARD_STATE_UNAVAILABLE | SCARD_STATE_CHANGED;
        state.cbAtr = 0;
        return true;
    }

    const auto shown = it->state == Ctk::SlotState::Probing ? it->settled : it->state;
    event = flagsOf(shown) | (static_cast<DWORD>(it->transitions & 0xFFFF) << 16);
    state.cbAtr = 0;
    if (shown == Ctk::SlotState::ValidCard) {
        const auto n = std::min<std::size_t>(it->atr.size(), sizeof(state.rgbAtr));
        std::copy_n(it->atr.begin(), n, state.rgbAtr);
        state.cbAtr = static_cast<decltype(state.cbAtr)>(n);
    }
    if (current == event) {
        state.dwEventState = event;
        return false;
    }
    state.dwEventState = event | SCARD_STATE_CHANGED;
    return true;
}

} // namespace

CtkScanProvider::CtkScanProvider() : CtkScanProvider(std::make_unique<Ctk::CtkSlots>()) {}

CtkScanProvider::CtkScanProvider(std::unique_ptr<Ctk::CtkSlots> s) : slots(std::move(s)) {}

LONG CtkScanProvider::establishContext(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT phContext)
{
    if (slots->acquire() == Ctk::CtkStatus::NoManager) {
        return static_cast<LONG>(SCARD_E_NO_ACCESS);
    }
    sawSlots.store(!slots->snapshot().empty());
    *phContext = kContext;
    return kSuccess;
}

LONG CtkScanProvider::releaseContext(SCARDCONTEXT)
{
    return kSuccess;
}

LONG CtkScanProvider::listReaders(SCARDCONTEXT, LPCSTR, LPSTR mszReaders, LPDWORD pcchReaders)
{
    const auto snapshot = slots->snapshot();
    if (snapshot.empty()) {
        *pcchReaders = 0;
        return static_cast<LONG>(sawSlots.load() ? SCARD_E_NO_SERVICE : SCARD_E_NO_READERS_AVAILABLE);
    }
    sawSlots.store(true);

    std::string multi;
    for (const auto& slot : snapshot) {
        multi += slot.name;
        multi.push_back('\0');
    }
    multi.push_back('\0');
    const auto needed = static_cast<DWORD>(multi.size());
    if (mszReaders == nullptr) {
        *pcchReaders = needed;
        return kSuccess;
    }
    if (*pcchReaders < needed) {
        *pcchReaders = needed;
        return static_cast<LONG>(SCARD_E_INSUFFICIENT_BUFFER);
    }
    std::memcpy(mszReaders, multi.data(), multi.size());
    *pcchReaders = needed;
    return kSuccess;
}

LONG CtkScanProvider::getStatusChange(SCARDCONTEXT, DWORD dwTimeout, SCARD_READERSTATE* rgReaderStates, DWORD cReaders)
{
    using Clock = std::chrono::steady_clock;
    const bool forever = dwTimeout == INFINITE;
    const auto deadline = Clock::now() + std::chrono::milliseconds(dwTimeout);

    for (;;) {
        const auto seen = slots->generation();
        const auto snapshot = slots->snapshot();
        if (!snapshot.empty()) {
            sawSlots.store(true);
        } else if (sawSlots.load()) {
            return static_cast<LONG>(SCARD_E_NO_SERVICE);
        }

        bool changed = false;
        for (DWORD i = 0; i < cReaders; ++i) {
            changed = fill(rgReaderStates[i], snapshot) || changed;
        }
        if (changed) {
            return kSuccess;
        }

        std::optional<std::chrono::milliseconds> wait;
        if (!forever) {
            const auto left = deadline - Clock::now();
            if (left <= Clock::duration::zero()) {
                return static_cast<LONG>(SCARD_E_TIMEOUT);
            }
            // Rounded up: a wait cut short would time out before the deadline.
            wait = std::chrono::ceil<std::chrono::milliseconds>(left);
        }
        switch (slots->waitForChange(seen, wait)) {
        case Ctk::WaitResult::Cancelled:
            return static_cast<LONG>(SCARD_E_CANCELLED);
        case Ctk::WaitResult::TimedOut:
            // The deadline is the provider's to judge, on the next pass.
        case Ctk::WaitResult::Changed:
            break;
        }
    }
}

LONG CtkScanProvider::cancel(SCARDCONTEXT)
{
    slots->cancel();
    return kSuccess;
}

} // namespace LibreSCRS::SmartCard::Internal
