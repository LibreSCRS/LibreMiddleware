// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Reader events from CryptoTokenKit's slots in PC/SC terms, against the
// scripted CryptoTokenKit: what each slot state reads as, when a wait
// returns, and when the provider asks for the slot manager again.

#include <gtest/gtest.h>

#include "ctk_fake.h"
#include "ctk_scan_provider.h"

#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

using LibreSCRS::SmartCard::Internal::CtkScanProvider;
using LibreSCRS::SmartCard::Internal::kPnpReaderName;
namespace Ctk = LibreSCRS::SmartCard::Internal::Ctk;
namespace Fake = LibreSCRS::SmartCard::Internal::Ctk::Fake;
using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

const std::string kA = "Fake Reader A";
const std::string kB = "Fake Reader B";
const std::string kMute = "Fake Reader Mute";
const std::string kGone = "Fake Reader Gone";

// The state keeps a pointer to the name: pass one that outlives it.
SCARD_READERSTATE stateFor(const std::string& reader, DWORD current = SCARD_STATE_UNAWARE)
{
    SCARD_READERSTATE s{};
    s.szReader = reader.c_str();
    s.dwCurrentState = current;
    return s;
}

DWORD low(DWORD state)
{
    return state & 0xFFFF;
}

class CtkScanProviderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Fake::reset();
    }

    // A provider with its context taken.
    std::unique_ptr<CtkScanProvider> established()
    {
        auto provider = std::make_unique<CtkScanProvider>();
        SCARDCONTEXT ctx = 0;
        EXPECT_EQ(provider->establishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx),
                  static_cast<LONG>(SCARD_S_SUCCESS));
        EXPECT_NE(ctx, 0);
        return provider;
    }
};

} // namespace

TEST_F(CtkScanProviderTest, ConstructionDoesNotTouchTheSlotManager)
{
    (void)Fake::slot(kA);
    CtkScanProvider provider;
    EXPECT_EQ(Fake::slotsManagerLookups(), 0);
}

TEST_F(CtkScanProviderTest, NilManagerIsNoAccess)
{
    Fake::setManagerPresent(false);
    CtkScanProvider provider;
    SCARDCONTEXT ctx = 0;
    EXPECT_EQ(provider.establishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx),
              static_cast<LONG>(SCARD_E_NO_ACCESS));
    // The monitor reports the refusal with this text: it names the entitlement.
    EXPECT_NE(std::string(provider.refusalDetail()).find("com.apple.security.smartcard"), std::string::npos)
        << provider.refusalDetail();
}

TEST_F(CtkScanProviderTest, MapsSlotStates)
{
    Fake::slot(kA).atr = {0x3B, 0x8E, 0x80, 0x01};
    (void)Fake::slot(kB);
    Fake::setSlotState(kB, Ctk::SlotState::Empty);
    (void)Fake::slot(kMute);
    Fake::setSlotState(kMute, Ctk::SlotState::MuteCard);
    auto provider = established();

    std::vector<SCARD_READERSTATE> states{stateFor(kA), stateFor(kB), stateFor(kMute), stateFor(kGone)};
    ASSERT_EQ(provider->getStatusChange(1, 0, states.data(), static_cast<DWORD>(states.size())),
              static_cast<LONG>(SCARD_S_SUCCESS));

    EXPECT_EQ(low(states[0].dwEventState), static_cast<DWORD>(SCARD_STATE_PRESENT | SCARD_STATE_CHANGED));
    ASSERT_EQ(states[0].cbAtr, 4U);
    EXPECT_EQ(std::vector<std::uint8_t>(states[0].rgbAtr, states[0].rgbAtr + states[0].cbAtr),
              (std::vector<std::uint8_t>{0x3B, 0x8E, 0x80, 0x01}));
    EXPECT_EQ(low(states[1].dwEventState), static_cast<DWORD>(SCARD_STATE_EMPTY | SCARD_STATE_CHANGED));
    EXPECT_EQ(low(states[2].dwEventState),
              static_cast<DWORD>(SCARD_STATE_PRESENT | SCARD_STATE_MUTE | SCARD_STATE_CHANGED));
    EXPECT_EQ(low(states[3].dwEventState),
              static_cast<DWORD>(SCARD_STATE_UNKNOWN | SCARD_STATE_UNAVAILABLE | SCARD_STATE_CHANGED));
    for (const auto& s : states) {
        EXPECT_EQ(s.dwEventState & static_cast<DWORD>(SCARD_STATE_INUSE | SCARD_STATE_EXCLUSIVE), 0U);
    }
}

TEST_F(CtkScanProviderTest, UnawareAlwaysReportsAChange)
{
    (void)Fake::slot(kA);
    auto provider = established();
    for (int i = 0; i < 3; ++i) {
        auto s = stateFor(kA);
        ASSERT_EQ(provider->getStatusChange(1, 0, &s, 1), static_cast<LONG>(SCARD_S_SUCCESS));
        EXPECT_NE(s.dwEventState & static_cast<DWORD>(SCARD_STATE_CHANGED), 0U);
    }
}

TEST_F(CtkScanProviderTest, ProbingWithNoHistoryIsEmpty)
{
    (void)Fake::slot(kA);
    Fake::setSlotState(kA, Ctk::SlotState::Empty);
    Fake::setSlotState(kA, Ctk::SlotState::Probing);
    auto provider = established();
    auto s = stateFor(kA);
    ASSERT_EQ(provider->getStatusChange(1, 0, &s, 1), static_cast<LONG>(SCARD_S_SUCCESS));
    EXPECT_EQ(low(s.dwEventState), static_cast<DWORD>(SCARD_STATE_EMPTY | SCARD_STATE_CHANGED));

    // A card that was there and is being probed again still reads present.
    Fake::setSlotState(kA, Ctk::SlotState::ValidCard);
    Fake::setSlotState(kA, Ctk::SlotState::Probing);
    s = stateFor(kA);
    ASSERT_EQ(provider->getStatusChange(1, 0, &s, 1), static_cast<LONG>(SCARD_S_SUCCESS));
    EXPECT_EQ(low(s.dwEventState) & static_cast<DWORD>(SCARD_STATE_PRESENT), static_cast<DWORD>(SCARD_STATE_PRESENT));
}

TEST_F(CtkScanProviderTest, ReturnsAtOnceWhenStateDiffers)
{
    (void)Fake::slot(kA);
    auto provider = established();
    auto s = stateFor(kA, SCARD_STATE_EMPTY);
    const auto start = Clock::now();
    EXPECT_EQ(provider->getStatusChange(1, INFINITE, &s, 1), static_cast<LONG>(SCARD_S_SUCCESS));
    EXPECT_LT(Clock::now() - start, milliseconds{50});
}

TEST_F(CtkScanProviderTest, BlocksUntilASlotChanges)
{
    (void)Fake::slot(kA);
    auto provider = established();
    auto s = stateFor(kA);
    ASSERT_EQ(provider->getStatusChange(1, 0, &s, 1), static_cast<LONG>(SCARD_S_SUCCESS));
    s.dwCurrentState = s.dwEventState & ~static_cast<DWORD>(SCARD_STATE_CHANGED);

    std::thread remover([] {
        std::this_thread::sleep_for(milliseconds{200});
        Fake::setSlotState(kA, Ctk::SlotState::Empty);
    });
    const auto start = Clock::now();
    const LONG rv = provider->getStatusChange(1, INFINITE, &s, 1);
    const auto took = Clock::now() - start;
    remover.join();
    EXPECT_EQ(rv, static_cast<LONG>(SCARD_S_SUCCESS));
    EXPECT_EQ(low(s.dwEventState), static_cast<DWORD>(SCARD_STATE_EMPTY | SCARD_STATE_CHANGED));
    EXPECT_GE(took, milliseconds{150});
    EXPECT_LT(took, milliseconds{1000});
}

TEST_F(CtkScanProviderTest, HonoursTheTimeout)
{
    (void)Fake::slot(kA);
    auto provider = established();
    auto s = stateFor(kA);
    ASSERT_EQ(provider->getStatusChange(1, 0, &s, 1), static_cast<LONG>(SCARD_S_SUCCESS));
    s.dwCurrentState = s.dwEventState & ~static_cast<DWORD>(SCARD_STATE_CHANGED);

    const auto start = Clock::now();
    EXPECT_EQ(provider->getStatusChange(1, 200, &s, 1), static_cast<LONG>(SCARD_E_TIMEOUT));
    const auto took = Clock::now() - start;
    EXPECT_GE(took, milliseconds{200});
    EXPECT_LT(took, milliseconds{1000});
}

TEST_F(CtkScanProviderTest, CancelWakesAWaitingCall)
{
    (void)Fake::slot(kA);
    auto provider = established();
    auto s = stateFor(kA);
    ASSERT_EQ(provider->getStatusChange(1, 0, &s, 1), static_cast<LONG>(SCARD_S_SUCCESS));
    s.dwCurrentState = s.dwEventState & ~static_cast<DWORD>(SCARD_STATE_CHANGED);

    std::thread canceller([&] {
        std::this_thread::sleep_for(milliseconds{100});
        provider->cancel(1);
    });
    const auto start = Clock::now();
    const LONG rv = provider->getStatusChange(1, INFINITE, &s, 1);
    const auto took = Clock::now() - start;
    canceller.join();
    EXPECT_EQ(rv, static_cast<LONG>(SCARD_E_CANCELLED));
    EXPECT_LT(took, milliseconds{500});
}

TEST_F(CtkScanProviderTest, PnpEntryChangesWhenSlotsAppear)
{
    (void)Fake::slot(kA);
    auto provider = established();
    SCARD_READERSTATE pnp{};
    pnp.szReader = kPnpReaderName;
    pnp.dwCurrentState = SCARD_STATE_UNAWARE;
    ASSERT_EQ(provider->getStatusChange(1, 0, &pnp, 1), static_cast<LONG>(SCARD_S_SUCCESS));
    EXPECT_EQ(pnp.dwEventState & static_cast<DWORD>(SCARD_STATE_UNKNOWN), 0U) << "PnP is supported";
    pnp.dwCurrentState = pnp.dwEventState & ~static_cast<DWORD>(SCARD_STATE_CHANGED);
    EXPECT_EQ(provider->getStatusChange(1, 0, &pnp, 1), static_cast<LONG>(SCARD_E_TIMEOUT));

    std::thread plug([] {
        std::this_thread::sleep_for(milliseconds{100});
        (void)Fake::slot(kB);
    });
    EXPECT_EQ(provider->getStatusChange(1, 2000, &pnp, 1), static_cast<LONG>(SCARD_S_SUCCESS));
    plug.join();
    EXPECT_NE(pnp.dwEventState & static_cast<DWORD>(SCARD_STATE_CHANGED), 0U);
    EXPECT_EQ(pnp.dwEventState >> 16, 2U);
}

TEST_F(CtkScanProviderTest, EventCounterAdvancesPerTransition)
{
    (void)Fake::slot(kA);
    auto provider = established();
    auto s = stateFor(kA);
    ASSERT_EQ(provider->getStatusChange(1, 0, &s, 1), static_cast<LONG>(SCARD_S_SUCCESS));
    const DWORD before = s.dwEventState >> 16;

    // Out and back in between two looks: same flags, the counter tells.
    Fake::setSlotState(kA, Ctk::SlotState::Empty);
    Fake::setSlotState(kA, Ctk::SlotState::ValidCard);
    s.dwCurrentState = s.dwEventState & ~static_cast<DWORD>(SCARD_STATE_CHANGED);
    ASSERT_EQ(provider->getStatusChange(1, 0, &s, 1), static_cast<LONG>(SCARD_S_SUCCESS));
    EXPECT_NE(s.dwEventState & static_cast<DWORD>(SCARD_STATE_CHANGED), 0U);
    EXPECT_EQ((s.dwEventState >> 16) - before, 2U);
}

TEST_F(CtkScanProviderTest, ListReadersIsTheSlotNamesMultiString)
{
    (void)Fake::slot(kA);
    (void)Fake::slot(kB);
    auto provider = established();
    DWORD size = 0;
    ASSERT_EQ(provider->listReaders(1, nullptr, nullptr, &size), static_cast<LONG>(SCARD_S_SUCCESS));
    EXPECT_EQ(size, kA.size() + 1 + kB.size() + 1 + 1);

    std::vector<char> small(size - 1);
    DWORD smallSize = static_cast<DWORD>(small.size());
    EXPECT_EQ(provider->listReaders(1, nullptr, small.data(), &smallSize),
              static_cast<LONG>(SCARD_E_INSUFFICIENT_BUFFER));

    std::vector<char> buffer(size);
    ASSERT_EQ(provider->listReaders(1, nullptr, buffer.data(), &size), static_cast<LONG>(SCARD_S_SUCCESS));
    std::vector<std::string> names;
    for (const char* p = buffer.data(); *p != '\0'; p += std::strlen(p) + 1)
        names.emplace_back(p);
    EXPECT_EQ(names, (std::vector<std::string>{kA, kB}));
}

TEST_F(CtkScanProviderTest, EmptyAtStartDoesNotReacquire)
{
    auto provider = established();
    DWORD size = 0;
    EXPECT_EQ(provider->listReaders(1, nullptr, nullptr, &size), static_cast<LONG>(SCARD_E_NO_READERS_AVAILABLE));
    SCARD_READERSTATE pnp{};
    pnp.szReader = kPnpReaderName;
    pnp.dwCurrentState = SCARD_STATE_UNAWARE;
    EXPECT_EQ(provider->getStatusChange(1, 100, &pnp, 1), static_cast<LONG>(SCARD_E_TIMEOUT))
        << "no readers yet is not a lost service";
    EXPECT_EQ(Fake::slotsAcquires(), 1);
}

TEST_F(CtkScanProviderTest, EmptySlotNamesWithALiveManagerReacquiresIt)
{
    (void)Fake::slot(kA);
    auto provider = established();
    auto s = stateFor(kA);
    ASSERT_EQ(provider->getStatusChange(1, 0, &s, 1), static_cast<LONG>(SCARD_S_SUCCESS));

    // Every slot gone at once: the service behind the manager restarted.
    Fake::removeSlot(kA);
    s.dwCurrentState = s.dwEventState & ~static_cast<DWORD>(SCARD_STATE_CHANGED);
    EXPECT_EQ(provider->getStatusChange(1, 0, &s, 1), static_cast<LONG>(SCARD_E_NO_SERVICE));

    SCARDCONTEXT ctx = 0;
    EXPECT_EQ(provider->establishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx),
              static_cast<LONG>(SCARD_S_SUCCESS));
    EXPECT_EQ(Fake::slotsAcquires(), 2);
}
