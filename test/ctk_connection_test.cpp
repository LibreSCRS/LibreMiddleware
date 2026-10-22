// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The CryptoTokenKit body of PCSCConnection against a scripted CryptoTokenKit:
// one exclusive session held per connection, what happens when it is lost,
// and that the PC/SC codes the rest of the library classifies come out the
// same. Runs on every platform: the facade is replaced at link time.

#include <gtest/gtest.h>

#include "ctk_fake.h"
#include "pcsc_connection.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::CardTransaction;
using LibreSCRS::SmartCard::Internal::PCSCConnection;
using LibreSCRS::SmartCard::Internal::PCSCError;
namespace Ctk = LibreSCRS::SmartCard::Internal::Ctk;
namespace Fake = LibreSCRS::SmartCard::Internal::Ctk::Fake;
using Bytes = std::vector<std::uint8_t>;

const std::string kReaderA = "Fake Reader A";
const std::string kReaderB = "Fake Reader B";
const Bytes kReadBinary{0x00, 0xB0, 0x00, 0x00, 0x04};

std::unique_ptr<PCSCConnection> connect(const std::string& reader)
{
    return PCSCConnection::openRawDiagnostic(reader);
}

APDUCommand readBinaryCommand()
{
    return LibreSCRS::SmartCard::Internal::readBinary(0x0000, 0x10);
}

// The PCSCError code of @p f, or 0 when it does not throw one.
template <typename F>
LONG codeOf(F&& f, std::string* message = nullptr)
{
    try {
        f();
    } catch (const PCSCError& e) {
        if (message)
            *message = e.what();
        return e.code();
    }
    return 0;
}

class CtkConnection : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Fake::reset();
        (void)Fake::slot(kReaderA);
    }
};

} // namespace

TEST_F(CtkConnection, OpenHoldsOneSessionUntilDestroyed)
{
    {
        auto conn = connect(kReaderA);
        for (int i = 0; i < 5; ++i)
            (void)conn->transmitRaw(std::span<const std::uint8_t>(kReadBinary));
        EXPECT_EQ(Fake::calls(kReaderA).ends, 0);
    }
    const auto c = Fake::calls(kReaderA);
    EXPECT_EQ(c.opens, 1);
    EXPECT_EQ(c.exchanges, 5);
    EXPECT_EQ(c.ends, 1);
    EXPECT_EQ(c.maxLiveSessions, 1);
    EXPECT_EQ(c.lastDeadline, std::chrono::seconds{10});
}

TEST_F(CtkConnection, TransactionsNeverTouchTheSession)
{
    auto conn = connect(kReaderA);
    {
        CardTransaction outer(*conn);
        {
            CardTransaction inner(*conn);
            (void)conn->transmit(readBinaryCommand());
        }
        (void)conn->transmit(readBinaryCommand());
    }
    {
        CardTransaction again(*conn);
        (void)conn->transmit(readBinaryCommand());
    }
    const auto c = Fake::calls(kReaderA);
    EXPECT_EQ(c.opens, 1);
    EXPECT_EQ(c.ends, 0);
}

TEST_F(CtkConnection, LostSessionWithCardPresentReconnectsOnceAndRetries)
{
    // A secure-messaging wrapped READ BINARY: the body passes it on as bytes,
    // and the card's plain refusal reaches the caller unchanged.
    const Bytes wrapped{0x0C, 0xB0, 0x00, 0x00, 0x0D, 0x97, 0x01, 0x00, 0x8E, 0x08,
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00};
    Fake::slot(kReaderA).responder = [](std::span<const std::uint8_t>) -> std::expected<Bytes, Ctk::CtkStatus> {
        return Bytes{0x69, 0x88};
    };
    auto conn = connect(kReaderA);
    (void)conn->transmitRaw(std::span<const std::uint8_t>(kReadBinary));
    Fake::loseSession(kReaderA);

    const auto response = conn->transmitRaw(std::span<const std::uint8_t>(wrapped));

    const auto c = Fake::calls(kReaderA);
    EXPECT_EQ(c.opens, 2);
    EXPECT_EQ(c.ends, 1);
    EXPECT_EQ(c.order, (std::vector<std::string>{"open", "end", "open"})) << "the dead session ends before a new one";
    ASSERT_EQ(c.received.size(), 3U) << "the first APDU, then the wrapped one exactly twice";
    EXPECT_EQ(c.received[1], wrapped);
    EXPECT_EQ(c.received[2], wrapped);
    EXPECT_EQ(response.statusWord(), 0x6988);
}

TEST_F(CtkConnection, LostSessionHeldElsewhereFailsWithinTheBound)
{
    auto conn = connect(kReaderA);
    Fake::loseSession(kReaderA);
    Fake::slot(kReaderA).refuseOpenWith = Ctk::CtkStatus::SessionRefused;

    EXPECT_EQ(codeOf([&] { (void)conn->transmitRaw(std::span<const std::uint8_t>(kReadBinary)); }),
              static_cast<LONG>(SCARD_E_SHARING_VIOLATION));
    EXPECT_EQ(Fake::calls(kReaderA).opens, 2) << "one reopen attempt for the call, no loop";
    EXPECT_EQ(codeOf([&] { conn->beginTransaction(); }), static_cast<LONG>(SCARD_E_SHARING_VIOLATION));
    const auto c = Fake::calls(kReaderA);
    EXPECT_EQ(c.opens, 3) << "one more for the transaction";
    EXPECT_EQ(c.lastDeadline, std::chrono::seconds{10});
    EXPECT_EQ(c.liveSessions, 0);
}

TEST_F(CtkConnection, LostSessionWithCardGoneIsRemoved)
{
    auto conn = connect(kReaderA);
    Fake::removeCard(kReaderA);

    EXPECT_EQ(codeOf([&] { (void)conn->transmitRaw(std::span<const std::uint8_t>(kReadBinary)); }),
              static_cast<LONG>(SCARD_W_REMOVED_CARD));
    EXPECT_EQ(Fake::calls(kReaderA).opens, 1);
}

TEST_F(CtkConnection, SwappedCardIsRemovedNotRetried)
{
    auto conn = connect(kReaderA);
    (void)conn->transmitRaw(std::span<const std::uint8_t>(kReadBinary));
    Fake::swapCard(kReaderA, Fake::slot(kReaderA).atr); // another card, the same ATR

    const Bytes second{0x00, 0xB0, 0x00, 0x10, 0x04};
    EXPECT_EQ(codeOf([&] { (void)conn->transmitRaw(std::span<const std::uint8_t>(second)); }),
              static_cast<LONG>(SCARD_W_REMOVED_CARD));
    const auto c = Fake::calls(kReaderA);
    EXPECT_EQ(c.opens, 1);
    EXPECT_EQ(std::count(c.received.begin(), c.received.end(), second), 0) << "the new card never sees the command";
}

TEST_F(CtkConnection, SensitiveCommandIsNeverRetriedAfterSessionLoss)
{
    const std::vector<Bytes> pinCommands{
        {0x00, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF},
        {0x00, 0x24, 0x00, 0x01, 0x04, 0xAA, 0xBB, 0xCC, 0xDD},
        {0x00, 0x2C, 0x00, 0x01, 0x04, 0xAA, 0xBB, 0xCC, 0xDD},
        {0x0C, 0x20, 0x00, 0x01, 0x04, 0x87, 0x02, 0x01, 0x00},
    };
    for (const auto& pin : pinCommands) {
        SCOPED_TRACE(static_cast<int>(pin[1]));
        Fake::reset();
        (void)Fake::slot(kReaderA);
        auto conn = connect(kReaderA);
        Fake::loseSession(kReaderA);

        EXPECT_EQ(codeOf([&] { (void)conn->transmitRaw(std::span<const std::uint8_t>(pin)); }),
                  static_cast<LONG>(SCARD_W_RESET_CARD));
        const auto c = Fake::calls(kReaderA);
        EXPECT_EQ(std::count(c.received.begin(), c.received.end(), pin), 1) << "sent once, never resent";
        EXPECT_EQ(c.opens, 2) << "the session is begun again for the next call";
    }

    // Control: a plain command is resent once.
    Fake::reset();
    (void)Fake::slot(kReaderA);
    auto conn = connect(kReaderA);
    Fake::loseSession(kReaderA);
    (void)conn->transmitRaw(std::span<const std::uint8_t>(kReadBinary));
    const auto c = Fake::calls(kReaderA);
    EXPECT_EQ(std::count(c.received.begin(), c.received.end(), kReadBinary), 2);
}

TEST_F(CtkConnection, ReaderUnpluggedDuringHeldSessionIsRemoved)
{
    auto conn = connect(kReaderA);
    Fake::removeSlot(kReaderA);

    EXPECT_EQ(codeOf([&] { (void)conn->transmitRaw(std::span<const std::uint8_t>(kReadBinary)); }),
              static_cast<LONG>(SCARD_W_REMOVED_CARD));
    EXPECT_EQ(Fake::calls(kReaderA).opens, 1);
}

TEST_F(CtkConnection, ReconnectOnLiveSessionIsANoOp)
{
    auto conn = connect(kReaderA);
    conn->reconnect();
    const auto c = Fake::calls(kReaderA);
    EXPECT_EQ(c.opens, 1);
    EXPECT_EQ(c.exchanges, 0);
}

TEST_F(CtkConnection, ResetIsUnsupported)
{
    auto conn = connect(kReaderA);
    EXPECT_EQ(codeOf([&] { conn->reconnectWithReset(); }), static_cast<LONG>(SCARD_E_UNSUPPORTED_FEATURE));
}

TEST_F(CtkConnection, ErrorMapping)
{
    struct Case
    {
        const char* name;
        std::function<void()> arrange;
        LONG code;
        const char* says;
    };
    const Case cases[] = {
        {"NoManager", [] { Fake::setManagerPresent(false); }, static_cast<LONG>(SCARD_E_NO_ACCESS),
         "com.apple.security.smartcard"},
        {"UnknownSlot", [] { Fake::removeSlot(kReaderA); }, static_cast<LONG>(SCARD_E_UNKNOWN_READER),
         "unknown reader"},
        {"NoCard", [] { Fake::slot(kReaderA).state = Ctk::SlotState::Empty; }, static_cast<LONG>(SCARD_E_NO_SMARTCARD),
         "no smartcard"},
        {"Mute", [] { Fake::slot(kReaderA).state = Ctk::SlotState::MuteCard; },
         static_cast<LONG>(SCARD_W_UNRESPONSIVE_CARD), "mute"},
        {"SessionRefused", [] { Fake::slot(kReaderA).refuseOpenWith = Ctk::CtkStatus::SessionRefused; },
         static_cast<LONG>(SCARD_E_SHARING_VIOLATION), "exclusive session refused"},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.name);
        Fake::reset();
        (void)Fake::slot(kReaderA);
        c.arrange();
        std::string message;
        EXPECT_EQ(codeOf([&] { (void)connect(kReaderA); }, &message), c.code);
        EXPECT_NE(message.find(c.says), std::string::npos) << message;
        // CardSession classifies an open failure from these words: only a
        // missing card reads as "no card", and none reads as a protocol error.
        if (std::string(c.name) != "NoCard") {
            EXPECT_EQ(message.find("no smartcard"), std::string::npos) << message;
        }
        EXPECT_EQ(message.find("comm"), std::string::npos) << message;
        EXPECT_EQ(message.find("protocol"), std::string::npos) << message;
    }

    // A failed exchange.
    Fake::reset();
    Fake::slot(kReaderA).responder = [](std::span<const std::uint8_t>) -> std::expected<Bytes, Ctk::CtkStatus> {
        return std::unexpected(Ctk::CtkStatus::CommError);
    };
    auto conn = connect(kReaderA);
    std::string message;
    EXPECT_EQ(codeOf([&] { (void)conn->transmitRaw(std::span<const std::uint8_t>(kReadBinary)); }, &message),
              static_cast<LONG>(SCARD_F_COMM_ERROR));
    EXPECT_NE(message.find("transmit failed"), std::string::npos) << message;
}

TEST_F(CtkConnection, RefusedSessionIsNotRetried)
{
    Fake::slot(kReaderA).refuseOpenWith = Ctk::CtkStatus::SessionRefused;
    EXPECT_EQ(codeOf([&] { (void)connect(kReaderA); }), static_cast<LONG>(SCARD_E_SHARING_VIOLATION));
    EXPECT_EQ(Fake::calls(kReaderA).opens, 1);
}

TEST_F(CtkConnection, T0WrongLengthAndGetResponseUseTheSharedLoop)
{
    Fake::slot(kReaderA).protocol = Ctk::CtkProtocol::T0;
    std::vector<Bytes> replies{{0x6C, 0x07}, {0x01, 0x02, 0x03, 0x90, 0x00}};
    Fake::slot(kReaderA).responder = [&replies](std::span<const std::uint8_t>) -> std::expected<Bytes, Ctk::CtkStatus> {
        auto r = replies.front();
        replies.erase(replies.begin());
        return r;
    };
    auto conn = connect(kReaderA);
    auto response = conn->transmit(readBinaryCommand());
    auto c = Fake::calls(kReaderA);
    ASSERT_EQ(c.received.size(), 2U);
    EXPECT_EQ(c.received[1], (Bytes{0x00, 0xB0, 0x00, 0x00, 0x07}));
    EXPECT_EQ(response.data, (Bytes{0x01, 0x02, 0x03}));

    // 61xx: the rest of the answer is fetched with GET RESPONSE.
    replies = {{0x61, 0x02}, {0xAA, 0xBB, 0x90, 0x00}};
    response = conn->transmit(readBinaryCommand());
    c = Fake::calls(kReaderA);
    ASSERT_EQ(c.received.size(), 4U);
    EXPECT_EQ(c.received[3], (Bytes{0x00, 0xC0, 0x00, 0x00, 0x02}));
    EXPECT_EQ(response.data, (Bytes{0xAA, 0xBB}));
}

TEST_F(CtkConnection, ProtocolComesFromTheSession)
{
    for (const auto protocol : {Ctk::CtkProtocol::T0, Ctk::CtkProtocol::T1}) {
        Fake::reset();
        Fake::slot(kReaderA).protocol = protocol;
        std::vector<Bytes> replies{{0x6C, 0x07}, {0x01, 0x90, 0x00}};
        Fake::slot(kReaderA).responder =
            [&replies](std::span<const std::uint8_t>) -> std::expected<Bytes, Ctk::CtkStatus> {
            auto r = replies.front();
            replies.erase(replies.begin());
            return r;
        };
        auto conn = connect(kReaderA);
        const auto response = conn->transmit(readBinaryCommand());
        const auto c = Fake::calls(kReaderA);
        if (protocol == Ctk::CtkProtocol::T0) {
            EXPECT_EQ(c.received.size(), 2U) << "T=0: 6C is answered by a resend";
            EXPECT_TRUE(response.isSuccess());
        } else {
            EXPECT_EQ(c.received.size(), 1U) << "T=1: 6C reaches the caller";
            EXPECT_EQ(response.statusWord(), 0x6C07);
        }
    }
}

TEST_F(CtkConnection, DetachedConnectionMatchesThePcscBody)
{
    // Measured on the PC/SC body with a null handle (macOS PCSC.framework):
    // SCARD_E_INVALID_HANDLE with these messages; transactions do nothing.
    PCSCConnection conn(PCSCConnection::DetachedTag{}, "detached");
    std::string message;
    EXPECT_EQ(codeOf([&] { (void)conn.transmitRaw(std::span<const std::uint8_t>(kReadBinary)); }, &message),
              static_cast<LONG>(SCARD_E_INVALID_HANDLE));
    EXPECT_EQ(message, "SCardTransmit failed");
    EXPECT_EQ(codeOf([&] { (void)conn.getATR(); }, &message), static_cast<LONG>(SCARD_E_INVALID_HANDLE));
    EXPECT_EQ(message, "SCardStatus failed");
    EXPECT_EQ(codeOf([&] { conn.reconnect(); }, &message), static_cast<LONG>(SCARD_E_INVALID_HANDLE));
    EXPECT_EQ(message, "SCardReconnect failed");
    EXPECT_EQ(codeOf([&] { conn.reconnectWithReset(); }, &message), static_cast<LONG>(SCARD_E_INVALID_HANDLE));
    EXPECT_EQ(message, "SCardReconnect (reset) failed");
    EXPECT_EQ(codeOf([&] { conn.beginTransaction(); }), 0);
    EXPECT_EQ(codeOf([&] { conn.endTransaction(); }), 0);
}

TEST_F(CtkConnection, ListReadersIsTheSlotNames)
{
    (void)Fake::slot(kReaderB);
    auto names = PCSCConnection::listReaders();
    std::sort(names.begin(), names.end());
    EXPECT_EQ(names, (std::vector<std::string>{kReaderA, kReaderB}));
    Fake::setManagerPresent(false);
    EXPECT_TRUE(PCSCConnection::listReaders().empty());
}

TEST_F(CtkConnection, ReaderBIsNotDelayedByReaderA)
{
    (void)Fake::slot(kReaderB);
    // A's exchange stays inside the card until B has finished its work (at
    // most 10 s). B finishing while A is still inside is the verdict: anything
    // B shared with A would have made it wait for A instead.
    std::mutex mtx;
    std::condition_variable cv;
    bool aInside = false;
    bool bDone = false;
    Fake::slot(kReaderA).responder = [&](std::span<const std::uint8_t>) -> std::expected<Bytes, Ctk::CtkStatus> {
        std::unique_lock lock(mtx);
        aInside = true;
        cv.notify_all();
        cv.wait_for(lock, std::chrono::seconds{10}, [&] { return bDone; });
        return Bytes{0x90, 0x00};
    };
    std::atomic<bool> aReturned{false};
    std::thread busyA([&] {
        auto conn = connect(kReaderA);
        (void)conn->transmitRaw(std::span<const std::uint8_t>(kReadBinary));
        aReturned.store(true);
    });
    {
        std::unique_lock lock(mtx);
        ASSERT_TRUE(cv.wait_for(lock, std::chrono::seconds{10}, [&] { return aInside; }))
            << "reader A's exchange never started";
    }

    for (int i = 0; i < 40; ++i) {
        auto conn = connect(kReaderB);
        for (int k = 0; k < 5; ++k)
            (void)conn->transmitRaw(std::span<const std::uint8_t>(kReadBinary));
    }
    const bool aStillInside = !aReturned.load();
    {
        std::lock_guard lock(mtx);
        bDone = true;
    }
    cv.notify_all();
    busyA.join();

    EXPECT_TRUE(aStillInside) << "reader B's operations waited for reader A's exchange";
}
