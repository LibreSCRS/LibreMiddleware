// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <piv/piv_card.h>
#include <piv/piv_types.h>
#include <smartcard/pcsc_connection.h>

#include <cstdlib>
#include <memory>
#include <string>

// ---------------------------------------------------------------------------
// PIV hardware tests — require a PIV card inserted in a reader.
// Skipped automatically if no reader or no PIV card is present.
// PIN tests require LIBRESCRS_TEST_PIN environment variable.
// ---------------------------------------------------------------------------

static bool g_pinFailed = false;

#define SKIP_IF_PIN_FAILED()                                                                                           \
    do {                                                                                                               \
        if (g_pinFailed)                                                                                               \
            GTEST_SKIP() << "Skipped: previous PIN verification failed";                                               \
    } while (0)

static std::string getTestPIN()
{
    const char* pin = std::getenv("LIBRESCRS_TEST_PIN");
    return pin ? std::string(pin) : std::string();
}

class PIVHardwareTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        auto readers = smartcard::PCSCConnection::listReaders();
        if (readers.empty())
            GTEST_SKIP() << "No smart card readers found";

        // Try each reader until we find one with a PIV card
        for (const auto& reader : readers) {
            try {
                auto c = std::make_unique<smartcard::PCSCConnection>(reader);
                auto p = std::make_unique<piv::PIVCard>(*c);
                if (p->probe()) {
                    conn = std::move(c);
                    card = std::move(p);
                    return;
                }
            } catch (...) {
            }
        }
        GTEST_SKIP() << "No PIV card detected in any reader";
    }

    std::unique_ptr<smartcard::PCSCConnection> conn;
    std::unique_ptr<piv::PIVCard> card;
};

TEST_F(PIVHardwareTest, Probe)
{
    // probe() already succeeded in SetUp; verify it returns true on repeat
    EXPECT_TRUE(card->probe());
}

TEST_F(PIVHardwareTest, ReadCHUID)
{
    auto chuid = card->readCHUID();
    EXPECT_EQ(chuid.guid.size(), 16u);
    EXPECT_FALSE(chuid.expirationDate.empty());
}

TEST_F(PIVHardwareTest, ReadCCC)
{
    auto ccc = card->readCCC();
    EXPECT_FALSE(ccc.cardIdentifier.empty());
}

TEST_F(PIVHardwareTest, ReadDiscovery)
{
    auto discovery = card->readDiscovery();
    EXPECT_FALSE(discovery.pivAID.empty());
    EXPECT_NE(discovery.pinUsagePolicy, 0u);
}

TEST_F(PIVHardwareTest, ReadCertificates)
{
    auto certs = card->readCertificates();
    ASSERT_FALSE(certs.empty()) << "Expected at least one certificate";
    EXPECT_FALSE(certs[0].certBytes.empty());
    EXPECT_EQ(certs[0].certBytes[0], 0x30) << "X.509 DER should start with SEQUENCE tag 0x30";
    EXPECT_FALSE(certs[0].slotName.empty());
}

TEST_F(PIVHardwareTest, ReadPrintedInfo)
{
    auto info = card->readPrintedInfo();
    if (!info.has_value())
        GTEST_SKIP() << "Printed Information not available on this card";
    EXPECT_FALSE(info->name.empty());
}

TEST_F(PIVHardwareTest, ReadKeyHistory)
{
    // Optional object — just verify no crash
    auto history = card->readKeyHistory();
    (void)history;
}

TEST_F(PIVHardwareTest, DiscoverPINs)
{
    auto pins = card->discoverPINs();
    ASSERT_FALSE(pins.empty()) << "Expected at least one PIN";
    EXPECT_FALSE(pins[0].label.empty());
}

TEST_F(PIVHardwareTest, PINTriesLeft)
{
    auto pins = card->discoverPINs();
    ASSERT_FALSE(pins.empty());
    int tries = card->getPINTriesLeft(pins[0].keyReference);
    EXPECT_GT(tries, 0) << "PIN tries should be > 0";
}

TEST_F(PIVHardwareTest, VerifyPIN)
{
    SKIP_IF_PIN_FAILED();

    auto pin = getTestPIN();
    if (pin.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run PIN verification test";

    auto pins = card->discoverPINs();
    ASSERT_FALSE(pins.empty());

    auto result = card->verifyPIN(pins[0].keyReference, pin);
    if (!result.success)
        g_pinFailed = true;
    EXPECT_TRUE(result.success) << "PIN verification failed, retriesLeft=" << result.retriesLeft;
}

TEST_F(PIVHardwareTest, DiscoverKeys)
{
    auto keys = card->discoverKeys();
    ASSERT_FALSE(keys.empty()) << "Expected at least one key";
    EXPECT_FALSE(keys[0].first.empty()) << "Key slot name should not be empty";
}

TEST_F(PIVHardwareTest, ReadAll)
{
    auto data = card->readAll();
    EXPECT_EQ(data.chuid.guid.size(), 16u);
    EXPECT_FALSE(data.certificates.empty());
}
