// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/pkcs11_token.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"

using namespace libresign;

class Pkcs11TokenTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
    }
    const char* softHsmPath = nullptr;
};

TEST_F(Pkcs11TokenTest, OpenAndClose)
{
    ASSERT_NO_THROW({
        Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
    });
}

TEST(Pkcs11TokenStandalone, FailsWithInvalidModule)
{
    ASSERT_THROW(
        {
            Pkcs11Token token("/nonexistent.so", libresign::as_pin("1234"), "key",
                              libresign::Pkcs11Token::TestSlotId{0});
        },
        std::runtime_error);
}

#else
TEST(Pkcs11TokenTest, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif
