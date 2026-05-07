// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "types.h"
#include "signing_service.h"

// --- Types tests ---
//
// TrustStoreManager-specific tests were retired with the class itself
// (LibreSCRS::Trust::TrustStoreService is the lifecycle owner now).
// Bundled-cert + system-store coverage lives in LibreSCRSTrust +
// TrustStoreServiceTests; TL fetch coverage lives in
// trust_store_service_test.cpp's hermetic + network-gated paths.

TEST(LibreSignTypes, SignatureFormatEnum)
{
    EXPECT_NE(libresign::SignatureFormat::PAdES, libresign::SignatureFormat::CAdES);
}

TEST(LibreSignTypes, SignatureLevelOrdering)
{
    EXPECT_LT(static_cast<int>(libresign::SignatureLevel::B_B), static_cast<int>(libresign::SignatureLevel::B_T));
    EXPECT_LT(static_cast<int>(libresign::SignatureLevel::B_T), static_cast<int>(libresign::SignatureLevel::B_LT));
    EXPECT_LT(static_cast<int>(libresign::SignatureLevel::B_LT), static_cast<int>(libresign::SignatureLevel::B_LTA));
}

TEST(LibreSignTypes, SigningRequestDefaults)
{
    libresign::SigningRequest req;
    EXPECT_EQ(req.format, libresign::SignatureFormat::PAdES);
    EXPECT_EQ(req.level, libresign::SignatureLevel::B_T);
    EXPECT_TRUE(req.document.empty());
    EXPECT_TRUE(req.fileName.empty());
    EXPECT_FALSE(req.visual.enabled);
    EXPECT_EQ(req.visual.page, -1);
}

TEST(LibreSignTypes, SigningResultDefaults)
{
    libresign::SigningResult res;
    EXPECT_FALSE(res.success);
    EXPECT_TRUE(res.signedDocument.empty());
    EXPECT_TRUE(res.errorMessage.empty());
}
