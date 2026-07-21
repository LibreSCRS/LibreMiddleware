// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// Suite-1 card EF.AODF, hardware-scanned 2026-07-18.
//
// Raw bytes of the card's EF.AODF (FID 4408 inside the PKCS#15 DF), status
// words stripped, trailing 0x00 file padding trimmed. Four ASN.1 SEQUENCE
// entries, in on-card order:
//
//   1. "PACE CAN"      ref 0x02, min/stored/max 4/6/12, path 3F00;
//                      pinFlags 0xB8 0x01 = case-sensitive, change-disabled,
//                      unblock-disabled, initialized (+ exchangeRefData).
//   2. "User PIN"      ref 0x86, 6/6/6, path 3F00; pinFlags 0x08 =
//                      initialized. CommonObjectAttributes carries the
//                      protecting authId 0x03 (the Global PUK object) —
//                      the unblock-authority chain. Own object id 0x06.
//   3. "Global PUK"    ref 0x93, 8/8/8, path 3F00; pinFlags 0x99 =
//                      case-sensitive, unblock-disabled, initialized, soPin.
//                      Own object id 0x03 (chain target of entries 2 and 4).
//   4. "Signature PIN" ref 0x92, 6/6/6, path 3F00/0DF5 (the signature /
//                      QSCD DF); pinFlags 0x48 = local, initialized.
//                      Protecting authId 0x03. Own object id 0x22.
//
// Expected parse cross-check (from the same scan):
//   PACE CAN      ref=0x02, local=false
//   User PIN      ref=0x86, local=false
//   Global PUK    ref=0x93, local=false, soPin, unblock-disabled,
//                 unblocking authority for the User PIN (authId chain 0x03)
//   Signature PIN ref=0x92, local=true, path 3F00/0DF5

#include <array>
#include <cstdint>

namespace librescrs::test::fixtures {

inline constexpr std::array<std::uint8_t, 280> kSuite1Aodf20260718 = {
    // --- entry 1: "PACE CAN" ---------------------------------------------
    0x30,
    0x2F, // SEQUENCE (47)
    0x30,
    0x0A, //   CommonObjectAttributes
    0x0C,
    0x08,
    0x50,
    0x41,
    0x43,
    0x45,
    0x20,
    0x43,
    0x41,
    0x4E, //     UTF8String "PACE CAN"
    0x30,
    0x03,
    0x04,
    0x01,
    0x02, //   CommonAuthObjectAttributes: id 02
    0xA1,
    0x1C,
    0x30,
    0x1A, //   [1] { PinAttributes
    0x03,
    0x03,
    0x00,
    0xB8,
    0x01, //     pinFlags 0xB8 0x01
    0x0A,
    0x01,
    0x01, //     pinType ascii
    0x02,
    0x01,
    0x04, //     minLength 4
    0x02,
    0x01,
    0x06, //     storedLength 6
    0x02,
    0x01,
    0x0C, //     maxLength 12
    0x80,
    0x01,
    0x02, //     pinReference 0x02
    0x30,
    0x04,
    0x04,
    0x02,
    0x3F,
    0x00, //     path 3F00 }
    // --- entry 2: "User PIN" ---------------------------------------------
    0x30,
    0x49, // SEQUENCE (73)
    0x30,
    0x25, //   CommonObjectAttributes
    0x0C,
    0x08,
    0x55,
    0x73,
    0x65,
    0x72,
    0x20,
    0x50,
    0x49,
    0x4E, //     UTF8String "User PIN"
    0x03,
    0x02,
    0x06,
    0x40, //     flags (modifiable)
    0x04,
    0x01,
    0x03, //     authId 0x03 — protected by PUK
    0x30,
    0x12,
    0x30,
    0x10,
    0x03,
    0x02,
    0x05,
    0x20, //     accessControlRules
    0xA2,
    0x06,
    0x04,
    0x01,
    0x02,
    0x04,
    0x01,
    0x06, //       ...
    0x03,
    0x02,
    0x06,
    0x40, //       ...
    0x30,
    0x03,
    0x04,
    0x01,
    0x06, //   CommonAuthObjectAttributes: id 06
    0xA1,
    0x1B,
    0x30,
    0x19, //   [1] { PinAttributes
    0x03,
    0x02,
    0x00,
    0x08, //     pinFlags 0x08 (initialized)
    0x0A,
    0x01,
    0x01, //     pinType ascii
    0x02,
    0x01,
    0x06, //     minLength 6
    0x02,
    0x01,
    0x06, //     storedLength 6
    0x02,
    0x01,
    0x06, //     maxLength 6
    0x80,
    0x01,
    0x86, //     pinReference 0x86
    0x30,
    0x04,
    0x04,
    0x02,
    0x3F,
    0x00, //     path 3F00 }
    // --- entry 3: "Global PUK" -------------------------------------------
    0x30,
    0x48, // SEQUENCE (72)
    0x30,
    0x24, //   CommonObjectAttributes
    0x0C,
    0x0A,
    0x47,
    0x6C,
    0x6F,
    0x62,
    0x61,
    0x6C,
    0x20,
    0x50, //     UTF8String "Global PUK"
    0x55,
    0x4B, //     ...
    0x03,
    0x02,
    0x06,
    0x40, //     flags (modifiable)
    0x30,
    0x12,
    0x30,
    0x10,
    0x03,
    0x02,
    0x05,
    0x20, //     accessControlRules
    0xA2,
    0x06,
    0x04,
    0x01,
    0x02,
    0x04,
    0x01,
    0x03, //       ...
    0x03,
    0x02,
    0x06,
    0x40, //       ...
    0x30,
    0x03,
    0x04,
    0x01,
    0x03, //   CommonAuthObjectAttributes: id 03
    0xA1,
    0x1B,
    0x30,
    0x19, //   [1] { PinAttributes
    0x03,
    0x02,
    0x00,
    0x99, //     pinFlags 0x99 (case-sensitive,
          //       unblock-disabled, initialized, soPin)
    0x0A,
    0x01,
    0x01, //     pinType ascii
    0x02,
    0x01,
    0x08, //     minLength 8
    0x02,
    0x01,
    0x08, //     storedLength 8
    0x02,
    0x01,
    0x08, //     maxLength 8
    0x80,
    0x01,
    0x93, //     pinReference 0x93
    0x30,
    0x04,
    0x04,
    0x02,
    0x3F,
    0x00, //     path 3F00 }
    // --- entry 4: "Signature PIN" ----------------------------------------
    0x30,
    0x50, // SEQUENCE (80)
    0x30,
    0x2A, //   CommonObjectAttributes
    0x0C,
    0x0D,
    0x53,
    0x69,
    0x67,
    0x6E,
    0x61,
    0x74,
    0x75,
    0x72, //     UTF8String "Signature PIN"
    0x65,
    0x20,
    0x50,
    0x49,
    0x4E, //     ...
    0x03,
    0x02,
    0x06,
    0x40, //     flags (modifiable)
    0x04,
    0x01,
    0x03, //     authId 0x03 — protected by PUK
    0x30,
    0x12,
    0x30,
    0x10,
    0x03,
    0x02,
    0x05,
    0x20, //     accessControlRules
    0xA2,
    0x06,
    0x04,
    0x01,
    0x02,
    0x04,
    0x01,
    0x22, //       ...
    0x03,
    0x02,
    0x06,
    0x40, //       ...
    0x30,
    0x03,
    0x04,
    0x01,
    0x22, //   CommonAuthObjectAttributes: id 22
    0xA1,
    0x1D,
    0x30,
    0x1B, //   [1] { PinAttributes
    0x03,
    0x02,
    0x00,
    0x48, //     pinFlags 0x48 (local, initialized)
    0x0A,
    0x01,
    0x01, //     pinType ascii
    0x02,
    0x01,
    0x06, //     minLength 6
    0x02,
    0x01,
    0x06, //     storedLength 6
    0x02,
    0x01,
    0x06, //     maxLength 6
    0x80,
    0x01,
    0x92, //     pinReference 0x92
    0x30,
    0x06,
    0x04,
    0x04,
    0x3F,
    0x00,
    0x0D,
    0xF5, //     path 3F00/0DF5 }
};

} // namespace librescrs::test::fixtures
