// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// CryptoTokenKit reached directly, for the hardware checks. Compiled with ARC;
// includes no PC/SC header.

#include "ctk_hw_probe.h"

#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Foundation/Foundation.h>

#include <condition_variable>
#include <memory>
#include <mutex>

namespace LibreSCRS::Tests::CtkHw {

namespace {

std::string utf8(NSString* string)
{
    const char* bytes = string.UTF8String;
    return bytes != nullptr ? std::string(bytes) : std::string();
}

std::vector<std::uint8_t> bytesOf(NSData* data)
{
    if (data.length == 0)
        return {};
    const auto* bytes = static_cast<const std::uint8_t*>(data.bytes);
    return std::vector<std::uint8_t>(bytes, bytes + data.length);
}

double msSince(std::chrono::steady_clock::time_point start)
{
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
}

// One asynchronous reply and the caller waiting for it.
struct Reply
{
    std::mutex mtx;
    std::condition_variable cv;
    bool done = false;
    bool abandoned = false;
    bool success = false;
    std::vector<std::uint8_t> data;
    long errorCode = 0;
    std::string errorDomain;

    bool waitFor(std::chrono::milliseconds deadline)
    {
        std::unique_lock lock(mtx);
        if (cv.wait_for(lock, deadline, [this] { return done; }))
            return true;
        abandoned = true;
        return false;
    }

    void recordError(NSError* error)
    {
        if (error == nil)
            return;
        errorCode = static_cast<long>(error.code);
        errorDomain = utf8(error.domain);
    }
};

} // namespace

std::vector<PassiveSlot> passiveSlots()
{
    @autoreleasepool {
        std::vector<PassiveSlot> slots;
        TKSmartCardSlotManager* manager = [TKSmartCardSlotManager defaultManager];
        for (NSString* name in manager.slotNames) {
            PassiveSlot entry;
            entry.name = utf8(name);
            TKSmartCardSlot* slot = [manager slotNamed:name];
            if (slot != nil) {
                entry.state = static_cast<SlotState>(slot.state);
                entry.maxInputLength = static_cast<long>(slot.maxInputLength);
                entry.maxOutputLength = static_cast<long>(slot.maxOutputLength);
                if (slot.state == TKSmartCardSlotStateValidCard)
                    entry.atr = bytesOf(slot.ATR.bytes);
            }
            slots.push_back(std::move(entry));
        }
        return slots;
    }
}

RawSession rawSession(const std::string& slotName, bool useExtendedLength, bool useCommandChaining,
                      const std::vector<std::vector<std::uint8_t>>& apdus, std::chrono::milliseconds grantDeadline)
{
    @autoreleasepool {
        RawSession result;
        TKSmartCardSlotManager* manager = [TKSmartCardSlotManager defaultManager];
        if (manager == nil) {
            result.beginErrorDomain = "no slot manager";
            return result;
        }
        TKSmartCardSlot* slot = [manager slotNamed:@(slotName.c_str())];
        if (slot == nil || slot.state != TKSmartCardSlotStateValidCard) {
            result.beginErrorDomain = "no valid card in the slot";
            return result;
        }
        TKSmartCard* card = [slot makeSmartCard];
        if (card == nil) {
            result.beginErrorDomain = "makeSmartCard returned nil";
            return result;
        }
        card.allowedProtocols = TKSmartCardProtocolT0 | TKSmartCardProtocolT1;
        card.useExtendedLength = useExtendedLength;
        card.useCommandChaining = useCommandChaining;

        auto begin = std::make_shared<Reply>();
        const auto beginStart = std::chrono::steady_clock::now();
        [card beginSessionWithReply:^(BOOL success, NSError* error) {
          {
              std::lock_guard lock(begin->mtx);
              if (!begin->abandoned) {
                  begin->done = true;
                  begin->success = success;
                  begin->recordError(error);
                  begin->cv.notify_all();
                  return;
              }
          }
          // Nobody waits for this session any more.
          if (success)
              [card endSession];
        }];
        const bool answered = begin->waitFor(grantDeadline);
        result.beginMs = msSince(beginStart);
        if (!answered) {
            result.beginErrorDomain = "not granted within the deadline";
            return result;
        }
        result.began = begin->success;
        result.beginErrorCode = begin->errorCode;
        result.beginErrorDomain = begin->errorDomain;
        if (!result.began)
            return result;
        result.protocol = static_cast<int>(card.currentProtocol);

        for (const auto& apdu : apdus) {
            @autoreleasepool {
                RawExchange exchange;
                auto reply = std::make_shared<Reply>();
                NSData* request = [NSData dataWithBytes:apdu.data() length:apdu.size()];
                const auto start = std::chrono::steady_clock::now();
                [card transmitRequest:request
                                reply:^(NSData* response, NSError* error) {
                                  std::lock_guard lock(reply->mtx);
                                  if (reply->abandoned)
                                      return;
                                  reply->done = true;
                                  reply->success = response != nil;
                                  reply->data = bytesOf(response);
                                  reply->recordError(error);
                                  reply->cv.notify_all();
                                }];
                const bool replied = reply->waitFor(std::chrono::seconds(60));
                exchange.ms = msSince(start);
                if (replied) {
                    std::lock_guard lock(reply->mtx);
                    exchange.replied = reply->success;
                    exchange.reply = reply->data;
                    exchange.errorCode = reply->errorCode;
                    exchange.errorDomain = reply->errorDomain;
                } else {
                    exchange.errorDomain = "no reply within 60 s";
                }
                result.exchanges.push_back(std::move(exchange));
            }
        }

        [card endSession];
        return result;
    }
}

} // namespace LibreSCRS::Tests::CtkHw
