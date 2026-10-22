// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The CryptoTokenKit facade (ctk_smartcard.mm) against Objective-C objects
// that answer the slot-manager, slot and card selectors: when sessions begin
// and end, what a late or refused grant does, how a lost session and a card
// that left are told apart, and which queue the replies run on.

#include <gtest/gtest.h>

#include "ctk_smartcard.h"

#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Foundation/Foundation.h>
#include <objc/runtime.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace Ctk = LibreSCRS::SmartCard::Internal::Ctk;

namespace {

std::atomic<int> g_defaultManagerCalls{0};
IMP g_originalDefaultManager = nullptr;

id countingDefaultManager(id self, SEL cmd)
{
    ++g_defaultManagerCalls;
    return reinterpret_cast<id (*)(id, SEL)>(g_originalDefaultManager)(self, cmd);
}

std::string currentQueueLabel()
{
    const char* label = dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL);
    return label != nullptr ? label : "";
}

dispatch_queue_t fakeQueue()
{
    static dispatch_queue_t queue = dispatch_queue_create("test.fake.ctk", DISPATCH_QUEUE_SERIAL);
    return queue;
}

} // namespace

// Counts +[TKSmartCardSlotManager defaultManager] from before any C++ static
// initializer of this image runs (+load comes first), so a facade that takes
// the manager at load time is caught.
@interface LibreSCRSDefaultManagerCounter : NSObject
@end
@implementation LibreSCRSDefaultManagerCounter
+ (void)load
{
    Method method = class_getClassMethod([TKSmartCardSlotManager class], @selector(defaultManager));
    g_originalDefaultManager = method_setImplementation(method, reinterpret_cast<IMP>(countingDefaultManager));
}
@end

@class FakeSlot;

@interface FakeATR : NSObject
@property(nonatomic, copy) NSData* bytes;
@end
@implementation FakeATR
@end

@interface FakeCard : NSObject
@property(nonatomic, weak) FakeSlot* slot;
@property(atomic) BOOL valid;
@property(atomic, strong) id context;
@property(atomic) TKSmartCardProtocol currentProtocol;
@property(nonatomic) TKSmartCardProtocol allowedProtocols;
@property(nonatomic) BOOL useExtendedLength;
@property(nonatomic) BOOL useCommandChaining;
@property(atomic) int ends;
@property(atomic) BOOL holding;
@property(atomic, copy) NSString* endQueueLabel;
@property(atomic, strong) NSData* lastRequest; // the object the facade handed in
@property(atomic, copy) NSData* sentBytes;     // its bytes when it was handed in
@end

// One card slot, with the behaviour a test scripts into it.
@interface FakeSlot : NSObject
@property(nonatomic) TKSmartCardSlotState state;
@property(atomic, strong) NSMutableSet<NSString*>* stateReadQueues; // queue labels the state was read on
@property(nonatomic, strong) FakeATR* ATR;
@property(nonatomic, copy) NSString* name;
@property(nonatomic) NSInteger maxInputLength;
@property(nonatomic) NSInteger maxOutputLength;
@property(atomic) int grantDelayMs;
@property(atomic) NSInteger beginErrorCode;    // 0: grant
@property(atomic) NSInteger transmitErrorCode; // 0: answer
@property(atomic) TKSmartCardProtocol protocolToGrant;
@property(atomic, strong) FakeCard* holder; // the card holding the exclusive session
@property(atomic, strong) NSMutableArray<FakeCard*>* cards;
@property(atomic, strong) NSMutableArray<NSString*>* events;
- (void)record:(NSString*)event;
- (void)releaseHolder:(FakeCard*)card;
@end

@implementation FakeCard {
    NSMutableArray* _waiters;
}

- (void)setAllowedProtocols:(TKSmartCardProtocol)protocols
{
    _allowedProtocols = protocols;
    [self.slot record:@"allowedProtocols"];
}

- (void)setUseExtendedLength:(BOOL)value
{
    _useExtendedLength = value;
    [self.slot record:@"useExtendedLength"];
}

- (void)setUseCommandChaining:(BOOL)value
{
    _useCommandChaining = value;
    [self.slot record:@"useCommandChaining"];
}

- (void)grant:(void (^)(BOOL, NSError*))reply
{
    FakeSlot* slot = self.slot;
    if (slot.beginErrorCode != 0) {
        reply(NO, [NSError errorWithDomain:TKErrorDomain code:slot.beginErrorCode userInfo:nil]);
        return;
    }
    @synchronized(slot) {
        if (slot.holder != nil && slot.holder != self) {
            // Exclusive: wait until the holder ends its session.
            [slot.events addObject:@"queued"];
            if (_waiters == nil)
                _waiters = [NSMutableArray array];
            [_waiters addObject:reply];
            return;
        }
        slot.holder = self;
    }
    self.holding = YES;
    self.currentProtocol = slot.protocolToGrant;
    reply(YES, nil);
}

- (void)retryQueued
{
    NSArray* waiters;
    @synchronized(self.slot) {
        waiters = _waiters;
        _waiters = nil;
    }
    for (void (^reply)(BOOL, NSError*) in waiters)
        [self grant:reply];
}

- (void)beginSessionWithReply:(void (^)(BOOL success, NSError* error))reply
{
    [self.slot record:@"beginSession"];
    FakeSlot* slot = self.slot;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)slot.grantDelayMs * NSEC_PER_MSEC), fakeQueue(), ^{
      [self grant:reply];
    });
}

- (void)transmitRequest:(NSData*)request reply:(void (^)(NSData* response, NSError* error))reply
{
    self.lastRequest = request;
    self.sentBytes = request;
    FakeSlot* slot = self.slot;
    dispatch_async(fakeQueue(), ^{
      if (slot.transmitErrorCode != 0) {
          reply(nil, [NSError errorWithDomain:TKErrorDomain code:slot.transmitErrorCode userInfo:nil]);
          return;
      }
      const uint8_t ok[] = {0x90, 0x00};
      reply([NSData dataWithBytes:ok length:sizeof ok], nil);
    });
}

- (void)endSession
{
    self.ends = self.ends + 1;
    self.endQueueLabel = @(currentQueueLabel().c_str());
    [self.slot record:@"endSession"];
    self.holding = NO;
    [self.slot releaseHolder:self];
}

@end

@implementation FakeSlot

@synthesize state = _state;

- (TKSmartCardSlotState)state
{
    @synchronized(self) {
        [_stateReadQueues addObject:@(currentQueueLabel().c_str())];
    }
    return _state;
}

- (instancetype)init
{
    if ((self = [super init])) {
        _stateReadQueues = [NSMutableSet set];
        _state = TKSmartCardSlotStateValidCard;
        _ATR = [FakeATR new];
        const uint8_t atr[] = {0x3B, 0x00};
        _ATR.bytes = [NSData dataWithBytes:atr length:sizeof atr];
        _name = @"Fake Slot";
        _maxInputLength = 261;
        _maxOutputLength = 258;
        _protocolToGrant = TKSmartCardProtocolT1;
        _cards = [NSMutableArray array];
        _events = [NSMutableArray array];
    }
    return self;
}

- (void)record:(NSString*)event
{
    @synchronized(self) {
        [_events addObject:event];
    }
}

- (FakeCard*)makeSmartCard
{
    if (self.state != TKSmartCardSlotStateValidCard)
        return nil;
    FakeCard* card = [FakeCard new];
    card.slot = self;
    card.valid = YES;
    [self.cards addObject:card];
    return card;
}

- (void)releaseHolder:(FakeCard*)card
{
    NSArray<FakeCard*>* others;
    @synchronized(self) {
        if (self.holder != card)
            return;
        self.holder = nil;
        others = [self.cards copy];
    }
    for (FakeCard* other in others)
        [other retryQueued];
}

@end

@interface FakeManager : NSObject
@property(atomic) int lookups;
@property(nonatomic, strong) NSMutableDictionary<NSString*, FakeSlot*>* slots;
@property(atomic, copy) NSArray<NSString*>* slotNames; // KVO-observable, as the real one
- (void)addSlot:(FakeSlot*)slot named:(NSString*)name;
@end
@implementation FakeManager
- (instancetype)init
{
    if ((self = [super init])) {
        _slots = [NSMutableDictionary dictionary];
        _slotNames = @[];
    }
    return self;
}
- (FakeSlot*)slotNamed:(NSString*)name
{
    self.lookups = self.lookups + 1;
    @synchronized(self) {
        return self.slots[name];
    }
}
- (void)addSlot:(FakeSlot*)slot named:(NSString*)name
{
    @synchronized(self) {
        self.slots[name] = slot;
    }
    self.slotNames = [self.slotNames arrayByAddingObject:name];
}
@end

namespace {

using std::chrono::milliseconds;

class CtkSmartCard : public ::testing::Test
{
protected:
    void SetUp() override
    {
        manager = [FakeManager new];
        slot = [FakeSlot new];
        [manager addSlot:slot named:@"Fake Slot"];
        FakeManager* m = manager;
        provider = [m, this]() -> void* {
            ++providerCalls;
            return (__bridge void*)m;
        };
    }

    std::expected<std::unique_ptr<Ctk::CtkCard>, Ctk::CtkFailure> open(milliseconds deadline = milliseconds{2000})
    {
        return Ctk::CtkCard::open("Fake Slot", deadline, provider);
    }

    // Lets queued replies and slot notifications run.
    static void settle(milliseconds pause = milliseconds{50})
    {
        std::this_thread::sleep_for(pause);
        dispatch_sync(fakeQueue(), ^{
                      });
    }

    FakeManager* manager = nil;
    FakeSlot* slot = nil;
    std::atomic<int> providerCalls{0};
    Ctk::ManagerProvider provider;
};

} // namespace

TEST(CtkSmartCardLoad, NoCtkCallBeforeOpen)
{
    // Nothing in this binary has opened a card yet when the first test runs,
    // and loading the facade must not have asked for the manager.
    EXPECT_EQ(g_defaultManagerCalls.load(), 0);
}

TEST_F(CtkSmartCard, NoCtkCallBeforeOpen)
{
    EXPECT_EQ(providerCalls.load(), 0);
    EXPECT_EQ(manager.lookups, 0);
    auto card = open();
    ASSERT_TRUE(card.has_value());
    EXPECT_EQ(providerCalls.load(), 1);
    EXPECT_EQ(manager.lookups, 1);
}

TEST_F(CtkSmartCard, NilManagerIsNoManagerWithoutCtkCalls)
{
    const int before = g_defaultManagerCalls.load();
    const Ctk::ManagerProvider none = []() -> void* { return nullptr; };
    auto card = Ctk::CtkCard::open("Fake Slot", milliseconds{200}, none);
    ASSERT_FALSE(card.has_value());
    EXPECT_EQ(card.error().status, Ctk::CtkStatus::NoManager);
    EXPECT_TRUE(Ctk::slotNames(none).empty());
    EXPECT_EQ(g_defaultManagerCalls.load(), before);
    EXPECT_EQ(slot.cards.count, 0U);
}

TEST_F(CtkSmartCard, WaitsForAReplyDeliveredOnAnotherQueue)
{
    slot.grantDelayMs = 150;
    const auto start = std::chrono::steady_clock::now();
    auto card = open();
    const auto took = std::chrono::steady_clock::now() - start;
    ASSERT_TRUE(card.has_value());
    EXPECT_GE(took, milliseconds{150});
    auto reply = (*card)->exchange(std::vector<std::uint8_t>{0x00, 0xB0, 0x00, 0x00, 0x04});
    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(*reply, (std::vector<std::uint8_t>{0x90, 0x00}));
}

TEST_F(CtkSmartCard, GrantAfterTheDeadlineIsRefusedAndClosed)
{
    slot.grantDelayMs = 400;
    auto card = open(milliseconds{200});
    ASSERT_FALSE(card.has_value());
    EXPECT_EQ(card.error().status, Ctk::CtkStatus::SessionRefused);
    settle(milliseconds{400});
    ASSERT_EQ(slot.cards.count, 1U);
    EXPECT_EQ(slot.cards[0].ends, 1) << "the late grant is ended";
    EXPECT_FALSE(slot.cards[0].holding);
}

TEST_F(CtkSmartCard, EndSessionExactlyOnceOnEveryPath)
{
    { // success
        auto card = open();
        ASSERT_TRUE(card.has_value());
    }
    EXPECT_EQ(slot.cards.lastObject.ends, 1);

    { // refused: no session, nothing to end
        slot.beginErrorCode = -2;
        auto card = open();
        ASSERT_FALSE(card.has_value());
        slot.beginErrorCode = 0;
    }
    EXPECT_EQ(slot.cards.lastObject.ends, 0);

    { // late grant
        slot.grantDelayMs = 300;
        auto card = open(milliseconds{100});
        ASSERT_FALSE(card.has_value());
        settle(milliseconds{350});
        slot.grantDelayMs = 0;
    }
    EXPECT_EQ(slot.cards.lastObject.ends, 1);

    { // lost session, then reopen, then destroyed
        auto card = open();
        ASSERT_TRUE(card.has_value());
        FakeCard* first = slot.cards.lastObject;
        first.context = nil; // another client took the card
        EXPECT_FALSE((*card)->alive());
        EXPECT_EQ((*card)->lossKind(), Ctk::CtkStatus::SessionLost);
        ASSERT_TRUE((*card)->reopen(milliseconds{2000}).has_value());
        EXPECT_EQ(first.ends, 1);
        FakeCard* second = slot.cards.lastObject;
        EXPECT_NE(first, second);
        card->reset();
        EXPECT_EQ(first.ends, 1);
        EXPECT_EQ(second.ends, 1);
    }
}

TEST_F(CtkSmartCard, MinusTwoAtBeginIsSessionRefused)
{
    slot.beginErrorCode = -2;
    auto card = open();
    ASSERT_FALSE(card.has_value());
    EXPECT_EQ(card.error().status, Ctk::CtkStatus::SessionRefused);
}

TEST_F(CtkSmartCard, MinusTwoDuringHeldSessionIsSessionLost)
{
    auto card = open();
    ASSERT_TRUE(card.has_value());
    slot.transmitErrorCode = -2;
    auto reply = (*card)->exchange(std::vector<std::uint8_t>{0x00, 0xB0, 0x00, 0x00, 0x04});
    ASSERT_FALSE(reply.has_value());
    EXPECT_EQ(reply.error().status, Ctk::CtkStatus::SessionLost);
}

// A command may carry a PIN; the facade's own copy of it does not outlive the
// exchange.
TEST_F(CtkSmartCard, TheCommandCopyIsWipedAfterTheExchange)
{
    auto card = open();
    ASSERT_TRUE(card.has_value());
    const std::vector<std::uint8_t> verify{0x00, 0x20, 0x00, 0x80, 0x04, 0x31, 0x32, 0x33, 0x34};
    ASSERT_TRUE((*card)->exchange(verify).has_value());
    FakeCard* used = slot.cards.lastObject;
    ASSERT_EQ(used.sentBytes.length, verify.size());
    EXPECT_EQ(std::memcmp(used.sentBytes.bytes, verify.data(), verify.size()), 0) << "the card got another command";
    ASSERT_EQ(used.lastRequest.length, verify.size());
    const auto* left = static_cast<const std::uint8_t*>(used.lastRequest.bytes);
    EXPECT_TRUE(std::all_of(left, left + verify.size(), [](std::uint8_t b) { return b == 0; }))
        << "the facade's copy of the command still holds it";
}

TEST_F(CtkSmartCard, SecondSessionOnTheSameSlotEndsAtTheDeadline)
{
    auto first = open();
    ASSERT_TRUE(first.has_value());

    const auto start = std::chrono::steady_clock::now();
    auto second = open(milliseconds{200});
    const auto took = std::chrono::steady_clock::now() - start;
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().status, Ctk::CtkStatus::SessionRefused);
    EXPECT_GE(took, milliseconds{200});
    EXPECT_LT(took, milliseconds{1000});

    auto reply = (*first)->exchange(std::vector<std::uint8_t>{0x00, 0xB0, 0x00, 0x00, 0x04});
    EXPECT_TRUE(reply.has_value()) << "the first session is undisturbed";

    // When the first ends, the queued grant arrives late and is ended too.
    first->reset();
    settle();
    for (FakeCard* card in slot.cards)
        EXPECT_FALSE(card.holding);
}

TEST_F(CtkSmartCard, HeldSlotLeavingValidCardMarksTheCardGone)
{
    auto card = open();
    ASSERT_TRUE(card.has_value());
    EXPECT_TRUE((*card)->alive());

    // Out and back in, fast; the old card object still claims to be valid, so
    // only the slot's state change tells.
    slot.state = TKSmartCardSlotStateEmpty;
    slot.state = TKSmartCardSlotStateValidCard;
    settle(milliseconds{100});

    EXPECT_FALSE((*card)->alive());
    EXPECT_EQ((*card)->lossKind(), Ctk::CtkStatus::CardGone);
    auto reopened = (*card)->reopen(milliseconds{500});
    ASSERT_FALSE(reopened.has_value());
    EXPECT_EQ(reopened.error().status, Ctk::CtkStatus::CardGone);
    EXPECT_EQ(slot.cards.count, 1U) << "no session is begun on the card now in the slot";
}

TEST_F(CtkSmartCard, LengthOptionsAreSetBeforeTheSession)
{
    for (const NSInteger maxInput : {NSInteger{261}, NSInteger{65544}}) {
        SCOPED_TRACE(maxInput);
        [slot.events removeAllObjects];
        slot.maxInputLength = maxInput;
        auto card = open();
        ASSERT_TRUE(card.has_value());
        NSArray* events = [slot.events copy];
        const NSUInteger begin = [events indexOfObject:@"beginSession"];
        ASSERT_NE(begin, NSNotFound);
        EXPECT_LT([events indexOfObject:@"useExtendedLength"], begin);
        EXPECT_LT([events indexOfObject:@"useCommandChaining"], begin);
        FakeCard* fake = slot.cards.lastObject;
        EXPECT_EQ(fake.useExtendedLength, maxInput > 261 ? YES : NO);
        EXPECT_EQ(fake.useCommandChaining, NO);
    }
}

TEST_F(CtkSmartCard, ProtocolPrefersT1ThenT0)
{
    for (const auto granted : {TKSmartCardProtocolT1, TKSmartCardProtocolT0}) {
        slot.protocolToGrant = granted;
        auto card = open();
        ASSERT_TRUE(card.has_value());
        EXPECT_EQ(slot.cards.lastObject.allowedProtocols, TKSmartCardProtocolT1 | TKSmartCardProtocolT0);
        EXPECT_EQ((*card)->protocol(), granted == TKSmartCardProtocolT0 ? Ctk::CtkProtocol::T0 : Ctk::CtkProtocol::T1);
    }
}

TEST_F(CtkSmartCard, RepliesRunNoCallerCode)
{
    // The card answers on its own queue; the facade's handler only hands the
    // result to org.librescrs.ctk.reply, and the caller's thread goes on.
    const auto caller = std::this_thread::get_id();
    slot.grantDelayMs = 300;
    auto refused = open(milliseconds{100});
    ASSERT_FALSE(refused.has_value());
    settle(milliseconds{350});
    EXPECT_EQ(std::string(slot.cards.lastObject.endQueueLabel.UTF8String), "org.librescrs.ctk.reply");

    slot.grantDelayMs = 0;
    auto card = open();
    ASSERT_TRUE(card.has_value());
    auto reply = (*card)->exchange(std::vector<std::uint8_t>{0x00, 0xB0, 0x00, 0x00, 0x04});
    EXPECT_TRUE(reply.has_value());
    EXPECT_EQ(std::this_thread::get_id(), caller);
}

TEST_F(CtkSmartCard, SlotsNeverOpenACardSession)
{
    Ctk::CtkSlots slots(provider);
    ASSERT_EQ(slots.acquire(), Ctk::CtkStatus::Ok);
    slot.state = TKSmartCardSlotStateEmpty;
    slot.state = TKSmartCardSlotStateValidCard;
    slot.state = TKSmartCardSlotStateMuteCard;
    settle(milliseconds{100});
    const auto snapshot = slots.snapshot();
    ASSERT_EQ(snapshot.size(), 1U);
    EXPECT_EQ(snapshot[0].state, Ctk::SlotState::MuteCard);
    EXPECT_EQ(slot.cards.count, 0U) << "a watcher never makes a card object";
}

TEST_F(CtkSmartCard, KvoRunsNoCallerCode)
{
    Ctk::CtkSlots slots(provider);
    ASSERT_EQ(slots.acquire(), Ctk::CtkStatus::Ok);
    @synchronized(slot) {
        [slot.stateReadQueues removeAllObjects];
    }

    const auto waiter = std::this_thread::get_id();
    const auto seen = slots.generation();
    FakeSlot* watched = slot;
    std::thread changer([watched] {
        std::this_thread::sleep_for(milliseconds{100});
        watched.state = TKSmartCardSlotStateEmpty;
    });
    EXPECT_EQ(slots.waitForChange(seen, milliseconds{2000}), Ctk::WaitResult::Changed);
    changer.join();
    EXPECT_EQ(std::this_thread::get_id(), waiter) << "the wait returns on the waiting thread";
    settle(milliseconds{50});
    NSSet* queues = nil;
    @synchronized(slot) {
        queues = [slot.stateReadQueues copy];
    }
    EXPECT_EQ(queues.count, 1U) << queues.description.UTF8String;
    EXPECT_TRUE([queues containsObject:@"org.librescrs.ctk.kvo"]) << queues.description.UTF8String;
    ASSERT_EQ(slots.snapshot().size(), 1U);
    EXPECT_EQ(slots.snapshot()[0].state, Ctk::SlotState::Empty);
}

TEST_F(CtkSmartCard, DestroyWhileKvoFiresIsSafe)
{
    std::atomic<bool> stop{false};
    FakeSlot* watched = slot;
    std::thread toggler([&stop, watched] {
        while (!stop.load()) {
            watched.state = TKSmartCardSlotStateEmpty;
            watched.state = TKSmartCardSlotStateValidCard;
        }
    });
    for (int i = 0; i < 200; ++i) {
        auto slots = std::make_unique<Ctk::CtkSlots>(provider);
        ASSERT_EQ(slots->acquire(), Ctk::CtkStatus::Ok);
        slots.reset();
    }
    stop.store(true);
    toggler.join();
    SUCCEED();
}

// The held card's own observer, torn down while its slot's state changes on
// another thread.
TEST_F(CtkSmartCard, CardDestroyedWhileItsSlotChangesIsSafe)
{
    std::atomic<bool> stop{false};
    FakeSlot* watched = slot;
    std::thread toggler([&stop, watched] {
        while (!stop.load()) {
            watched.state = TKSmartCardSlotStateEmpty;
            watched.state = TKSmartCardSlotStateValidCard;
        }
    });
    int opened = 0;
    for (int i = 0; i < 200; ++i) {
        auto card = open();
        if (card.has_value()) // the toggler may have emptied the slot just then
            ++opened;
    }
    stop.store(true);
    toggler.join();
    EXPECT_GT(opened, 0);
}
