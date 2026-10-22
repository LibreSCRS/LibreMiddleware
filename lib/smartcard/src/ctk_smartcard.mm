// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The CryptoTokenKit body of ctk_smartcard.h. Compiled with ARC.
//
// Every CryptoTokenKit object is reached through the selectors of
// TKSmartCardSlotManager, TKSmartCardSlot and TKSmartCard only, so a test can
// hand in objects of its own that answer the same selectors.

#include "ctk_smartcard.h"

#include <smartcard/secure_wipe.h>

#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Foundation/Foundation.h>

#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>

namespace Ctk = LibreSCRS::SmartCard::Internal::Ctk;

namespace {

// Replies land here: they store a result and signal, nothing else.
dispatch_queue_t replyQueue()
{
    static dispatch_queue_t queue = dispatch_queue_create("org.librescrs.ctk.reply", DISPATCH_QUEUE_SERIAL);
    return queue;
}

// Slot state changes land here: they set a flag, nothing else.
dispatch_queue_t kvoQueue()
{
    static dispatch_queue_t queue = dispatch_queue_create("org.librescrs.ctk.kvo", DISPATCH_QUEUE_SERIAL);
    return queue;
}

// How long one exchange waits for its reply. CryptoTokenKit bounds a
// transmit itself; this only keeps a lost reply from hanging the caller.
constexpr std::int64_t kExchangeReplyBoundNs = 120LL * NSEC_PER_SEC;

// TKErrorCodeCommunicationError: at beginSession the card is held by another
// client; during a held session the session was taken away.
constexpr NSInteger kCommunicationError = -2;

// One asynchronous call: the reply and the waiting caller meet here. Shared
// with the reply block, so a reply that arrives after the caller gave up
// writes into memory that is still there.
struct Pending
{
    std::mutex mtx;
    bool done = false;
    bool abandoned = false;
    BOOL success = NO;
    NSData* data = nil;
    NSError* error = nil;
    dispatch_semaphore_t signal = dispatch_semaphore_create(0);
};

// Waits until the reply or the deadline. False when the deadline came
// first; the call is then abandoned and a late reply knows it.
bool waitFor(const std::shared_ptr<Pending>& pending, std::int64_t deadlineNs)
{
    (void)dispatch_semaphore_wait(pending->signal, dispatch_time(DISPATCH_TIME_NOW, deadlineNs));
    std::lock_guard lock(pending->mtx);
    if (pending->done) {
        return true;
    }
    pending->abandoned = true;
    return false;
}

std::string utf8(NSString* text)
{
    const char* bytes = text.UTF8String;
    return bytes != nullptr ? std::string(bytes) : std::string();
}

std::string describe(NSError* error)
{
    if (error == nil) {
        return "no detail";
    }
    return utf8(error.domain) + " " + std::to_string(error.code) + ": " + utf8(error.localizedDescription);
}

id resolveManager(const Ctk::ManagerProvider& provider)
{
    if (provider) {
        return (__bridge id)provider();
    }
    return [TKSmartCardSlotManager defaultManager];
}

} // namespace

// Watches the held slot's state. The notification arrives on whatever thread
// CryptoTokenKit changes the slot on; the handler reads the new state from the
// notification and hands a flag write to the kvo queue.
@interface LibreSCRSCtkSlotObserver : NSObject
- (instancetype)initWithFlag:(std::shared_ptr<std::atomic<bool>>)cardLeft;
@end

@implementation LibreSCRSCtkSlotObserver {
    std::shared_ptr<std::atomic<bool>> _cardLeft;
}

- (instancetype)initWithFlag:(std::shared_ptr<std::atomic<bool>>)cardLeft
{
    if ((self = [super init])) {
        _cardLeft = std::move(cardLeft);
    }
    return self;
}

- (void)observeValueForKeyPath:(NSString*)keyPath
                      ofObject:(id)object
                        change:(NSDictionary<NSKeyValueChangeKey, id>*)change
                       context:(void*)context
{
    (void)keyPath;
    (void)object;
    (void)context;
    NSNumber* state = change[NSKeyValueChangeNewKey];
    if (![state isKindOfClass:[NSNumber class]] || state.integerValue == TKSmartCardSlotStateValidCard) {
        return;
    }
    // Sticky: once the card left, a card in the slot later is another card.
    auto cardLeft = _cardLeft;
    dispatch_async(kvoQueue(), ^{
      cardLeft->store(true);
    });
}

@end

namespace {

Ctk::SlotState slotStateOf(TKSmartCardSlotState state)
{
    switch (state) {
    case TKSmartCardSlotStateMissing:
        return Ctk::SlotState::Missing;
    case TKSmartCardSlotStateEmpty:
        return Ctk::SlotState::Empty;
    case TKSmartCardSlotStateProbing:
        return Ctk::SlotState::Probing;
    case TKSmartCardSlotStateMuteCard:
        return Ctk::SlotState::MuteCard;
    case TKSmartCardSlotStateValidCard:
        return Ctk::SlotState::ValidCard;
    }
    return Ctk::SlotState::Empty;
}

// What a CtkSlots and its watcher share. The Objective-C members are touched
// on the kvo queue only; the rest under mtx.
struct SlotsShared
{
    std::mutex mtx;
    std::condition_variable changed;
    std::vector<Ctk::SlotSnapshot> snapshot;
    std::uint64_t generation = 0;
    bool cancelled = false;
    bool dead = false;

    id manager = nil;
    NSMutableDictionary<NSString*, TKSmartCardSlot*>* slots = [NSMutableDictionary dictionary];
    std::map<std::string, std::pair<Ctk::SlotState, std::uint32_t>> history; // settled state, transitions
};

} // namespace

// Watches the manager's slot list and each slot's state. A notification only
// queues a refresh on the kvo queue; the refresh rebuilds the snapshot and
// wakes the waiters. No caller code runs on either.
@interface LibreSCRSCtkSlotsWatcher : NSObject
- (instancetype)initWithShared:(std::shared_ptr<SlotsShared>)shared;
- (void)refresh;      // on the kvo queue only
- (void)stopWatching; // on the kvo queue only
@end

@implementation LibreSCRSCtkSlotsWatcher {
    std::shared_ptr<SlotsShared> _shared;
}

- (instancetype)initWithShared:(std::shared_ptr<SlotsShared>)shared
{
    if ((self = [super init])) {
        _shared = std::move(shared);
    }
    return self;
}

- (void)observeValueForKeyPath:(NSString*)keyPath
                      ofObject:(id)object
                        change:(NSDictionary<NSKeyValueChangeKey, id>*)change
                       context:(void*)context
{
    (void)keyPath;
    (void)object;
    (void)change;
    (void)context;
    LibreSCRSCtkSlotsWatcher* watcher = self;
    dispatch_async(kvoQueue(), ^{
      [watcher refresh];
    });
}

- (void)refresh
{
    auto& shared = *_shared;
    if (shared.dead || shared.manager == nil) {
        return;
    }
    NSArray<NSString*>* names = [shared.manager slotNames];
    if (names == nil) {
        names = @[];
    }
    for (NSString* name in names) {
        if (shared.slots[name] == nil) {
            TKSmartCardSlot* slot = [shared.manager slotNamed:name];
            if (slot != nil) {
                // No options: the refresh reads the state itself, on the kvo queue.
                [slot addObserver:self forKeyPath:@"state" options:0 context:nullptr];
                shared.slots[name] = slot;
            }
        }
    }
    for (NSString* name in [shared.slots.allKeys copy]) {
        if (![names containsObject:name]) {
            [shared.slots[name] removeObserver:self forKeyPath:@"state" context:nullptr];
            [shared.slots removeObjectForKey:name];
        }
    }

    std::vector<Ctk::SlotSnapshot> fresh;
    for (NSString* name in names) {
        TKSmartCardSlot* slot = shared.slots[name];
        if (slot == nil) {
            continue;
        }
        Ctk::SlotSnapshot snap;
        snap.name = utf8(name);
        snap.state = slotStateOf(slot.state);
        if (snap.state == Ctk::SlotState::ValidCard) {
            NSData* atr = slot.ATR.bytes;
            if (atr != nil) {
                const auto* bytes = static_cast<const std::uint8_t*>(atr.bytes);
                snap.atr.assign(bytes, bytes + atr.length);
            }
        }
        auto& [settled, transitions] = shared.history.try_emplace(snap.name, Ctk::SlotState::Empty, 0U).first->second;
        if (snap.state != Ctk::SlotState::Probing && snap.state != settled) {
            settled = snap.state;
            ++transitions;
        }
        snap.settled = settled;
        snap.transitions = transitions;
        fresh.push_back(std::move(snap));
    }
    {
        std::lock_guard lock(shared.mtx);
        shared.snapshot = std::move(fresh);
        ++shared.generation;
    }
    shared.changed.notify_all();
}

- (void)stopWatching
{
    auto& shared = *_shared;
    for (NSString* name in shared.slots) {
        [shared.slots[name] removeObserver:self forKeyPath:@"state" context:nullptr];
    }
    [shared.slots removeAllObjects];
    if (shared.manager != nil) {
        [shared.manager removeObserver:self forKeyPath:@"slotNames" context:nullptr];
        shared.manager = nil;
    }
}

@end

namespace LibreSCRS::SmartCard::Internal::Ctk {

struct CtkCard::Impl
{
    mutable std::mutex mtx; // one per card: two cards never wait for each other
    std::string slotName;
    TKSmartCardSlot* slot = nil;
    TKSmartCard* card = nil;
    bool sessionOpen = false;
    CtkProtocol protocol = CtkProtocol::T1;
    std::shared_ptr<std::atomic<bool>> cardLeft = std::make_shared<std::atomic<bool>>(false);
    LibreSCRSCtkSlotObserver* observer = nil;

    // The card left the slot, or another took its place.
    [[nodiscard]] bool cardGoneLocked() const
    {
        return cardLeft->load() || card == nil || !card.valid || slot.state != TKSmartCardSlotStateValidCard;
    }

    void endSessionLocked()
    {
        if (sessionOpen) {
            sessionOpen = false;
            [card endSession];
        }
    }

    // Makes a card object for the slot's card and begins the exclusive
    // session on it, waiting up to @p deadline for the grant.
    std::expected<void, CtkFailure> beginLocked(std::chrono::milliseconds deadline)
    {
        TKSmartCard* fresh = [slot makeSmartCard];
        if (fresh == nil) {
            return std::unexpected(CtkFailure{CtkStatus::NoCard, slotName});
        }
        fresh.allowedProtocols = TKSmartCardProtocolT1 | TKSmartCardProtocolT0;
        // Set before the session, which is when they are read.
        fresh.useExtendedLength = slot.maxInputLength > 261 || slot.maxOutputLength > 258;
        fresh.useCommandChaining = NO;

        auto pending = std::make_shared<Pending>();
        TKSmartCard* granted = fresh;
        [fresh beginSessionWithReply:^(BOOL success, NSError* error) {
          dispatch_async(replyQueue(), ^{
            bool closeLate = false;
            {
                std::lock_guard lock(pending->mtx);
                if (pending->abandoned) {
                    closeLate = success;
                } else {
                    pending->done = true;
                    pending->success = success;
                    pending->error = error;
                }
            }
            if (closeLate) {
                // Nobody waits for this session any more.
                [granted endSession];
            }
            dispatch_semaphore_signal(pending->signal);
          });
        }];

        const auto deadlineNs = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline).count();
        if (!waitFor(pending, deadlineNs)) {
            return std::unexpected(CtkFailure{CtkStatus::SessionRefused, "not granted within the deadline"});
        }
        if (!pending->success) {
            if (pending->error.code == kCommunicationError) {
                return std::unexpected(CtkFailure{CtkStatus::SessionRefused, describe(pending->error)});
            }
            return std::unexpected(CtkFailure{CtkStatus::CommError, describe(pending->error)});
        }

        card = fresh;
        sessionOpen = true;
        // Cleared by CryptoTokenKit when the card goes or another card object
        // opens a session on it: that is how a lost session shows.
        card.context = @YES;
        protocol = card.currentProtocol == TKSmartCardProtocolT0 ? CtkProtocol::T0 : CtkProtocol::T1;
        return {};
    }
};

CtkCard::CtkCard(std::unique_ptr<Impl> i) noexcept : impl(std::move(i)) {}

std::expected<std::unique_ptr<CtkCard>, CtkFailure>
CtkCard::open(const std::string& slotName, std::chrono::milliseconds grantDeadline, const ManagerProvider& manager)
{
    @autoreleasepool {
        id slotManager = resolveManager(manager);
        if (slotManager == nil) {
            return std::unexpected(CtkFailure{CtkStatus::NoManager, "no slot manager"});
        }
        TKSmartCardSlot* slot = [slotManager slotNamed:@(slotName.c_str())];
        if (slot == nil) {
            return std::unexpected(CtkFailure{CtkStatus::UnknownSlot, slotName});
        }
        switch (slot.state) {
        case TKSmartCardSlotStateValidCard:
            break;
        case TKSmartCardSlotStateMuteCard:
            return std::unexpected(CtkFailure{CtkStatus::Mute, slotName});
        default:
            return std::unexpected(CtkFailure{CtkStatus::NoCard, slotName});
        }

        auto impl = std::make_unique<Impl>();
        impl->slotName = slotName;
        impl->slot = slot;
        std::lock_guard lock(impl->mtx);
        if (auto begun = impl->beginLocked(grantDeadline); !begun) {
            return std::unexpected(begun.error());
        }
        impl->observer = [[LibreSCRSCtkSlotObserver alloc] initWithFlag:impl->cardLeft];
        [slot addObserver:impl->observer forKeyPath:@"state" options:NSKeyValueObservingOptionNew context:nullptr];
        return std::make_unique<CtkCard>(std::move(impl));
    }
}

CtkCard::~CtkCard()
{
    @autoreleasepool {
        std::lock_guard lock(impl->mtx);
        if (impl->observer != nil) {
            LibreSCRSCtkSlotObserver* observer = impl->observer;
            [impl->slot removeObserver:observer forKeyPath:@"state" context:nullptr];
            impl->observer = nil;
            // A notification already being delivered on another thread may
            // still reach the observer; keep it alive well past that, as the
            // slots watcher is kept.
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), kvoQueue(), ^{
              (void)observer;
            });
        }
        impl->endSessionLocked();
    }
}

std::expected<std::vector<std::uint8_t>, CtkFailure> CtkCard::exchange(std::span<const std::uint8_t> command)
{
    @autoreleasepool {
        std::lock_guard lock(impl->mtx);
        if (impl->cardGoneLocked()) {
            return std::unexpected(CtkFailure{CtkStatus::CardGone, "card left the slot"});
        }
        if (!impl->sessionOpen || impl->card.context == nil) {
            return std::unexpected(CtkFailure{CtkStatus::SessionLost, "session no longer held"});
        }

        auto pending = std::make_shared<Pending>();
        // The command may carry a PIN: this copy is wiped once the call is
        // over, answered or abandoned.
        NSMutableData* request = [NSMutableData dataWithBytes:command.data() length:command.size()];
        struct WipeRequest
        {
            NSMutableData* data;
            ~WipeRequest()
            {
                LibreSCRS::SmartCard::Internal::secureWipe(data.mutableBytes, data.length);
            }
        } wipeRequest{request};
        [impl->card transmitRequest:request
                              reply:^(NSData* response, NSError* error) {
                                dispatch_async(replyQueue(), ^{
                                  {
                                      std::lock_guard pendingLock(pending->mtx);
                                      if (!pending->abandoned) {
                                          pending->done = true;
                                          pending->data = response;
                                          pending->error = error;
                                      }
                                  }
                                  dispatch_semaphore_signal(pending->signal);
                                });
                              }];
        if (!waitFor(pending, kExchangeReplyBoundNs)) {
            return std::unexpected(CtkFailure{CtkStatus::CommError, "no reply from the card"});
        }
        if (impl->cardGoneLocked()) {
            return std::unexpected(CtkFailure{CtkStatus::CardGone, "card left the slot"});
        }
        if (pending->data == nil) {
            if (pending->error.code == kCommunicationError || impl->card.context == nil) {
                return std::unexpected(CtkFailure{CtkStatus::SessionLost, describe(pending->error)});
            }
            return std::unexpected(CtkFailure{CtkStatus::CommError, describe(pending->error)});
        }
        if (impl->card.context == nil) {
            return std::unexpected(CtkFailure{CtkStatus::SessionLost, "session taken during the exchange"});
        }
        const auto* bytes = static_cast<const std::uint8_t*>(pending->data.bytes);
        return std::vector<std::uint8_t>(bytes, bytes + pending->data.length);
    }
}

std::expected<void, CtkFailure> CtkCard::reopen(std::chrono::milliseconds grantDeadline)
{
    @autoreleasepool {
        std::lock_guard lock(impl->mtx);
        const bool gone = impl->cardGoneLocked();
        impl->endSessionLocked();
        if (gone) {
            return std::unexpected(CtkFailure{CtkStatus::CardGone, impl->slotName});
        }
        return impl->beginLocked(grantDeadline);
    }
}

bool CtkCard::alive() const noexcept
{
    @autoreleasepool {
        std::lock_guard lock(impl->mtx);
        return impl->sessionOpen && !impl->cardGoneLocked() && impl->card.context != nil;
    }
}

CtkStatus CtkCard::lossKind() const noexcept
{
    @autoreleasepool {
        std::lock_guard lock(impl->mtx);
        return impl->cardGoneLocked() ? CtkStatus::CardGone : CtkStatus::SessionLost;
    }
}

CtkProtocol CtkCard::protocol() const noexcept
{
    std::lock_guard lock(impl->mtx);
    return impl->protocol;
}

std::vector<std::uint8_t> CtkCard::atr() const
{
    @autoreleasepool {
        std::lock_guard lock(impl->mtx);
        if (impl->slot.state != TKSmartCardSlotStateValidCard) {
            return {};
        }
        NSData* bytes = impl->slot.ATR.bytes;
        if (bytes == nil) {
            return {};
        }
        const auto* data = static_cast<const std::uint8_t*>(bytes.bytes);
        return std::vector<std::uint8_t>(data, data + bytes.length);
    }
}

std::vector<std::string> slotNames(const ManagerProvider& manager)
{
    @autoreleasepool {
        id slotManager = resolveManager(manager);
        if (slotManager == nil) {
            return {};
        }
        std::vector<std::string> names;
        for (NSString* name in [slotManager slotNames]) {
            names.push_back(utf8(name));
        }
        return names;
    }
}

struct CtkSlots::Impl
{
    ManagerProvider provider;
    std::shared_ptr<SlotsShared> shared = std::make_shared<SlotsShared>();
    LibreSCRSCtkSlotsWatcher* watcher = [[LibreSCRSCtkSlotsWatcher alloc] initWithShared:shared];
};

CtkSlots::CtkSlots(ManagerProvider manager) : impl(std::make_unique<Impl>())
{
    impl->provider = std::move(manager);
}

CtkSlots::~CtkSlots()
{
    @autoreleasepool {
        auto shared = impl->shared;
        LibreSCRSCtkSlotsWatcher* watcher = impl->watcher;
        // Not a handler: the destructor may wait for the kvo queue, so no
        // refresh runs after the observers are gone.
        dispatch_sync(kvoQueue(), ^{
          [watcher stopWatching];
          shared->dead = true;
        });
        // A notification already being delivered on another thread may still
        // reach the watcher; keep it alive well past that.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), kvoQueue(), ^{
          (void)watcher;
        });
        {
            std::lock_guard lock(shared->mtx);
            shared->cancelled = true;
        }
        shared->changed.notify_all();
    }
}

CtkStatus CtkSlots::acquire()
{
    @autoreleasepool {
        {
            std::lock_guard lock(impl->shared->mtx);
            impl->shared->cancelled = false;
        }
        id manager = resolveManager(impl->provider);
        if (manager == nil) {
            return CtkStatus::NoManager;
        }
        auto shared = impl->shared;
        LibreSCRSCtkSlotsWatcher* watcher = impl->watcher;
        dispatch_sync(kvoQueue(), ^{
          [watcher stopWatching];
          shared->manager = manager;
          [manager addObserver:watcher forKeyPath:@"slotNames" options:0 context:nullptr];
          [watcher refresh];
        });
        return CtkStatus::Ok;
    }
}

std::vector<SlotSnapshot> CtkSlots::snapshot() const
{
    std::lock_guard lock(impl->shared->mtx);
    return impl->shared->snapshot;
}

std::uint64_t CtkSlots::generation() const noexcept
{
    std::lock_guard lock(impl->shared->mtx);
    return impl->shared->generation;
}

WaitResult CtkSlots::waitForChange(std::uint64_t seen, std::optional<std::chrono::milliseconds> timeout)
{
    auto& shared = *impl->shared;
    std::unique_lock lock(shared.mtx);
    const auto ready = [&] { return shared.cancelled || shared.generation != seen; };
    if (timeout) {
        if (!shared.changed.wait_for(lock, *timeout, ready)) {
            return WaitResult::TimedOut;
        }
    } else {
        shared.changed.wait(lock, ready);
    }
    return shared.cancelled ? WaitResult::Cancelled : WaitResult::Changed;
}

void CtkSlots::cancel() noexcept
{
    {
        std::lock_guard lock(impl->shared->mtx);
        impl->shared->cancelled = true;
    }
    impl->shared->changed.notify_all();
}

} // namespace LibreSCRS::SmartCard::Internal::Ctk
