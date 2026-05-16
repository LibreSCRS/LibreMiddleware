// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Header-only configurable mock provider, card, and slot used
///        by the multi-PIN PKCS#11 integration tests (multi-slot,
///        login isolation, CAN-in-PIN, reconnect, concurrency).
///
/// Each registered reader maps to a @ref CardSpec describing PACE flag,
/// CAN, and per-slot PIN+label. The provider's @ref probe() returns a
/// @ref MockConfigurableCard whose @ref bind() populates one
/// @ref MockConfigurableSlot per @ref SlotSpec, with a stable slot ID
/// computed via @ref computeSlotId.

#include "internal/Crv.h"
#include "internal/PKCS11Card.h"
#include "internal/PKCS11CardProvider.h"
#include "internal/PKCS11Slot.h"
#include "internal/PKCS11TokenInfo.h"
#include "internal/SlotIdHash.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal::Test {

class MockConfigurableCard;
class MockPKCS11CardProvider;

/// @brief Per-slot specification for the mock provider.
/// @since 4.1
struct MockSlotSpec
{
    /// @brief PKCS#15 PIN identifier byte string for this slot.
    std::vector<std::uint8_t> pinId;

    /// @brief Human-readable PIN label (e.g. @c "Auth PIN").
    std::string pinLabel;

    /// @brief ASCII PIN compared (strict equality) against the bytes
    ///        passed to @ref MockConfigurableSlot::login.
    std::string correctPin;

    /// @brief Logical kind, fed into @ref computeSlotId.
    SlotKind kind{SlotKind::Generic};
};

/// @brief Per-card specification for the mock provider.
/// @since 4.1
struct MockCardSpec
{
    /// @brief Whether @ref MockConfigurableCard::needsPaceFlag returns
    ///        true for this card; controls CAN-in-PIN parsing in
    ///        @ref MockConfigurableSlot::login.
    bool needsPace{false};

    /// @brief 6-digit ASCII CAN. Ignored when @ref needsPace is false.
    std::string correctCan;

    /// @brief One @ref MockSlotSpec per slot the card will surface.
    std::vector<MockSlotSpec> slots;
};

/// @brief Concrete @ref PKCS11Slot used by @ref MockConfigurableCard.
///
/// On @ref login the slot:
///  - parses an optional @c "CAN:PIN" prefix when the parent card
///    requires PACE and increments the card-level PACE counter on first
///    successful CAN extraction;
///  - compares the PIN portion (strict equality) against
///    @ref MockSlotSpec::correctPin;
///  - tracks per-slot retry counter (3 wrong attempts → @ref Crv::PinLocked).
///
/// @par Thread-safety
/// All public methods acquire @ref slotMutex internally. The card-level
/// PACE counter is bumped under the parent card's @c cardMutex via
/// @ref MockConfigurableCard::recordPaceEstablishment, with no nested
/// locks (slotMutex is released before reaching into the card).
///
/// @since 4.1
class MockConfigurableSlot final : public PKCS11Slot
{
public:
    /// @brief Construct a slot whose login compares against @p spec.
    MockConfigurableSlot(std::weak_ptr<PKCS11Card> parentCard, MockSlotSpec spec)
        : PKCS11Slot(parentCard, spec.pinId, spec.pinLabel), slotSpec(std::move(spec)), ownerCard(std::move(parentCard))
    {}

    [[nodiscard]] unsigned long login(unsigned long userType, std::span<const std::uint8_t> pin) override;

    [[nodiscard]] unsigned long logout() override
    {
        std::scoped_lock lock(slotMutex);
        loggedIn = false;
        cachedPin = Secure::String{};
        return Crv::Ok;
    }

    [[nodiscard]] std::vector<PKCS11ObjectInfo> enumerateObjects() override
    {
        std::scoped_lock lock(slotMutex);
        // One stub private key + one stub certificate per slot.
        PKCS11ObjectInfo key;
        key.objectClass = 3UL; // CKO_PRIVATE_KEY
        key.keyType = 0UL;     // CKK_RSA
        key.label = slotSpec.pinLabel + " Key";
        key.id = slotSpec.pinId;
        key.privateObj = true;
        key.sensitive = true;

        PKCS11ObjectInfo cert;
        cert.objectClass = 1UL; // CKO_CERTIFICATE
        cert.label = slotSpec.pinLabel + " Cert";
        cert.id = slotSpec.pinId;
        cert.value = std::vector<std::uint8_t>{0x30, 0x82, 0x00, 0x00}; // stub DER prefix

        return {key, cert};
    }

    [[nodiscard]] std::vector<std::uint8_t> signData(std::span<const std::uint8_t> data, unsigned long mechanism,
                                                     std::span<const std::uint8_t> keyId) override;

    [[nodiscard]] std::vector<std::uint8_t> signWithDigestInfo(std::span<const std::uint8_t> digestInfo,
                                                               std::span<const std::uint8_t> rawData,
                                                               unsigned long mechanism,
                                                               std::span<const std::uint8_t> keyId) override;

    [[nodiscard]] std::size_t signatureSize(std::span<const std::uint8_t> /*keyId*/) const override
    {
        return 256u;
    }

    [[nodiscard]] std::vector<unsigned long> mechanisms() const override
    {
        return {0x00000001UL}; // CKM_RSA_PKCS — stub
    }

    /// @brief Test-only setter to bind the cached token info during
    ///        @ref MockConfigurableCard::bind. Must be called BEFORE
    ///        the slot is published to a consumer.
    void initializeForBind(unsigned long stableId)
    {
        std::scoped_lock lock(slotMutex);
        stableSlotId = stableId;
        cachedTokenInfo.label = "Mock";
        cachedTokenInfo.manufacturerId = "LibreSCRS Mock";
        cachedTokenInfo.model = "MockCard";
        cachedTokenInfo.serialNumber = "MOCK-SERIAL";
        cachedTokenInfo.pinLabel = slotSpec.pinLabel;
        cachedTokenInfo.minPinLen = 4;
        cachedTokenInfo.maxPinLen = 16;
    }

private:
    MockSlotSpec slotSpec;
    std::weak_ptr<PKCS11Card> ownerCard;
    /// @guarded_by slotMutex
    int retryCount{0};
    /// @guarded_by slotMutex
    bool locked{false};
};

/// @brief Concrete @ref PKCS11Card backing @ref MockPKCS11CardProvider.
/// @since 4.1
class MockConfigurableCard final : public PKCS11Card
{
public:
    explicit MockConfigurableCard(MockCardSpec spec, std::weak_ptr<MockPKCS11CardProvider> providerRef = {})
        : cardSpec(std::move(spec)), provider(std::move(providerRef))
    {
        needsPace = cardSpec.needsPace;
    }

    [[nodiscard]] unsigned long bind(const std::string& reader) override
    {
        std::scoped_lock lock(cardMutex);
        readerName = reader;
        for (const auto& slotSpec : cardSpec.slots) {
            const std::uint32_t stableId = computeSlotId(reader, slotSpec.pinId, slotSpec.kind);
            auto slot = std::make_shared<MockConfigurableSlot>(weak_from_this(), slotSpec);
            slot->initializeForBind(static_cast<unsigned long>(stableId));
            slots.push_back(std::move(slot));
        }
        return Crv::Ok;
    }

    /// @brief Establish PACE with @p can; mock implementation just caches
    ///        the CAN, increments the card-level PACE counter, and
    ///        returns @ref Crv::Ok if @p can equals @ref MockCardSpec::correctCan.
    /// @par Thread-safety
    /// Acquires @ref cardMutex. Called by @ref MockConfigurableSlot::login
    /// outside @c slotMutex to keep lock ordering linear.
    [[nodiscard]] unsigned long establishPaceWithCan(const std::string& can);

    /// @brief PACE counter (test introspection).
    [[nodiscard]] int paceCount() const
    {
        std::scoped_lock lock(cardMutex);
        return paceCallCount;
    }

    /// @brief Test-only fault injection: arm a single sign-fault on the
    ///        next @ref MockConfigurableSlot::signData (or
    ///        @ref MockConfigurableSlot::signWithDigestInfo) call. The
    ///        flag is consumed (one-shot) by the next sign attempt
    ///        regardless of which slot drives the call.
    /// @par Thread-safety
    /// Acquires @ref cardMutex.
    void armSignFaultOnce()
    {
        std::scoped_lock lock(cardMutex);
        signFaultPending = true;
    }

    /// @brief Test-only introspection: returns @c true while a sign-fault
    ///        is armed and not yet consumed.
    /// @par Thread-safety
    /// Acquires @ref cardMutex.
    [[nodiscard]] bool signFaultArmed() const
    {
        std::scoped_lock lock(cardMutex);
        return signFaultPending;
    }

    /// @brief Test-only test-side hook: consume the armed sign-fault.
    ///        Returns @c true when a fault was pending (and thus the
    ///        sign call should fail), @c false otherwise.
    [[nodiscard]] bool consumeSignFaultLocked()
    {
        std::scoped_lock lock(cardMutex);
        if (!signFaultPending) {
            return false;
        }
        signFaultPending = false;
        return true;
    }

protected:
    [[nodiscard]] unsigned long establishPACE() override
    {
        // Direct call without a CAN is unused in this mock — slots invoke
        // @ref establishPaceWithCan instead. Kept as a satisfying override
        // of the pure-virtual base hook.
        return Crv::Ok;
    }

    [[nodiscard]] unsigned long completeBind() override
    {
        return Crv::Ok;
    }

private:
    [[nodiscard]] unsigned long reconnectInline() override;

    MockCardSpec cardSpec;
    std::weak_ptr<MockPKCS11CardProvider> provider;
    /// @guarded_by cardMutex
    int paceCallCount{0};
    /// @brief One-shot sign-fault injection. Consumed by the next
    ///        @ref MockConfigurableSlot::signData /
    ///        @ref MockConfigurableSlot::signWithDigestInfo call.
    /// @guarded_by cardMutex
    bool signFaultPending{false};
};

/// @brief Configurable mock provider used by the multi-PIN integration tests.
///
/// Each registered reader maps to a @ref MockCardSpec describing PACE
/// flag, CAN, and per-slot PIN+label. @ref probe constructs and binds a
/// @ref MockConfigurableCard each call; @ref probeCallCount and
/// @ref establishPACECallCount let tests assert on call counts.
/// @ref injectResetOnReader / @ref resetInjected provide a tiny
/// fault-injection surface for reconnect tests landing later.
///
/// @par Thread-safety
/// Internal counters / registry guarded by @ref registryMutex. Concurrent
/// @ref probe calls are safe.
///
/// @since 4.1
class MockPKCS11CardProvider final : public PKCS11CardProvider,
                                     public std::enable_shared_from_this<MockPKCS11CardProvider>
{
public:
    /// @brief Register @p reader with the supplied @p spec. Replaces any
    ///        existing entry for the same reader.
    void registerCard(std::string reader, MockCardSpec spec)
    {
        std::scoped_lock lock(registryMutex);
        registry.insert_or_assign(std::move(reader), std::move(spec));
    }

    [[nodiscard]] std::shared_ptr<PKCS11Card> probe(const std::string& readerName) override
    {
        MockCardSpec spec;
        {
            std::scoped_lock lock(registryMutex);
            ++probeCounts[readerName];
            const auto it = registry.find(readerName);
            if (it == registry.end()) {
                return nullptr;
            }
            spec = it->second;
        }
        auto card = std::make_shared<MockConfigurableCard>(std::move(spec), weak_from_this());
        if (card->bind(readerName) != Crv::Ok) {
            return nullptr;
        }
        return card;
    }

    /// @brief Probe-call counter for @p reader.
    [[nodiscard]] int probeCallCount(const std::string& reader) const
    {
        std::scoped_lock lock(registryMutex);
        const auto it = probeCounts.find(reader);
        return it == probeCounts.end() ? 0 : it->second;
    }

    /// @brief PACE-establishment counter aggregated for @p reader.
    ///
    /// The counter lives on the per-probe @ref MockConfigurableCard
    /// instance; this introspection helper returns the most recent
    /// per-reader bookkeeping the provider observed via
    /// @ref recordPaceEstablishment.
    [[nodiscard]] int establishPACECallCount(const std::string& reader) const
    {
        std::scoped_lock lock(registryMutex);
        const auto it = paceCounts.find(reader);
        return it == paceCounts.end() ? 0 : it->second;
    }

    /// @brief Mark @p reader as having a card-reset condition pending.
    void injectResetOnReader(const std::string& reader)
    {
        std::scoped_lock lock(registryMutex);
        resetFlags.insert(reader);
    }

    /// @brief Whether a reset has been injected for @p reader.
    [[nodiscard]] bool resetInjected(const std::string& reader) const
    {
        std::scoped_lock lock(registryMutex);
        return resetFlags.contains(reader);
    }

    /// @brief Provider-side bookkeeping invoked by the card on PACE.
    ///        Test helper — not part of the @ref PKCS11CardProvider
    ///        interface.
    void recordPaceEstablishment(const std::string& reader)
    {
        std::scoped_lock lock(registryMutex);
        ++paceCounts[reader];
    }

private:
    mutable std::mutex registryMutex;
    std::map<std::string, MockCardSpec> registry;
    std::map<std::string, int> probeCounts;
    std::map<std::string, int> paceCounts;
    std::set<std::string> resetFlags;
};

inline unsigned long MockConfigurableSlot::login(unsigned long /*userType*/, std::span<const std::uint8_t> pin)
{
    std::string canPart;
    std::string pinPart;
    bool canExtracted = false;

    std::shared_ptr<PKCS11Card> cardLocked = ownerCard.lock();
    const bool cardNeedsPace = cardLocked && cardLocked->needsPaceFlag();

    if (cardNeedsPace) {
        const auto colonIt = std::find(pin.begin(), pin.end(), static_cast<std::uint8_t>(':'));
        if (colonIt != pin.end()) {
            canPart.assign(pin.begin(), colonIt);
            pinPart.assign(colonIt + 1, pin.end());
            canExtracted = true;
        } else {
            pinPart.assign(pin.begin(), pin.end());
        }
    } else {
        pinPart.assign(pin.begin(), pin.end());
    }

    // Trigger PACE on the card if a CAN was extracted from the PIN. Done
    // OUTSIDE slotMutex to keep the documented lock order linear
    // (slotMutex never held while reaching into cardMutex).
    if (canExtracted && cardLocked) {
        auto* configurable = static_cast<MockConfigurableCard*>(cardLocked.get());
        const unsigned long paceRv = configurable->establishPaceWithCan(canPart);
        if (paceRv != Crv::Ok) {
            return paceRv;
        }
    }

    // Gate / verify the PIN under slotMutex.
    std::scoped_lock lock(slotMutex);
    if (locked) {
        return Crv::PinLocked;
    }
    if (pinPart == slotSpec.correctPin) {
        loggedIn = true;
        cachedPin = Secure::String{pinPart};
        retryCount = 0;
        return Crv::Ok;
    }
    ++retryCount;
    if (retryCount >= 3) {
        locked = true;
        return Crv::PinLocked;
    }
    return Crv::PinIncorrect;
}

inline std::vector<std::uint8_t> MockConfigurableSlot::signData(std::span<const std::uint8_t> /*data*/,
                                                                unsigned long /*mechanism*/,
                                                                std::span<const std::uint8_t> /*keyId*/)
{
    // Consult the card-level sign-fault flag OUTSIDE slotMutex to honour
    // the project lock order (slotMutex never held while reaching into
    // cardMutex).
    if (auto cardLocked = ownerCard.lock()) {
        auto* configurable = static_cast<MockConfigurableCard*>(cardLocked.get());
        if (configurable->consumeSignFaultLocked()) {
            return {};
        }
    }
    std::scoped_lock lock(slotMutex);
    if (!loggedIn) {
        return {};
    }
    return std::vector<std::uint8_t>(64, std::uint8_t{0xAA});
}

inline std::vector<std::uint8_t> MockConfigurableSlot::signWithDigestInfo(std::span<const std::uint8_t> /*digestInfo*/,
                                                                          std::span<const std::uint8_t> /*rawData*/,
                                                                          unsigned long /*mechanism*/,
                                                                          std::span<const std::uint8_t> /*keyId*/)
{
    if (auto cardLocked = ownerCard.lock()) {
        auto* configurable = static_cast<MockConfigurableCard*>(cardLocked.get());
        if (configurable->consumeSignFaultLocked()) {
            return {};
        }
    }
    std::scoped_lock lock(slotMutex);
    if (!loggedIn) {
        return {};
    }
    return std::vector<std::uint8_t>(64, std::uint8_t{0xAA});
}

inline unsigned long MockConfigurableCard::reconnectInline()
{
    // Mock reconnect: if the card requires PACE and a CAN is cached
    // from a previous successful login sequence, replay PACE using the
    // cached CAN. This bumps @ref paceCallCount so reconnect tests can
    // verify PACE was rerun after a transport-level reset.
    // NOTE: caller (PKCS11Card::handleReset) already holds cardMutex,
    // so we touch fields directly without re-locking.
    if (needsPace && !cachedCan.empty()) {
        ++paceCallCount;
        if (auto p = provider.lock()) {
            // recordPaceEstablishment takes registryMutex (mock-side
            // lock), entirely separate from cardMutex — no inversion.
            p->recordPaceEstablishment(readerName);
        }
    }
    return Crv::Ok;
}

inline unsigned long MockConfigurableCard::establishPaceWithCan(const std::string& can)
{
    {
        std::scoped_lock lock(cardMutex);
        ++paceCallCount;
        if (can != cardSpec.correctCan) {
            return Crv::GeneralError;
        }
        cachedCan = Secure::String{can};
    }
    if (auto p = provider.lock()) {
        p->recordPaceEstablishment(readerName);
    }
    return Crv::Ok;
}

} // namespace LibreSCRS::Pkcs11::Internal::Test
