// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Secrets must not reach the allocator unwiped. This binary replaces the
// global operator new/delete so every block handed back to the heap can be
// searched for a marker while it is still owned -- the search runs before
// free(), so no freed memory is ever read. Each case arms the search around
// one call and asserts that no block freed during it still held the secret.

#include <bac.h>
#include <crypto_utils.h>
#include <secure_messaging.h>
#include <smartcard/secure_buffer.h>
#include <smartcard/secure_wipe.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

std::atomic<bool> g_armed{false};
std::atomic<int> g_hits{0};
const std::uint8_t* g_needle = nullptr;
std::size_t g_needleLen = 0;

// Every block carries a header in front of the bytes handed out, holding the
// requested size, so a block is zeroed and searched over exactly what was asked
// for and nothing the allocator rounded up. The header is as large as the
// alignment, so the pointer handed out keeps it.
constexpr std::size_t kDefaultAlign = __STDCPP_DEFAULT_NEW_ALIGNMENT__;
static_assert(kDefaultAlign >= sizeof(std::size_t));

std::size_t headerFor(std::size_t align) noexcept
{
    return std::max(align, kDefaultAlign);
}

std::size_t& requestedSize(void* user) noexcept
{
    return *reinterpret_cast<std::size_t*>(static_cast<std::uint8_t*>(user) - sizeof(std::size_t));
}

void* allocateZeroed(std::size_t n, std::size_t align, bool nothrow)
{
    const std::size_t header = headerFor(align);
    void* base = nullptr;
    if (align <= kDefaultAlign) {
        base = std::malloc(header + n);
    } else {
        // aligned_alloc wants a size that is a multiple of the alignment.
        base = std::aligned_alloc(align, (header + n + align - 1) / align * align);
    }
    if (base == nullptr) {
        if (nothrow)
            return nullptr;
        throw std::bad_alloc();
    }
    void* user = static_cast<std::uint8_t*>(base) + header;
    requestedSize(user) = n;
    std::memset(user, 0, n);
    return user;
}

void inspectAndFree(void* user, std::size_t align) noexcept
{
    if (user == nullptr)
        return;
    if (g_armed.load(std::memory_order_relaxed)) {
        const auto* begin = static_cast<const std::uint8_t*>(user);
        const auto* end = begin + requestedSize(user);
        if (std::search(begin, end, g_needle, g_needle + g_needleLen) != end)
            g_hits.fetch_add(1, std::memory_order_relaxed);
    }
    std::free(static_cast<std::uint8_t*>(user) - headerFor(align));
}

/// Arms the search for @p secret for the lifetime of the scope.
class FreedBlockWatch
{
public:
    explicit FreedBlockWatch(std::span<const std::uint8_t> secret)
    {
        g_needle = secret.data();
        g_needleLen = secret.size();
        g_hits.store(0);
        g_armed.store(true);
    }
    ~FreedBlockWatch()
    {
        g_armed.store(false);
    }
    FreedBlockWatch(const FreedBlockWatch&) = delete;
    FreedBlockWatch& operator=(const FreedBlockWatch&) = delete;

    [[nodiscard]] int hits() const noexcept
    {
        return g_hits.load();
    }
};

std::span<const std::uint8_t> bytesOf(std::string_view s)
{
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

using LibreSCRS::SmartCard::Internal::SecureBuffer;

// The optimizer may drop stores into a block that is about to be deleted, and
// even the new/delete pair itself: it does not know our delete reads the
// block. Volatile stores are kept.
void plantSecret(char* dst, std::string_view secret)
{
    volatile char* out = dst;
    for (std::size_t i = 0; i < secret.size(); ++i)
        out[i] = secret[i];
}

} // namespace

// The whole replaceable set, so no allocation pairs a block of ours with the
// library's free or the other way round.
void* operator new(std::size_t n)
{
    return allocateZeroed(n, kDefaultAlign, false);
}
void* operator new[](std::size_t n)
{
    return allocateZeroed(n, kDefaultAlign, false);
}
void* operator new(std::size_t n, const std::nothrow_t&) noexcept
{
    return allocateZeroed(n, kDefaultAlign, true);
}
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept
{
    return allocateZeroed(n, kDefaultAlign, true);
}
void* operator new(std::size_t n, std::align_val_t a)
{
    return allocateZeroed(n, static_cast<std::size_t>(a), false);
}
void* operator new[](std::size_t n, std::align_val_t a)
{
    return allocateZeroed(n, static_cast<std::size_t>(a), false);
}
void* operator new(std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept
{
    return allocateZeroed(n, static_cast<std::size_t>(a), true);
}
void* operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept
{
    return allocateZeroed(n, static_cast<std::size_t>(a), true);
}
void operator delete(void* p) noexcept
{
    inspectAndFree(p, kDefaultAlign);
}
void operator delete[](void* p) noexcept
{
    inspectAndFree(p, kDefaultAlign);
}
void operator delete(void* p, std::size_t) noexcept
{
    inspectAndFree(p, kDefaultAlign);
}
void operator delete[](void* p, std::size_t) noexcept
{
    inspectAndFree(p, kDefaultAlign);
}
void operator delete(void* p, const std::nothrow_t&) noexcept
{
    inspectAndFree(p, kDefaultAlign);
}
void operator delete[](void* p, const std::nothrow_t&) noexcept
{
    inspectAndFree(p, kDefaultAlign);
}
void operator delete(void* p, std::align_val_t a) noexcept
{
    inspectAndFree(p, static_cast<std::size_t>(a));
}
void operator delete[](void* p, std::align_val_t a) noexcept
{
    inspectAndFree(p, static_cast<std::size_t>(a));
}
void operator delete(void* p, std::size_t, std::align_val_t a) noexcept
{
    inspectAndFree(p, static_cast<std::size_t>(a));
}
void operator delete[](void* p, std::size_t, std::align_val_t a) noexcept
{
    inspectAndFree(p, static_cast<std::size_t>(a));
}
void operator delete(void* p, std::align_val_t a, const std::nothrow_t&) noexcept
{
    inspectAndFree(p, static_cast<std::size_t>(a));
}
void operator delete[](void* p, std::align_val_t a, const std::nothrow_t&) noexcept
{
    inspectAndFree(p, static_cast<std::size_t>(a));
}

static_assert(
    std::is_same_v<SecureBuffer::Storage::allocator_type, LibreSCRS::Secure::detail::secure_allocator<std::uint8_t>>,
    "SecureBuffer must keep its bytes in storage that is wiped on every deallocation");

// The watcher itself: a block freed with the secret in it is seen, by the
// plain and by the over-aligned allocation path alike.
TEST(SecretWipeOnFree, WatcherSeesASecretLeftInAFreedBlock)
{
    constexpr std::string_view secret = "SECRET-91d0c2e7-MARK";
    struct alignas(64) OverAligned
    {
        char bytes[64];
    };
    FreedBlockWatch watch(bytesOf(secret));
    {
        std::vector<char> plain(secret.size());
        plantSecret(plain.data(), secret);
    }
    EXPECT_EQ(watch.hits(), 1);
    {
        auto aligned = std::make_unique<OverAligned>();
        ASSERT_EQ(reinterpret_cast<std::uintptr_t>(aligned.get()) % alignof(OverAligned), 0u);
        plantSecret(aligned->bytes, secret);
    }
    EXPECT_EQ(watch.hits(), 2);
}

TEST(SecretWipeOnFree, SecureBufferGrowthLeavesNoPinInFreedHeap)
{
    // A PIN padded to the stored length: the buffer grows past the capacity
    // the PIN was copied into, so the first block goes back to the heap.
    constexpr std::string_view pin = "PIN-7c3e19a4-MARK";
    FreedBlockWatch watch(bytesOf(pin));
    {
        SecureBuffer padded(pin);
        padded.resize(pin.size() + 48, 0xFF);
        ASSERT_EQ(padded.size(), pin.size() + 48);
    }
    EXPECT_EQ(watch.hits(), 0);
}

TEST(SecretWipeOnFree, SecureBufferAdoptWipesTheAdoptedVector)
{
    constexpr std::string_view pin = "PIN-0b5d8e21-MARK";
    std::vector<std::uint8_t> serialized(pin.begin(), pin.end());
    FreedBlockWatch watch(bytesOf(pin));
    {
        SecureBuffer adopted(std::move(serialized));
        ASSERT_EQ(adopted.size(), pin.size());
        EXPECT_TRUE(std::equal(adopted.begin(), adopted.end(), pin.begin(), pin.end()));
        serialized = {}; // whatever storage the source still held goes back now
    }
    EXPECT_EQ(watch.hits(), 0);
}

TEST(SecretWipeOnFree, SecureMessagingProtectLeavesNoPinInFreedHeap)
{
    constexpr std::string_view pin = "PIN-e4a91f07-MARK";
    for (const auto algo : {emrtd::crypto::SMAlgorithm::DES3, emrtd::crypto::SMAlgorithm::AES}) {
        emrtd::crypto::SessionKeys keys;
        keys.encKey = std::vector<std::uint8_t>(16, 0x11);
        keys.macKey = std::vector<std::uint8_t>(16, 0x22);
        keys.ssc = std::vector<std::uint8_t>(algo == emrtd::crypto::SMAlgorithm::DES3 ? 8 : 16, 0x00);
        emrtd::crypto::SecureMessaging sm(std::move(keys), algo);

        // VERIFY (00 20 00 01, Lc, PIN): the command data is the PIN.
        std::vector<std::uint8_t> verify = {0x00, 0x20, 0x00, 0x01, static_cast<std::uint8_t>(pin.size())};
        verify.insert(verify.end(), pin.begin(), pin.end());

        std::vector<std::uint8_t> wrapped;
        {
            FreedBlockWatch watch(bytesOf(pin));
            wrapped = sm.protect(verify);
            EXPECT_EQ(watch.hits(), 0) << "algorithm " << static_cast<int>(algo);
        }
        EXPECT_GT(wrapped.size(), verify.size());
    }
}

TEST(SecretWipeOnFree, KdfLeavesNoSeedInFreedHeap)
{
    // K_seed, a shared secret K or a PACE CAN/PIN all enter the KDF as seed.
    constexpr std::string_view seed = "SEED-5a2c7e90MARK";
    const std::vector<std::uint8_t> seedBytes(seed.begin(), seed.end());
    FreedBlockWatch watch(bytesOf(seed));
    auto key = emrtd::crypto::detail::kdf(seedBytes, 1, true);
    EXPECT_EQ(key.size(), 16u);
    EXPECT_EQ(watch.hits(), 0);
}

TEST(SecretWipeOnFree, RetailMacLeavesNoKeyHalfInFreedHeap)
{
    constexpr std::string_view ka = "Ka-3f9b1"; // the first key half, 8 bytes
    std::vector<std::uint8_t> key(ka.begin(), ka.end());
    key.resize(16, 0x5C);
    const std::vector<std::uint8_t> data(24, 0x00); // more than one block
    FreedBlockWatch watch(bytesOf(ka));
    auto mac = emrtd::crypto::detail::retailMAC(key, data);
    EXPECT_EQ(mac.size(), 8u);
    EXPECT_EQ(watch.hits(), 0);
}

TEST(SecretWipeOnFree, DeriveBacKeysLeavesNoMrzInFreedHeap)
{
    // The MRZ fields are the BAC access secret; MRZ_information holds them.
    const std::string documentNumber = "MRZ7Q3X95";
    const std::string dateOfBirth = "740727";
    const std::string dateOfExpiry = "120714";
    FreedBlockWatch watch(bytesOf(documentNumber));
    {
        const auto keys = emrtd::crypto::deriveBACKeys(documentNumber, dateOfBirth, dateOfExpiry);
        EXPECT_EQ(keys.encKey.size(), 16u);
    }
    EXPECT_EQ(watch.hits(), 0);
}

TEST(SecretWipeOnFree, BuildMrzInformationLeavesNoMrzInFreedHeap)
{
    // Long enough to leave the small-string buffer and, without a reserve,
    // to outgrow the first heap block on either standard library.
    constexpr std::string_view documentNumber = "MRZ7Q3X95ABCDEFGHJKLMNPQRSTUVWXYZ0123456";
    FreedBlockWatch watch(bytesOf(documentNumber));
    {
        std::string mrzInfo = emrtd::crypto::detail::buildMrzInformation(documentNumber, "740727", "120714");
        EXPECT_EQ(mrzInfo.size(), documentNumber.size() + 1 + 7 + 7);
        // Wiping the result is the caller's part of the contract.
        LibreSCRS::SmartCard::Internal::secureWipe(mrzInfo.data(), mrzInfo.size());
    }
    EXPECT_EQ(watch.hits(), 0);
}

TEST(SecretWipeOnFree, BuildMrzInformationWipesOnAnInvalidCharacter)
{
    constexpr std::string_view documentNumber = "MRZ7Q3X95ABCDEFGHJKLMNPQRSTUVWXYZ0123456";
    FreedBlockWatch watch(bytesOf(documentNumber));
    EXPECT_THROW((void)emrtd::crypto::detail::buildMrzInformation(documentNumber, "7407!7", "120714"),
                 std::invalid_argument);
    EXPECT_EQ(watch.hits(), 0);
}
