// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// opensc-plugin channel lifecycle + probe-gate unit tests (no hardware).
//
// Compiles the plugin translation unit directly (OpenscPinLifecycleTests
// precedent) so the channel-run seam (runUnderChannel), the probe gates
// (driverPresent / efDirAdvertisesAppletSuiteGen2) and the activation-error
// vocabulary mappers can be driven without a card. Live-SM scenarios ride a
// detached CardSession with an injected FakeChannel: the session's
// transmitInternal funnel and the activateChannelWithSm live-protocol reuse
// path then route every APDU through the scripted double, which lets the
// tests pin the deferred-claim probe branches and the channel-run teardown
// rules (fatality by channel STATE, partial teardown preserving the
// sc_context, cancel semantics) end to end.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <thread>
#include <vector>

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>

#include <apdu.h>
#include <fake_channel.h>
#include <pcsc_connection.h>

#include "opensc_reader_bridge.h"
#include "opensc_session.h"
#include "opensc_user_consent.h"

using LibreSCRS::CancelSource;
using LibreSCRS::CancelToken;
using LibreSCRS::OpenSc::ChannelRunReport;
using LibreSCRS::OpenSc::OpenSCSession;
using LibreSCRS::SecureChannel::ChannelActivationError;
using LibreSCRS::SecureChannel::ChannelState;
using LibreSCRS::SecureChannel::TestSupport::FakeChannel;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::PaceRequest;
using LibreSCRS::SmartCard::SmProtocolRequest;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Internal::PCSCConnection;

// The plugin factory exported by the compiled-in translation unit.
extern "C" LibreSCRS::Plugin::CardPlugin* create_card_plugin() noexcept;
extern "C" void destroy_card_plugin(LibreSCRS::Plugin::CardPlugin*) noexcept;

namespace {

AppletAid pkcs15Aid()
{
    return AppletAid{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
}

APDUResponse sw(std::uint8_t sw1, std::uint8_t sw2, std::vector<std::uint8_t> body = {})
{
    APDUResponse r;
    r.data = std::move(body);
    r.sw1 = sw1;
    r.sw2 = sw2;
    return r;
}

bool isSelectAid(const APDUCommand& cmd)
{
    return cmd.ins == 0xA4 && cmd.p1 == 0x04;
}

bool isSelectMf(const APDUCommand& cmd)
{
    return cmd.ins == 0xA4 && cmd.p1 == 0x00 && cmd.data == std::vector<std::uint8_t>{0x3F, 0x00};
}

bool isSelectEfDir(const APDUCommand& cmd)
{
    return cmd.ins == 0xA4 && cmd.p1 == 0x00 && cmd.data == std::vector<std::uint8_t>{0x2F, 0x00};
}

bool isReadBinary(const APDUCommand& cmd)
{
    return cmd.ins == 0xB0;
}

std::uint16_t readBinaryOffset(const APDUCommand& cmd)
{
    return static_cast<std::uint16_t>((cmd.p1 << 8) | cmd.p2);
}

/// Detached CardSession + injected FakeChannel wired for live-SM scenarios:
/// carriesSm + Open (hasLiveSecureChannel() == true), cross-applet reuse on,
/// and PaceRequest{Can} recorded so activateChannelWithSm rides the live
/// protocol through the double instead of attempting a real PACE handshake.
struct LiveSmSession
{
    LiveSmSession(const std::string& readerName = "ChannelTestReader")
        : session(LibreSCRS::SmartCard::detail::makeDetachedCardSession(readerName))
    {
        auto owned = std::make_unique<FakeChannel>(pkcs15Aid(), ChannelState::Open, /*carriesSm=*/true,
                                                   /*crossAppletReuse=*/true);
        channel = owned.get();
        LibreSCRS::SmartCard::detail::ChannelInjector::installForTesting(
            *session, std::move(owned), SmProtocolRequest{PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can}});
    }

    std::shared_ptr<CardSession> session;
    FakeChannel* channel = nullptr; // borrowed; owned by the session
};

struct PluginHandle
{
    PluginHandle() : plugin(create_card_plugin()) {}
    ~PluginHandle()
    {
        destroy_card_plugin(plugin);
    }
    PluginHandle(const PluginHandle&) = delete;
    PluginHandle& operator=(const PluginHandle&) = delete;

    LibreSCRS::Plugin::CardPlugin* plugin;
};

const std::vector<std::uint8_t> kTestAtr{0x3B, 0x00};

// ── Probe gates (seams) ────────────────────────────────────────────────────

TEST(OpenscProbeGates, DriverWalkFindsVendoredDriverAndMissesAbsentOne)
{
    sc_context_t* ctx = nullptr;
    ASSERT_EQ(sc_establish_context(&ctx, "librescrs-lifecycle-test"), 0);
    // srbeid always ships in the vendored snapshot; a name no driver carries
    // must miss; a null context must miss. srbeid2 is deliberately NOT
    // asserted either way: it is absent until the snapshot bump and present
    // under the local hardware-verification override — the probe-level
    // branch test below adapts to whichever state the build is in.
    EXPECT_TRUE(LibreSCRS::OpenSc::driverPresent(ctx, "srbeid"));
    EXPECT_FALSE(LibreSCRS::OpenSc::driverPresent(ctx, "no-such-driver"));
    EXPECT_FALSE(LibreSCRS::OpenSc::driverPresent(nullptr, "srbeid"));
    sc_release_context(ctx);
}

namespace {

// EF.DIR transmit double modelling the LM transport's real behaviour: SELECT
// MF / EF.DIR answer 9000; a READ returns up to `chunkSize` bytes; a FULL
// chunk with more data to follow answers 9000, the final (short) chunk
// answers 6282 (ISO 7816-4 end of file). A READ at or past end of file — one
// the gate must never issue — answers `pastEofSw1 pastEofSw2` (default 6B00;
// pass 6988 to model the SM-fatal card) and increments `pastEofReads` so a
// test can prove the walk stopped in time.
struct EfDirScript
{
    std::function<APDUResponse(const APDUCommand&)> transmit;
    std::shared_ptr<int> pastEofReads;
};

EfDirScript efDirScript(std::vector<std::uint8_t> content, std::size_t chunkSize, std::uint8_t pastEofSw1 = 0x6B,
                        std::uint8_t pastEofSw2 = 0x00)
{
    auto counter = std::make_shared<int>(0);
    auto fn = [content = std::move(content), chunkSize, pastEofSw1, pastEofSw2,
               counter](const APDUCommand& cmd) -> APDUResponse {
        if (isSelectMf(cmd) || isSelectEfDir(cmd))
            return sw(0x90, 0x00);
        if (!isReadBinary(cmd))
            return sw(0x6A, 0x82);
        const std::size_t off = readBinaryOffset(cmd);
        if (off >= content.size()) {
            ++*counter;
            return sw(pastEofSw1, pastEofSw2); // a READ the gate should never make
        }
        const std::size_t n = std::min(chunkSize, content.size() - off);
        std::vector<std::uint8_t> body(content.begin() + static_cast<std::ptrdiff_t>(off),
                                       content.begin() + static_cast<std::ptrdiff_t>(off + n));
        const bool full = n == chunkSize && off + n < content.size();
        return full ? sw(0x90, 0x00, std::move(body)) : sw(0x62, 0x82, std::move(body));
    };
    return {std::move(fn), counter};
}

} // namespace

TEST(OpenscProbeGates, EfDirGateFindsAidPrefixInSingleChunk)
{
    auto script = efDirScript({0x61, 0x09, 0x4F, 0x07, 0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45}, /*chunkSize=*/256);
    EXPECT_TRUE(LibreSCRS::OpenSc::efDirAdvertisesAppletSuiteGen2(script.transmit));
    EXPECT_EQ(*script.pastEofReads, 0);
}

TEST(OpenscProbeGates, EfDirGateConcatenatesFullChunksBeforeSearching)
{
    // A genuinely multi-read EF.DIR (> 256 bytes): the prefix straddles the
    // 256-byte boundary — F3 81 ends the first FULL (9000) chunk, 00 00 02
    // opens the final (6282) chunk. Only a search over the concatenated
    // content finds it, and the walk stops at the 6282 without a past-EOF READ.
    std::vector<std::uint8_t> efdir(254, 0x00);
    for (std::uint8_t b : {0xF3, 0x81, 0x00, 0x00, 0x02, 0x53})
        efdir.push_back(b);
    auto script = efDirScript(efdir, /*chunkSize=*/256);
    EXPECT_TRUE(LibreSCRS::OpenSc::efDirAdvertisesAppletSuiteGen2(script.transmit));
    EXPECT_EQ(*script.pastEofReads, 0);
}

TEST(OpenscProbeGates, EfDirGateNeverReadsPastEofEvenWhenPrefixAbsent)
{
    // The safety property: on the decline path (prefix absent) the gate must
    // NOT probe one offset past the last data-bearing read. Some cards answer
    // that read with an SM-fatal 6988 that tears down a foreign provider's
    // live tunnel. The card here would answer 6988 past EOF; the gate must
    // decline WITHOUT ever making that read.
    std::vector<std::uint8_t> efdir(151, 0x11); // one-pass file, no prefix
    auto script = efDirScript(efdir, /*chunkSize=*/256, /*pastEofSw1=*/0x69, /*pastEofSw2=*/0x88);
    EXPECT_FALSE(LibreSCRS::OpenSc::efDirAdvertisesAppletSuiteGen2(script.transmit));
    EXPECT_EQ(*script.pastEofReads, 0) << "gate issued a READ at end-of-file — would kill a live SM tunnel";
}

TEST(OpenscProbeGates, EfDirGateDeclinesWhenPrefixAbsent)
{
    auto script = efDirScript({0x61, 0x09, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00}, /*chunkSize=*/256);
    EXPECT_FALSE(LibreSCRS::OpenSc::efDirAdvertisesAppletSuiteGen2(script.transmit));
    EXPECT_EQ(*script.pastEofReads, 0);
}

TEST(OpenscProbeGates, EfDirGateDeclinesWhenUnreadable)
{
    // SELECT MF fails.
    auto mfFails = [](const APDUCommand&) { return sw(0x6A, 0x82); };
    EXPECT_FALSE(LibreSCRS::OpenSc::efDirAdvertisesAppletSuiteGen2(mfFails));

    // EF.DIR absent.
    auto dirFails = [](const APDUCommand& cmd) -> APDUResponse {
        if (isSelectMf(cmd))
            return sw(0x90, 0x00);
        return sw(0x6A, 0x82);
    };
    EXPECT_FALSE(LibreSCRS::OpenSc::efDirAdvertisesAppletSuiteGen2(dirFails));

    // EF.DIR selected but READ BINARY rejected.
    auto readFails = [](const APDUCommand& cmd) -> APDUResponse {
        if (isSelectMf(cmd) || isSelectEfDir(cmd))
            return sw(0x90, 0x00);
        return sw(0x69, 0x82);
    };
    EXPECT_FALSE(LibreSCRS::OpenSc::efDirAdvertisesAppletSuiteGen2(readFails));
}

TEST(OpenscProbeGates, EfDirGateUsesSelectWithoutLeOnly)
{
    // Every SELECT in the walk must be P2=0C with NO Le: SELECT-with-FCI
    // carrying DO97 Le!=00 is the measured killer of a live SM channel.
    bool sawLeOnSelect = false;
    const auto script = efDirScript({0xF3, 0x81, 0x00, 0x00, 0x02}, /*chunkSize=*/256);
    auto transmit = [&](const APDUCommand& cmd) -> APDUResponse {
        if (cmd.ins == 0xA4 && (cmd.hasLe || cmd.p2 != 0x0C))
            sawLeOnSelect = true;
        return script.transmit(cmd);
    };
    EXPECT_TRUE(LibreSCRS::OpenSc::efDirAdvertisesAppletSuiteGen2(transmit));
    EXPECT_FALSE(sawLeOnSelect);
}

// ── Probe branches under a live SM channel ─────────────────────────────────

TEST(OpenscProbeLiveSm, SelectSuccessClaimsDeferredWithoutBinding)
{
    PluginHandle h;
    LiveSmSession live;

    // Wrapped SELECT of the PKCS#15 AID answers 9000: claim with the bind
    // DEFERRED. Exactly ONE wrapped APDU may reach the channel — a bind
    // would emit dozens (driver match + PKCS#15 parse) through it.
    live.channel->transmitHandler = [](const APDUCommand& cmd) -> APDUResponse {
        EXPECT_TRUE(isSelectAid(cmd));
        EXPECT_FALSE(cmd.hasLe);
        EXPECT_EQ(cmd.p2, 0x0C);
        return sw(0x90, 0x00);
    };
    EXPECT_TRUE(h.plugin->canHandleConnection(kTestAtr, *live.session));
    EXPECT_EQ(live.channel->transmits(), 1);

    // The deferred claim announces the CAN requirement to the host.
    EXPECT_EQ(h.plugin->preReadAuth(*live.session), LibreSCRS::Auth::PreReadAuthMethod::Can);
}

TEST(OpenscProbeLiveSm, SecurityStatusNotSatisfiedRequiresBothDeferredGates)
{
    PluginHandle h;
    LiveSmSession live;

    // 6982 sends the probe to the deferred-claim gates, and the scripted
    // card fails whichever gate applies: without the srbeid2 driver in the
    // vendored snapshot gate 2a declines before EF.DIR is touched (exactly
    // one wrapped APDU — the AID SELECT); under the local driver override
    // gate 2b runs and the unreadable EF.DIR (every follow-up answers 6982)
    // declines conservatively. Either way: no claim, no CAN announcement.
    live.channel->transmitHandler = [](const APDUCommand&) { return sw(0x69, 0x82); };
    EXPECT_FALSE(h.plugin->canHandleConnection(kTestAtr, *live.session));

    sc_context_t* probeCtx = nullptr;
    ASSERT_EQ(sc_establish_context(&probeCtx, "librescrs-lifecycle-test"), 0);
    const bool driverShipped = LibreSCRS::OpenSc::driverPresent(probeCtx, "srbeid2");
    sc_release_context(probeCtx);
    if (driverShipped) {
        EXPECT_GT(live.channel->transmits(), 1); // gate 2b walked EF.DIR
    } else {
        EXPECT_EQ(live.channel->transmits(), 1); // the AID SELECT only
    }
    EXPECT_EQ(h.plugin->preReadAuth(*live.session), LibreSCRS::Auth::PreReadAuthMethod::None);
}

TEST(OpenscProbeLiveSm, AnyOtherAnswerDeclines)
{
    PluginHandle h;
    LiveSmSession live;

    // Under a live SM the bind is forbidden in its entirety, so there is no
    // bind-probe fallback here: anything but 9000/6982 declines outright.
    live.channel->transmitHandler = [](const APDUCommand&) { return sw(0x6A, 0x82); };
    EXPECT_FALSE(h.plugin->canHandleConnection(kTestAtr, *live.session));
    EXPECT_EQ(live.channel->transmits(), 1);
}

TEST(OpenscProbeLiveSm, ReprobeErasesPredecessorGenerationsOfSameReader)
{
    PluginHandle h;

    LiveSmSession first("SameReader");
    first.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
    ASSERT_TRUE(h.plugin->canHandleConnection(kTestAtr, *first.session));
    ASSERT_EQ(h.plugin->preReadAuth(*first.session), LibreSCRS::Auth::PreReadAuthMethod::Can);

    // A NEW session (fresh generation) on the same reader name: its probe
    // erases every predecessor entry of that reader, so the first session's
    // claim is gone while the new one stands.
    LiveSmSession second("SameReader");
    second.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
    ASSERT_TRUE(h.plugin->canHandleConnection(kTestAtr, *second.session));

    EXPECT_EQ(h.plugin->preReadAuth(*first.session), LibreSCRS::Auth::PreReadAuthMethod::None);
    EXPECT_EQ(h.plugin->preReadAuth(*second.session), LibreSCRS::Auth::PreReadAuthMethod::Can);
}

// ── runUnderChannel semantics (seam-driven) ────────────────────────────────

namespace {

/// Assembles an OpenSCSession the way the probe's deferred-claim branch
/// does: a lease on a real plugin context + bridge bound to a detached
/// connection, requiresPace set, bind deferred.
struct DeferredSessionFixture
{
    DeferredSessionFixture()
    {
        s = std::make_shared<OpenSCSession>();
        s->readerName = "ChannelTestReader";
        sc_context_t* ctx = owner.context();
        if (!ctx)
            std::abort();
        s->context = owner.lease();
        s->bridge = std::make_unique<LibreSCRS::OpenSc::Bridge::OpenScBridge>();
        s->bridge->data.conn = &conn;
        s->bridge->readerName = s->readerName;
        LibreSCRS::OpenSc::Bridge::initBridgeReader(ctx, *s->bridge, kTestAtr);
        s->requiresPace = true;
    }

    // Declared first so it outlives the session that leases it.
    LibreSCRS::OpenSc::PluginContext owner;
    PCSCConnection conn{PCSCConnection::DetachedTag{}, "ChannelTestReader"};
    std::shared_ptr<OpenSCSession> s;
};

/// The RAW branch of the same fixture: no PACE gate, so runUnderChannel takes
/// no ActiveChannelHolder and (before this gate existed) took nothing at all.
struct RawSessionFixture : DeferredSessionFixture
{
    RawSessionFixture()
    {
        s->requiresPace = false;
        s->bound = true; // bind already done; fn is reached directly
    }
};

} // namespace

TEST(OpenscChannelRun, ActivationFailureWithoutLiveChannelIsCredentialsRequired)
{
    // No live channel, no cached CAN, no provider: activation reports
    // CredentialsRequired and the session state is untouched.
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("ChannelTestReader");
    DeferredSessionFixture f;
    f.s->bound = true; // simulate an already-bound session (spec obligation a)

    bool ran = false;
    const ChannelRunReport report =
        LibreSCRS::OpenSc::runUnderChannel(*session, *f.s, CancelToken{}, [&](OpenSCSession&) { ran = true; });
    EXPECT_TRUE(report.activationFailed);
    EXPECT_EQ(report.activationError, ChannelActivationError::CredentialsRequired);
    EXPECT_FALSE(ran);
    // Activation failure with bound==true must NOT reset card state.
    EXPECT_TRUE(f.s->bound);
    EXPECT_NE(f.s->context.get(), nullptr);
}

// The bridge opens its OWN PC/SC transaction per libopensc call whenever none
// is held (OpenScBridgeLock.AcquiresOwnTransactionWhenNoneHeld proves exactly
// that, and that behaviour is correct FOR THE BRIDGE). What was missing is an
// outer owner on the raw branch, so two consecutive libopensc calls were two
// consecutive PC/SC transactions with the card open to another process in
// between. This asserts the property, not a proxy for it: inside fn the
// connection reports a held transaction, and it is released by the time
// runUnderChannel returns.
TEST(OpenscChannelRun, RawBranchHoldsTheCardTransaction)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("ChannelTestReader");
    RawSessionFixture f;

    EXPECT_FALSE(f.conn.isTransactionHeld()) << "nothing held before the run";

    bool heldInsideFn = false;
    const ChannelRunReport report = LibreSCRS::OpenSc::runUnderChannel(
        *session, *f.s, CancelToken{}, [&](OpenSCSession&) { heldInsideFn = f.conn.isTransactionHeld(); });

    EXPECT_FALSE(report.activationFailed) << "the raw branch never activates a channel";
    EXPECT_TRUE(report.ran) << "fn must have been reached";
    EXPECT_TRUE(heldInsideFn) << "VERIFY and PSO must not be able to fall into two transactions";
    // Only that nothing is left held. WHERE it was released -- on the channel
    // holder's seam, before the teardown, rather than at function exit -- is
    // not visible from out here and is measured by the next test.
    EXPECT_FALSE(f.conn.isTransactionHeld()) << "nothing is left held after the run";
}

// A PIN deposited for a key operation is presented in the SAME card
// transaction as the operation: runUnderChannel holds one transaction for the
// whole callback, and verifyThenRun keeps VERIFY first and inside it. The
// control half runs the two steps as two calls -- the shape a host used to
// have -- and must land in two transactions, so the assertion discriminates.
TEST(OpenscOperationPin, VerifyAndOperationShareOneCardTransaction)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("ChannelTestReader");
    RawSessionFixture f;
    int transaction = 0;
    f.conn.setDetachedTransactionReleaseObserver([&transaction] { ++transaction; });
    struct Step
    {
        bool held = false;
        int transaction = -1;
    };
    Step verified;
    Step operated;
    const LibreSCRS::Secure::String pin{std::string_view{"1234"}};

    (void)LibreSCRS::OpenSc::runUnderChannel(*session, *f.s, CancelToken{}, [&](OpenSCSession&) {
        (void)LibreSCRS::OpenSc::verifyThenRun(
            pin, /*perOperation=*/true,
            [&](const LibreSCRS::Secure::String&) {
                verified = {f.conn.isTransactionHeld(), transaction};
                return SC_SUCCESS;
            },
            [&] { operated = {f.conn.isTransactionHeld(), transaction}; });
    });
    EXPECT_TRUE(verified.held);
    EXPECT_TRUE(operated.held);
    EXPECT_EQ(verified.transaction, operated.transaction) << "VERIFY and the operation must share one transaction";

    // Control: two separate calls fall into two transactions.
    Step first;
    Step second;
    (void)LibreSCRS::OpenSc::runUnderChannel(
        *session, *f.s, CancelToken{}, [&](OpenSCSession&) { first = {f.conn.isTransactionHeld(), transaction}; });
    (void)LibreSCRS::OpenSc::runUnderChannel(
        *session, *f.s, CancelToken{}, [&](OpenSCSession&) { second = {f.conn.isTransactionHeld(), transaction}; });
    EXPECT_NE(first.transaction, second.transaction) << "rig regression: two calls no longer mean two transactions";
}

TEST(OpenscOperationPin, WrongPinNeverReachesTheOperation)
{
    bool operated = false;
    const int rc = LibreSCRS::OpenSc::verifyThenRun(
        LibreSCRS::Secure::String{std::string_view{"0000"}}, /*perOperation=*/true,
        [](const LibreSCRS::Secure::String&) { return SC_ERROR_PIN_CODE_INCORRECT; }, [&] { operated = true; });
    EXPECT_EQ(rc, SC_ERROR_PIN_CODE_INCORRECT) << "the card's answer must reach the caller";
    EXPECT_FALSE(operated);
}

TEST(OpenscOperationPin, NoDepositedPinRunsAnOrdinaryKeysOperationAsBefore)
{
    bool verifyCalled = false;
    bool operated = false;
    const int rc = LibreSCRS::OpenSc::verifyThenRun(
        LibreSCRS::Secure::String{}, /*perOperation=*/false,
        [&](const LibreSCRS::Secure::String&) {
            verifyCalled = true;
            return SC_SUCCESS;
        },
        [&] { operated = true; });
    EXPECT_EQ(rc, SC_SUCCESS);
    EXPECT_FALSE(verifyCalled);
    EXPECT_TRUE(operated);
}

// CardPlugin::setCredentials: a key the card wants the PIN for per operation
// is never used without a deposited PIN -- the sign that follows an erase
// (an empty "pin") fails before anything reaches the card. Driven through the
// plugin's own gate with an unbound session: a gate that let the operation
// through would run it here.
TEST(OpenscOperationPin, PerOperationKeyWithoutADepositedPinNeverRuns)
{
    for (const bool erased : {false, true}) {
        SCOPED_TRACE(erased ? "PIN deposited, then erased" : "no PIN ever deposited");
        OpenSCSession session;
        if (erased) {
            session.operationPin = LibreSCRS::Secure::String{std::string_view{"1234"}};
            session.operationPin = LibreSCRS::Secure::String{};
        }
        sc_pkcs15_object_t key{};
        key.user_consent = 1; // the PIV Digital Signature key (9C)
        bool operated = false;
        const auto refused = LibreSCRS::OpenSc::verifyDepositedPinThenRun(session, key, [&] { operated = true; });
        EXPECT_FALSE(operated) << "a per-operation key signed without its PIN";
        ASSERT_TRUE(refused.has_value());
        EXPECT_EQ(LibreSCRS::OpenSc::signOutcomeForRefusedPin(refused->rc),
                  LibreSCRS::Plugin::SignResultOutcome::PluginError)
            << "no PIN is not the card's verdict on one";
        EXPECT_EQ(LibreSCRS::OpenSc::decipherOutcomeForRefusedPin(refused->rc),
                  LibreSCRS::Plugin::DecipherResultOutcome::PluginError);
    }

    // Control: an ordinary key without a PIN still runs, as it always has.
    OpenSCSession session;
    sc_pkcs15_object_t key{};
    bool operated = false;
    EXPECT_FALSE(LibreSCRS::OpenSc::verifyDepositedPinThenRun(session, key, [&] { operated = true; }).has_value());
    EXPECT_TRUE(operated);
}

// A key no PIN guards -- the PIV Card Authentication key (9E), any PrKDF
// entry without an authId -- runs with a PIN deposited exactly as it runs
// without one: no VERIFY, and the deposit stays for the host's next operation
// with a guarded key. There is no PIN object to present the PIN to: a lookup
// by the key's empty auth_id finds none, so a VERIFY attempted here refuses
// an operation that ran before deposits existed. The session carries an
// empty PKCS#15 binding so that lookup can run and come back empty-handed
// instead of dereferencing a null card; only a path that never looks can
// report the operation as run.
TEST(OpenscOperationPin, KeyWithoutAPinRunsWithADepositedPinAndNoVerify)
{
    sc_pkcs15_card_t noObjects{};
    OpenSCSession session;
    session.p15card = &noObjects;
    session.operationPin = LibreSCRS::Secure::String{std::string_view{"1234"}};
    sc_pkcs15_object_t key{}; // auth_id.len == 0, user_consent == 0
    bool operated = false;
    const auto refused = LibreSCRS::OpenSc::verifyDepositedPinThenRun(session, key, [&] { operated = true; });
    session.p15card = nullptr; // not a binding of OpenSC's: nothing to unbind at teardown
    EXPECT_FALSE(refused.has_value()) << "a key without a PIN was refused over the deposited PIN";
    EXPECT_TRUE(operated);
    EXPECT_EQ(session.operationPin.view(), std::string_view{"1234"}) << "the deposit is the host's to erase";
}

// A refused PIN on the atomic path must say so, as verifyPIN always has: a
// host that sees PluginError cannot tell a wrong PIN from a broken card.
// The verdict is the one the OpenSC PKCS#11 slot gives the same VERIFY answer.
TEST(OpenscOperationPin, RefusedPinIsReportedAsAPinOutcome)
{
    using LibreSCRS::OpenSc::decipherOutcomeForRefusedPin;
    using LibreSCRS::OpenSc::signOutcomeForRefusedPin;
    using LibreSCRS::Plugin::DecipherResultOutcome;
    using LibreSCRS::Plugin::SignResultOutcome;
    EXPECT_EQ(signOutcomeForRefusedPin(SC_ERROR_PIN_CODE_INCORRECT), SignResultOutcome::PinIncorrect);
    EXPECT_EQ(signOutcomeForRefusedPin(SC_ERROR_AUTH_METHOD_BLOCKED), SignResultOutcome::PinBlocked);
    EXPECT_EQ(signOutcomeForRefusedPin(SC_ERROR_CARD_CMD_FAILED), SignResultOutcome::PluginError);
    EXPECT_EQ(signOutcomeForRefusedPin(SC_ERROR_INVALID_PIN_LENGTH), SignResultOutcome::PluginError)
        << "only the card's verdict on the PIN is a PIN outcome";
    EXPECT_EQ(decipherOutcomeForRefusedPin(SC_ERROR_PIN_CODE_INCORRECT), DecipherResultOutcome::PinIncorrect);
    EXPECT_EQ(decipherOutcomeForRefusedPin(SC_ERROR_AUTH_METHOD_BLOCKED), DecipherResultOutcome::PinBlocked);
    EXPECT_EQ(decipherOutcomeForRefusedPin(SC_ERROR_CARD_CMD_FAILED), DecipherResultOutcome::PluginError);
}

// The same erase-only-the-PIN contract as the PKCS#15 plugin: an empty "pin"
// leaves the session's claim (and with it the PACE requirement) in place.
TEST(OpenscOperations, EmptyPinCredentialKeepsTheSessionClaim)
{
    PluginHandle h;
    LiveSmSession live;
    live.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
    ASSERT_TRUE(h.plugin->canHandleConnection(kTestAtr, *live.session));

    h.plugin->setCredentials(*live.session, "pin", LibreSCRS::Secure::String{std::string_view{"1234"}});
    h.plugin->setCredentials(*live.session, "pin", LibreSCRS::Secure::String{});
    EXPECT_EQ(h.plugin->preReadAuth(*live.session), LibreSCRS::Auth::PreReadAuthMethod::Can);
}

// That acquisition is the FIRST PC/SC touch of the operation and it sits
// OUTSIDE the try that contains fn, so a card removed, reset or claimed
// exclusively by another process makes SCardBeginTransaction fail and
// CardTransaction's constructor throw PCSCError. That throw would leave a
// dlopen'd plugin through the C ABI, which CardPlugin.h calls undefined
// behaviour. The bridge's own sc_lock has always caught the identical failure
// and returned SC_ERROR_READER, so losing the outer transaction must degrade
// to exactly that per-call behaviour -- never to an escaping exception.
TEST(OpenscChannelRun, RawTransactionFailureIsContainedNotPropagated)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("ChannelTestReader");
    RawSessionFixture f;
    f.conn.setDetachedTransactionFailure(SCARD_E_SHARING_VIOLATION);

    bool heldInsideFn = false;
    ChannelRunReport report;
    ASSERT_NO_THROW(
        report = LibreSCRS::OpenSc::runUnderChannel(*session, *f.s, CancelToken{},
                                                    [&](OpenSCSession&) { heldInsideFn = f.conn.isTransactionHeld(); }))
        << "no exception may cross the plugin ABI boundary";
    EXPECT_TRUE(report.ran) << "the operation still runs; the bridge falls back to its own per-call transaction";
    EXPECT_FALSE(heldInsideFn) << "the outer transaction was not acquired";
    EXPECT_FALSE(f.conn.isTransactionHeld()) << "and nothing is left held behind it";
}

// The release has to land on the CHANNEL HOLDER'S seam, not merely somewhere
// before the call returns. runWithChannelPtr tears the card state down AFTER
// that seam -- a failed bind or a dead tunnel unbinds PKCS#15 and disconnects
// the card -- and a transaction still held across that teardown is the
// cross-process window this branch exists to close, held open at the worst
// moment. isTransactionHeld() asked after the call cannot tell the two apart:
// the local owner dies at function exit either way, so the flag reads false in
// both. The flag is therefore sampled AT the release, from inside
// endTransaction, and compared against a piece of state the teardown is about
// to clear.
TEST(OpenscChannelRun, RawTransactionIsReleasedBeforeCardStateReset)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("ChannelTestReader");
    RawSessionFixture f;

    bool observedRelease = false;
    bool boundAtRelease = false;
    f.conn.setDetachedTransactionReleaseObserver([&] {
        observedRelease = true;
        boundAtRelease = f.s->bound;
    });

    // A throwing fn is what drives the teardown: the exception is contained,
    // the operation is reported as failed, and resetCardState() runs.
    const ChannelRunReport report = LibreSCRS::OpenSc::runUnderChannel(
        *session, *f.s, CancelToken{}, [](OpenSCSession&) { throw std::runtime_error("fn"); });

    EXPECT_TRUE(report.ran) << "fn must have been reached";
    EXPECT_TRUE(report.bindFailed) << "a throwing fn is reported as a failed operation";
    EXPECT_FALSE(f.s->bound) << "so the teardown after the release seam really ran";
    EXPECT_TRUE(observedRelease) << "the outer transaction was acquired and released";
    EXPECT_TRUE(boundAtRelease) << "released BEFORE the teardown, on the seam the channel holder uses";
    EXPECT_FALSE(f.conn.isTransactionHeld());
}

// The post-activation phase (bind + fn + verdict + teardown) is driven
// through the runWithChannelPtr seam with the FakeChannel installed directly
// as the active tunnel: the production activateChannelWithSm reuse path
// accepts only genuine protocol channels (dynamic_cast against PaceChannel /
// BacChannel / ChipAuthChannel), so a scripted double can never come out of
// a real activation. runUnderChannel's own activation leg is covered by the
// CredentialsRequired test above and by the HW phase.

namespace {

const std::function<void()> kNoHolderRelease = []() {};

} // namespace

TEST(OpenscChannelRun, BindFailureResetsCardStateButPreservesContext)
{
    FakeChannel channel{pkcs15Aid(), ChannelState::Open, /*carriesSm=*/true};
    DeferredSessionFixture f;

    // Every tunneled APDU of the deferred bind answers 6A82: no driver
    // matches, sc_connect_card fails, and the partial teardown runs — the
    // sc_context and the bridge SURVIVE for the next attempt.
    channel.transmitHandler = [](const APDUCommand&) { return sw(0x6A, 0x82); };

    bool ran = false;
    const ChannelRunReport report = LibreSCRS::OpenSc::runWithChannelPtr(
        *f.s, &channel, CancelToken{}, [&](OpenSCSession&) { ran = true; }, kNoHolderRelease);
    EXPECT_FALSE(report.activationFailed);
    EXPECT_TRUE(report.bindFailed);
    EXPECT_FALSE(ran);
    EXPECT_FALSE(f.s->bound);
    EXPECT_EQ(f.s->card, nullptr);
    EXPECT_EQ(f.s->p15card, nullptr);
    EXPECT_NE(f.s->context.get(), nullptr); // partial teardown never touches the context
    EXPECT_NE(f.s->bridge, nullptr);        // nor the bridge
    EXPECT_GT(channel.transmits(), 0);      // the bind DID ride the tunnel

    // A second run starts a FRESH sc_connect_card over the same ctx/bridge —
    // no second sc_card piles up on the bridge (ASan would flag the leak).
    const ChannelRunReport second =
        LibreSCRS::OpenSc::runWithChannelPtr(*f.s, &channel, CancelToken{}, [&](OpenSCSession&) {}, kNoHolderRelease);
    EXPECT_TRUE(second.bindFailed);
    EXPECT_EQ(f.s->card, nullptr);
}

TEST(OpenscChannelRun, ChannelDeathIsJudgedByStateAndTriggersReset)
{
    FakeChannel channel{pkcs15Aid(), ChannelState::Open, /*carriesSm=*/true};
    DeferredSessionFixture f;
    f.s->bound = true; // bind already done; fn is reached directly

    // The FIRST SM-fatal reply (measured 6988) flips the channel to Failed —
    // even as the LAST APDU of the run. The verdict is the channel STATE at
    // the end of the run, never the SW pattern.
    const ChannelRunReport report = LibreSCRS::OpenSc::runWithChannelPtr(
        *f.s, &channel, CancelToken{},
        [&](OpenSCSession& session) {
            channel.transmitHandler = [&](const APDUCommand&) {
                channel.setState(ChannelState::Failed);
                return sw(0x69, 0x88);
            };
            sc_apdu_t a{};
            a.cse = SC_APDU_CASE_1;
            a.cla = 0x00;
            a.ins = 0xA4;
            a.p1 = 0x04;
            a.p2 = 0x0C;
            // SW passthrough: libopensc sees the raw 6988 (mapped to an SC
            // error by the caller above the reader op), the channel run sees
            // only the state change.
            (void)session.bridge->reader.ops->transmit(&session.bridge->reader, &a);
            EXPECT_EQ(a.sw1, 0x69u);
            EXPECT_EQ(a.sw2, 0x88u);
        },
        kNoHolderRelease);
    EXPECT_TRUE(report.channelFatal);
    EXPECT_FALSE(f.s->bound); // resetCardState ran
    EXPECT_NE(f.s->context.get(), nullptr);
}

TEST(OpenscChannelRun, BenignStatusWordDoesNotReset)
{
    FakeChannel channel{pkcs15Aid(), ChannelState::Open, /*carriesSm=*/true};
    DeferredSessionFixture f;
    f.s->bound = true;

    // A benign card SW (6A82 — file not found, NOT a PIN outcome) leaves the
    // channel Open: no reset, the session stays bound, and the next
    // operation needs no re-PACE.
    const ChannelRunReport report = LibreSCRS::OpenSc::runWithChannelPtr(
        *f.s, &channel, CancelToken{},
        [&](OpenSCSession& session) {
            channel.transmitHandler = [](const APDUCommand&) { return sw(0x6A, 0x82); };
            sc_apdu_t a{};
            a.cse = SC_APDU_CASE_1;
            a.cla = 0x00;
            a.ins = 0xA4;
            a.p1 = 0x00;
            a.p2 = 0x0C;
            (void)session.bridge->reader.ops->transmit(&session.bridge->reader, &a);
        },
        kNoHolderRelease);
    EXPECT_FALSE(report.channelFatal);
    EXPECT_FALSE(report.bindFailed);
    EXPECT_TRUE(report.ran);
    EXPECT_TRUE(f.s->bound); // no reset, no re-PACE needed
    EXPECT_EQ(channel.state(), ChannelState::Open);
}

TEST(OpenscChannelRun, CancelDuringFnLeavesChannelOpenWithoutReset)
{
    FakeChannel channel{pkcs15Aid(), ChannelState::Open, /*carriesSm=*/true};
    DeferredSessionFixture f;
    f.s->bound = true;

    CancelSource src;
    const ChannelRunReport report = LibreSCRS::OpenSc::runWithChannelPtr(
        *f.s, &channel, src.token(), [&](OpenSCSession&) { src.requestCancel(); }, kNoHolderRelease);
    EXPECT_TRUE(report.cancelled);
    EXPECT_TRUE(report.ran);
    EXPECT_FALSE(report.channelFatal);
    EXPECT_FALSE(report.bindFailed);
    EXPECT_TRUE(f.s->bound);                        // no reset
    EXPECT_EQ(channel.state(), ChannelState::Open); // no channel teardown
}

TEST(OpenscChannelRun, CancelDuringBindResetsCardStateAndChannelStaysOpen)
{
    FakeChannel channel{pkcs15Aid(), ChannelState::Open, /*carriesSm=*/true};
    DeferredSessionFixture f;

    // Cancel fires during the deferred bind: the tunnel replies with the
    // 6F01 cancel sentinel (channel stays Open), the bind fails, and the
    // reset MUST run — otherwise a second sc_card leaks on the same bridge.
    CancelSource src;
    channel.transmitHandler = [&src](const APDUCommand&) {
        src.requestCancel();
        return sw(0x6F, 0x01);
    };

    bool ran = false;
    const ChannelRunReport report = LibreSCRS::OpenSc::runWithChannelPtr(
        *f.s, &channel, src.token(), [&](OpenSCSession&) { ran = true; }, kNoHolderRelease);
    EXPECT_FALSE(ran);
    EXPECT_TRUE(report.bindFailed);
    EXPECT_TRUE(report.cancelled);
    EXPECT_FALSE(f.s->bound); // reset fired
    EXPECT_EQ(f.s->card, nullptr);
    EXPECT_EQ(channel.state(), ChannelState::Open); // cancel never kills the channel
}

TEST(OpenscChannelRun, ExceptionFromFnIsContainedNotPropagated)
{
    // No C++ exception may cross the plugin ABI boundary (the plugin is
    // dlopen'd with a potentially-mismatched C++ runtime). A throw from fn
    // (e.g. bad_alloc sizing a card-reported buffer) must be caught inside
    // runWithChannelPtr, folded into the report as a transport failure, and
    // the cleanup (channel/token clear + reset) must still run.
    FakeChannel channel{pkcs15Aid(), ChannelState::Open, /*carriesSm=*/true};
    DeferredSessionFixture f;
    f.s->bound = true; // bind already done; fn is reached directly

    ChannelRunReport report;
    EXPECT_NO_THROW({
        report = LibreSCRS::OpenSc::runWithChannelPtr(
            *f.s, &channel, CancelToken{},
            [](OpenSCSession&) { throw std::runtime_error("bad_alloc-like failure inside fn"); }, kNoHolderRelease);
    });
    EXPECT_TRUE(report.ran);                       // fn WAS entered
    EXPECT_TRUE(report.bindFailed);                // folded into a transport-class failure
    EXPECT_FALSE(f.s->bound);                      // reset fired on the failure path
    EXPECT_EQ(f.s->bridge->data.channel, nullptr); // borrowed channel cleared
}

// ── Activation-error vocabulary (one test per table cell) ──────────────────

TEST(OpenscErrorVocabulary, ReadResultCells)
{
    using LibreSCRS::OpenSc::mapActivationErrorToReadResult;
    using Status = LibreSCRS::Plugin::ReadResult::Status;
    EXPECT_EQ(mapActivationErrorToReadResult(ChannelActivationError::Cancelled, "t").status, Status::Cancelled);
    EXPECT_EQ(mapActivationErrorToReadResult(ChannelActivationError::UserCancelled, "t").status, Status::Cancelled);
    EXPECT_EQ(mapActivationErrorToReadResult(ChannelActivationError::CredentialsRequired, "t").status,
              Status::AuthenticationFailed);
    EXPECT_EQ(mapActivationErrorToReadResult(ChannelActivationError::PaceWrongSecret, "t").status,
              Status::AuthenticationFailed);
    EXPECT_EQ(mapActivationErrorToReadResult(ChannelActivationError::CardRemoved, "t").status,
              Status::CommunicationError);
    EXPECT_EQ(mapActivationErrorToReadResult(ChannelActivationError::SelectAppletFailed, "t").status,
              Status::CommunicationError);
}

TEST(OpenscErrorVocabulary, PinOutcomeCells)
{
    using LibreSCRS::OpenSc::mapActivationErrorToPinOutcome;
    using Outcome = LibreSCRS::Plugin::PINResultOutcome;
    EXPECT_EQ(mapActivationErrorToPinOutcome(ChannelActivationError::Cancelled), Outcome::UserCancelled);
    EXPECT_EQ(mapActivationErrorToPinOutcome(ChannelActivationError::UserCancelled), Outcome::UserCancelled);
    EXPECT_EQ(mapActivationErrorToPinOutcome(ChannelActivationError::CredentialsRequired), Outcome::MissingFields);
    EXPECT_EQ(mapActivationErrorToPinOutcome(ChannelActivationError::PaceWrongSecret), Outcome::PluginError);
    EXPECT_EQ(mapActivationErrorToPinOutcome(ChannelActivationError::CardRemoved), Outcome::PluginError);
}

TEST(OpenscErrorVocabulary, SignOutcomeCells)
{
    using LibreSCRS::OpenSc::mapActivationErrorToSignOutcome;
    using Outcome = LibreSCRS::Plugin::SignResultOutcome;
    EXPECT_EQ(mapActivationErrorToSignOutcome(ChannelActivationError::Cancelled), Outcome::Cancelled);
    EXPECT_EQ(mapActivationErrorToSignOutcome(ChannelActivationError::UserCancelled), Outcome::Cancelled);
    EXPECT_EQ(mapActivationErrorToSignOutcome(ChannelActivationError::CredentialsRequired), Outcome::PluginError);
    EXPECT_EQ(mapActivationErrorToSignOutcome(ChannelActivationError::PaceWrongSecret), Outcome::PluginError);
}

TEST(OpenscErrorVocabulary, DecipherOutcomeCells)
{
    using LibreSCRS::OpenSc::mapActivationErrorToDecipherOutcome;
    using Outcome = LibreSCRS::Plugin::DecipherResultOutcome;
    EXPECT_EQ(mapActivationErrorToDecipherOutcome(ChannelActivationError::Cancelled), Outcome::Cancelled);
    EXPECT_EQ(mapActivationErrorToDecipherOutcome(ChannelActivationError::UserCancelled), Outcome::Cancelled);
    EXPECT_EQ(mapActivationErrorToDecipherOutcome(ChannelActivationError::CredentialsRequired), Outcome::PluginError);
    EXPECT_EQ(mapActivationErrorToDecipherOutcome(ChannelActivationError::PaceWrongSecret), Outcome::PluginError);
}

// ── Operation-level vocabulary integration ─────────────────────────────────

TEST(OpenscOperations, DeferredClaimWithoutChannelOrCanIsTyped)
{
    PluginHandle h;
    LiveSmSession live;

    // Claim under the live SM (deferred bind)…
    live.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
    ASSERT_TRUE(h.plugin->canHandleConnection(kTestAtr, *live.session));

    // …then the tunnel is gone before the first operation: activation now
    // cache-misses with no provider — CredentialsRequired, surfaced TYPED on
    // every operation shape (never collapsed into a generic plugin error).
    live.session->clearActiveChannel();

    const auto pinResult = h.plugin->verifyPIN(*live.session, LibreSCRS::Secure::String{"0000"});
    EXPECT_EQ(pinResult.outcome, LibreSCRS::Plugin::PINResultOutcome::MissingFields);

    const auto readResult = h.plugin->readCard(*live.session);
    EXPECT_EQ(readResult.status, LibreSCRS::Plugin::ReadResult::Status::AuthenticationFailed);

    const auto signResult = h.plugin->sign(*live.session, 0x47, std::vector<std::uint8_t>(32, 0xAB),
                                           LibreSCRS::Plugin::SignMechanism::RSA_PKCS);
    EXPECT_EQ(signResult.outcome, LibreSCRS::Plugin::SignResultOutcome::PluginError);

    // getPINList has no error channel: an activation failure yields the empty
    // list (the only representable outcome on this surface).
    EXPECT_TRUE(h.plugin->getPINList(*live.session).empty());
}

TEST(OpenscOperations, EcdsaInputOfAWrongLengthIsRefusedBeforeAnyChannelWork)
{
    PluginHandle h;
    LiveSmSession live;

    live.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
    ASSERT_TRUE(h.plugin->canHandleConnection(kTestAtr, *live.session));

    // The tunnel is gone, so any channel activation would ask the credential
    // provider; a request refused before that never reaches it.
    live.session->clearActiveChannel();
    live.channel = nullptr; // destroyed with the tunnel
    int providerCalls = 0;
    live.session->setCredentialProvider([&providerCalls](const LibreSCRS::Auth::AuthRequirement&) {
        ++providerCalls;
        return LibreSCRS::Auth::CredentialResult::cancelled();
    });

    const auto wrongLength = h.plugin->sign(*live.session, 0x47, std::vector<std::uint8_t>(20, 0xAB),
                                            LibreSCRS::Plugin::SignMechanism::ECDSA_SHA256);
    EXPECT_EQ(wrongLength.outcome, LibreSCRS::Plugin::SignResultOutcome::PluginError);
    EXPECT_EQ(providerCalls, 0) << "no channel activation for a SHA-1 length";

    // Control: the same session does activate for a well-formed request.
    (void)h.plugin->sign(*live.session, 0x47, std::vector<std::uint8_t>(32, 0xAB),
                         LibreSCRS::Plugin::SignMechanism::ECDSA_SHA256);
    EXPECT_GT(providerCalls, 0) << "the control must reach activation, or the assertion above proves nothing";
}

TEST(OpenscOperations, ClearCredentialsOnlyErasesTheMapEntry)
{
    PluginHandle h;
    LiveSmSession live;

    live.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
    ASSERT_TRUE(h.plugin->canHandleConnection(kTestAtr, *live.session));
    ASSERT_EQ(h.plugin->preReadAuth(*live.session), LibreSCRS::Auth::PreReadAuthMethod::Can);

    h.plugin->clearCredentials(*live.session);
    EXPECT_EQ(h.plugin->preReadAuth(*live.session), LibreSCRS::Auth::PreReadAuthMethod::None);
}

TEST(OpenscSessionOwnership, TeardownRunsAtLastOwnerRelease)
{
    // The plugin map holds shared_ptr<OpenSCSession>; an operation pins a
    // copy before any I/O. A probe/clearCredentials erase removes ONLY the
    // map entry — the libopensc teardown runs when the LAST owner (here: the
    // pinned copy) lets go, never under the map lock.
    LibreSCRS::OpenSc::PluginContext owner;
    ASSERT_NE(owner.context(), nullptr);
    auto mapEntry = std::make_shared<OpenSCSession>();
    mapEntry->readerName = "OwnershipReader";
    mapEntry->context = owner.lease();

    std::weak_ptr<OpenSCSession> watch = mapEntry;
    auto pinned = mapEntry; // the in-flight operation's pin
    mapEntry.reset();       // the map erase

    ASSERT_FALSE(watch.expired());
    EXPECT_NE(pinned->context.get(), nullptr); // still fully alive for the operation

    pinned.reset(); // operation completes — LAST owner runs the teardown
    EXPECT_TRUE(watch.expired());
}

// ── One OpenSC context per plugin instance ────────────────────────────────
//
// The plugin creates one OpenSC context for its whole lifetime and every
// session it claims shares it; a context established per probe and released
// per session was a context, a driver load and a configuration read for every
// card event. The counts are process-wide, so each test measures differences.

namespace {

LibreSCRS::OpenSc::ContextCounts contextCounts()
{
    return LibreSCRS::OpenSc::contextCountsForTest();
}

} // namespace

TEST(OpenscPluginContext, OnePluginEstablishesOneContextForManyProbes)
{
    const auto before = contextCounts();
    {
        PluginHandle h;
        LiveSmSession a("ContextReaderA");
        LiveSmSession b("ContextReaderB");
        a.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
        b.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };

        ASSERT_TRUE(h.plugin->canHandleConnection(kTestAtr, *a.session));
        ASSERT_TRUE(h.plugin->canHandleConnection(kTestAtr, *b.session));
        (void)h.plugin->readCard(*a.session);
        (void)h.plugin->readCard(*b.session);
        // A re-probe of the same reader starts a fresh claim, not a fresh context.
        ASSERT_TRUE(h.plugin->canHandleConnection(kTestAtr, *a.session));

        const auto during = contextCounts();
        EXPECT_EQ(during.created - before.created, 1u) << "one context for three probes and two operations";
        EXPECT_EQ(during.released - before.released, 0u) << "no context is released while the plugin lives";
    }
    const auto after = contextCounts();
    EXPECT_EQ(after.created - before.created, 1u);
    EXPECT_EQ(after.released - before.released, 1u) << "the plugin releases its context when it is destroyed";
}

TEST(OpenscPluginContext, NormalShutdownReleasesSessionsBeforeThePlugin)
{
    // The order a host shuts down in: the card sessions go first, the plugin
    // service last. Every OpenSC session is gone by the time the plugin is, so
    // the plugin releases its context exactly once and nothing stops the process.
    const auto before = contextCounts();
    auto h = std::make_unique<PluginHandle>();
    {
        LiveSmSession a("ShutdownReaderA");
        LiveSmSession b("ShutdownReaderB");
        a.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
        b.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
        ASSERT_TRUE(h->plugin->canHandleConnection(kTestAtr, *a.session));
        ASSERT_TRUE(h->plugin->canHandleConnection(kTestAtr, *b.session));
        (void)h->plugin->readCard(*a.session);
        h->plugin->clearCredentials(*a.session);
    }
    EXPECT_EQ(contextCounts().released - before.released, 0u);
    h.reset();
    const auto after = contextCounts();
    EXPECT_EQ(after.created - before.created, 1u);
    EXPECT_EQ(after.released - before.released, 1u);
}

TEST(OpenscPluginContext, AThousandProbesOnOneContextLeakNothing)
{
    // Each probe claims the reader afresh and drops the previous claim; under
    // a leak checker every one of the thousand dropped sessions must have
    // given back its bridge and its lease, and the plugin still holds one
    // context.
    const auto before = contextCounts();
    {
        PluginHandle h;
        LiveSmSession live("ThousandProbesReader");
        live.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
        for (int i = 0; i < 1000; ++i)
            ASSERT_TRUE(h.plugin->canHandleConnection(kTestAtr, *live.session)) << "probe " << i;
        EXPECT_EQ(live.channel->transmits(), 1000) << "every probe reached the card";
        EXPECT_EQ(contextCounts().created - before.created, 1u);
    }
    EXPECT_EQ(contextCounts().released - before.released, 1u);
}

TEST(OpenscPluginContext, TwoReadersWorkConcurrentlyOnTheSharedContext)
{
    // Each reader has its own worker thread, and both now drive libopensc
    // through the one context: claims, binds and disconnects of the two
    // readers interleave on it. Run under a thread sanitizer this is the
    // case the context's thread callbacks exist for.
    PluginHandle h;
    LiveSmSession a("ConcurrentReaderA");
    LiveSmSession b("ConcurrentReaderB");
    a.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };
    b.channel->transmitHandler = [](const APDUCommand&) { return sw(0x90, 0x00); };

    std::atomic<int> claims{0};
    auto worker = [&](LiveSmSession& live) {
        for (int i = 0; i < 100; ++i) {
            if (h.plugin->canHandleConnection(kTestAtr, *live.session))
                ++claims;
            (void)h.plugin->readCard(*live.session);
            h.plugin->clearCredentials(*live.session);
        }
    };
    std::thread ta(worker, std::ref(a));
    std::thread tb(worker, std::ref(b));
    ta.join();
    tb.join();
    EXPECT_EQ(claims.load(), 200);
}

TEST(OpenscPluginContextDeathTest, ASessionThatOutlivesItsPluginStopsTheProcess)
{
    // A session the plugin no longer holds can still be pinned elsewhere: an
    // operation abandoned while stuck in a transmit keeps its session when the
    // process shuts down. Its plugin's context is gone by then, so the plugin
    // stops the process instead of letting that session reach freed memory.
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_DEATH(
        {
            auto owner = std::make_unique<LibreSCRS::OpenSc::PluginContext>();
            if (!owner->context())
                std::_Exit(0); // no context, nothing to prove: the death assertion then fails
            auto session = std::make_shared<OpenSCSession>();
            session->context = owner->lease();
            owner.reset();
        },
        "outlived the plugin");
}

// ── EC surface: mechanism-family key filter, lengths, family mapping ───────

TEST(OpenscEcSurface, ReferenceCollisionResolvesByMechanismFamily)
{
    // Same key reference on an RSA and an EC key (references are only
    // unique within a family on some cards); three objects, the target in
    // the MIDDLE, so a first-match or off-by-one bug cannot pass.
    sc_pkcs15_prkey_info_t rsaOther{};
    rsaOther.key_reference = 0x46;
    rsaOther.modulus_length = 3072;
    sc_pkcs15_object_t rsaOtherObj{};
    rsaOtherObj.type = SC_PKCS15_TYPE_PRKEY_RSA;
    rsaOtherObj.data = &rsaOther;

    sc_pkcs15_prkey_info_t ecInfo{};
    ecInfo.key_reference = 0x47;
    ecInfo.field_length = 384;
    sc_pkcs15_object_t ecObj{};
    ecObj.type = SC_PKCS15_TYPE_PRKEY_EC;
    ecObj.data = &ecInfo;

    sc_pkcs15_prkey_info_t rsaInfo{};
    rsaInfo.key_reference = 0x47;
    rsaInfo.modulus_length = 3072;
    sc_pkcs15_object_t rsaObj{};
    rsaObj.type = SC_PKCS15_TYPE_PRKEY_RSA;
    rsaObj.data = &rsaInfo;

    sc_pkcs15_object_t* objs[] = {&rsaOtherObj, &ecObj, &rsaObj};

    EXPECT_EQ(LibreSCRS::OpenSc::selectKeyByReferenceAndType(objs, 3, 0x47, SC_PKCS15_TYPE_PRKEY_EC), &ecObj);
    EXPECT_EQ(LibreSCRS::OpenSc::selectKeyByReferenceAndType(objs, 3, 0x47, SC_PKCS15_TYPE_PRKEY_RSA), &rsaObj);
    EXPECT_EQ(LibreSCRS::OpenSc::selectKeyByReferenceAndType(objs, 3, 0x46, SC_PKCS15_TYPE_PRKEY_RSA), &rsaOtherObj);
    EXPECT_EQ(LibreSCRS::OpenSc::selectKeyByReferenceAndType(objs, 3, 0x46, SC_PKCS15_TYPE_PRKEY_EC), nullptr);
    EXPECT_EQ(LibreSCRS::OpenSc::selectKeyByReferenceAndType(objs, 3, 0x48, SC_PKCS15_TYPE_PRKEY_EC), nullptr);
}

TEST(OpenscEcSurface, EcdsaSignatureLengthIsTwiceCeilFieldBytes)
{
    // 2*ceil(field/8), NEVER an RSA modulus idiom: 96 for P-384 even though
    // a 3072-bit RSA modulus on the same card would suggest 384.
    EXPECT_EQ(LibreSCRS::OpenSc::ecdsaSignatureLength(384), 96u);
    EXPECT_EQ(LibreSCRS::OpenSc::ecdsaSignatureLength(256), 64u);
    EXPECT_EQ(LibreSCRS::OpenSc::ecdsaSignatureLength(521), 132u); // P-521: 2*ceil(521/8)=2*66
}

TEST(OpenscEcSurface, KeySizeBitsComesFromModulusOrFieldLength)
{
    sc_pkcs15_prkey_info_t rsaInfo{};
    rsaInfo.modulus_length = 3072;
    EXPECT_EQ(LibreSCRS::OpenSc::keySizeBitsFromKeyInfo(rsaInfo), 3072);

    sc_pkcs15_prkey_info_t ecInfo{};
    ecInfo.field_length = 384;
    EXPECT_EQ(LibreSCRS::OpenSc::keySizeBitsFromKeyInfo(ecInfo), 384);
}

// OpenSC's own reading of PKCS#15 userConsent -- the one its PKCS#11 framework
// turns into CKA_ALWAYS_AUTHENTICATE, and the one the plugin and the slot share.
TEST(OpenscUserConsent, PerOperationAuthIsOpenScsOwnRule)
{
    sc_pkcs15_object_t object{};
    EXPECT_FALSE(LibreSCRS::OpenSc::requiresPerOperationAuth(object));
    object.user_consent = 1; // what the PIV emulator sets on the Digital Signature key (9C)
    EXPECT_TRUE(LibreSCRS::OpenSc::requiresPerOperationAuth(object));
    object.user_consent = 3;
    EXPECT_TRUE(LibreSCRS::OpenSc::requiresPerOperationAuth(object));
}

TEST(OpenscEcSurface, DriverShortNameMapsToQuirkFamily)
{
    using LibreSCRS::Plugin::Internal::FamilyId;
    EXPECT_EQ(LibreSCRS::OpenSc::familyFromDriverShortName("srbeid2"), FamilyId::AppletSuiteGen2);
    EXPECT_EQ(LibreSCRS::OpenSc::familyFromDriverShortName("srbeid"), FamilyId::CurrentLkCardEdge);
    EXPECT_EQ(LibreSCRS::OpenSc::familyFromDriverShortName("PIV-II"), FamilyId::Piv);
    EXPECT_EQ(LibreSCRS::OpenSc::familyFromDriverShortName(nullptr), FamilyId::Unknown);
    EXPECT_EQ(LibreSCRS::OpenSc::familyFromDriverShortName("cardos"), FamilyId::Unknown);
}

// ── EC key agreement and ECDSA: everything refusable is refused off-card ───

struct EcKeyObject
{
    explicit EcKeyObject(std::size_t fieldLengthBits, int userConsent = 0)
    {
        info.field_length = fieldLengthBits;
        info.usage = SC_PKCS15_PRKEY_USAGE_DERIVE | SC_PKCS15_PRKEY_USAGE_SIGN;
        object.type = SC_PKCS15_TYPE_PRKEY_EC;
        object.user_consent = userConsent;
        object.data = &info;
    }
    EcKeyObject(const EcKeyObject&) = delete;
    EcKeyObject& operator=(const EcKeyObject&) = delete;

    sc_pkcs15_prkey_info_t info{};
    sc_pkcs15_object_t object{};
};

std::vector<std::uint8_t> uncompressedPoint(std::size_t fieldBytes)
{
    std::vector<std::uint8_t> point(1 + 2 * fieldBytes, 0x3C);
    point[0] = 0x04;
    return point;
}

// What the card's driver advertises for an EC key of that field: raw ECDH.
constexpr unsigned long kCardEcdh = SC_ALGORITHM_ECDH_CDH_RAW;

TEST(OpenscEcSurface, CanDeriveNeedsAnEcKeyTheDeriveBitAFieldLengthAndTheCardsEcdh)
{
    using LibreSCRS::OpenSc::canDeriveWith;
    EcKeyObject key(384);
    EXPECT_TRUE(canDeriveWith(key.object, kCardEcdh));
    EXPECT_FALSE(canDeriveWith(key.object, SC_ALGORITHM_ECDSA_RAW))
        << "the driver signs with the key but has no ECDH: derive would fail after the PIN";
    EXPECT_FALSE(canDeriveWith(key.object, 0)) << "no algorithm for this field on the card";

    key.info.usage = SC_PKCS15_PRKEY_USAGE_SIGN;
    EXPECT_FALSE(canDeriveWith(key.object, kCardEcdh)) << "no derive bit";

    key.info.usage = SC_PKCS15_PRKEY_USAGE_DERIVE;
    key.info.field_length = 0;
    EXPECT_FALSE(canDeriveWith(key.object, kCardEcdh)) << "no field length: no buffer, no curve width";

    key.info.field_length = 384;
    key.object.type = SC_PKCS15_TYPE_PRKEY_RSA;
    EXPECT_FALSE(canDeriveWith(key.object, kCardEcdh)) << "not an EC key";
}

TEST(OpenscEcSurface, NoCardAdvertisesNothing)
{
    EXPECT_EQ(LibreSCRS::OpenSc::ecAlgorithmFlags(nullptr, 384), 0UL);
}

// sc_card_find_ec_alg reads only the card's algorithm table: one entry per
// field length, and the flags are that entry's -- the same lookup the derive
// and sign paths make.
TEST(OpenscEcSurface, FlagsComeFromTheEntryForTheKeysField)
{
    sc_algorithm_info_t algorithms[3]{};
    algorithms[0].algorithm = SC_ALGORITHM_RSA;
    algorithms[0].key_length = 384;
    algorithms[0].flags = SC_ALGORITHM_RSA_RAW;
    algorithms[1].algorithm = SC_ALGORITHM_EC;
    algorithms[1].key_length = 256;
    algorithms[1].flags = SC_ALGORITHM_ECDSA_RAW;
    algorithms[2].algorithm = SC_ALGORITHM_EC;
    algorithms[2].key_length = 384;
    algorithms[2].flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW;
    sc_card_t card{};
    card.algorithms = algorithms;
    card.algorithm_count = 3;

    using LibreSCRS::OpenSc::ecAlgorithmFlags;
    EXPECT_EQ(ecAlgorithmFlags(&card, 384),
              static_cast<unsigned long>(SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW));
    EXPECT_EQ(ecAlgorithmFlags(&card, 256), static_cast<unsigned long>(SC_ALGORITHM_ECDSA_RAW));
    EXPECT_EQ(ecAlgorithmFlags(&card, 521), 0UL) << "no entry for that field";
    EXPECT_EQ(ecAlgorithmFlags(&card, 0), 0UL) << "no field length";

    EcKeyObject key(384);
    EXPECT_TRUE(LibreSCRS::OpenSc::canDeriveWith(key.object, ecAlgorithmFlags(&card, 384)));
    key.info.field_length = 256;
    EXPECT_FALSE(LibreSCRS::OpenSc::canDeriveWith(key.object, ecAlgorithmFlags(&card, 256)))
        << "the driver signs over P-256 but has no ECDH there";
}

// ECDH_RAW is a mechanism decipher knows: without a bound session it fails as
// any key operation does, not as NotImplemented. (Where it is routed is not
// proved here.)
TEST(OpenscEcdh, EcdhRawIsNotRefusedAsAnUnknownMechanism)
{
    PluginHandle h;
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("ChannelTestReader");
    using LibreSCRS::Plugin::DecipherMechanism;
    using LibreSCRS::Plugin::DecipherResultOutcome;
    const auto point = uncompressedPoint(48);

    EXPECT_EQ(h.plugin->decipher(*session, 0x01, point, DecipherMechanism::ECDH_RAW).outcome,
              DecipherResultOutcome::PluginError);
    EXPECT_EQ(h.plugin->decipher(*session, 0x01, point, static_cast<DecipherMechanism>(0x7F)).outcome,
              DecipherResultOutcome::NotImplemented)
        << "a mechanism this plugin does not know";
}

// 04 opens both the raw point and its DER OCTET STRING wrapper (04 61 04 ...),
// so length decides; 02/03 are compressed points, 00 is the point at infinity.
TEST(OpenscEcSurface, PeerPointMustBeUncompressedOfTheKeysWidth)
{
    using LibreSCRS::OpenSc::isUncompressedPeerPoint;
    EXPECT_TRUE(isUncompressedPeerPoint(uncompressedPoint(48), 384));
    EXPECT_TRUE(isUncompressedPeerPoint(uncompressedPoint(32), 256));
    EXPECT_TRUE(isUncompressedPeerPoint(uncompressedPoint(66), 521)) << "133 bytes for P-521";

    EXPECT_FALSE(isUncompressedPeerPoint(uncompressedPoint(32), 384)) << "another curve's width";
    auto wrapped = uncompressedPoint(48);
    wrapped.insert(wrapped.begin(), {0x04, 0x61});
    EXPECT_FALSE(isUncompressedPeerPoint(wrapped, 384)) << "DER-wrapped point";
    for (const std::uint8_t lead : {std::uint8_t{0x02}, std::uint8_t{0x03}, std::uint8_t{0x00}}) {
        auto point = uncompressedPoint(48);
        point[0] = lead;
        EXPECT_FALSE(isUncompressedPeerPoint(point, 384)) << "leading byte " << static_cast<int>(lead);
    }
    EXPECT_FALSE(isUncompressedPeerPoint(std::vector<std::uint8_t>{0x00}, 384));
    EXPECT_FALSE(isUncompressedPeerPoint(uncompressedPoint(48), 0)) << "no field length";
}

TEST(OpenscEcdh, DerivesWithCdhRawIntoAFieldWideBuffer)
{
    EcKeyObject key(384);
    OpenSCSession session;
    const auto point = uncompressedPoint(48);
    unsigned long seenFlags = 0;
    std::size_t seenCapacity = 0;
    std::vector<std::uint8_t> seenIn;
    LibreSCRS::Plugin::DecipherResult result;

    const auto refused =
        LibreSCRS::OpenSc::deriveEcdhBound(session, key.object, kCardEcdh, point, result,
                                           [&](unsigned long flags, const std::uint8_t* in, std::size_t inLength,
                                               std::uint8_t* out, std::size_t* outLength) {
                                               seenFlags = flags;
                                               seenCapacity = *outLength;
                                               seenIn.assign(in, in + inLength);
                                               std::fill_n(out, 48, std::uint8_t{0xC3});
                                               *outLength = 48;
                                               return 48;
                                           });

    EXPECT_FALSE(refused.has_value());
    EXPECT_EQ(seenFlags, static_cast<unsigned long>(SC_ALGORITHM_ECDH_CDH_RAW))
        << "the flag OpenSC's own C_DeriveKey passes";
    EXPECT_EQ(seenCapacity, 48U) << "a smaller buffer is a size query that never asks the card";
    EXPECT_EQ(seenIn, point);
    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.plaintext, std::vector<std::uint8_t>(48, 0xC3));
}

TEST(OpenscEcdh, BadPointOrUnknownFieldNeverReachesTheCard)
{
    OpenSCSession session;
    bool called = false;
    const auto derive = [&](unsigned long, const std::uint8_t*, std::size_t, std::uint8_t*, std::size_t*) {
        called = true;
        return 48;
    };

    EcKeyObject key(384);
    auto compressed = uncompressedPoint(48);
    compressed[0] = 0x02;
    LibreSCRS::Plugin::DecipherResult result;
    EXPECT_FALSE(
        LibreSCRS::OpenSc::deriveEcdhBound(session, key.object, kCardEcdh, compressed, result, derive).has_value());
    EXPECT_FALSE(called);
    EXPECT_FALSE(result.ok());

    EcKeyObject unknownField(0);
    EXPECT_FALSE(LibreSCRS::OpenSc::deriveEcdhBound(session, unknownField.object, kCardEcdh, uncompressedPoint(48),
                                                    result, derive)
                     .has_value());
    EXPECT_FALSE(called) << "no field length: refused before the card";
    EXPECT_FALSE(result.ok());
}

// sc_pkcs15_derive answers 0 for a size query and for a key the card keeps
// on board: no secret came back, so it is never a result.
TEST(OpenscEcdh, SizeQueryOrShortSecretIsNeverOk)
{
    struct Answer
    {
        int rc;
        std::size_t length;
    };
    for (const auto answer : {Answer{0, 48}, Answer{47, 47}, Answer{-1, 48}}) {
        SCOPED_TRACE(answer.rc);
        EcKeyObject key(384);
        OpenSCSession session;
        LibreSCRS::Plugin::DecipherResult result;
        (void)LibreSCRS::OpenSc::deriveEcdhBound(
            session, key.object, kCardEcdh, uncompressedPoint(48), result,
            [&](unsigned long, const std::uint8_t*, std::size_t, std::uint8_t*, std::size_t* outLength) {
                *outLength = answer.length;
                return answer.rc;
            });
        EXPECT_FALSE(result.ok());
        EXPECT_TRUE(result.plaintext.empty());
    }
}

TEST(OpenscEcdh, PerOperationKeyWithoutAPinNeverDerives)
{
    EcKeyObject key(384, /*userConsent=*/1);
    OpenSCSession session; // no PIN deposited
    bool called = false;
    LibreSCRS::Plugin::DecipherResult result;

    const auto refused = LibreSCRS::OpenSc::deriveEcdhBound(
        session, key.object, kCardEcdh, uncompressedPoint(48), result,
        [&](unsigned long, const std::uint8_t*, std::size_t, std::uint8_t*, std::size_t*) {
            called = true;
            return 48;
        });

    EXPECT_FALSE(called);
    ASSERT_TRUE(refused.has_value());
    EXPECT_EQ(LibreSCRS::OpenSc::decipherOutcomeForRefusedPin(refused->rc),
              LibreSCRS::Plugin::DecipherResultOutcome::PluginError);
}

// The derive runs inside runUnderChannel's card transaction, where the
// deposited PIN's VERIFY runs too (OpenscOperationPin above).
TEST(OpenscEcdh, DeriveRunsInsideTheCardTransaction)
{
    auto cardSession = LibreSCRS::SmartCard::detail::makeDetachedCardSession("ChannelTestReader");
    RawSessionFixture f;
    EcKeyObject key(384);
    bool held = false;
    LibreSCRS::Plugin::DecipherResult result;

    (void)LibreSCRS::OpenSc::runUnderChannel(*cardSession, *f.s, CancelToken{}, [&](OpenSCSession& s) {
        (void)LibreSCRS::OpenSc::deriveEcdhBound(
            s, key.object, kCardEcdh, uncompressedPoint(48), result,
            [&](unsigned long, const std::uint8_t*, std::size_t, std::uint8_t* out, std::size_t* outLength) {
                held = f.conn.isTransactionHeld();
                std::fill_n(out, *outLength, std::uint8_t{0x5A});
                return static_cast<int>(*outLength);
            });
    });

    EXPECT_TRUE(held);
    EXPECT_TRUE(result.ok());
}

// A key the card does not let derive, or a card whose driver has no raw ECDH
// for the key's field, is refused before the PIN rule: for this per-operation
// key without a PIN that rule would answer RefusedPin, and with a PIN it
// would spend a try on an operation that cannot run.
TEST(OpenscEcdh, KeyTheCardCannotDeriveWithNeverReachesThePin)
{
    OpenSCSession session; // no PIN deposited
    bool called = false;
    const auto derive = [&](unsigned long, const std::uint8_t*, std::size_t, std::uint8_t*, std::size_t*) {
        called = true;
        return 48;
    };
    LibreSCRS::Plugin::DecipherResult result;

    EcKeyObject signOnly(384, /*userConsent=*/1);
    signOnly.info.usage = SC_PKCS15_PRKEY_USAGE_SIGN;
    EXPECT_FALSE(
        LibreSCRS::OpenSc::deriveEcdhBound(session, signOnly.object, kCardEcdh, uncompressedPoint(48), result, derive)
            .has_value())
        << "no derive bit";

    EcKeyObject key(384, /*userConsent=*/1);
    EXPECT_FALSE(LibreSCRS::OpenSc::deriveEcdhBound(session, key.object, SC_ALGORITHM_ECDSA_RAW, uncompressedPoint(48),
                                                    result, derive)
                     .has_value())
        << "no raw ECDH on the card";

    EXPECT_FALSE(called);
    EXPECT_FALSE(result.ok());
}

TEST(OpenscEcdsa, UnknownFieldLengthOrNonHashNeverSigns)
{
    OpenSCSession session;
    bool called = false;
    const auto compute = [&](unsigned long, const std::uint8_t*, std::size_t, std::uint8_t*, std::size_t) {
        called = true;
        return 96;
    };
    LibreSCRS::Plugin::SignResult result;

    EcKeyObject unknownField(0);
    (void)LibreSCRS::OpenSc::signEcdsaBound(session, unknownField.object, std::vector<std::uint8_t>(48, 0x01), result,
                                            compute);
    EXPECT_FALSE(called) << "the buffer would be empty";

    EcKeyObject key(384);
    (void)LibreSCRS::OpenSc::signEcdsaBound(session, key.object, std::vector<std::uint8_t>(20, 0x01), result, compute);
    EXPECT_FALSE(called) << "a SHA-1 length is no ECDSA_SHA* input";
    EXPECT_FALSE(result.ok());
}

TEST(OpenscEcdsa, SignsTheHashIntoAFixedWidthBuffer)
{
    EcKeyObject key(384);
    OpenSCSession session;
    unsigned long seenFlags = 0;
    std::size_t seenCapacity = 0;
    LibreSCRS::Plugin::SignResult result;

    (void)LibreSCRS::OpenSc::signEcdsaBound(
        session, key.object, std::vector<std::uint8_t>(48, 0x01), result,
        [&](unsigned long flags, const std::uint8_t*, std::size_t, std::uint8_t* out, std::size_t outLength) {
            seenFlags = flags;
            seenCapacity = outLength;
            std::fill_n(out, outLength, std::uint8_t{0x77});
            return static_cast<int>(outLength);
        });

    EXPECT_EQ(seenFlags, static_cast<unsigned long>(SC_ALGORITHM_ECDSA_HASH_NONE));
    EXPECT_EQ(seenCapacity, 96U);
    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.signature.size(), 96U);
}

// A driver writes the fixed-width r || s into the whole buffer and returns
// either its length or 0 (OpenSC's C_Sign reads 0 as "the whole buffer"; EDO
// answers so). Any other positive count is not the contract's r || s, and is
// never returned -- even over a filled buffer.
TEST(OpenscEcdsa, SignatureOfAnotherLengthIsNeverOk)
{
    for (const int rc : {48, 95, 97}) {
        SCOPED_TRACE(rc);
        EcKeyObject key(384);
        OpenSCSession session;
        LibreSCRS::Plugin::SignResult result;

        (void)LibreSCRS::OpenSc::signEcdsaBound(
            session, key.object, std::vector<std::uint8_t>(48, 0x01), result,
            [&](unsigned long, const std::uint8_t*, std::size_t, std::uint8_t* out, std::size_t outLength) {
                std::fill_n(out, outLength, std::uint8_t{0x77});
                return rc;
            });

        EXPECT_FALSE(result.ok());
        EXPECT_TRUE(result.signature.empty());
    }
}

TEST(OpenscEcdsa, ZeroReturnOverAFilledBufferIsTheSignature)
{
    EcKeyObject key(384);
    OpenSCSession session;
    LibreSCRS::Plugin::SignResult result;

    (void)LibreSCRS::OpenSc::signEcdsaBound(
        session, key.object, std::vector<std::uint8_t>(48, 0x01), result,
        [&](unsigned long, const std::uint8_t*, std::size_t, std::uint8_t* out, std::size_t outLength) {
            std::fill_n(out, outLength, std::uint8_t{0x77});
            return 0;
        });

    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.signature, std::vector<std::uint8_t>(96, 0x77));
}

// The buffer starts zeroed and neither r nor s of a signature is ever 0, so
// an all-zero half means the driver did not write it -- whatever it returned.
TEST(OpenscEcdsa, HalfTheDriverDidNotWriteIsNeverASignature)
{
    struct Answer
    {
        int rc;
        std::size_t from;
        std::size_t count;
    };
    for (const auto answer :
         {Answer{0, 0, 0}, Answer{0, 0, 48}, Answer{0, 48, 48}, Answer{96, 0, 48}, Answer{96, 48, 48}}) {
        SCOPED_TRACE(testing::Message() << answer.rc << " " << answer.from << "+" << answer.count);
        EcKeyObject key(384);
        OpenSCSession session;
        LibreSCRS::Plugin::SignResult result;

        (void)LibreSCRS::OpenSc::signEcdsaBound(
            session, key.object, std::vector<std::uint8_t>(48, 0x01), result,
            [&](unsigned long, const std::uint8_t*, std::size_t, std::uint8_t* out, std::size_t) {
                std::fill_n(out + answer.from, answer.count, std::uint8_t{0x77});
                return answer.rc;
            });

        EXPECT_FALSE(result.ok());
        EXPECT_TRUE(result.signature.empty());
    }
}

} // namespace
