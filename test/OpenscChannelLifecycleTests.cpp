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

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>

#include <apdu.h>
#include <fake_channel.h>
#include <pcsc_connection.h>

#include "opensc_reader_bridge.h"
#include "opensc_session.h"

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
/// does: real sc_context + bridge bound to a detached connection,
/// requiresPace set, bind deferred.
struct DeferredSessionFixture
{
    DeferredSessionFixture()
    {
        s = std::make_shared<OpenSCSession>();
        s->readerName = "ChannelTestReader";
        if (sc_establish_context(&s->ctx, "librescrs-lifecycle-test") != 0)
            std::abort();
        s->bridge = std::make_unique<LibreSCRS::OpenSc::Bridge::OpenScBridge>();
        s->bridge->data.conn = &conn;
        s->bridge->readerName = s->readerName;
        LibreSCRS::OpenSc::Bridge::initBridgeReader(s->ctx, *s->bridge, kTestAtr);
        s->requiresPace = true;
    }

    PCSCConnection conn{PCSCConnection::DetachedTag{}, "ChannelTestReader"};
    std::shared_ptr<OpenSCSession> s;
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
    EXPECT_NE(f.s->ctx, nullptr);
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
    EXPECT_NE(f.s->ctx, nullptr);      // partial teardown never touches ctx
    EXPECT_NE(f.s->bridge, nullptr);   // nor the bridge
    EXPECT_GT(channel.transmits(), 0); // the bind DID ride the tunnel

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
    EXPECT_NE(f.s->ctx, nullptr);
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
    auto mapEntry = std::make_shared<OpenSCSession>();
    mapEntry->readerName = "OwnershipReader";
    ASSERT_EQ(sc_establish_context(&mapEntry->ctx, "librescrs-lifecycle-test"), 0);

    std::weak_ptr<OpenSCSession> watch = mapEntry;
    auto pinned = mapEntry; // the in-flight operation's pin
    mapEntry.reset();       // the map erase

    ASSERT_FALSE(watch.expired());
    EXPECT_NE(pinned->ctx, nullptr); // still fully alive for the operation

    pinned.reset(); // operation completes — LAST owner runs the teardown
    EXPECT_TRUE(watch.expired());
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

TEST(OpenscEcSurface, DriverShortNameMapsToQuirkFamily)
{
    using LibreSCRS::Plugin::Internal::FamilyId;
    EXPECT_EQ(LibreSCRS::OpenSc::familyFromDriverShortName("srbeid2"), FamilyId::AppletSuiteGen2);
    EXPECT_EQ(LibreSCRS::OpenSc::familyFromDriverShortName("srbeid"), FamilyId::CurrentLkCardEdge);
    EXPECT_EQ(LibreSCRS::OpenSc::familyFromDriverShortName("PIV-II"), FamilyId::Piv);
    EXPECT_EQ(LibreSCRS::OpenSc::familyFromDriverShortName(nullptr), FamilyId::Unknown);
    EXPECT_EQ(LibreSCRS::OpenSc::familyFromDriverShortName("cardos"), FamilyId::Unknown);
}

} // namespace
