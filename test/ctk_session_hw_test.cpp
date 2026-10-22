// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Hardware checks of the CryptoTokenKit body of the connection on macOS: one
// exclusive TKSmartCard session held for the life of the connection.
//
// What is checked, against real cards and readers:
//   - secure messaging survives a long idle held session, and a second client
//     (CryptoTokenKit or PC/SC, another process) cannot take the card away;
//   - a ctkd restart, sleep/wake and card removal surface as mapped PC/SC
//     codes in bounded time, and the connection recovers where it can;
//   - what ending and beginning the session does to the card's state;
//   - extended-length APDUs through secure messaging, the OpenSC bridge,
//     and how the two length options of TKSmartCard behave per card;
//   - a held session on one reader does not delay another reader;
//   - the ATR CryptoTokenKit reports equals the one PC/SC reports.
//
// Every case skips unless LIBRESCRS_HW_CTK=1, so ctest reports them Skipped.
// No case skips after a failure: ctest reads any "[  SKIPPED ]" in the output
// as Skipped, which would hide the failure.
// They are meant to be run one at a time by the person at the readers:
//
//   LIBRESCRS_HW_CTK=1 ./CtkSessionHardwareTests --gtest_filter=CtkSessionHardware.<Case>
//
// Card safety:
//   - a card is chosen only by the prefix of its ATR, read without a session;
//     a slot whose ATR matches no test-card prefix never gets a session;
//   - CAN from LIBRESCRS_TEST_CAN, PIN from LIBRESCRS_TEST_PIN, never in
//     source; a PIN is presented only when the retry counter reads full, and
//     the first refusal stops the suite (three refusals block the card).
//
// Steps that need a person (ctkd restart, sleep, removal, another client) wait
// on stdin for Enter, for at most LIBRESCRS_HW_CTK_WAIT_SECONDS (default 600);
// end of input or the timeout skips the case, so the binary never hangs.
//
// Measurements go to stderr as single lines starting with "CTKHW ".

#include "ctk_hw_probe.h"
#include "pin_guard.h"
#include "signature_verify.h"

#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SmartCard/ActiveChannelHolderInternal.h>

#include <pcsc_connection.h>

#include <gtest/gtest.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

extern char** environ;

namespace {

namespace CtkHw = LibreSCRS::Tests::CtkHw;
using LibreSCRS::SmartCard::ActiveChannelHolder;
using LibreSCRS::SmartCard::AppletAid;
using LibreSCRS::SmartCard::CardSession;
using LibreSCRS::SmartCard::Internal::APDUCommand;
using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Internal::PCSCConnection;
using LibreSCRS::SmartCard::Internal::PCSCError;
using LibreSCRS::Tests::E2E::markPinFailedAndAbort;
using Clock = std::chrono::steady_clock;

// --- environment -------------------------------------------------------------

std::optional<std::string> envOpt(const char* name)
{
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0')
        return std::nullopt;
    return std::string(value);
}

long envLong(const char* name, long fallback)
{
    const auto value = envOpt(name);
    if (!value)
        return fallback;
    char* end = nullptr;
    const long parsed = std::strtol(value->c_str(), &end, 0);
    return end != nullptr && *end == '\0' ? parsed : fallback;
}

std::vector<std::string> splitList(const std::string& text)
{
    std::vector<std::string> items;
    std::stringstream stream(text);
    std::string item;
    while (std::getline(stream, item, ','))
        if (!item.empty())
            items.push_back(item);
    return items;
}

// --- formatting and logging ----------------------------------------------------

std::string hex(std::span<const std::uint8_t> bytes)
{
    static constexpr char kDigits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out.push_back(kDigits[(b >> 4) & 0x0F]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

std::string hex4(std::uint16_t value)
{
    const std::uint8_t bytes[] = {static_cast<std::uint8_t>(value >> 8), static_cast<std::uint8_t>(value)};
    return hex(bytes);
}

std::string pcscCode(long code)
{
    char buffer[16];
    std::snprintf(buffer, sizeof buffer, "0x%08lX", static_cast<unsigned long>(code) & 0xFFFFFFFFUL);
    return buffer;
}

std::string upper(std::string text)
{
    for (auto& c : text)
        if (c >= 'a' && c <= 'f')
            c = static_cast<char>(c - 'a' + 'A');
    return text;
}

// One measurement line: "CTKHW <case> key=value ...".
void record(const std::string& line)
{
    std::fprintf(stderr, "CTKHW %s\n", line.c_str());
    std::fflush(stderr);
}

double msSince(Clock::time_point start)
{
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

std::string fixed(double value)
{
    char buffer[32];
    std::snprintf(buffer, sizeof buffer, "%.3f", value);
    return buffer;
}

// --- test cards, chosen by ATR prefix only -------------------------------------

// Prefixes of the test cards (upper-case hex). An environment variable of the
// role's name replaces the defaults with a comma-separated list.
struct CardRole
{
    const char* name;
    const char* envOverride;
    std::vector<std::string> defaults;
};

constexpr const char* kLkContact = "3BDE97008031FE4553434520382E302D43325630"; // test LK, contact (SCE 8.0-C2V0)
constexpr const char* kLkContactless = "3B8D80015352422D6549442D56322E3030";   // test LK, contactless (SRB-eID-V2.00)
constexpr const char* kGeoContactless = "3B8E800153434520382E302D43325630";    // GEO test card, contactless
constexpr const char* kGeoContact = "3B9E968031FE4553434520382E302D43325630";  // GEO test card, contact

// A card with PACE (CAN) and an eMRTD applet, reached contactless.
const CardRole kPaceCard{"pace", "LIBRESCRS_HW_CTK_ATR_PACE", {kLkContactless, kGeoContactless}};
// The test LK on the contact interface: no PACE, PIN on the card.
const CardRole kLkContactCard{"lk-contact", "LIBRESCRS_HW_CTK_ATR_LK_CONTACT", {kLkContact}};
// The test LK on the contactless interface.
const CardRole kLkContactlessCard{"lk-contactless", "LIBRESCRS_HW_CTK_ATR_LK_CONTACTLESS", {kLkContactless}};
// A contact card whose eMRTD applet reads without secure messaging.
const CardRole kPlainCard{"plain", "LIBRESCRS_HW_CTK_ATR_PLAIN", {kLkContact, kGeoContact}};
// The card in the second physical reader.
const CardRole kSecondReaderCard{"second-reader", "LIBRESCRS_HW_CTK_ATR_B", {kGeoContact}};

std::vector<std::string> prefixesOf(const CardRole& role)
{
    if (const auto override = envOpt(role.envOverride)) {
        std::vector<std::string> prefixes;
        for (const auto& item : splitList(*override))
            prefixes.push_back(upper(item));
        return prefixes;
    }
    return role.defaults;
}

// Every prefix of every role: what counts as a test card at all.
std::vector<std::string> allTestPrefixes()
{
    std::vector<std::string> all;
    for (const auto* role : {&kPaceCard, &kLkContactCard, &kLkContactlessCard, &kPlainCard, &kSecondReaderCard})
        for (const auto& prefix : prefixesOf(*role))
            if (std::find(all.begin(), all.end(), prefix) == all.end())
                all.push_back(prefix);
    return all;
}

bool atrHasPrefix(std::span<const std::uint8_t> atr, std::string_view hexPrefix)
{
    const auto atrHex = hex(atr);
    return !hexPrefix.empty() && atrHex.size() >= hexPrefix.size() &&
           atrHex.compare(0, hexPrefix.size(), hexPrefix) == 0;
}

/// The first slot holding a valid card whose ATR, read without a session,
/// starts with @p hexPrefix.
std::optional<std::string> slotWithAtrPrefix(std::string_view hexPrefix)
{
    const auto prefix = upper(std::string(hexPrefix));
    for (const auto& slot : CtkHw::passiveSlots())
        if (slot.state == CtkHw::SlotState::ValidCard && atrHasPrefix(slot.atr, prefix))
            return slot.name;
    return std::nullopt;
}

std::optional<std::string> slotFor(const CardRole& role)
{
    for (const auto& prefix : prefixesOf(role))
        if (auto slot = slotWithAtrPrefix(prefix)) {
            record(std::string("select role=") + role.name + " slot=\"" + *slot + "\" prefix=" + prefix);
            return slot;
        }
    record(std::string("select role=") + role.name + " slot=none");
    return std::nullopt;
}

std::optional<CtkHw::PassiveSlot> passiveSlotNamed(const std::string& name)
{
    for (auto& slot : CtkHw::passiveSlots())
        if (slot.name == name)
            return slot;
    return std::nullopt;
}

// --- the person at the readers -------------------------------------------------

// Prints the instruction and waits for Enter. False on end of input or when
// the wait runs out: the caller skips, nothing hangs.
bool ownerStep(const std::string& instruction)
{
    const long seconds = envLong("LIBRESCRS_HW_CTK_WAIT_SECONDS", 600);
    record("owner-step pid=" + std::to_string(::getpid()) + " wait_s=" + std::to_string(seconds));
    std::fprintf(stderr, "\n>>> %s\n>>> Press Enter when done (waiting up to %ld s).\n", instruction.c_str(), seconds);
    std::fflush(stderr);
    pollfd input{STDIN_FILENO, POLLIN, 0};
    const int ready = ::poll(&input, 1, static_cast<int>(std::min<long>(seconds, 86400) * 1000));
    if (ready <= 0)
        return false;
    char buffer[256];
    const auto got = ::read(STDIN_FILENO, buffer, sizeof buffer);
    return got > 0;
}

// --- APDUs ---------------------------------------------------------------------

const AppletAid kEmrtdAid{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
const std::vector<std::uint8_t> kEmrtdAidBytes{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

APDUCommand selectFile(std::uint16_t fid)
{
    return APDUCommand{0x00, 0xA4, 0x02, 0x0C, {static_cast<std::uint8_t>(fid >> 8), static_cast<std::uint8_t>(fid)},
                       0,    false};
}

APDUCommand selectMf()
{
    return APDUCommand{0x00, 0xA4, 0x00, 0x0C, {0x3F, 0x00}, 0, false};
}

APDUCommand readBinary(std::uint16_t offset, std::uint16_t le)
{
    return APDUCommand{0x00, 0xB0, static_cast<std::uint8_t>(offset >> 8), static_cast<std::uint8_t>(offset), {},
                       le,   true};
}

std::uint16_t dataGroupFid(long dg)
{
    return static_cast<std::uint16_t>(0x0100 + dg);
}

// --- reading one EF through a secure channel, exactly to its end ----------------

struct FileRead
{
    bool ok = false;
    std::vector<std::uint8_t> content;
    std::vector<std::string> steps; // "<apdu>:<sw>:<bytes>"
    std::string failure;
};

// Reads the BER-TLV object that fills the selected EF without ever reading
// past its end (past the end, a secure-messaging read can end the channel).
// @p chunk above 256 makes every read after the header an extended-Le APDU.
FileRead readTlvFile(LibreSCRS::SecureChannel::ISecureChannel& channel, std::uint16_t fid, std::uint16_t chunk)
{
    FileRead result;
    const LibreSCRS::CancelToken token;
    const auto select = channel.transmit(selectFile(fid), token);
    result.steps.push_back("select:" + hex4(select.statusWord()) + ":0");
    if (select.statusWord() != 0x9000) {
        result.failure = "select " + hex4(fid) + " sw=" + hex4(select.statusWord());
        return result;
    }
    const auto head = channel.transmit(readBinary(0, 8), token);
    result.steps.push_back("head:" + hex4(head.statusWord()) + ":" + std::to_string(head.data.size()));
    if ((head.statusWord() != 0x9000 && head.sw1 != 0x62) || head.data.size() < 2) {
        result.failure = "header read sw=" + hex4(head.statusWord());
        return result;
    }
    // Tag (one or two bytes), then the length.
    std::size_t pos = (head.data[0] & 0x1F) == 0x1F ? 2 : 1;
    if (pos >= head.data.size()) {
        result.failure = "header too short";
        return result;
    }
    std::size_t length = head.data[pos];
    std::size_t lengthBytes = 1;
    if (length & 0x80) {
        const std::size_t count = length & 0x7F;
        if (count == 0 || count > 3 || pos + 1 + count > head.data.size()) {
            result.failure = "unsupported length encoding";
            return result;
        }
        length = 0;
        for (std::size_t i = 0; i < count; ++i)
            length = (length << 8) | head.data[pos + 1 + i];
        lengthBytes = 1 + count;
    }
    const std::size_t total = pos + lengthBytes + length;
    if (total > 0x7FFF) {
        result.failure = "file larger than an even-INS read reaches";
        return result;
    }
    result.content.assign(head.data.begin(), head.data.begin() + std::min(head.data.size(), total));
    while (result.content.size() < total) {
        const auto remaining = total - result.content.size();
        const auto le = static_cast<std::uint16_t>(std::min<std::size_t>(remaining, chunk));
        const auto reply = channel.transmit(readBinary(static_cast<std::uint16_t>(result.content.size()), le), token);
        result.steps.push_back("read@" + std::to_string(result.content.size()) + "/le=" + std::to_string(le) + ":" +
                               hex4(reply.statusWord()) + ":" + std::to_string(reply.data.size()));
        if ((reply.statusWord() != 0x9000 && reply.sw1 != 0x62) || reply.data.empty()) {
            result.failure = "read at " + std::to_string(result.content.size()) + " sw=" + hex4(reply.statusWord());
            return result;
        }
        if (reply.data.size() > remaining) {
            result.failure = "card returned more than asked";
            return result;
        }
        result.content.insert(result.content.end(), reply.data.begin(), reply.data.end());
    }
    result.ok = true;
    return result;
}

std::string sha256(std::span<const std::uint8_t> bytes)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest, &length, EVP_sha256(), nullptr) != 1)
        return {};
    return hex(std::span<const std::uint8_t>(digest, length));
}

// --- a PACE session holding a secure channel -------------------------------------

struct PaceHold
{
    std::unique_ptr<CardSession> session;
    std::optional<ActiveChannelHolder> holder;
    LibreSCRS::SecureChannel::ISecureChannel* channel = nullptr;
};

std::expected<PaceHold, std::string> openPace(const std::string& slot, const std::string& can)
{
    auto opened = CardSession::open(slot);
    if (!opened)
        return std::unexpected("CardSession::open failed: " + opened.error().diagnosticDetail.value_or("no detail"));
    PaceHold hold;
    hold.session = std::make_unique<CardSession>(std::move(*opened));
    hold.session->setPaceSecret(LibreSCRS::Auth::PaceSecretKind::Can, LibreSCRS::Secure::String{can});
    const auto start = Clock::now();
    auto holder = hold.session->activateChannelWithSm(
        kEmrtdAid, LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can}, LibreSCRS::CancelToken{});
    record("pace slot=\"" + slot + "\" ok=" + std::to_string(holder.has_value()) + " ms=" + fixed(msSince(start)));
    if (!holder)
        return std::unexpected(std::string("PACE (CAN) did not establish a channel"));
    hold.holder.emplace(std::move(*holder));
    hold.channel = LibreSCRS::SmartCard::Internal::HolderChannelAccessor::channel(*hold.holder);
    if (hold.channel == nullptr)
        return std::unexpected(std::string("no channel behind the holder"));
    return hold;
}

// One secure-messaging read of EF.COM, logged with its status words.
bool smReadCom(PaceHold& hold, const std::string& label)
{
    const auto start = Clock::now();
    FileRead read;
    try {
        read = readTlvFile(*hold.channel, 0x011E, 0xDF);
    } catch (const std::exception& e) {
        read.failure = std::string("exception: ") + e.what();
    }
    std::string steps;
    for (const auto& step : read.steps)
        steps += (steps.empty() ? "" : ",") + step;
    record("sm-read at=" + label + " ok=" + std::to_string(read.ok) + " bytes=" + std::to_string(read.content.size()) +
           " ms=" + fixed(msSince(start)) + " live=" + std::to_string(hold.session->hasLiveSecureChannel()) +
           " steps=" + steps + (read.ok ? "" : " failure=\"" + read.failure + "\""));
    return read.ok;
}

// --- plugins and the PIN ----------------------------------------------------------

struct PluginSession
{
    std::unique_ptr<LibreSCRS::Plugin::CardPluginService> registry; // outlives the plugin handle
    std::shared_ptr<CardSession> session;
    std::shared_ptr<LibreSCRS::Plugin::CardPlugin> plugin;
};

// Opens the slot and picks the plugin: @p wanted (or LIBRESCRS_HW_CTK_PLUGIN)
// when it is a candidate; otherwise the first candidate that lists a PIN when
// @p needsPin, the first candidate at all when not.
std::expected<PluginSession, std::string> openWithPlugin(const std::string& slot, const std::string& wanted,
                                                         const std::optional<std::string>& can, bool needsPin = true)
{
    PluginSession result;
    result.registry = std::make_unique<LibreSCRS::Plugin::CardPluginService>(std::filesystem::path(PLUGIN_DIR));
    if (!result.registry->isUsable())
        return std::unexpected(std::string("no plugins loaded from ") + PLUGIN_DIR);
    auto opened = CardSession::open(slot);
    if (!opened)
        return std::unexpected("CardSession::open failed: " + opened.error().diagnosticDetail.value_or("no detail"));
    result.session = std::make_shared<CardSession>(std::move(*opened));
    if (can) {
        const std::string canValue = *can;
        result.session->setCredentialProvider([canValue](const LibreSCRS::Auth::AuthRequirement&) {
            std::vector<LibreSCRS::Auth::CredentialEntry> values;
            values.push_back({"can", LibreSCRS::Secure::String{canValue}});
            return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
        });
    }
    const auto candidates = result.registry->findAllCandidates(result.session->atr(), *result.session);
    std::string ids;
    for (const auto& candidate : candidates)
        ids += (ids.empty() ? "" : ",") + candidate->pluginId();
    const auto preferred = envOpt("LIBRESCRS_HW_CTK_PLUGIN").value_or(wanted);
    for (const auto& candidate : candidates)
        if (candidate->pluginId() == preferred)
            result.plugin = candidate;
    if (!result.plugin && preferred.empty() && !needsPin && !candidates.empty())
        result.plugin = candidates.front();
    if (!result.plugin && preferred.empty()) {
        for (const auto& candidate : candidates)
            if (!candidate->getPINList(*result.session).empty()) {
                result.plugin = candidate;
                break;
            }
    }
    record("plugins slot=\"" + slot + "\" candidates=" + ids +
           " chosen=" + (result.plugin ? result.plugin->pluginId() : std::string("none")));
    if (!result.plugin)
        return std::unexpected("no candidate plugin " + (preferred.empty() ? "listing a PIN" : "'" + preferred + "'") +
                               " for the card (candidates: " + ids + ")");
    return result;
}

// The retry counter of the PIN at @p reference, from VERIFY without data
// (consumes no try): 63Cx gives x. nullopt when the card answers otherwise.
std::optional<int> pinTriesFromStatus(CardSession& session, std::uint8_t reference, std::uint16_t* swOut = nullptr)
{
    const auto reply = session.transmitInternal(APDUCommand{0x00, 0x20, 0x00, reference, {}, 0, false});
    if (swOut != nullptr)
        *swOut = reply.statusWord();
    if (reply.sw1 == 0x63 && (reply.sw2 & 0xF0) == 0xC0)
        return reply.sw2 & 0x0F;
    return std::nullopt;
}

// Presents a PIN only when its counter reads full. Returns the reference of
// the PIN that will be verified, or why it will not be.
std::expected<std::uint8_t, std::string> pinReadyToVerify(PluginSession& ps)
{
    const auto pins = ps.plugin->getPINList(*ps.session);
    for (const auto& entry : pins)
        record("pin label=\"" + entry.label + "\" ref=" + hex(std::span<const std::uint8_t>(&entry.reference, 1)) +
               " retries=" + (entry.retriesLeft ? std::to_string(*entry.retriesLeft) : std::string("unknown")) +
               " blocked=" + std::to_string(entry.blocked));
    if (pins.empty())
        return std::unexpected(std::string("the plugin lists no PIN"));
    const auto& entry = pins.front();
    const long full = envLong("LIBRESCRS_HW_CTK_PIN_TRIES", 3);
    std::uint16_t sw = 0;
    const auto tries = entry.retriesLeft ? entry.retriesLeft : pinTriesFromStatus(*ps.session, entry.reference, &sw);
    if (!entry.retriesLeft)
        record("pin-status ref=" + hex(std::span<const std::uint8_t>(&entry.reference, 1)) + " sw=" + hex4(sw));
    if (entry.blocked || !tries || *tries < full)
        return std::unexpected("PIN retry counter is not full (" +
                               (tries ? std::to_string(*tries) : std::string("unknown")) + " of " +
                               std::to_string(full) + "); refusing to present a PIN");
    return entry.reference;
}

// --- one APDU through a raw connection, as an outcome line ------------------------

struct Outcome
{
    bool replied = false;
    std::uint16_t sw = 0;
    long code = 0;
    double ms = 0;
    std::string text() const
    {
        return replied ? "sw=" + hex4(sw) + " ms=" + fixed(ms) : "pcsc=" + pcscCode(code) + " ms=" + fixed(ms);
    }
};

Outcome attempt(PCSCConnection& conn, const APDUCommand& cmd)
{
    Outcome outcome;
    const auto start = Clock::now();
    try {
        outcome.sw = conn.transmit(cmd).statusWord();
        outcome.replied = true;
    } catch (const PCSCError& e) {
        outcome.code = e.code();
    }
    outcome.ms = msSince(start);
    return outcome;
}

// --- distributions -------------------------------------------------------------------

double percentile(std::vector<double> values, double p)
{
    if (values.empty())
        return 0;
    std::sort(values.begin(), values.end());
    const auto rank = static_cast<std::size_t>(std::ceil(p * static_cast<double>(values.size())));
    return values[std::clamp<std::size_t>(rank, 1, values.size()) - 1];
}

std::string distribution(const std::vector<double>& values)
{
    return "n=" + std::to_string(values.size()) + " p50=" + fixed(percentile(values, 0.50)) +
           " p90=" + fixed(percentile(values, 0.90)) + " p99=" + fixed(percentile(values, 0.99)) +
           " max=" + fixed(values.empty() ? 0 : *std::max_element(values.begin(), values.end()));
}

// --- a helper program, run without a shell ----------------------------------------

std::optional<std::string> runProgram(const std::string& path, const std::vector<std::string>& args)
{
    int pipeFds[2];
    if (::pipe(pipeFds) != 0)
        return std::nullopt;
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipeFds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipeFds[0]);
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(path.c_str()));
    for (const auto& arg : args)
        argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);
    pid_t pid = 0;
    const int spawned = posix_spawn(&pid, path.c_str(), &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    ::close(pipeFds[1]);
    if (spawned != 0) {
        ::close(pipeFds[0]);
        return std::nullopt;
    }
    std::string output;
    char buffer[512];
    ssize_t got = 0;
    while ((got = ::read(pipeFds[0], buffer, sizeof buffer)) > 0)
        output.append(buffer, static_cast<std::size_t>(got));
    ::close(pipeFds[0]);
    int status = 0;
    ::waitpid(pid, &status, 0);
    return output;
}

} // namespace

// ---------------------------------------------------------------------------------------

class CtkSessionHardware : public ::testing::Test
{
protected:
    void SetUp() override
    {
        if (envOpt("LIBRESCRS_HW_CTK").value_or("") != "1")
            GTEST_SKIP() << "hardware check: set LIBRESCRS_HW_CTK=1 with the test cards in the readers";
        const auto slots = CtkHw::passiveSlots();
        ASSERT_FALSE(slots.empty()) << "no CryptoTokenKit slot: is the binary signed with "
                                       "com.apple.security.smartcard, and is a reader attached?";
        for (const auto& slot : slots)
            record("slot name=\"" + slot.name + "\" state=" + std::to_string(static_cast<long>(slot.state)) +
                   " atr=" + hex(slot.atr) + " maxIn=" + std::to_string(slot.maxInputLength) +
                   " maxOut=" + std::to_string(slot.maxOutputLength));
    }

    // A ctkd restart or sleep/wake while the connection holds its session:
    // the next APDU answers or fails with a mapped code in bounded time, and
    // the connection works again after reconnect.
    void disruptHeldSession(const char* caseName, const std::string& instruction)
    {
        const auto slot = slotFor(kPlainCard);
        if (!slot)
            GTEST_SKIP() << "no contact test card (by ATR prefix) in any reader";
        auto conn = PCSCConnection::openRawDiagnostic(*slot);
        const auto before = attempt(*conn, selectMf());
        record(std::string(caseName) + " before " + before.text());
        ASSERT_TRUE(before.replied);
        if (!ownerStep(instruction))
            GTEST_SKIP() << "owner step not confirmed";

        const auto first = attempt(*conn, selectMf());
        record(std::string(caseName) + " first-after " + first.text());
        const double boundMs = static_cast<double>(envLong("LIBRESCRS_HW_CTK_BOUND_MS", 10000));
        EXPECT_LE(first.ms, boundMs) << "the first APDU after the disruption took longer than the bound";
        if (!first.replied) {
            const auto start = Clock::now();
            long code = 0;
            try {
                conn->reconnect();
            } catch (const PCSCError& e) {
                code = e.code();
            }
            record(std::string(caseName) + " reconnect pcsc=" + pcscCode(code) + " ms=" + fixed(msSince(start)));
            EXPECT_EQ(code, 0) << "reconnect did not give a new session";
        }
        const auto after = attempt(*conn, selectMf());
        record(std::string(caseName) + " operation-after " + after.text());
        EXPECT_TRUE(after.replied) << "the connection does not work after the disruption";
    }
};

// Secure messaging over one held session survives long idle periods with no
// new PACE: nothing in CryptoTokenKit or ctkd touches a card whose session is
// held. Run with LIBRESCRS_PCSC_TRACE=1: the trace must show one "connect"
// and no "reconnect" for the slot.
TEST_F(CtkSessionHardware, SecureMessagingSurvivesAnIdleHeldSession)
{
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");
    const auto slot = slotFor(kPaceCard);
    if (!slot)
        GTEST_SKIP() << "no PACE test card (by ATR prefix) in any reader";
    auto hold = openPace(*slot, *envOpt("LIBRESCRS_TEST_CAN"));
    ASSERT_TRUE(hold.has_value()) << hold.error();

    const auto t0 = Clock::now();
    ASSERT_TRUE(smReadCom(*hold, "t0+0min"));
    for (const auto& item : splitList(envOpt("LIBRESCRS_HW_CTK_IDLE_MINUTES").value_or("5,30"))) {
        const long minutes = std::strtol(item.c_str(), nullptr, 10);
        record("idle until=t0+" + std::to_string(minutes) + "min");
        std::this_thread::sleep_until(t0 + std::chrono::minutes(minutes));
        EXPECT_TRUE(hold->session->hasLiveSecureChannel()) << "secure channel not live at t0+" << minutes << "min";
        EXPECT_TRUE(smReadCom(*hold, "t0+" + std::to_string(minutes) + "min"))
            << "secure messaging failed after " << minutes << " idle minutes";
    }
    record("pace-count=1 (one activation; any later PACE would need another activateChannelWithSm)");
}

// While the session is held, another process asks for the same card through
// CryptoTokenKit and through PC/SC. The other client waits or fails; our
// next secure-messaging APDU still works.
TEST_F(CtkSessionHardware, ForeignClientWaitsWhileTheSessionIsHeld)
{
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");
    const auto slot = slotFor(kPaceCard);
    if (!slot)
        GTEST_SKIP() << "no PACE test card (by ATR prefix) in any reader";
    auto hold = openPace(*slot, *envOpt("LIBRESCRS_TEST_CAN"));
    ASSERT_TRUE(hold.has_value()) << hold.error();
    ASSERT_TRUE(smReadCom(*hold, "before-foreign"));

    if (!ownerStep("The session on \"" + *slot +
                   "\" is held. In another terminal run foreign_session and then foreign_pcsc against that slot "
                   "name and keep their output."))
        GTEST_SKIP() << "owner step not confirmed";

    EXPECT_TRUE(hold->session->hasLiveSecureChannel());
    EXPECT_TRUE(smReadCom(*hold, "after-foreign")) << "our session was lost to the other client";
}

TEST_F(CtkSessionHardware, CtkdRestartIsMappedAndRecovers)
{
    disruptHeldSession("ctkd-restart", "Restart ctkd now: launchctl kickstart -k gui/$(id -u)/com.apple.ctkd");
}

TEST_F(CtkSessionHardware, SleepWakeIsMappedAndRecovers)
{
    disruptHeldSession("sleep-wake", "Put the Mac to sleep (pmset sleepnow), wake it, log in");
}

// The card leaves the reader in the middle of a sequence of APDUs: the
// connection reports SCARD_W_REMOVED_CARD and ends its session cleanly.
TEST_F(CtkSessionHardware, RemovalMidSequenceIsRemoved)
{
    const auto slot = slotFor(kPlainCard);
    if (!slot)
        GTEST_SKIP() << "no contact test card (by ATR prefix) in any reader";
    auto conn = PCSCConnection::openRawDiagnostic(*slot);
    const long seconds = envLong("LIBRESCRS_HW_CTK_WAIT_SECONDS", 600);
    std::fprintf(stderr, "\n>>> Remove the card from \"%s\" now (APDUs every 100 ms for up to %ld s).\n", slot->c_str(),
                 seconds);
    std::fflush(stderr);

    const auto start = Clock::now();
    int sent = 0;
    std::optional<Outcome> failed;
    while (msSince(start) < static_cast<double>(seconds) * 1000.0) {
        const auto outcome = attempt(*conn, selectMf());
        ++sent;
        if (!outcome.replied) {
            failed = outcome;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!failed)
        GTEST_SKIP() << "the card was not removed within the wait";
    record("removal apdus-before=" + std::to_string(sent - 1) + " " + failed->text() +
           " at_s=" + fixed(msSince(start) / 1000.0));
    EXPECT_EQ(failed->code, SCARD_W_REMOVED_CARD);

    const auto closeStart = Clock::now();
    conn.reset(); // ends the session
    record("removal close ms=" + fixed(msSince(closeStart)));
    ownerStep("Optional: run `leaks " + std::to_string(::getpid()) +
              "` in another terminal and keep its summary. Put the card back.");
}

// What ending and beginning the session does to the card: a PIN verified and
// a file selected, then the session ends and a new one begins (at once and,
// if the state survived, after 1 s). Recorded, not judged: the answer decides
// what a reset through CryptoTokenKit may promise.
TEST_F(CtkSessionHardware, SessionRestartClearsCardState)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");
    const auto interfaces = splitList(envOpt("LIBRESCRS_HW_CTK_RESET_INTERFACES").value_or("contact"));
    bool ranAny = false;
    for (const auto& iface : interfaces) {
        SKIP_IF_PIN_FAILED();
        const bool contactless = iface == "contactless";
        const auto slot = slotFor(contactless ? kLkContactlessCard : kLkContactCard);
        if (!slot) {
            record("restart iface=" + iface + " skipped=no-card");
            continue;
        }
        const auto can = contactless ? envOpt("LIBRESCRS_TEST_CAN") : std::nullopt;
        if (contactless && !can) {
            record("restart iface=contactless skipped=no-LIBRESCRS_TEST_CAN");
            continue;
        }
        auto ps = openWithPlugin(*slot, "rs-eid", can);
        ASSERT_TRUE(ps.has_value()) << ps.error();
        const auto reference = pinReadyToVerify(*ps);
        if (!reference)
            GTEST_SKIP() << reference.error();

        const auto verified =
            ps->plugin->verifyPIN(*ps->session, LibreSCRS::Secure::String{*envOpt("LIBRESCRS_TEST_PIN")});
        if (verified.outcome != LibreSCRS::Plugin::PINResultOutcome::Ok) {
            markPinFailedAndAbort(__LINE__, "verifyPIN outcome=" + std::to_string(static_cast<int>(verified.outcome)));
            return;
        }
        ranAny = true;

        auto& session = *ps->session;
        const auto efSelect = session.transmitInternal(selectFile(0x2F00)); // EF.DIR, made current
        std::uint16_t statusBefore = 0;
        (void)pinTriesFromStatus(session, *reference, &statusBefore);
        const auto readBefore = session.transmitInternal(readBinary(0, 1));
        const auto atrBefore = session.atr();
        record("restart iface=" + iface + " before verify-status=" + hex4(statusBefore) +
               " select-2F00=" + hex4(efSelect.statusWord()) + " read-current=" + hex4(readBefore.statusWord()) +
               " atr=" + hex(atrBefore));
        ASSERT_EQ(statusBefore, 0x9000) << "the PIN does not read as verified; nothing to observe";

        bool cleared = false;
        for (const int pauseMs : {0, 1000}) {
            if (cleared)
                break;
            // The session ends with the CardSession and begins with the next.
            ps->session.reset();
            std::this_thread::sleep_for(std::chrono::milliseconds(pauseMs));
            auto reopened = CardSession::open(*slot);
            ASSERT_TRUE(reopened.has_value()) << reopened.error().diagnosticDetail.value_or("no detail");
            ps->session = std::make_shared<CardSession>(std::move(*reopened));
            std::uint16_t statusAfter = 0;
            (void)pinTriesFromStatus(*ps->session, *reference, &statusAfter);
            const auto readAfter = ps->session->transmitInternal(readBinary(0, 1));
            cleared = statusAfter != 0x9000;
            record("restart iface=" + iface + " pause_ms=" + std::to_string(pauseMs) +
                   " after verify-status=" + hex4(statusAfter) + " read-current=" + hex4(readAfter.statusWord()) +
                   " atr=" + hex(ps->session->atr()) + " atr-same=" + std::to_string(ps->session->atr() == atrBefore) +
                   " state-cleared=" + (cleared ? "yes" : "no"));
        }
    }
    if (!ranAny)
        GTEST_SKIP() << "no test LK (by ATR prefix) on the requested interfaces";
}

// The largest data group through secure messaging with extended Le, compared
// with the same file read in short chunks in this run and, when given, with
// the hash the PC/SC body produced for the same card
// (LIBRESCRS_HW_CTK_REFERENCE_SHA256).
TEST_F(CtkSessionHardware, ExtendedReadThroughSecureMessagingMatchesTheReference)
{
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");
    const auto slot = slotFor(kPaceCard);
    if (!slot)
        GTEST_SKIP() << "no PACE test card (by ATR prefix) in any reader";
    if (const auto passive = passiveSlotNamed(*slot))
        record("lengths slot=\"" + *slot + "\" maxIn=" + std::to_string(passive->maxInputLength) +
               " maxOut=" + std::to_string(passive->maxOutputLength));
    auto hold = openPace(*slot, *envOpt("LIBRESCRS_TEST_CAN"));
    ASSERT_TRUE(hold.has_value()) << hold.error();

    const long dg = envLong("LIBRESCRS_HW_CTK_DG", 2);
    const auto chunk =
        static_cast<std::uint16_t>(std::clamp<long>(envLong("LIBRESCRS_HW_CTK_EXTENDED_LE", 0x1000), 257, 0xFFFF));
    const auto readWith = [&](std::uint16_t le, const char* label) {
        const auto start = Clock::now();
        FileRead read;
        try {
            read = readTlvFile(*hold->channel, dataGroupFid(dg), le);
        } catch (const std::exception& e) {
            read.failure = std::string("exception: ") + e.what();
        }
        std::string steps;
        for (const auto& step : read.steps)
            steps += (steps.empty() ? "" : ",") + step;
        record(std::string("dg-read mode=") + label + " dg=" + std::to_string(dg) + " le=" + std::to_string(le) +
               " ok=" + std::to_string(read.ok) + " bytes=" + std::to_string(read.content.size()) +
               " sha256=" + sha256(read.content) + " ms=" + fixed(msSince(start)) + " steps=" + steps +
               (read.ok ? "" : " failure=\"" + read.failure + "\""));
        return read;
    };
    const auto extended = readWith(chunk, "extended");
    ASSERT_TRUE(extended.ok) << "extended read failed: " << extended.failure;
    const auto shortRead = readWith(0xDF, "short");
    ASSERT_TRUE(shortRead.ok) << "short read failed: " << shortRead.failure;
    EXPECT_EQ(sha256(extended.content), sha256(shortRead.content)) << "extended and short reads differ";

    const auto reference = envOpt("LIBRESCRS_HW_CTK_REFERENCE_SHA256");
    if (!reference && HasFailure())
        return; // never skip after a failure: ctest would report the case Skipped
    if (!reference)
        GTEST_SKIP() << "no LIBRESCRS_HW_CTK_REFERENCE_SHA256: the comparison with the PC/SC body did not run";
    EXPECT_EQ(sha256(extended.content), upper(*reference)) << "differs from the PC/SC body's read of the same card";
}

// The OpenSC plugin binds the contact test LK through the bridge's raw
// transmit and signs once (one PIN presentation); the signature verifies
// against the certificate.
TEST_F(CtkSessionHardware, OpenScBridgeBindsAndSigns)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");
    const auto slot = slotFor(kLkContactCard);
    if (!slot)
        GTEST_SKIP() << "no contact test LK (by ATR prefix) in any reader";
    auto ps = openWithPlugin(*slot, "opensc", std::nullopt);
    if (!ps)
        GTEST_SKIP() << ps.error();

    auto start = Clock::now();
    const auto reference = pinReadyToVerify(*ps);
    record("opensc bind+pins ms=" + fixed(msSince(start)));
    if (!reference)
        GTEST_SKIP() << reference.error();

    start = Clock::now();
    const auto certs = ps->plugin->readCertificates(*ps->session);
    record("opensc certificates n=" + std::to_string(certs.size()) + " ms=" + fixed(msSince(start)));
    const LibreSCRS::Plugin::CertificateData* signing = nullptr;
    for (const auto& cert : certs)
        if (cert.keyFID) {
            signing = &cert;
            break;
        }
    ASSERT_NE(signing, nullptr) << "no certificate carries a key reference";

    // The key type decides the mechanism and the digest.
    bool ec = false;
    int bits = 0;
    {
        const unsigned char* p = signing->derBytes.data();
        std::unique_ptr<X509, decltype(&X509_free)> cert{
            d2i_X509(nullptr, &p, static_cast<long>(signing->derBytes.size())), &X509_free};
        ASSERT_TRUE(cert);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{X509_get_pubkey(cert.get()), &EVP_PKEY_free};
        ASSERT_TRUE(key);
        ec = EVP_PKEY_base_id(key.get()) == EVP_PKEY_EC;
        bits = EVP_PKEY_bits(key.get());
    }
    const EVP_MD* md = !ec ? EVP_sha256() : bits > 384 ? EVP_sha512() : bits > 256 ? EVP_sha384() : EVP_sha256();
    const auto mechanism = !ec          ? LibreSCRS::Plugin::SignMechanism::RSA_PKCS
                           : bits > 384 ? LibreSCRS::Plugin::SignMechanism::ECDSA_SHA512
                           : bits > 256 ? LibreSCRS::Plugin::SignMechanism::ECDSA_SHA384
                                        : LibreSCRS::Plugin::SignMechanism::ECDSA_SHA256;
    const std::vector<std::uint8_t> payload{'C', 'T', 'K', '-', 'H', 'W'};
    std::vector<std::uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int digestLength = 0;
    ASSERT_EQ(EVP_Digest(payload.data(), payload.size(), digest.data(), &digestLength, md, nullptr), 1);
    digest.resize(digestLength);
    std::vector<std::uint8_t> toSign = digest;
    if (!ec) {
        // DigestInfo for SHA-256, which RSA_PKCS signs verbatim.
        static constexpr std::uint8_t kSha256Prefix[] = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                         0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        toSign.insert(toSign.begin(), std::begin(kSha256Prefix), std::end(kSha256Prefix));
    }

    start = Clock::now();
    const auto verified = ps->plugin->verifyPIN(*ps->session, LibreSCRS::Secure::String{*envOpt("LIBRESCRS_TEST_PIN")});
    if (verified.outcome != LibreSCRS::Plugin::PINResultOutcome::Ok) {
        markPinFailedAndAbort(__LINE__, "verifyPIN outcome=" + std::to_string(static_cast<int>(verified.outcome)));
        return;
    }
    const auto signedResult = ps->plugin->sign(*ps->session, *signing->keyFID, toSign, mechanism);
    record("opensc verify+sign ms=" + fixed(msSince(start)) + " key=" + (ec ? "ec" : "rsa") +
           " bits=" + std::to_string(bits) + " outcome=" + std::to_string(static_cast<int>(signedResult.outcome)) +
           " sig-bytes=" + std::to_string(signedResult.signature.size()));
    if (signedResult.outcome == LibreSCRS::Plugin::SignResultOutcome::PinIncorrect ||
        signedResult.outcome == LibreSCRS::Plugin::SignResultOutcome::PinBlocked) {
        markPinFailedAndAbort(__LINE__, "sign refused the PIN");
        return;
    }
    ASSERT_EQ(signedResult.outcome, LibreSCRS::Plugin::SignResultOutcome::Ok);
    EXPECT_TRUE(ec ? LibreSCRS::Tests::ecdsaVerifyRaw(signing->derBytes, signedResult.signature, digest)
                   : LibreSCRS::Tests::rsaPkcs1Sha256Verify(signing->derBytes, signedResult.signature, digest));
}

// How long a full read of the contact test LK takes through the plugin.
// Recorded, not judged: compare with the same case built over the PC/SC body.
TEST_F(CtkSessionHardware, FullReadTimeIsRecorded)
{
    const auto slot = slotFor(kLkContactCard);
    if (!slot)
        GTEST_SKIP() << "no contact test LK (by ATR prefix) in any reader";
    const long runs = std::max(1L, envLong("LIBRESCRS_HW_CTK_TIMING_RUNS", 3));
    for (long run = 0; run < runs; ++run) {
        const auto openStart = Clock::now();
        auto ps = openWithPlugin(*slot, envOpt("LIBRESCRS_HW_CTK_READ_PLUGIN").value_or(""), std::nullopt, false);
        ASSERT_TRUE(ps.has_value()) << ps.error();
        const double openMs = msSince(openStart);
        const auto start = Clock::now();
        const auto read = ps->plugin->readCard(*ps->session);
        record("full-read run=" + std::to_string(run) + " plugin=" + ps->plugin->pluginId() +
               " status=" + std::to_string(static_cast<int>(read.status)) + " open+probe_ms=" + fixed(openMs) +
               " read_ms=" + fixed(msSince(start)));
        EXPECT_EQ(read.status, LibreSCRS::Plugin::ReadResult::Status::Ok);
    }
}

// The two length options of TKSmartCard in all four combinations, set before
// a bare session, against the same extended and case-4 APDUs, on every contact
// test card present. Recorded per card: which combination carries which APDU.
TEST_F(CtkSessionHardware, LengthOptionsMatrix)
{
    const auto prefixes = prefixesOf(kPlainCard);
    const long dg = envLong("LIBRESCRS_HW_CTK_DG", 2);
    const auto le =
        static_cast<std::uint16_t>(std::clamp<long>(envLong("LIBRESCRS_HW_CTK_EXTENDED_LE", 0x1000), 257, 0xFFFF));
    const std::vector<std::vector<std::uint8_t>> apdus{
        // case 4: SELECT the eMRTD applet asking for its FCI
        {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01, 0x00},
        // case 3: SELECT the eMRTD applet, no answer data
        {0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01},
        // case 3: SELECT the data group
        {0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, static_cast<std::uint8_t>(dg)},
        // case 2 extended: READ BINARY with a two-byte Le
        {0x00, 0xB0, 0x00, 0x00, 0x00, static_cast<std::uint8_t>(le >> 8), static_cast<std::uint8_t>(le)},
        // case 2 short: READ BINARY, Le = 256
        {0x00, 0xB0, 0x00, 0x00, 0x00},
    };
    int cards = 0;
    for (const auto& slot : CtkHw::passiveSlots()) {
        if (slot.state != CtkHw::SlotState::ValidCard)
            continue;
        if (std::none_of(prefixes.begin(), prefixes.end(),
                         [&](const std::string& prefix) { return atrHasPrefix(slot.atr, prefix); }))
            continue;
        ++cards;
        for (const bool extended : {false, true})
            for (const bool chaining : {false, true}) {
                const auto session = CtkHw::rawSession(slot.name, extended, chaining, apdus, std::chrono::seconds(10));
                const std::string head = "matrix slot=\"" + slot.name + "\" atr=" + hex(slot.atr) +
                                         " maxIn=" + std::to_string(slot.maxInputLength) +
                                         " maxOut=" + std::to_string(slot.maxOutputLength) +
                                         " ext=" + std::to_string(extended) + " chain=" + std::to_string(chaining);
                record(head + " began=" + std::to_string(session.began) +
                       " protocol=" + std::to_string(session.protocol) + " begin_ms=" + fixed(session.beginMs) +
                       (session.began ? ""
                                      : " begin-error=" + std::to_string(session.beginErrorCode) + "/" +
                                            session.beginErrorDomain));
                EXPECT_TRUE(session.began) << head;
                for (std::size_t i = 0; i < session.exchanges.size(); ++i) {
                    const auto& x = session.exchanges[i];
                    const auto sw = x.reply.size() >= 2
                                        ? hex(std::span<const std::uint8_t>(x.reply).subspan(x.reply.size() - 2))
                                        : std::string("none");
                    record(head + " apdu=" + std::to_string(i) + " replied=" + std::to_string(x.replied) +
                           " data=" + std::to_string(x.reply.size() >= 2 ? x.reply.size() - 2 : 0) + " sw=" + sw +
                           " ms=" + fixed(x.ms) +
                           (x.replied ? "" : " error=" + std::to_string(x.errorCode) + "/" + x.errorDomain));
                }
            }
    }
    if (cards == 0)
        GTEST_SKIP() << "no contact test card (by ATR prefix) in any reader";
}

// A long APDU loop on reader A does not delay short operations on reader B:
// each held session has its own lock, and CryptoTokenKit must not serialise
// across slots either.
TEST_F(CtkSessionHardware, ReaderBIsNotDelayedByReaderAOnHardware)
{
    const auto slotA = slotFor(kLkContactCard);
    const auto slotB = slotFor(kSecondReaderCard);
    if (!slotA || !slotB)
        GTEST_SKIP() << "needs the contact test LK and a second test card in another reader";
    ASSERT_NE(*slotA, *slotB);
    auto connA = PCSCConnection::openRawDiagnostic(*slotA);
    auto connB = PCSCConnection::openRawDiagnostic(*slotB);
    const long count = std::max(10L, envLong("LIBRESCRS_HW_CTK_B_COUNT", 200));
    const auto aLe = static_cast<std::uint16_t>(envLong("LIBRESCRS_HW_CTK_A_LE", 0));
    const long dg = envLong("LIBRESCRS_HW_CTK_DG", 2);

    const auto runB = [&](const char* label) {
        std::vector<double> times;
        for (long i = 0; i < count; ++i) {
            const auto outcome = attempt(*connB, selectMf());
            EXPECT_TRUE(outcome.replied) << label << " " << outcome.text();
            times.push_back(outcome.ms);
        }
        record(std::string("reader-b ") + label + " " + distribution(times));
        return times;
    };

    const auto alone = runB("without-a");

    // Reader A: the eMRTD data group, read again and again.
    ASSERT_TRUE(attempt(*connA, APDUCommand{0x00, 0xA4, 0x04, 0x0C, kEmrtdAidBytes, 0, false}).replied);
    ASSERT_TRUE(attempt(*connA, selectFile(dataGroupFid(dg))).replied);
    std::atomic<bool> stop{false};
    std::vector<double> aTimes;
    std::thread loopA([&] {
        while (!stop.load()) {
            const auto outcome = attempt(*connA, readBinary(0, aLe));
            aTimes.push_back(outcome.ms);
            if (!outcome.replied)
                break;
        }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    const auto withA = runB("with-a");
    stop = true;
    loopA.join();
    record("reader-a " + distribution(aTimes));

    const double budget = static_cast<double>(envLong("LIBRESCRS_HW_CTK_P99_BUDGET_MS", 5));
    const double delta = percentile(withA, 0.99) - percentile(alone, 0.99);
    record("reader-b p99-delta_ms=" + fixed(delta) + " budget_ms=" + fixed(budget));
    EXPECT_GT(aTimes.size(), 1u) << "reader A did not run alongside";
    EXPECT_GT(percentile(aTimes, 0.50), budget) << "reader A's APDU is too short to show a delay of this size";
    EXPECT_LE(delta, budget) << "reader B is delayed by reader A";
}

// The ATR CryptoTokenKit reports for a slot, read without a session, equals
// the one PC/SC reports from SCardGetStatusChange in a separate process
// (LIBRESCRS_HW_CTK_PCSC_STATUS, a helper that never connects to the card).
TEST_F(CtkSessionHardware, AtrMatchesThePassivePcscAtr)
{
    const auto helper = envOpt("LIBRESCRS_HW_CTK_PCSC_STATUS");
    if (!helper)
        GTEST_SKIP() << "LIBRESCRS_HW_CTK_PCSC_STATUS does not name the PC/SC status helper";
    const auto& tool = *helper;
    if (::access(tool.c_str(), X_OK) != 0)
        GTEST_SKIP() << "PC/SC status helper not executable: " << tool;
    const auto prefixes = allTestPrefixes();
    int compared = 0;
    for (const auto& slot : CtkHw::passiveSlots()) {
        if (slot.state != CtkHw::SlotState::ValidCard)
            continue;
        if (std::none_of(prefixes.begin(), prefixes.end(),
                         [&](const std::string& prefix) { return atrHasPrefix(slot.atr, prefix); }))
            continue;
        const auto output = runProgram(tool, {slot.name});
        ASSERT_TRUE(output.has_value()) << "could not run " << tool;
        // Expected line: PCSC_STATUS rv=0x... state=0x... atr=<hex> reader=<name>
        std::string pcscAtr;
        std::stringstream lines(*output);
        std::string line;
        while (std::getline(lines, line)) {
            const auto at = line.find(" atr=");
            if (line.rfind("PCSC_STATUS ", 0) == 0 && at != std::string::npos) {
                const auto end = line.find(' ', at + 5);
                pcscAtr = upper(line.substr(at + 5, end == std::string::npos ? std::string::npos : end - at - 5));
            }
        }
        record("atr slot=\"" + slot.name + "\" ctk=" + hex(slot.atr) + " pcsc=" + pcscAtr +
               " equal=" + std::to_string(hex(slot.atr) == pcscAtr));
        EXPECT_EQ(hex(slot.atr), pcscAtr) << slot.name;
        ++compared;
    }
    if (compared == 0)
        GTEST_SKIP() << "no test card (by ATR prefix) in any reader";
}
