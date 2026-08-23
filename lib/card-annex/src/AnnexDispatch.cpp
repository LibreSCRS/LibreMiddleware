// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "AnnexDispatch.h"

#include "AnnexRegistry.h"

#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/detail/ChannelStateMutator.h>

#include <apdu.h>
#include <ef_dir.h>
#include <smartcard/chunked_read.h>
#include <smartcard/i_connection.h>

namespace LibreSCRS::Annex {
namespace {

namespace SC = LibreSCRS::SmartCard::Internal;

constexpr std::uint8_t kMfHi = 0x3F;
constexpr std::uint8_t kMfLo = 0x00;
constexpr std::uint8_t kEfDirHi = 0x2F;
constexpr std::uint8_t kEfDirLo = 0x00;

[[nodiscard]] SC::APDUResponse dispatch(const AnnexContext& ctx, const SC::APDUCommand& cmd)
{
    if (ctx.channel != nullptr && ctx.channel->state() == LibreSCRS::SecureChannel::ChannelState::Open) {
        return ctx.channel->transmit(cmd, ctx.token);
    }
    return ctx.conn->transmit(cmd);
}

/// Puts the master file back however the scope is left, including on a throw.
class MasterFileRestore
{
public:
    explicit MasterFileRestore(const AnnexContext& ctx) : ctx_(ctx) {}

    ~MasterFileRestore()
    {
        // The MF select goes THROUGH the SM channel but does not update its
        // cached applet AID (that is only stamped by CardSession after an
        // activation). Left as-is, the channel would claim to be on the
        // eMRTD applet while the card sits elsewhere, and a second read's
        // same-applet fast path would skip the re-SELECT and read the wrong
        // file. Clear the cached AID to the empty sentinel (the state a fresh
        // PACE/CA handshake leaves) BEFORE attempting the select: host-side
        // bookkeeping must not depend on the wire call surviving — a throw
        // (cancellation, transient PC/SC failure) would otherwise leave the
        // stale AID armed. Harmless on a plain read (no channel).
        if (ctx_.channel != nullptr) {
            LibreSCRS::SecureChannel::detail::ChannelStateMutator::setCurrentApplet(*ctx_.channel,
                                                                                    LibreSCRS::SmartCard::AppletAid{});
        }
        try {
            (void)dispatch(ctx_, SC::selectByFileId(kMfHi, kMfLo, 0x0C));
        } catch (...) {
            // Nothing useful to do in a destructor; the next caller selects its
            // own application anyway and will see the failure there.
        }
    }

    MasterFileRestore(const MasterFileRestore&) = delete;
    MasterFileRestore& operator=(const MasterFileRestore&) = delete;

private:
    const AnnexContext& ctx_;
};

/// Data came back and is usable. A short read ends with a 62xx/63xx warning
/// rather than 9000 -- EF.DIR is smaller than the length asked for, so the real
/// card answers 6282 every time and treating that as failure loses the file.
[[nodiscard]] bool carriesData(const SC::APDUResponse& r)
{
    return r.isSuccess() || r.sw1 == 0x62 || r.sw1 == 0x63;
}

[[nodiscard]] std::vector<std::uint8_t> readEfDir(const AnnexContext& ctx)
{
    if (!dispatch(ctx, SC::selectByFileId(kMfHi, kMfLo, 0x0C)).isSuccess()) {
        return {};
    }
    if (!dispatch(ctx, SC::selectByFileId(kEfDirHi, kEfDirLo, 0x0C)).isSuccess()) {
        return {};
    }

    // EF.DIR is a bare record list with no length header of its own, so it is
    // read in one go rather than through the header-driven chunked reader.
    std::vector<std::uint8_t> out;
    for (std::uint16_t offset = 0; offset < 0x1000;) {
        const auto resp = dispatch(ctx, SC::readBinary(offset, 0xFF));
        if (!carriesData(resp) || resp.data.empty()) {
            break;
        }
        out.insert(out.end(), resp.data.begin(), resp.data.end());
        if (!resp.isSuccess() || resp.data.size() < 0xFF) {
            break; // warning status or a short read: the file ended here
        }
        offset = static_cast<std::uint16_t>(offset + resp.data.size());
    }
    return out;
}

} // namespace

std::vector<LibreSCRS::Plugin::CardFieldGroup> readAllAnnexes(const AnnexContext& ctx) noexcept
{
    std::vector<LibreSCRS::Plugin::CardFieldGroup> groups;
    if (ctx.conn == nullptr) {
        return groups;
    }

    try {
        const MasterFileRestore restore(ctx);

        // Every record is offered to every reader. The base applications are not
        // filtered out by name here: no reader claims them, and a hardcoded list
        // of what to skip is one more thing that drifts from the card.
        for (const auto& entry : SC::parseEfDir(readEfDir(ctx))) {
            auto found = readAnnexFor(entry, ctx);
            groups.insert(groups.end(), std::make_move_iterator(found.begin()), std::make_move_iterator(found.end()));
        }
    } catch (...) {
        // An annex must never be able to fail the read around it.
        return {};
    }
    return groups;
}

} // namespace LibreSCRS::Annex
