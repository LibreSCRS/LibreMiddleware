// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief A scripted PKCS#15 card for the transmit-filter test double, and
///        the profile files most of its tests serve from it.
///
/// The card answers SELECT by AID, SELECT by FID and READ BINARY from a
/// FID-to-bytes map, optionally the empty-VERIFY retry-counter probe, and
/// "instruction not supported" (6D00) for everything else. A test that needs
/// the card to do more -- CHANGE REFERENCE DATA, a signature, a DOCP GET
/// DATA -- derives from it and answers in @ref ScriptedPkcs15Card::answer;
/// one that needs to see each command as it arrives overrides
/// @ref ScriptedPkcs15Card::observe.
///
/// Every APDU is recorded BY VALUE in @ref ScriptedPkcs15Card::log, so
/// assertions scan value snapshots and never hold pointers into the card's
/// state across transmits.

#pragma once

#include <LibreSCRS/SmartCard/AppletAid.h>

#include <apdu.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::TestSupport {

struct ScriptedPkcs15Card
{
    using APDUCommand = LibreSCRS::SmartCard::Internal::APDUCommand;
    using APDUResponse = LibreSCRS::SmartCard::Internal::APDUResponse;

    virtual ~ScriptedPkcs15Card() = default;

    /// EF contents by FID (ODF / TokenInfo / AODF ...).
    std::map<std::uint16_t, std::vector<std::uint8_t>> files;
    /// FIDs that select OK but have no readable content (DFs on the path).
    /// Ignored when @ref parentOf is set.
    std::vector<std::uint16_t> selectableDfs{0x3F00};
    /// A file tree instead of a flat namespace: child FID -> the FID that
    /// must be selected for it to be selectable. When non-empty, SELECT by
    /// FID succeeds only for 3F00 (the root) and for a child of whatever is
    /// selected now; a FID absent here never selects.
    std::map<std::uint16_t, std::uint16_t> parentOf;
    /// SELECT by AID: 9000 when true, 6A82 when false.
    bool selectAidSucceeds = true;
    /// Answer the empty-VERIFY retry-counter probe: 6983 for a reference in
    /// @ref probeBlocked, 63Cx from @ref probeTries, 6A88 otherwise. Off, the
    /// probe is unsupported like any other command the card does not script.
    bool answersRetryProbe = false;
    std::map<std::uint8_t, int> probeTries;
    std::set<std::uint8_t> probeBlocked;
    /// Every APDU seen, copied by value.
    std::vector<APDUCommand> log;

    std::uint16_t selectedFid = 0;

    APDUResponse operator()(const APDUCommand& cmd)
    {
        log.push_back(cmd);
        observe(cmd);

        if (cmd.ins == 0xA4 && cmd.p1 == 0x04) // SELECT by AID
            return selectAidSucceeds ? APDUResponse{{}, 0x90, 0x00} : APDUResponse{{}, 0x6A, 0x82};

        if (cmd.ins == 0xA4 && cmd.p1 == 0x00 && cmd.data.size() == 2) { // SELECT by FID
            const auto fid = static_cast<std::uint16_t>((cmd.data[0] << 8) | cmd.data[1]);
            if (!selectable(fid))
                return {{}, 0x6A, 0x82};
            selectedFid = fid;
            return {{}, 0x90, 0x00};
        }

        if (cmd.ins == 0xB0) { // READ BINARY
            const auto it = files.find(selectedFid);
            if (it == files.end())
                return {{}, 0x69, 0x86};
            const std::size_t offset = (static_cast<std::size_t>(cmd.p1 & 0x7F) << 8) | cmd.p2;
            if (offset >= it->second.size())
                return {{}, 0x62, 0x82}; // EOF
            const std::size_t n = std::min<std::size_t>(cmd.le != 0 ? cmd.le : 256, it->second.size() - offset);
            std::vector<std::uint8_t> chunk(it->second.begin() + static_cast<std::ptrdiff_t>(offset),
                                            it->second.begin() + static_cast<std::ptrdiff_t>(offset + n));
            return {std::move(chunk), 0x90, 0x00};
        }

        if (answersRetryProbe && cmd.ins == 0x20 && cmd.data.empty()) { // empty-VERIFY retry-counter probe
            if (probeBlocked.contains(cmd.p2))
                return {{}, 0x69, 0x83};
            const auto it = probeTries.find(cmd.p2);
            if (it == probeTries.end())
                return {{}, 0x6A, 0x88};
            return {{}, 0x63, static_cast<std::uint8_t>(0xC0 | (it->second & 0x0F))};
        }

        if (auto reply = answer(cmd))
            return std::move(*reply);
        return {{}, 0x6D, 0x00}; // anything else: instruction not supported
    }

protected:
    /// The card's answer to a command the file system and the probe do not
    /// serve; nullopt answers 6D00.
    virtual std::optional<APDUResponse> answer(const APDUCommand&)
    {
        return std::nullopt;
    }

    /// Sees every command after it is logged and before it is answered.
    virtual void observe(const APDUCommand&) {}

private:
    bool selectable(std::uint16_t fid) const
    {
        if (!parentOf.empty()) {
            if (fid == 0x3F00)
                return true;
            const auto parent = parentOf.find(fid);
            return parent != parentOf.end() && parent->second == selectedFid;
        }
        return files.contains(fid) || std::find(selectableDfs.begin(), selectableDfs.end(), fid) != selectableDfs.end();
    }
};

// ---------------------------------------------------------------------------
// Profile files.
// ---------------------------------------------------------------------------

/// PKCS#15 application AID (A0 00 00 00 63 "PKCS-15") -- the AID the plugin
/// activates its channel for.
inline LibreSCRS::SmartCard::AppletAid pkcs15Aid()
{
    return LibreSCRS::SmartCard::AppletAid{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
}

/// EF.ODF with a single authObjects entry pointing at FID 4408.
inline std::vector<std::uint8_t> odfPointingAtAodf()
{
    return {0xA8, 0x06, 0x30, 0x04, 0x04, 0x02, 0x44, 0x08};
}

/// Minimal EF.TokenInfo: SEQUENCE { INTEGER 0, OCTET STRING serial,
/// [0] IMPLICIT label }.
inline std::vector<std::uint8_t> tokenInfoWithLabel(const std::string& label)
{
    std::vector<std::uint8_t> inner = {0x02, 0x01, 0x00, 0x04, 0x02, 0x30, 0x31};
    inner.push_back(0x80);
    inner.push_back(static_cast<std::uint8_t>(label.size()));
    inner.insert(inner.end(), label.begin(), label.end());
    std::vector<std::uint8_t> out = {0x30, static_cast<std::uint8_t>(inner.size())};
    out.insert(out.end(), inner.begin(), inner.end());
    return out;
}

/// EF.AODF of an unseen PKCS#15 card: ONE plain PIN ("PIN", ref 0x01,
/// initialized, 4/4/8, path 3F00) with no soPin / unblocking / PACE marks.
inline std::vector<std::uint8_t> plainPinAodf()
{
    return {0x30, 0x29,                               // SEQUENCE (41)
            0x30, 0x05, 0x0C, 0x03, 0x50, 0x49, 0x4E, //   CommonObjectAttributes "PIN"
            0x30, 0x03, 0x04, 0x01, 0x01,             //   CommonAuthObjectAttributes: id 01
            0xA1, 0x1B, 0x30, 0x19,                   //   [1] { PinAttributes
            0x03, 0x02, 0x00, 0x08,                   //     pinFlags 0x08 (initialized)
            0x0A, 0x01, 0x01,                         //     pinType ascii
            0x02, 0x01, 0x04,                         //     minLength 4
            0x02, 0x01, 0x04,                         //     storedLength 4
            0x02, 0x01, 0x08,                         //     maxLength 8
            0x80, 0x01, 0x01,                         //     pinReference 0x01
            0x30, 0x04, 0x04, 0x02, 0x3F, 0x00};      //     path 3F00 }
}

} // namespace LibreSCRS::TestSupport
