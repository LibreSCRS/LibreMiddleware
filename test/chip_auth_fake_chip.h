// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief A synthetic eMRTD chip for Chip Authentication tests: an EC key pair,
///        the DG14/DG15 DER that advertises it, and channels that speak the
///        card side of the CA / AA protocols. Everything is built from the
///        spec, never from card bytes, so the tests carry no personal data.
///
/// The honest fake in @ref EcdhCaCardChannel actually runs card-side ECDH
/// against the terminal's ephemeral key and derives the same session keys, so
/// a real plain→CA→SM upgrade can be driven and a wrong-key clone is caught on
/// the wire rather than by a hand-set flag.

#include "apdu.h"
#include "chip_auth_card_oracle.h"
#include "crypto_utils.h"

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace LibreSCRS::Test {

// --- BER-TLV helpers -------------------------------------------------------

inline void appendBer(std::vector<std::uint8_t>& out, std::size_t len)
{
    if (len < 0x80) {
        out.push_back(static_cast<std::uint8_t>(len));
    } else if (len <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(len));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<std::uint8_t>(len >> 8));
        out.push_back(static_cast<std::uint8_t>(len & 0xFF));
    }
}

inline std::vector<std::uint8_t> tlv(std::uint8_t tag, const std::vector<std::uint8_t>& value)
{
    std::vector<std::uint8_t> out;
    out.push_back(tag);
    appendBer(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

// --- EC card key -----------------------------------------------------------

struct EcDeleter
{
    void operator()(EVP_PKEY* p) const noexcept
    {
        EVP_PKEY_free(p);
    }
};
using EcKeyPtr = std::unique_ptr<EVP_PKEY, EcDeleter>;

/// A P-256 chip key: the private key stays on the "card" (this object), the
/// SubjectPublicKeyInfo DER goes into DG14/DG15.
struct EcCardKey
{
    EcKeyPtr pkey;
    std::vector<std::uint8_t> spkiDer;           // SubjectPublicKeyInfo
    std::vector<std::uint8_t> pointUncompressed; // 0x04 || X || Y

    static EcCardKey generate()
    {
        EcCardKey out;
        EVP_PKEY* raw = EVP_EC_gen("P-256");
        if (raw == nullptr) {
            throw std::runtime_error("EVP_EC_gen failed");
        }
        out.pkey.reset(raw);

        unsigned char* der = nullptr;
        const int len = i2d_PUBKEY(raw, &der);
        if (len <= 0) {
            throw std::runtime_error("i2d_PUBKEY failed");
        }
        out.spkiDer.assign(der, der + len);
        OPENSSL_free(der);

        std::size_t plen = 0;
        if (EVP_PKEY_get_octet_string_param(raw, "pub", nullptr, 0, &plen) != 1) {
            throw std::runtime_error("pub size query failed");
        }
        out.pointUncompressed.resize(plen);
        if (EVP_PKEY_get_octet_string_param(raw, "pub", out.pointUncompressed.data(), plen, &plen) != 1) {
            throw std::runtime_error("pub read failed");
        }
        out.pointUncompressed.resize(plen);
        return out;
    }
};

// OID content bytes (after tag+len).
// id-CA-ECDH-AES-CBC-CMAC-128 = 0.4.0.127.0.7.2.2.3.2.2
inline std::vector<std::uint8_t> oidCaEcdhAes128()
{
    return {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x02};
}
// id-PK-ECDH = 0.4.0.127.0.7.2.2.1.2
inline std::vector<std::uint8_t> oidPkEcdh()
{
    return {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01, 0x02};
}

/// DG14 (tag 0x6E) advertising one ChipAuthenticationInfo (AES-128) and one
/// ChipAuthenticationPublicKeyInfo carrying @p spki. No keyId in either, so
/// performChipAuth pairs them by the "both absent" rule.
inline std::vector<std::uint8_t> buildDg14(const std::vector<std::uint8_t>& spki)
{
    // ChipAuthenticationInfo: SEQ { OID(id-CA-ECDH-AES-128), INTEGER version=1 }
    std::vector<std::uint8_t> caInfo;
    {
        auto oid = tlv(0x06, oidCaEcdhAes128());
        std::vector<std::uint8_t> version = {0x02, 0x01, 0x01};
        std::vector<std::uint8_t> seqBody = oid;
        seqBody.insert(seqBody.end(), version.begin(), version.end());
        caInfo = tlv(0x30, seqBody);
    }
    // ChipAuthenticationPublicKeyInfo: SEQ { OID(id-PK-ECDH), SubjectPublicKeyInfo }
    std::vector<std::uint8_t> pkInfo;
    {
        auto oid = tlv(0x06, oidPkEcdh());
        std::vector<std::uint8_t> seqBody = oid;
        seqBody.insert(seqBody.end(), spki.begin(), spki.end()); // spki is already a SEQUENCE (0x30..)
        pkInfo = tlv(0x30, seqBody);
    }
    std::vector<std::uint8_t> setBody = caInfo;
    setBody.insert(setBody.end(), pkInfo.begin(), pkInfo.end());
    auto set = tlv(0x31, setBody);
    return tlv(0x6E, set);
}

/// DG15 (tag 0x6F) carrying a SubjectPublicKeyInfo for Active Authentication.
inline std::vector<std::uint8_t> buildDg15(const std::vector<std::uint8_t>& spki)
{
    return tlv(0x6F, spki);
}

// --- Card-side ECDH + SM --------------------------------------------------

/// The terminal's ephemeral point from GENERAL AUTHENTICATE data
/// 7C len { 80 len <point> }; empty when the frame does not have that shape.
inline std::vector<std::uint8_t> gaTerminalPoint(const std::vector<std::uint8_t>& gaData)
{
    // 7C len 80 len <point>
    if (gaData.size() < 4 || gaData[0] != 0x7C) {
        return {};
    }
    std::size_t pos = 2; // skip 7C + 1-byte len (small frames)
    if (pos + 2 > gaData.size() || gaData[pos] != 0x80) {
        return {};
    }
    const std::size_t len = gaData[pos + 1];
    pos += 2;
    if (pos + len > gaData.size()) {
        return {};
    }
    return {gaData.begin() + static_cast<std::ptrdiff_t>(pos), gaData.begin() + static_cast<std::ptrdiff_t>(pos + len)};
}

/// Card-side ECDH on P-256: the shared secret of @p staticKey (the chip's
/// private key) and the terminal's ephemeral @p peerPoint; empty on failure.
inline std::vector<std::uint8_t> cardSideEcdh(EVP_PKEY* staticKey, const std::vector<std::uint8_t>& peerPoint)
{
    // Rebuild the terminal's ephemeral public key on P-256 from its point.
    EVP_PKEY* peerRaw = nullptr;
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, "group", "P-256", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, "pub", peerPoint.data(), peerPoint.size());
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX* fromctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    std::vector<std::uint8_t> z;
    if (fromctx != nullptr && params != nullptr && EVP_PKEY_fromdata_init(fromctx) == 1 &&
        EVP_PKEY_fromdata(fromctx, &peerRaw, EVP_PKEY_PUBLIC_KEY, params) == 1 && peerRaw != nullptr) {
        EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(staticKey, nullptr);
        std::size_t zlen = 0;
        if (dctx != nullptr && EVP_PKEY_derive_init(dctx) == 1 && EVP_PKEY_derive_set_peer(dctx, peerRaw) == 1 &&
            EVP_PKEY_derive(dctx, nullptr, &zlen) == 1) {
            z.resize(zlen);
            if (EVP_PKEY_derive(dctx, z.data(), &zlen) == 1) {
                z.resize(zlen);
            } else {
                z.clear();
            }
        }
        EVP_PKEY_CTX_free(dctx);
    }
    EVP_PKEY_free(peerRaw);
    EVP_PKEY_CTX_free(fromctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return z;
}

/// One physical fake chip presented as an ISecureChannel usable as the
/// @c current channel in performChipAuth / ChipAuthChannel::establish. It
/// answers MSE:Set AT and GENERAL AUTHENTICATE on the plain leg, derives the
/// CA session keys card-side via ECDH, and (once established) hands out an
/// @ref AesSmCardOracle for the SM leg.
class EcdhCaCardChannel final : public LibreSCRS::SecureChannel::ISecureChannel
{
public:
    EcdhCaCardChannel(const EcCardKey& key, LibreSCRS::SmartCard::AppletAid aid)
        : staticKey(key.pkey.get()), currentAid(std::move(aid))
    {}

    // Script a status-word refusal at a given INS (0x22 MSE, 0x86 GA); when set
    // the channel returns that SW instead of processing the command.
    void refuseIns(std::uint8_t ins, std::uint8_t sw1, std::uint8_t sw2)
    {
        refusedIns = ins;
        refusedSw1 = sw1;
        refusedSw2 = sw2;
    }

    // After the handshake, corrupt the card's MAC key so the terminal's proof
    // exchange fails — the clone signal.
    void makeClone()
    {
        cloned = true;
    }

    // The SM oracle initialised during GENERAL AUTHENTICATE; null before that.
    [[nodiscard]] std::shared_ptr<AesSmCardOracle> smOracle() const noexcept
    {
        return sm;
    }

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept override
    {
        return currentAid;
    }
    [[nodiscard]] LibreSCRS::SecureChannel::ChannelState state() const noexcept override
    {
        return LibreSCRS::SecureChannel::ChannelState::Open;
    }

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken /*token*/) override
    {
        if (refusedIns && cmd.ins == *refusedIns) {
            return {{}, refusedSw1, refusedSw2};
        }
        if (cmd.ins == 0x22) { // MSE:Set AT
            return {{}, 0x90, 0x00};
        }
        if (cmd.ins == 0x86) { // GENERAL AUTHENTICATE
            deriveFromGa(cmd.data);
            return {{}, 0x90, 0x00};
        }
        return {{}, 0x6D, 0x00};
    }

    void close() override {}

protected:
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept override
    {
        currentAid = std::move(aid);
    }
    void replaceKeys(LibreSCRS::SecureChannel::SessionKeys /*keys*/) noexcept override {}

private:
    // Parse 7C { 80 <terminal ephemeral point> }, ECDH with the static key,
    // KDF the CA session keys, and stand up the card-side SM oracle.
    void deriveFromGa(const std::vector<std::uint8_t>& gaData)
    {
        namespace det = emrtd::crypto::detail;
        std::vector<std::uint8_t> point = gaTerminalPoint(gaData);
        if (point.empty()) {
            return;
        }
        auto z = cardSideEcdh(staticKey, point);
        if (z.empty()) {
            return;
        }
        auto kEnc = det::kdf(z, 1, false, 16);
        auto kMac = det::kdf(z, 2, false, 16);
        if (cloned) {
            kMac[0] ^= 0xFF; // wrong keys: the proof exchange must fail
        }
        sm = std::make_shared<AesSmCardOracle>(kEnc, kMac, std::vector<std::uint8_t>(16, 0x00));
    }

    EVP_PKEY* staticKey; // borrowed from the EcCardKey (must outlive this)
    LibreSCRS::SmartCard::AppletAid currentAid;
    std::optional<std::uint8_t> refusedIns;
    std::uint8_t refusedSw1 = 0x69;
    std::uint8_t refusedSw2 = 0x82;
    bool cloned = false;
    std::shared_ptr<AesSmCardOracle> sm;
};

/// The same chip seen from the wire: the card side of every frame a
/// session's connection sends (plain and SM-wrapped alike), for driving
/// Chip Authentication through @c CardSession on a detached connection.
///
/// It answers MSE:Set AT and GENERAL AUTHENTICATE either plain or inside a
/// live AES tunnel (@ref startInTunnel). After GENERAL AUTHENTICATE it
/// derives the CA session keys by ECDH and from then on speaks SM only under
/// them (SSC reset to zero, BSI TR-03110): a terminal still holding the old
/// keys is answered 6988, exactly like a chip that has rotated. Any plain
/// frame ends a live tunnel (ISO 7816-4 SM abort); a plain GENERAL
/// AUTHENTICATE that arrives while a tunnel is live is refused, not run.
/// Other commands, plain or decrypted from SM, go to @ref setFiles when set.
class CaCardOnTheWire
{
public:
    using APDUCommand = LibreSCRS::SmartCard::Internal::APDUCommand;
    using APDUResponse = LibreSCRS::SmartCard::Internal::APDUResponse;

    explicit CaCardOnTheWire(const EcCardKey& key) : staticKey(key.pkey.get()) {}

    /// Start inside an existing AES tunnel keyed by @p enc / @p mac / @p ssc
    /// (the PACE or BAC session the terminal already holds).
    void startInTunnel(std::vector<std::uint8_t> enc, std::vector<std::uint8_t> mac, std::vector<std::uint8_t> ssc)
    {
        sm = std::make_shared<AesSmCardOracle>(std::move(enc), std::move(mac), std::move(ssc));
    }

    /// Answer @p ins with the status word @p sw1 @p sw2: bare on a plain
    /// channel, protected (verified MAC, SW in DO'99) inside a tunnel.
    void refuseIns(std::uint8_t ins, std::uint8_t sw1, std::uint8_t sw2)
    {
        refusedIns = ins;
        refusedSw1 = sw1;
        refusedSw2 = sw2;
    }

    /// Inside a tunnel, answer @p ins with an unprotected 6988 and drop the
    /// session: a secure-messaging integrity failure on the card's side.
    void breakSmOn(std::uint8_t ins)
    {
        brokenSmIns = ins;
    }

    /// Derive a wrong MAC key after the key agreement: the proof exchange
    /// under the new keys fails — the clone signal.
    void makeClone()
    {
        cloned = true;
    }

    /// Run @p hook when a frame with @p ins arrives, before it is answered.
    /// A hook that returns a response replaces the card's answer (raw, as it
    /// leaves the card); a hook may also throw, like a failing reader.
    void onIns(std::uint8_t ins, std::function<std::optional<APDUResponse>()> hook)
    {
        hookIns = ins;
        insHook = std::move(hook);
    }

    /// Serve every other command (plain, or decrypted under SM) from @p files.
    void setFiles(std::function<APDUResponse(const APDUCommand&)> files)
    {
        fileSystem = std::move(files);
    }

    /// The SM engine currently live on the card; null when no tunnel is up.
    [[nodiscard]] std::shared_ptr<AesSmCardOracle> smOracle() const noexcept
    {
        return sm;
    }

    /// How many key agreements the card completed.
    [[nodiscard]] int keyAgreements() const noexcept
    {
        return agreements;
    }

    /// INS byte of every frame that reached the card, in order.
    [[nodiscard]] const std::vector<std::uint8_t>& insLog() const noexcept
    {
        return log;
    }

    /// A frame as the transport sends it (plain or wrapped).
    [[nodiscard]] APDUResponse respond(std::span<const std::uint8_t> frame)
    {
        if (frame.size() < 4) {
            return {{}, 0x6F, 0x00};
        }
        if ((frame[0] & 0x0C) == 0) {
            return respondPlain(parsePlain(frame));
        }
        const std::uint8_t ins = frame[1];
        log.push_back(ins);
        if (auto hooked = runHook(ins)) {
            return *hooked;
        }
        if (!sm) {
            return {{}, 0x69, 0x88};
        }
        if (brokenSmIns && *brokenSmIns == ins) {
            sm.reset(); // the card drops the session and says so unprotected
            return {{}, 0x69, 0x88};
        }
        auto tunnel = sm; // the answer goes out under the keys the command came in
        const int before = tunnel->verifiedCommands();
        AesSmCardOracle::CommandHandler files;
        if (refusedIns && *refusedIns == ins) {
            // A refusal inside the tunnel is itself protected.
            files = [this](std::uint8_t, std::uint8_t, std::uint8_t, const std::vector<std::uint8_t>&) {
                return APDUResponse{{}, refusedSw1, refusedSw2};
            };
        } else if (fileSystem) {
            files = [this](std::uint8_t i, std::uint8_t p1, std::uint8_t p2, const std::vector<std::uint8_t>& data) {
                if (i == 0x22 || i == 0x86) {
                    return APDUResponse{{}, 0x90, 0x00};
                }
                return fileSystem(APDUCommand{0x00, i, p1, p2, data, 0x00, true});
            };
        }
        auto resp = tunnel->respond(frame, files);
        const bool refused = refusedIns && *refusedIns == ins;
        if (!refused && tunnel->verifiedCommands() != before && tunnel->lastCommandIns() == 0x86) {
            agree(tunnel->lastCommandData()); // rotates after the answer is wrapped
        }
        return resp;
    }

    /// A plain command, as a transport filter sees it.
    [[nodiscard]] APDUResponse respondPlain(const APDUCommand& cmd)
    {
        log.push_back(cmd.ins);
        if (auto hooked = runHook(cmd.ins)) {
            return *hooked;
        }
        const bool tunnelWasLive = static_cast<bool>(sm);
        sm.reset();
        if (refusedIns && *refusedIns == cmd.ins) {
            return {{}, refusedSw1, refusedSw2};
        }
        if (cmd.ins == 0x86) {
            if (tunnelWasLive) {
                return {{}, 0x69, 0x82}; // the tunnel it should have come through is gone
            }
            agree(cmd.data);
            return {{}, 0x90, 0x00};
        }
        if (cmd.ins == 0x22) {
            return {{}, 0x90, 0x00};
        }
        if (fileSystem) {
            return fileSystem(cmd);
        }
        if (cmd.ins == 0xA4) {
            return {{}, 0x90, 0x00};
        }
        return {{}, 0x6D, 0x00};
    }

private:
    std::optional<APDUResponse> runHook(std::uint8_t ins)
    {
        if (insHook && hookIns == ins) {
            return insHook();
        }
        return std::nullopt;
    }

    static APDUCommand parsePlain(std::span<const std::uint8_t> frame)
    {
        APDUCommand cmd{frame[0], frame[1], frame[2], frame[3], {}, 0x00, false};
        if (frame.size() == 5) {
            cmd.le = frame[4];
            cmd.hasLe = true;
        } else if (frame.size() > 5) {
            const std::size_t lc = frame[4];
            if (5 + lc <= frame.size()) {
                cmd.data.assign(frame.begin() + 5, frame.begin() + 5 + static_cast<std::ptrdiff_t>(lc));
                if (5 + lc < frame.size()) {
                    cmd.le = frame[5 + lc];
                    cmd.hasLe = true;
                }
            }
        }
        return cmd;
    }

    void agree(const std::vector<std::uint8_t>& gaData)
    {
        namespace det = emrtd::crypto::detail;
        const auto point = gaTerminalPoint(gaData);
        if (point.empty()) {
            return;
        }
        const auto z = cardSideEcdh(staticKey, point);
        if (z.empty()) {
            return;
        }
        auto kEnc = det::kdf(z, 1, false, 16);
        auto kMac = det::kdf(z, 2, false, 16);
        if (cloned) {
            kMac[0] ^= 0xFF;
        }
        sm = std::make_shared<AesSmCardOracle>(kEnc, kMac, std::vector<std::uint8_t>(16, 0x00));
        ++agreements;
    }

    EVP_PKEY* staticKey; // borrowed from the EcCardKey (must outlive this)
    std::shared_ptr<AesSmCardOracle> sm;
    std::optional<std::uint8_t> refusedIns;
    std::uint8_t refusedSw1 = 0x69;
    std::uint8_t refusedSw2 = 0x82;
    std::optional<std::uint8_t> hookIns;
    std::optional<std::uint8_t> brokenSmIns;
    std::function<std::optional<APDUResponse>()> insHook;
    std::function<APDUResponse(const APDUCommand&)> fileSystem;
    bool cloned = false;
    int agreements = 0;
    std::vector<std::uint8_t> log;
};

} // namespace LibreSCRS::Test
