// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "opensc_reader_bridge.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <pcsc_connection.h> // PCSCConnection + APDUResponse (lib/smartcard/src)

// libopensc's OWN APDU (de)serialisers — the exact helpers reader-pcsc.c's
// pcsc_transmit uses (reader-pcsc.c:332,349). Declared in libopensc/internal.h;
// forward-declared here (extern "C") so the bridge encodes/decodes byte-for-byte
// identically to the real PC/SC reader op, rather than re-deriving the APDU
// wire form (a divergence in Le/case encoding broke card-driver match_card).
extern "C" {
int sc_apdu_get_octets(sc_context_t* ctx, const sc_apdu_t* apdu, unsigned char** buf, size_t* len, unsigned int proto);
int sc_apdu_set_resp(sc_context_t* ctx, sc_apdu_t* apdu, const unsigned char* buf, size_t len);
}

namespace LibreSCRS::OpenSc::Bridge {

namespace {

using LibreSCRS::SmartCard::Internal::APDUResponse;
using LibreSCRS::SmartCard::Internal::PCSCConnection;

// C-linkage reader-op callbacks. extern "C" makes them assignment-compatible
// with the sc_reader_operations C function-pointer fields (no language-linkage
// mismatch under -Wpedantic). All are noexcept at the C boundary: a C++
// exception must never cross the libopensc C frames, so transmit/lock catch
// everything and return an SC error code instead. The unique prefix + hidden
// plugin visibility keep them off any export surface.
extern "C" {

int librescrs_opensc_bridge_connect(sc_reader_t* /*reader*/)
{
    // The LM CardSession owns connect/disconnect; the card is already open and
    // reader->atr was pre-populated by initBridgeReader. Nothing to do.
    return SC_SUCCESS;
}

int librescrs_opensc_bridge_disconnect(sc_reader_t* /*reader*/)
{
    return SC_SUCCESS; // LM owns the real connection lifecycle.
}

int librescrs_opensc_bridge_transmit(sc_reader_t* reader, sc_apdu_t* apdu)
{
    auto* d = static_cast<BridgeData*>(reader->drv_data);
    if (d == nullptr || d->conn == nullptr)
        return SC_ERROR_TRANSMIT_FAILED;

    // Mirror reader-pcsc.c:pcsc_transmit so the bridge is byte-identical to the
    // real PC/SC reader op — only the wire call differs (the single LM
    // connection instead of SCardTransmit). OpenSC encodes the APDU (case / Lc /
    // Le per reader->active_protocol), we do ONE raw exchange on the single LM
    // connection (deadlock-safe — touches no sessionMutex), then OpenSC parses
    // the [body SW1 SW2] response back. libopensc performs GET RESPONSE (61xx),
    // the 6Cxx wrong-length retry, and response-buffer sizing ABOVE this op
    // (apdu.c: sc_transmit / sc_get_response) — which is why this MUST use the
    // raw single-exchange primitive: the filtered conn.transmit() runs its own
    // GET RESPONSE and returns the full accumulated body, overrunning
    // apdu->resplen (SC_ERROR_WRONG_LENGTH) and hiding the raw SW the card
    // drivers reason about.
    unsigned char* sbuf = nullptr;
    size_t ssize = 0;
    int r = sc_apdu_get_octets(reader->ctx, apdu, &sbuf, &ssize, reader->active_protocol);
    if (r != SC_SUCCESS)
        return r;

    try {
        APDUResponse resp = d->conn->transmitRaw(sbuf, static_cast<DWORD>(ssize));
        std::free(sbuf);
        sbuf = nullptr;

        // Reassemble the raw response buffer [body... SW1 SW2] for sc_apdu_set_resp.
        std::vector<unsigned char> rbuf;
        rbuf.reserve(resp.data.size() + 2);
        rbuf.insert(rbuf.end(), resp.data.begin(), resp.data.end());
        rbuf.push_back(resp.sw1);
        rbuf.push_back(resp.sw2);
        return sc_apdu_set_resp(reader->ctx, apdu, rbuf.data(), rbuf.size());
    } catch (...) {
        std::free(sbuf);
        return SC_ERROR_TRANSMIT_FAILED;
    }
}

int librescrs_opensc_bridge_lock(sc_reader_t* reader)
{
    auto* d = static_cast<BridgeData*>(reader->drv_data);
    if (d == nullptr || d->conn == nullptr)
        return SC_ERROR_TRANSMIT_FAILED;
    try {
        // The agent's ActiveChannelHolder may already own the one PC/SC
        // transaction on this connection. beginTransaction() is NOT
        // refcounted, so begin our own only when none is held — a nested
        // SCardBeginTransaction would unbalance the holder's.
        if (!d->conn->isTransactionHeld()) {
            d->conn->beginTransaction();
            d->ownsTransaction = true;
        }
        return SC_SUCCESS;
    } catch (...) {
        return SC_ERROR_READER; // e.g. PCSCError from beginTransaction
    }
}

int librescrs_opensc_bridge_unlock(sc_reader_t* reader)
{
    auto* d = static_cast<BridgeData*>(reader->drv_data);
    if (d == nullptr || d->conn == nullptr)
        return SC_SUCCESS;
    if (d->ownsTransaction) {
        d->conn->endTransaction(); // noexcept
        d->ownsTransaction = false;
    }
    return SC_SUCCESS;
}

} // extern "C"

sc_reader_operations makeBridgeOps()
{
    sc_reader_operations ops{}; // every op NULL by default; all are NULL-guarded
                                // except the ones we set (see card.c / apdu.c).
    ops.connect = librescrs_opensc_bridge_connect;
    ops.disconnect = librescrs_opensc_bridge_disconnect;
    ops.transmit = librescrs_opensc_bridge_transmit;
    ops.lock = librescrs_opensc_bridge_lock;
    ops.unlock = librescrs_opensc_bridge_unlock;
    return ops;
}

sc_reader_operations g_bridgeOps = makeBridgeOps();
sc_reader_driver g_bridgeDriver = {"LibreSCRS single-session bridge", "librescrs-bridge", &g_bridgeOps, nullptr};

} // anonymous namespace

void initBridgeReader(sc_context_t* ctx, OpenScBridge& bridge, std::span<const std::uint8_t> atr)
{
    sc_reader_t& reader = bridge.reader;
    reader = sc_reader_t{};
    reader.ctx = ctx; // set directly — NOT appended to ctx->readers
    reader.driver = &g_bridgeDriver;
    reader.ops = &g_bridgeOps;
    reader.drv_data = &bridge.data;
    reader.name = bridge.readerName.data(); // stable: the OpenScBridge owns it
    reader.flags = SC_READER_CARD_PRESENT;
    reader.active_protocol = SC_PROTO_T1;
    reader.supported_protocols = SC_PROTO_T1 | SC_PROTO_T0;
    reader.max_send_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE; // 255
    reader.max_recv_size = SC_READER_SHORT_APDU_MAX_RECV_SIZE; // 256

    const std::size_t n = std::min(atr.size(), sizeof(reader.atr.value));
    if (n > 0)
        std::memcpy(reader.atr.value, atr.data(), n);
    reader.atr.len = n;
}

} // namespace LibreSCRS::OpenSc::Bridge
