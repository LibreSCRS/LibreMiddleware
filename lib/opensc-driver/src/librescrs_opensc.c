/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Copyright hirashix0@proton.me */

/*
 * librescrs_opensc.c — OpenSC external card driver for Serbian smart cards
 *                      with the CardEdge PKI applet.
 *
 * Supported cards:
 *   - Serbian eID Gemalto (2014+)   ATR: 3B FF 94 ...
 *   - Serbian eID IF2020 Foreigner  (AID-matched)
 *   - PKS Chamber of Commerce card  (AID-matched)
 *
 * Apollo 2008 eID has no CardEdge applet and is NOT supported.
 * Serbian health card (SERVSZK) is explicitly rejected in match_card().
 *
 * Build instructions:
 *   Linux:  cmake -DBUILD_OPENSC_DRIVER=ON ...
 *   macOS:  cmake -DBUILD_OPENSC_DRIVER=ON \
 *               -DOPENSC_INCLUDE_DIR=/path/to/OpenSC/src ...
 *
 * Usage: see conf/librescrs.conf for opensc.conf snippet.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "libopensc/opensc.h"
#include "libopensc/cards.h"
#include "libopensc/log.h"
#include "libopensc/internal.h"
#include "libopensc/pkcs15.h"
#include "libopensc/pkcs15-syn.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* -------------------------------------------------------------------------
 * CardEdge PKI applet AID  (A0 00 00 00 63 50 4B 43 53 2D 31 35)
 * Same AID used by Serbian eID Gemalto, IF2020 Foreigner, and PKS card.
 * ------------------------------------------------------------------------- */
static const u8 AID_PKCS15[] = {
    0xA0, 0x00, 0x00, 0x00, 0x63,
    0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35
};
#define AID_PKCS15_LEN  (sizeof(AID_PKCS15))

/* Serbian health card (SERVSZK) AID — must be rejected in match_card()
 * to avoid false-positive (health cards also respond to AID_PKCS15). */
static const u8 AID_SERVSZK[] = {
    0xF3, 0x81, 0x00, 0x00, 0x02,
    0x53, 0x45, 0x52, 0x56, 0x53, 0x5A, 0x4B, 0x01
};
#define AID_SERVSZK_LEN (sizeof(AID_SERVSZK))

/* CardEdge cmapfile constants (lib/cardedge/src/cardedge_protocol.h). */
#define CE_CMAP_RECORD_SIZE     86u
#define CE_CMAP_FLAGS_OFFSET    80u
#define CE_CMAP_SIG_SIZE_OFFSET 82u
#define CE_CMAP_KX_SIZE_OFFSET  84u
#define CE_CMAP_VALID_CONTAINER 0x01u
#define CE_KEYS_BASE_FID        0x6000u
#define CE_KEY_KIND_PRIVATE     1u
#define CE_AT_KEYEXCHANGE       1u
#define CE_AT_SIGNATURE         2u
#define CE_PKI_ROOT_DIR_FID     0x7000u
#define CE_PKI_READ_CHUNK       0x80u
#define CE_DIR_HEADER_SIZE      10u
#define CE_DIR_ENTRY_SIZE       12u

/* PIN constants. */
#define CE_PIN_REFERENCE        0x80u
#define CE_PIN_MAX_LENGTH       8u

/* MSE algorithm byte for RSA-2048 PKCS#1 v1.5. */
#define CE_MSE_ALG_RSA2048      0x02u

/* Private key FID formula: same as cardedge::protocol::privateKeyFID(). */
static unsigned int ce_private_key_fid(unsigned int cont_idx,
                                        unsigned int key_pair_id)
{
    return CE_KEYS_BASE_FID
        | ((cont_idx   << 4) & 0x0FF0u)
        | ((key_pair_id << 2) & 0x000Cu)
        | CE_KEY_KIND_PRIVATE;
}

/* Per-card private data stored in card->drv_data. */
typedef struct librescrs_private {
    int      card_type;  /* SC_CARD_TYPE_UNKNOWN for now; extended in Phase 3 */
    u8       pin_tries;  /* cached tries-left (0 = unknown/uncached) */
    unsigned key_ref;    /* 2-byte key FID saved by set_security_env */
} librescrs_private_t;

#define DRIVER_DESCRIPTION "LibreSCRS Serbian eID / CardEdge driver"
#define DRIVER_SHORT_NAME  "librescrs"

/*
 * ATR table.
 *
 * Gemalto (2014+) Serbian eID:  3B FF 94 ...
 * Mask FF FF FF matches the first 3 bytes; remaining bytes vary between
 * individual cards and are don't-cares.
 *
 * IF2020 Foreigner and PKS cards have no distinct ATR and are identified
 * via AID selection in match_card() (Phase 2).
 *
 * Apollo 2008 ATR 3B B9 18 ... is intentionally absent — no CardEdge applet.
 */
static struct sc_atr_table librescrs_atrs[] = {
    /* value          mask      name                           type                    flags  private */
    { "3B:FF:94",  "FF:FF:FF",  "Serbian eID (Gemalto 2014+)", SC_CARD_TYPE_UNKNOWN, 0,     NULL },
    { NULL, NULL, NULL, 0, 0, NULL }
};

/* Select an AID and return the status word (0 on transport error). */
static int librescrs_select_aid(sc_card_t *card, const u8 *aid, size_t aid_len)
{
    sc_apdu_t apdu;
    u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
    int r;

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
    apdu.data    = aid;
    apdu.datalen = aid_len;
    apdu.lc      = aid_len;
    apdu.resp    = rbuf;
    apdu.resplen = sizeof(rbuf);
    apdu.le      = 256;

    r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        return 0;
    return (apdu.sw1 << 8) | apdu.sw2;
}

static int librescrs_match_card(sc_card_t *card)
{
    int sw;

    /* ATR hit: Gemalto 2014+ Serbian eID (3B FF 94 ...) */
    if (_sc_match_atr(card, librescrs_atrs, &card->type) >= 0)
        return 1;

    /*
     * AID-based match for IF2020 Foreigner and PKS cards.
     *
     * Health cards (SERVSZK) also accept AID_PKCS15 — reject them first.
     * This mirrors the PKSCard::probe() false-positive fix in lib/pkscard/.
     */
    sw = librescrs_select_aid(card, AID_SERVSZK, AID_SERVSZK_LEN);
    if (sw == 0x9000) {
        sc_log(card->ctx, "librescrs: health card detected, not claiming\n");
        return 0;
    }

    sw = librescrs_select_aid(card, AID_PKCS15, AID_PKCS15_LEN);
    if (sw == 0x9000) {
        sc_log(card->ctx, "librescrs: CardEdge applet found via AID\n");
        return 1;
    }

    return 0;
}

static int librescrs_init(sc_card_t *card)
{
    librescrs_private_t *priv;

    priv = calloc(1, sizeof(*priv));
    if (!priv)
        return SC_ERROR_OUT_OF_MEMORY;

    priv->card_type = card->type;
    card->drv_data  = priv;

    /* Advertise RSA-2048 with PKCS#1 v1.5 padding, no hash (DigestInfo
     * is pre-formatted by the caller; the card does raw RSA). */
    _sc_card_add_rsa_alg(card, 2048,
        SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE,
        0);

    sc_log(card->ctx, "librescrs: init OK\n");
    return SC_SUCCESS;
}

static int librescrs_finish(sc_card_t *card)
{
    free(card->drv_data);
    card->drv_data = NULL;
    return SC_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Low-level file I/O helpers
 * ------------------------------------------------------------------------- */

/*
 * SELECT EF by 2-byte file ID using a raw APDU.
 *
 * CardEdge responds with a proprietary 10-byte FCI (not ISO 7816 TLV),
 * so we must NOT go through sc_select_file() / iso7816_select_file()
 * which would try to parse it as tag-0x6F TLV and return
 * SC_ERROR_UNKNOWN_DATA_RECEIVED.
 *
 * CardEdge FCI layout (10 bytes, all big-endian):
 *   [FID_H FID_L Size_H Size_L ACL*6]
 *
 * Returns the file size on success, or a negative SC_ERROR_* code.
 */
static int librescrs_select_fid_raw(sc_card_t *card, unsigned int fid)
{
    sc_apdu_t apdu;
    u8 fid_bytes[2];
    u8 fci[16];
    int r;

    fid_bytes[0] = (u8)((fid >> 8) & 0xFF);
    fid_bytes[1] = (u8)(fid & 0xFF);

    /* SELECT FILE by file ID (P1=0x00 P2=0x00), request FCI (Le=0x08) */
    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x00, 0x00);
    apdu.data    = fid_bytes;
    apdu.datalen = 2;
    apdu.lc      = 2;
    apdu.resp    = fci;
    apdu.resplen = sizeof(fci);
    apdu.le      = 10;  /* CardEdge FCI is exactly 10 bytes */

    r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        return r;
    if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
        return SC_ERROR_FILE_NOT_FOUND;

    /* Parse file size from bytes [2:3] (big-endian) */
    if (apdu.resplen < 4)
        return SC_ERROR_UNKNOWN_DATA_RECEIVED;

    return (int)(((unsigned)fci[2] << 8) | (unsigned)fci[3]);
}

/*
 * Select FID and read the entire file into a malloc'd buffer using raw APDUs.
 * *out_len receives the byte count; caller must free() the buffer.
 * Returns SC_SUCCESS or a negative SC_ERROR_* code.
 */
static int librescrs_read_fid(sc_card_t *card, unsigned int fid,
                               u8 **buf_out, size_t *out_len)
{
    int file_size;
    u8 *buf;
    size_t offset = 0;

    *buf_out = NULL;
    *out_len = 0;

    file_size = librescrs_select_fid_raw(card, fid);
    if (file_size < 0)
        return file_size;
    if (file_size == 0)
        return SC_SUCCESS;

    buf = malloc((size_t)file_size);
    if (!buf)
        return SC_ERROR_OUT_OF_MEMORY;

    while (offset < (size_t)file_size) {
        sc_apdu_t apdu;
        size_t chunk = CE_PKI_READ_CHUNK;
        int r;

        if (offset + chunk > (size_t)file_size)
            chunk = (size_t)file_size - offset;

        /* READ BINARY: 00 B0 [off_high] [off_low] Le */
        sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0,
                       (u8)((offset >> 8) & 0x7F),
                       (u8)(offset & 0xFF));
        apdu.resp    = buf + offset;
        apdu.resplen = chunk;
        apdu.le      = chunk;

        r = sc_transmit_apdu(card, &apdu);
        if (r < 0) { free(buf); return r; }

        /* Accept 0x9000 (success) and 0x62XX (warning/EOF) */
        if (apdu.sw1 != 0x90 && apdu.sw1 != 0x62) {
            free(buf);
            return SC_ERROR_CARD_CMD_FAILED;
        }
        if (apdu.resplen == 0)
            break;
        offset += apdu.resplen;
    }

    *buf_out = buf;
    *out_len = offset;
    return SC_SUCCESS;
}

/* -------------------------------------------------------------------------
 * CardEdge directory + cmapfile parsing
 * ------------------------------------------------------------------------- */

/* One entry from a CardEdge directory file. */
typedef struct ce_dir_entry {
    char     name[9];   /* 8-char name + NUL */
    unsigned fid;
    int      is_dir;
} ce_dir_entry_t;

/* Parse a CardEdge directory file into an array of ce_dir_entry_t.
 * *entries_out: caller must free().  Returns entry count or -1 on error. */
static int ce_parse_dir(const u8 *data, size_t len,
                        ce_dir_entry_t **entries_out)
{
    unsigned count, i;
    ce_dir_entry_t *entries;

    *entries_out = NULL;
    if (len < CE_DIR_HEADER_SIZE)
        return -1;

    count = (unsigned)data[6] | ((unsigned)data[7] << 8);
    if (count == 0)
        return 0;

    entries = calloc(count, sizeof(*entries));
    if (!entries)
        return -1;

    for (i = 0; i < count; i++) {
        size_t off = CE_DIR_HEADER_SIZE + (size_t)i * CE_DIR_ENTRY_SIZE;
        if (off + CE_DIR_ENTRY_SIZE > len) {
            free(entries);
            return -1;
        }
        /* Name: up to 8 ASCII chars, may not be NUL-terminated on card. */
        memcpy(entries[i].name, data + off, 8);
        entries[i].name[8] = '\0';
        /* Strip trailing spaces/NULs. */
        {
            int k = 7;
            while (k >= 0 && (entries[i].name[k] == ' ' ||
                               entries[i].name[k] == '\0'))
                entries[i].name[k--] = '\0';
        }
        entries[i].fid    = (unsigned)data[off + 8] |
                            ((unsigned)data[off + 9] << 8);
        entries[i].is_dir = (data[off + 10] != 0);
    }

    *entries_out = entries;
    return (int)count;
}

/* -------------------------------------------------------------------------
 * PKCS#15 emulation — bind callback
 * ------------------------------------------------------------------------- */

typedef struct cert_entry {
    char     label[32];
    unsigned cert_fid;
    unsigned key_fid;
    unsigned key_size_bits;
    unsigned cont_id;
    unsigned key_pair_id;  /* CE_AT_KEYEXCHANGE or CE_AT_SIGNATURE */
} cert_entry_t;

/* Select AID_PKCS15 and enumerate certificates from mscp/cmapfile.
 * *certs_out: caller must free().  Returns cert count or negative error. */
static int librescrs_enum_certs(sc_card_t *card,
                                 cert_entry_t **certs_out)
{
    u8 *dir_buf = NULL, *mscp_buf = NULL, *cmap_buf = NULL;
    size_t dir_len = 0, mscp_len = 0, cmap_len = 0;
    ce_dir_entry_t *root_entries = NULL, *mscp_entries = NULL;
    int root_count = 0, mscp_count = 0;
    unsigned mscp_fid = 0, cmap_fid = 0;
    cert_entry_t *certs = NULL;
    int ncerts = 0, cap = 8;
    int r, i;
    size_t cmap_offset = 0, cmap_nrec = 0;

    *certs_out = NULL;

    /* Select PKI applet. */
    if (librescrs_select_aid(card, AID_PKCS15, AID_PKCS15_LEN) != 0x9000) {
        r = SC_ERROR_CARD_CMD_FAILED;
        goto out;
    }

    /* Read root directory (FID 0x7000). */
    r = librescrs_read_fid(card, CE_PKI_ROOT_DIR_FID, &dir_buf, &dir_len);
    if (r < 0) goto out;

    root_count = ce_parse_dir(dir_buf, dir_len, &root_entries);
    if (root_count < 0) { r = SC_ERROR_INVALID_DATA; goto out; }

    for (i = 0; i < root_count; i++) {
        if (root_entries[i].is_dir &&
            strcmp(root_entries[i].name, "mscp") == 0) {
            mscp_fid = root_entries[i].fid;
            break;
        }
    }
    if (mscp_fid == 0) { r = SC_ERROR_FILE_NOT_FOUND; goto out; }

    /* Read mscp directory. */
    r = librescrs_read_fid(card, mscp_fid, &mscp_buf, &mscp_len);
    if (r < 0) goto out;

    mscp_count = ce_parse_dir(mscp_buf, mscp_len, &mscp_entries);
    if (mscp_count < 0) { r = SC_ERROR_INVALID_DATA; goto out; }

    /* Collect cert file entries and cmapfile FID. */
    certs = calloc((size_t)cap, sizeof(*certs));
    if (!certs) { r = SC_ERROR_OUT_OF_MEMORY; goto out; }

    for (i = 0; i < mscp_count; i++) {
        ce_dir_entry_t *e = &mscp_entries[i];
        if (e->is_dir) continue;

        if (strcmp(e->name, "cmapfile") == 0) {
            cmap_fid = e->fid;
        } else if (strlen(e->name) == 5) {
            unsigned kp_id;
            const char *lbl;
            if (strncmp(e->name, "kxc", 3) == 0) {
                kp_id = CE_AT_KEYEXCHANGE;
                lbl   = "Key Exchange Certificate";
            } else if (strncmp(e->name, "ksc", 3) == 0) {
                kp_id = CE_AT_SIGNATURE;
                lbl   = "Digital Signature Certificate";
            } else {
                continue;
            }

            if (ncerts >= cap) {
                cert_entry_t *tmp2 = realloc(certs,
                    (size_t)(cap * 2) * sizeof(*certs));
                if (!tmp2) { r = SC_ERROR_OUT_OF_MEMORY; goto out; }
                certs = tmp2;
                cap  *= 2;
            }

            certs[ncerts].cont_id     = (unsigned)(e->name[3] - '0') * 10
                                      + (unsigned)(e->name[4] - '0');
            certs[ncerts].cert_fid    = e->fid;
            certs[ncerts].key_pair_id = kp_id;
            snprintf(certs[ncerts].label, sizeof(certs[ncerts].label),
                     "%s", lbl);
            ncerts++;
        }
    }

    /* Read cmapfile and resolve key FIDs. */
    if (cmap_fid != 0) {
        r = librescrs_read_fid(card, cmap_fid, &cmap_buf, &cmap_len);
        if (r == SC_SUCCESS) {
            /* Optional 2-byte prefix present when len-2 is multiple of 86. */
            if (cmap_len >= 2 && (cmap_len - 2) % CE_CMAP_RECORD_SIZE == 0)
                cmap_offset = 2;
            cmap_nrec = (cmap_len - cmap_offset) / CE_CMAP_RECORD_SIZE;
        }
    }

    for (i = 0; i < ncerts; i++) {
        unsigned ci = certs[i].cont_id;
        if (cmap_buf && ci < cmap_nrec) {
            size_t rec = cmap_offset + (size_t)ci * CE_CMAP_RECORD_SIZE;
            u8 flags = cmap_buf[rec + CE_CMAP_FLAGS_OFFSET];
            if (flags & CE_CMAP_VALID_CONTAINER) {
                size_t sz_off = (certs[i].key_pair_id == CE_AT_KEYEXCHANGE)
                    ? rec + CE_CMAP_KX_SIZE_OFFSET
                    : rec + CE_CMAP_SIG_SIZE_OFFSET;
                unsigned kbits = (unsigned)cmap_buf[sz_off]
                               | ((unsigned)cmap_buf[sz_off + 1] << 8);
                if (kbits != 0) {
                    certs[i].key_size_bits = kbits;
                    certs[i].key_fid =
                        ce_private_key_fid(ci, certs[i].key_pair_id);
                }
            }
        }
        sc_log(card->ctx,
               "librescrs: cert[%d] \"%s\" cert_fid=0x%04x "
               "key_fid=0x%04x key_size=%u\n",
               i, certs[i].label, certs[i].cert_fid,
               certs[i].key_fid, certs[i].key_size_bits);
    }

    *certs_out = certs;
    certs = NULL;
    r = ncerts;

out:
    free(dir_buf);
    free(mscp_buf);
    free(cmap_buf);
    free(root_entries);
    free(mscp_entries);
    free(certs);
    return r;
}

/* -------------------------------------------------------------------------
 * PKCS#15 emulation — cert/key read helpers called by bind
 * ------------------------------------------------------------------------- */

/* Read the raw (possibly compressed) cert file and return DER bytes.
 * CardEdge cert file layout:
 *   [CardFS len prefix: 2 bytes LE]
 *   [0x01 0x00] [uncompressed len: 2 bytes LE] [zlib data]   — compressed
 *   OR [0x30 ...]                                             — raw DER
 */
static int librescrs_read_cert_der(sc_card_t *card, unsigned cert_fid,
                                    u8 **der_out, size_t *der_len_out)
{
    u8 *raw = NULL;
    size_t raw_len = 0;
    int r;

    *der_out     = NULL;
    *der_len_out = 0;

    r = librescrs_read_fid(card, cert_fid, &raw, &raw_len);
    if (r < 0)
        return r;

    if (raw_len < 6) {
        free(raw);
        return SC_ERROR_INVALID_DATA;
    }

    /* Skip 2-byte CardFS length prefix. */
    const u8 *data = raw + 2;
    size_t     dlen = raw_len - 2;

    if (dlen >= 4 && data[0] == 0x01 && data[1] == 0x00) {
        /* zlib-compressed DER */
        size_t uncompressed_len = (size_t)data[2] | ((size_t)data[3] << 8);
        u8 *der = malloc(uncompressed_len);
        if (!der) { free(raw); return SC_ERROR_OUT_OF_MEMORY; }

        uLongf dest_len = (uLongf)uncompressed_len;
        int zr = uncompress(der, &dest_len, data + 4,
                            (unsigned long)(dlen - 4));
        if (zr != 0) {
            sc_log(card->ctx,
                   "librescrs: zlib uncompress failed (ret=%d)\n", zr);
            free(der);
            free(raw);
            return SC_ERROR_INVALID_DATA;
        }
        *der_out     = der;
        *der_len_out = (size_t)dest_len;  /* uLongf → size_t */
    } else if (dlen >= 1 && data[0] == 0x30) {
        /* Uncompressed DER (ASN.1 SEQUENCE tag). */
        u8 *der = malloc(dlen);
        if (!der) { free(raw); return SC_ERROR_OUT_OF_MEMORY; }
        memcpy(der, data, dlen);
        *der_out     = der;
        *der_len_out = dlen;
    } else {
        sc_log(card->ctx,
               "librescrs: cert FID 0x%04x: unknown format (byte0=0x%02x)\n",
               cert_fid, data[0]);
        free(raw);
        return SC_ERROR_INVALID_DATA;
    }

    free(raw);
    return SC_SUCCESS;
}

/* -------------------------------------------------------------------------
 * PKCS#15 bind callback
 * ------------------------------------------------------------------------- */

static int librescrs_pkcs15_bind(sc_pkcs15_card_t *p15card,
                                  struct sc_aid *aid)
{
    sc_card_t      *card = p15card->card;
    cert_entry_t   *certs = NULL;
    int             ncerts, i, r = SC_SUCCESS;

    (void)aid;

    sc_log(card->ctx, "librescrs: pkcs15 bind\n");

    ncerts = librescrs_enum_certs(card, &certs);
    if (ncerts < 0) {
        sc_log(card->ctx, "librescrs: cert enumeration failed: %d\n", ncerts);
        return ncerts;
    }
    if (ncerts == 0) {
        sc_log(card->ctx, "librescrs: no certificates found\n");
        r = SC_SUCCESS;
        goto out;
    }

    /* Set card label. */
    free(p15card->tokeninfo->label);
    p15card->tokeninfo->label = strdup("LibreSCRS Card");
    free(p15card->tokeninfo->manufacturer_id);
    p15card->tokeninfo->manufacturer_id = strdup("LibreSCRS");

    /*
     * Query PIN tries_left now — AID_PKCS15 is still selected from enum_certs.
     * VERIFY Case 1 (no data body) checks status without consuming a try.
     */
    int pin_tries_left = -1;
    {
        sc_apdu_t tapdu;
        int rv;
        sc_format_apdu(card, &tapdu, SC_APDU_CASE_1, 0x20, 0x00,
                       CE_PIN_REFERENCE);
        rv = sc_transmit_apdu(card, &tapdu);
        if (rv >= 0) {
            if (tapdu.sw1 == 0x63 && (tapdu.sw2 & 0xF0) == 0xC0)
                pin_tries_left = tapdu.sw2 & 0x0F;
            else if (tapdu.sw1 == 0x69 && tapdu.sw2 == 0x83)
                pin_tries_left = 0;
            /* 0x9000 = PIN session active → tries_left stays -1 (unknown) */
        }
        sc_log(card->ctx, "librescrs: PIN tries_left=%d\n", pin_tries_left);
    }

    /* ---- PIN auth object ----
     * Must be registered before private keys so auth_id links work.
     * pkcs11-tool uses this to know which PIN to prompt for before signing. */
    {
        sc_pkcs15_auth_info_t auth_info;
        sc_pkcs15_object_t    auth_obj;

        memset(&auth_info, 0, sizeof(auth_info));
        memset(&auth_obj,  0, sizeof(auth_obj));

        auth_info.auth_type               = SC_PKCS15_PIN_AUTH_TYPE_PIN;
        auth_info.auth_method             = SC_AC_CHV;
        auth_info.tries_left              = pin_tries_left;
        auth_info.attrs.pin.reference     = CE_PIN_REFERENCE;
        auth_info.attrs.pin.min_length    = 4;
        auth_info.attrs.pin.max_length    = CE_PIN_MAX_LENGTH;
        auth_info.attrs.pin.stored_length = CE_PIN_MAX_LENGTH;
        auth_info.attrs.pin.type          = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
        auth_info.attrs.pin.pad_char      = 0x00;
        auth_info.attrs.pin.flags         = SC_PKCS15_PIN_FLAG_INITIALIZED |
                                            SC_PKCS15_PIN_FLAG_LOCAL;
        auth_info.auth_id.len      = 1;
        auth_info.auth_id.value[0] = 1;  /* PIN ID used by all private key auth_ids */

        strncpy(auth_obj.label, "User PIN", sizeof(auth_obj.label) - 1);
        /* No auth needed to query PIN info itself. */
        auth_obj.auth_id.len = 0;
        auth_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

        r = sc_pkcs15emu_add_pin_obj(p15card, &auth_obj, &auth_info);
        if (r < 0) {
            sc_log(card->ctx, "librescrs: add PIN obj failed: %d\n", r);
            goto out;
        }
    }

    for (i = 0; i < ncerts; i++) {
        sc_pkcs15_prkey_info_t  key_info;
        sc_pkcs15_object_t      key_obj;
        sc_pkcs15_cert_info_t   cert_info;
        sc_pkcs15_object_t      cert_obj;
        u8                     *der = NULL;
        size_t                  der_len = 0;
        int                     is_kxc = (certs[i].key_pair_id == CE_AT_KEYEXCHANGE);

        /* ---- Private key object ---- */
        memset(&key_info, 0, sizeof(key_info));
        memset(&key_obj,  0, sizeof(key_obj));

        key_info.id.len      = 1;
        key_info.id.value[0] = (u8)(i + 1);
        key_info.native      = 1;
        key_info.key_reference = (int)certs[i].key_fid;
        key_info.modulus_length = certs[i].key_size_bits
                                  ? certs[i].key_size_bits : 2048;

        /*
         * Key usage flags by type:
         *   kxc (AT_KEYEXCHANGE) — encryption / key wrapping / decryption
         *   ksc (AT_SIGNATURE)   — digital signature / non-repudiation only
         */
        if (is_kxc) {
            key_info.usage = SC_PKCS15_PRKEY_USAGE_ENCRYPT |
                             SC_PKCS15_PRKEY_USAGE_DECRYPT |
                             SC_PKCS15_PRKEY_USAGE_WRAP    |
                             SC_PKCS15_PRKEY_USAGE_UNWRAP  |
                             SC_PKCS15_PRKEY_USAGE_SIGN;
        } else {
            key_info.usage = SC_PKCS15_PRKEY_USAGE_SIGN |
                             SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
        }

        /*
         * Do NOT set key_info.path — that would trigger select_key_file()
         * in use_key(), which appends the key FID to the PKCS#15 app path
         * and calls sc_select_file(), which fails on CardEdge's non-TLV FCI.
         *
         * With path zeroed, use_key() skips select_key_file() entirely and
         * calls set_security_env() directly.  The key FID is reconstructed
         * there from key_info.key_reference via the CE_KEYS_BASE_FID formula.
         */

        strncpy(key_obj.label, certs[i].label, sizeof(key_obj.label) - 1);
        key_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
        /* Link to the PIN auth object registered above. */
        key_obj.auth_id.len      = 1;
        key_obj.auth_id.value[0] = 1;

        r = sc_pkcs15emu_add_rsa_prkey(p15card, &key_obj, &key_info);
        if (r < 0) {
            sc_log(card->ctx,
                   "librescrs: add prkey[%d] failed: %d\n", i, r);
            goto out;
        }

        /* ---- Certificate object ---- */
        if (librescrs_read_cert_der(card, certs[i].cert_fid,
                                    &der, &der_len) < 0) {
            sc_log(card->ctx,
                   "librescrs: could not read cert[%d] DER\n", i);
            continue;
        }

        memset(&cert_info, 0, sizeof(cert_info));
        memset(&cert_obj,  0, sizeof(cert_obj));

        cert_info.id.len      = 1;
        cert_info.id.value[0] = (u8)(i + 1);
        cert_info.authority   = 0;

        /* Store DER directly in the PKCS#15 value buffer. */
        cert_info.value.value = der;      /* ownership transferred */
        cert_info.value.len   = der_len;

        strncpy(cert_obj.label, certs[i].label, sizeof(cert_obj.label) - 1);

        r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
        if (r < 0) {
            sc_log(card->ctx,
                   "librescrs: add cert[%d] failed: %d\n", i, r);
            free(der);
            goto out;
        }
        /* der ownership now belongs to p15card; do not free. */
    }

    sc_log(card->ctx, "librescrs: pkcs15 bind OK (%d certs)\n", ncerts);

out:
    free(certs);
    return r;
}

static struct sc_card_operations librescrs_ops;

/* -------------------------------------------------------------------------
 * restore_security_env — no persistent SE on CardEdge; always succeeds.
 * OpenSC calls this before set_security_env on some code paths.
 * ------------------------------------------------------------------------- */
static int librescrs_restore_security_env(sc_card_t *card, int se_num)
{
    (void)card;
    (void)se_num;
    return SC_SUCCESS;
}

/* -------------------------------------------------------------------------
 * set_security_env — saves key FID from the path in the security environment.
 *
 * OpenSC's PKCS#15 layer populates env->file_ref from key_info.path (set in
 * librescrs_pkcs15_bind) and env->key_ref[0] from key_info.key_reference
 * (low byte only).  We reconstruct the 2-byte FID from file_ref because the
 * CardEdge MSE SET APDU requires the full 2-byte key file ID in tag 0x84.
 * ------------------------------------------------------------------------- */
static int librescrs_set_security_env(sc_card_t *card,
                                       const struct sc_security_env *env,
                                       int se_num)
{
    librescrs_private_t *priv = (librescrs_private_t *)card->drv_data;

    (void)se_num;

    /* Re-select AID_PKCS15: card may have been left in a different applet
     * context (e.g. after a PIN operation or between PKCS#11 calls). */
    if (librescrs_select_aid(card, AID_PKCS15, AID_PKCS15_LEN) != 0x9000) {
        sc_log(card->ctx, "librescrs: set_security_env: AID select failed\n");
        return SC_ERROR_CARD_CMD_FAILED;
    }

    if ((env->flags & SC_SEC_ENV_FILE_REF_PRESENT) && env->file_ref.len >= 2) {
        priv->key_ref = ((unsigned)env->file_ref.value[0] << 8)
                      | (unsigned)env->file_ref.value[1];
    } else if ((env->flags & SC_SEC_ENV_KEY_REF_PRESENT) && env->key_ref_len >= 1) {
        /* Fallback: reconstruct high byte from CE_KEYS_BASE_FID pattern. */
        priv->key_ref = CE_KEYS_BASE_FID | (unsigned)env->key_ref[0];
    } else {
        sc_log(card->ctx, "librescrs: set_security_env: no key reference\n");
        return SC_ERROR_INCORRECT_PARAMETERS;
    }

    sc_log(card->ctx, "librescrs: set_security_env: key_ref=0x%04x\n",
           priv->key_ref);
    return SC_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Crypto: compute_signature
 *
 * Mirrors cardedge::signData():
 *   1. MSE SET (00 22 41 B6): set algorithm=RSA-2048 and key reference.
 *   2. PSO COMPUTE DIGITAL SIGNATURE (00 2A 9E 00): sign DigestInfo blob.
 *
 * key_ref was saved by set_security_env (called by OpenSC before this).
 * ------------------------------------------------------------------------- */
static int librescrs_compute_signature(sc_card_t *card,
                                        const u8 *data, size_t datalen,
                                        u8 *out, size_t outlen)
{
    librescrs_private_t *priv = (librescrs_private_t *)card->drv_data;
    sc_apdu_t apdu;
    u8 mse_data[7];
    u8 resp[512];
    int r;

    /* MSE SET: tag 0x80 = algorithm (RSA2048), tag 0x84 = key ref (2 bytes BE) */
    mse_data[0] = 0x80;
    mse_data[1] = 0x01;
    mse_data[2] = CE_MSE_ALG_RSA2048;
    mse_data[3] = 0x84;
    mse_data[4] = 0x02;
    mse_data[5] = (u8)((priv->key_ref >> 8) & 0xFF);
    mse_data[6] = (u8)(priv->key_ref & 0xFF);

    sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB6);
    apdu.data    = mse_data;
    apdu.datalen = sizeof(mse_data);
    apdu.lc      = sizeof(mse_data);

    r = sc_transmit_apdu(card, &apdu);
    if (r < 0) return r;
    if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
        return SC_ERROR_CARD_CMD_FAILED;

    /* PSO COMPUTE DIGITAL SIGNATURE */
    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x00);
    apdu.data    = data;
    apdu.datalen = datalen;
    apdu.lc      = datalen;
    apdu.resp    = resp;
    apdu.resplen = sizeof(resp);
    apdu.le      = 256;

    r = sc_transmit_apdu(card, &apdu);
    if (r < 0) return r;
    if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
        return SC_ERROR_CARD_CMD_FAILED;

    if (apdu.resplen > outlen)
        return SC_ERROR_BUFFER_TOO_SMALL;
    memcpy(out, resp, apdu.resplen);
    return (int)apdu.resplen;
}

/* -------------------------------------------------------------------------
 * decipher — RSA decryption for kxc (key exchange) keys.
 *
 * Used by TLS client authentication and S/MIME decryption.
 * Mirrors compute_signature but with the confidentiality MSE template
 * (P2=0xB8) and PSO DECIPHER (00 2A 80 86).
 *
 * key_ref must have been set by set_security_env before this call.
 * ------------------------------------------------------------------------- */
static int librescrs_decipher(sc_card_t *card,
                               const u8 *crgram, size_t crgram_len,
                               u8 *out, size_t outlen)
{
    librescrs_private_t *priv = (librescrs_private_t *)card->drv_data;
    sc_apdu_t apdu;
    u8 mse_data[7];
    u8 resp[512];
    int r;

    /* MSE SET for confidentiality: P2=0xB8 (decipher template) */
    mse_data[0] = 0x80;
    mse_data[1] = 0x01;
    mse_data[2] = CE_MSE_ALG_RSA2048;
    mse_data[3] = 0x84;
    mse_data[4] = 0x02;
    mse_data[5] = (u8)((priv->key_ref >> 8) & 0xFF);
    mse_data[6] = (u8)(priv->key_ref & 0xFF);

    sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB8);
    apdu.data    = mse_data;
    apdu.datalen = sizeof(mse_data);
    apdu.lc      = sizeof(mse_data);

    r = sc_transmit_apdu(card, &apdu);
    if (r < 0) return r;
    if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
        return SC_ERROR_CARD_CMD_FAILED;

    /* PSO DECIPHER: 00 2A 80 86 Lc [ciphertext] Le */
    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
    apdu.data    = crgram;
    apdu.datalen = crgram_len;
    apdu.lc      = crgram_len;
    apdu.resp    = resp;
    apdu.resplen = sizeof(resp);
    apdu.le      = 256;

    r = sc_transmit_apdu(card, &apdu);
    if (r < 0) return r;
    if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
        return SC_ERROR_CARD_CMD_FAILED;

    if (apdu.resplen > outlen)
        return SC_ERROR_BUFFER_TOO_SMALL;
    memcpy(out, resp, apdu.resplen);
    return (int)apdu.resplen;
}

/* -------------------------------------------------------------------------
 * PIN management: pin_cmd
 *
 * Handles SC_PIN_CMD_GET_INFO, SC_PIN_CMD_VERIFY, SC_PIN_CMD_CHANGE.
 * PIN is null-padded to 8 bytes before transmission (CE_PIN_MAX_LENGTH).
 * Status word parsing mirrors cardedge::parsePINStatusWord():
 *   0x9000        → success
 *   0x6983        → blocked
 *   0x63 CX       → X tries remaining
 * ------------------------------------------------------------------------- */
static int librescrs_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
                              int *tries_left)
{
    sc_apdu_t apdu;
    u8 pin1_padded[CE_PIN_MAX_LENGTH];
    u8 pin2_padded[CE_PIN_MAX_LENGTH];
    u8 change_data[CE_PIN_MAX_LENGTH * 2];
    int r;

    if (tries_left)
        *tries_left = -1;

    /* Re-select AID_PKCS15 before any PIN APDU. */
    if (librescrs_select_aid(card, AID_PKCS15, AID_PKCS15_LEN) != 0x9000) {
        sc_log(card->ctx, "librescrs: pin_cmd: AID select failed\n");
        return SC_ERROR_CARD_CMD_FAILED;
    }

    /* Build padded PIN(s). */
    memset(pin1_padded, 0x00, sizeof(pin1_padded));
    memset(pin2_padded, 0x00, sizeof(pin2_padded));
    if (data->pin1.data && data->pin1.len > 0) {
        size_t l = data->pin1.len;
        if (l > CE_PIN_MAX_LENGTH) l = CE_PIN_MAX_LENGTH;
        memcpy(pin1_padded, data->pin1.data, l);
    }
    if (data->pin2.data && data->pin2.len > 0) {
        size_t l = data->pin2.len;
        if (l > CE_PIN_MAX_LENGTH) l = CE_PIN_MAX_LENGTH;
        memcpy(pin2_padded, data->pin2.data, l);
    }

    switch (data->cmd) {

    case SC_PIN_CMD_GET_INFO:
        /* VERIFY with no data = status check; does not decrement tries. */
        sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00,
                       CE_PIN_REFERENCE);
        r = sc_transmit_apdu(card, &apdu);
        if (r < 0) return r;
        /* Parse tries_left and always return SC_SUCCESS for GET_INFO. */
        if (apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0) {
            int tl = apdu.sw2 & 0x0F;
            if (tries_left) *tries_left = tl;
            data->pin1.tries_left = tl;   /* sc_pkcs15_get_pin_info reads this */
        } else if (apdu.sw1 == 0x69 && apdu.sw2 == 0x83) {
            if (tries_left) *tries_left = 0;
            data->pin1.tries_left = 0;
        }
        return SC_SUCCESS;

    case SC_PIN_CMD_VERIFY:
        sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x00,
                       CE_PIN_REFERENCE);
        apdu.data    = pin1_padded;
        apdu.datalen = CE_PIN_MAX_LENGTH;
        apdu.lc      = CE_PIN_MAX_LENGTH;
        r = sc_transmit_apdu(card, &apdu);
        if (r < 0) return r;
        break;

    case SC_PIN_CMD_CHANGE:
        /* CHANGE REFERENCE DATA: [old PIN 8 bytes] [new PIN 8 bytes] */
        memcpy(change_data,                    pin1_padded, CE_PIN_MAX_LENGTH);
        memcpy(change_data + CE_PIN_MAX_LENGTH, pin2_padded, CE_PIN_MAX_LENGTH);
        sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x00,
                       CE_PIN_REFERENCE);
        apdu.data    = change_data;
        apdu.datalen = sizeof(change_data);
        apdu.lc      = sizeof(change_data);
        r = sc_transmit_apdu(card, &apdu);
        if (r < 0) return r;
        break;

    default:
        return SC_ERROR_NOT_SUPPORTED;
    }

    /* Parse status word. */
    if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
        return SC_SUCCESS;
    if (apdu.sw1 == 0x69 && apdu.sw2 == 0x83) {
        if (tries_left) *tries_left = 0;
        return SC_ERROR_PIN_CODE_INCORRECT;
    }
    if (apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0) {
        int tries = apdu.sw2 & 0x0F;
        if (tries_left) *tries_left = tries;
        return (tries == 0) ? SC_ERROR_AUTH_METHOD_BLOCKED
                            : SC_ERROR_PIN_CODE_INCORRECT;
    }

    return SC_ERROR_CARD_CMD_FAILED;
}

static struct sc_card_driver librescrs_drv = {
    DRIVER_DESCRIPTION,   /* name (long) */
    DRIVER_SHORT_NAME,    /* short_name  */
    &librescrs_ops,       /* ops         */
    librescrs_atrs,       /* atr_map     */
    0,                    /* natrs       */
    NULL                  /* dll         */
};

/* -------------------------------------------------------------------------
 * PKCS#15 emulation — external module entry point.
 *
 * OpenSC looks for sc_get_pkcs15_emulators() when loading an external card
 * driver module.  The returned NULL-terminated table tells OpenSC which cards
 * this module can emulate PKCS#15 for and which function to call.
 *
 * opensc.conf must list the module under framework pkcs15:
 *
 *   framework pkcs15 {
 *       emulate librescrs {
 *           # same .so/.dylib as the card driver
 *           module = /usr/local/lib/librescrs-opensc.so;
 *       }
 *   }
 * ------------------------------------------------------------------------- */

/*
 * sc_pkcs15_init_func_ex — exported symbol looked up by parse_emu_block()
 * in pkcs15-syn.c when a module with sc_driver_version >= 0.9.3 is loaded
 * under [framework pkcs15 / emulate <name> { module = ... }].
 *
 * parse_emu_block() calls sc_dlsym(handle, "sc_pkcs15_init_func_ex") and
 * invokes it directly; sc_get_pkcs15_emulators() is NOT the right export.
 */
int sc_pkcs15_init_func_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
    return librescrs_pkcs15_bind(p15card, aid);
}

/* -------------------------------------------------------------------------
 * OpenSC module entry points (required by load_dynamic_driver in ctx.c)
 *
 * sc_driver_version() must return the exact PACKAGE_VERSION string of the
 * OpenSC build this module was compiled against; OpenSC rejects mismatches.
 *
 * sc_module_init() returns a pointer to sc_get_driver so OpenSC can call
 * it to obtain the sc_card_driver struct.
 * ------------------------------------------------------------------------- */

/* Forward declaration needed by sc_module_init. */
struct sc_card_driver *sc_get_driver(void);

const char *sc_driver_version(void)
{
    /* Return the version of the libopensc we are linked against.
     * OpenSC rejects modules where sc_driver_version() doesn't match
     * its own version exactly; sc_get_version() always returns the
     * right string regardless of which distro / release is installed. */
    return sc_get_version();
}

void *sc_module_init(const char *name)
{
    (void)name;
    return sc_get_driver;
}

/* -------------------------------------------------------------------------
 * Driver entry point
 * ------------------------------------------------------------------------- */

struct sc_card_driver *sc_get_driver(void)
{
    /* Copy all ISO 7816 default ops, then override only what we handle. */
    librescrs_ops = *sc_get_iso7816_driver()->ops;
    librescrs_ops.match_card            = librescrs_match_card;
    librescrs_ops.init                  = librescrs_init;
    librescrs_ops.finish                = librescrs_finish;
    librescrs_ops.set_security_env      = librescrs_set_security_env;
    librescrs_ops.restore_security_env  = librescrs_restore_security_env;
    librescrs_ops.compute_signature     = librescrs_compute_signature;
    librescrs_ops.decipher              = librescrs_decipher;
    librescrs_ops.pin_cmd               = librescrs_pin_cmd;

    return &librescrs_drv;
}
