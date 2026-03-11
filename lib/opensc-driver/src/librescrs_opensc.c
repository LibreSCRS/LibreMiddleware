/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Copyright hirashix0@proton.me */

/*
 * librescrs_opensc.c — OpenSC external card driver for Serbian smart cards
 *                      with the CardEdge PKI applet.
 *
 * Serbian eID, health insurance, and Chamber of Commerce cards use the
 * same CardEdge PKCS#15 applet.  Cards are matched either by ATR
 * (Gemalto 2014+ eID) or by AID selection.
 *
 * Apollo 2008 eID has no CardEdge applet and is NOT supported.
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

/* CardEdge PKI applet AID  (A0 00 00 00 63 50 4B 43 53 2D 31 35) */
static const u8 AID_PKCS15[] = {
    0xA0, 0x00, 0x00, 0x00, 0x63,
    0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35
};
#define AID_PKCS15_LEN  (sizeof(AID_PKCS15))

/* CardEdge cmapfile constants. */
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
#define CE_DIR_HEADER_SIZE      10u
#define CE_DIR_ENTRY_SIZE       12u

/* PIN constants. */
#define CE_PIN_REFERENCE        0x80u
#define CE_PIN_MAX_LENGTH       8u

/* MSE algorithm byte for RSA-2048 PKCS#1 v1.5. */
#define CE_MSE_ALG_RSA2048      0x02u

/* Private key FID formula. */
static unsigned int ce_private_key_fid(unsigned int cont_idx,
                                        unsigned int key_pair_id)
{
    return CE_KEYS_BASE_FID
        | ((cont_idx   << 4) & 0x0FF0u)
        | ((key_pair_id << 2) & 0x000Cu)
        | CE_KEY_KIND_PRIVATE;
}

#define DRIVER_DESCRIPTION "LibreSCRS Serbian CardEdge driver"
#define DRIVER_SHORT_NAME  "librescrs"

static struct sc_card_operations librescrs_ops;
static const struct sc_card_operations *iso_ops;

static struct sc_card_driver librescrs_drv = {
    DRIVER_DESCRIPTION,   /* name (long) */
    DRIVER_SHORT_NAME,    /* short_name  */
    &librescrs_ops,       /* ops         */
    NULL,                 /* atr_map     */
    0,                    /* natrs       */
    NULL                  /* dll         */
};

/*
 * ATR table.
 *
 * Gemalto (2014+) Serbian eID:  3B FF 94 ...
 * Mask FF FF FF matches the first 3 bytes; remaining bytes vary between
 * individual cards and are don't-cares.
 *
 * Other CardEdge cards have no distinct ATR and are identified via AID
 * selection in match_card().
 *
 * Apollo 2008 ATR 3B B9 18 ... is intentionally absent — no CardEdge applet.
 */
static struct sc_atr_table librescrs_atrs[] = {
    { "3B:FF:94",  "FF:FF:FF",  "Serbian eID (Gemalto 2014+)", SC_CARD_TYPE_UNKNOWN, 0, NULL },
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
    /* ATR hit: Gemalto 2014+ Serbian eID (3B FF 94 ...) */
    if (_sc_match_atr(card, librescrs_atrs, &card->type) >= 0)
        return 1;

    /* AID-based match for cards without a distinct ATR. */
    if (librescrs_select_aid(card, AID_PKCS15, AID_PKCS15_LEN) == 0x9000) {
        sc_log(card->ctx, "librescrs: CardEdge applet found via AID");
        return 1;
    }

    return 0;
}

static int librescrs_init(sc_card_t *card)
{
    LOG_FUNC_CALLED(card->ctx);

    card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO;

    _sc_card_add_rsa_alg(card, 2048,
        SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE, 0);

    LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * select_file — handle CardEdge's proprietary 10-byte FCI response.
 *
 * CardEdge FCI layout (10 bytes, big-endian):
 *   [FID_H FID_L Size_H Size_L ACL*6]
 *
 * iso7816_select_file() would try to parse this as ISO 7816-4 TLV (tag 0x6F)
 * and fail with SC_ERROR_UNKNOWN_DATA_RECEIVED.
 *
 * DF_NAME (AID) selection is delegated to the ISO layer.
 */
static int librescrs_select_file(sc_card_t *card, const sc_path_t *in_path,
                                  sc_file_t **file_out)
{
    sc_apdu_t apdu;
    u8 fci[16];
    sc_file_t *file;
    int r;

    if (in_path->type == SC_PATH_TYPE_DF_NAME)
        return iso_ops->select_file(card, in_path, file_out);

    /* AID-only path (path.len==0, path.aid.len>0): PKCS#15 layer wants
     * to select the applet before a PIN or key operation. */
    if (in_path->len == 0 && in_path->aid.len > 0) {
        if (librescrs_select_aid(card, in_path->aid.value,
                in_path->aid.len) != 0x9000)
            LOG_FUNC_RETURN(card->ctx, SC_ERROR_CARD_CMD_FAILED);
        LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
    }

    if (in_path->len != 2)
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x00, 0x00);
    apdu.data    = in_path->value;
    apdu.datalen = 2;
    apdu.lc      = 2;
    apdu.resp    = fci;
    apdu.resplen = sizeof(fci);
    apdu.le      = 10;

    r = sc_transmit_apdu(card, &apdu);
    LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(card->ctx, r, "SELECT FILE failed");

    if (apdu.resplen < 4)
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

    if (file_out) {
        file = sc_file_new();
        if (!file)
            LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

        file->id   = ((unsigned)in_path->value[0] << 8) | in_path->value[1];
        file->path = *in_path;
        file->size = ((size_t)fci[2] << 8) | (size_t)fci[3];
        file->type = SC_FILE_TYPE_WORKING_EF;
        *file_out  = file;
    }

    LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * set_security_env — send MSE SET to the card.
 *
 * The PKCS#15 layer selects the PKI applet via the AID attached to
 * key_info.path before calling this function (see select_key_file()
 * in pkcs15-sec.c).
 *
 * OpenSC populates env->key_ref[0] from key_info.key_reference (low byte).
 * The high byte is always 0x60 (CE_KEYS_BASE_FID >> 8) for all CardEdge
 * key FIDs, so the full 2-byte FID is reconstructed here.
 *
 * MSE SET template P2: 0xB6 for signing, 0xB8 for deciphering.
 */
static int librescrs_set_security_env(sc_card_t *card,
                                       const struct sc_security_env *env,
                                       int se_num)
{
    sc_apdu_t apdu;
    u8 mse_data[7];
    unsigned key_ref;
    u8 p2;
    int r;

    LOG_FUNC_CALLED(card->ctx);
    (void)se_num;

    /* Extract key FID. */
    if ((env->flags & SC_SEC_ENV_FILE_REF_PRESENT) && env->file_ref.len >= 2) {
        key_ref = ((unsigned)env->file_ref.value[0] << 8)
                | (unsigned)env->file_ref.value[1];
    } else if ((env->flags & SC_SEC_ENV_KEY_REF_PRESENT) && env->key_ref_len >= 1) {
        key_ref = CE_KEYS_BASE_FID | (unsigned)env->key_ref[0];
    } else {
        sc_log(card->ctx, "librescrs: set_security_env: no key reference");
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);
    }

    /* Determine MSE SET template from operation type. */
    switch (env->operation) {
    case SC_SEC_OPERATION_SIGN:
        p2 = 0xB6;
        break;
    case SC_SEC_OPERATION_DECIPHER:
        p2 = 0xB8;
        break;
    default:
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
    }

    /* MSE SET: tag 0x80 = algorithm (RSA2048), tag 0x84 = key ref (2 bytes BE) */
    mse_data[0] = 0x80;
    mse_data[1] = 0x01;
    mse_data[2] = CE_MSE_ALG_RSA2048;
    mse_data[3] = 0x84;
    mse_data[4] = 0x02;
    mse_data[5] = (u8)((key_ref >> 8) & 0xFF);
    mse_data[6] = (u8)(key_ref & 0xFF);

    sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, p2);
    apdu.data    = mse_data;
    apdu.datalen = sizeof(mse_data);
    apdu.lc      = sizeof(mse_data);

    r = sc_transmit_apdu(card, &apdu);
    LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(card->ctx, r, "MSE SET failed");

    sc_log(card->ctx, "librescrs: set_security_env: key_ref=0x%04x p2=0x%02x",
           key_ref, p2);
    LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * compute_signature — PSO COMPUTE DIGITAL SIGNATURE (00 2A 9E 00).
 *
 * MSE SET has already been sent by set_security_env().
 * CardEdge uses P2=0x00 (not 0x9A as in ISO 7816-8), so we cannot
 * delegate to iso7816_compute_signature().
 */
static int librescrs_compute_signature(sc_card_t *card,
                                        const u8 *data, size_t datalen,
                                        u8 *out, size_t outlen)
{
    sc_apdu_t apdu;
    u8 resp[256];
    int r;

    LOG_FUNC_CALLED(card->ctx);

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x00);
    apdu.data    = data;
    apdu.datalen = datalen;
    apdu.lc      = datalen;
    apdu.resp    = resp;
    apdu.resplen = sizeof(resp);
    apdu.le      = 256;

    r = sc_transmit_apdu(card, &apdu);
    LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(card->ctx, r, "PSO COMPUTE DIGITAL SIGNATURE failed");

    if (apdu.resplen > outlen)
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
    memcpy(out, resp, apdu.resplen);
    LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

/*
 * decipher — PSO DECIPHER (00 2A 80 86).
 *
 * MSE SET has already been sent by set_security_env().
 * CardEdge does not use a padding indicator byte, so we cannot
 * delegate to iso7816_decipher().
 */
static int librescrs_decipher(sc_card_t *card,
                               const u8 *crgram, size_t crgram_len,
                               u8 *out, size_t outlen)
{
    sc_apdu_t apdu;
    u8 resp[256];
    int r;

    LOG_FUNC_CALLED(card->ctx);

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
    apdu.data    = crgram;
    apdu.datalen = crgram_len;
    apdu.lc      = crgram_len;
    apdu.resp    = resp;
    apdu.resplen = sizeof(resp);
    apdu.le      = 256;

    r = sc_transmit_apdu(card, &apdu);
    LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(card->ctx, r, "PSO DECIPHER failed");

    if (apdu.resplen > outlen)
        LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
    memcpy(out, resp, apdu.resplen);
    LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

/*
 * Select FID and read the entire file into a malloc'd buffer.
 * Uses sc_select_file() (dispatched to card driver's select_file which
 * handles CardEdge's proprietary FCI) and sc_read_binary().
 *
 * *out_len receives the byte count; caller must free() the buffer.
 * Returns SC_SUCCESS or a negative SC_ERROR_* code.
 */
static int librescrs_read_file(sc_card_t *card, unsigned int fid,
                                u8 **buf_out, size_t *out_len)
{
    sc_path_t path;
    sc_file_t *file = NULL;
    u8 *buf;
    int r;

    *buf_out = NULL;
    *out_len = 0;

    memset(&path, 0, sizeof(path));
    path.value[0] = (u8)((fid >> 8) & 0xFF);
    path.value[1] = (u8)(fid & 0xFF);
    path.len  = 2;
    path.type = SC_PATH_TYPE_FILE_ID;

    r = sc_select_file(card, &path, &file);
    if (r < 0)
        return r;

    if (!file || file->size == 0) {
        sc_file_free(file);
        return SC_SUCCESS;
    }

    buf = malloc(file->size);
    if (!buf) {
        sc_file_free(file);
        return SC_ERROR_OUT_OF_MEMORY;
    }

    r = sc_read_binary(card, 0, buf, file->size, 0);
    sc_file_free(file);
    if (r < 0) {
        free(buf);
        return r;
    }

    *buf_out = buf;
    *out_len = (size_t)r;
    return SC_SUCCESS;
}

/* One entry from a CardEdge directory file. */
typedef struct ce_dir_entry {
    char     name[9];   /* 8-char name + NUL */
    unsigned fid;
    int      is_dir;
} ce_dir_entry_t;

/*
 * Parse a CardEdge directory file into an array of ce_dir_entry_t.
 *
 * CardEdge directories use a proprietary binary format:
 *   [10-byte header] [12-byte entries...]
 * This is NOT ISO 7816-4 EF.DIR (ASN.1 BER-TLV application templates),
 * so standard sc_enum_apps() / iso7816_read_ef_dir() cannot be used.
 *
 * *entries_out: caller must free().  Returns entry count or -1 on error.
 */
static int ce_parse_dir(const u8 *data, size_t len,
                        ce_dir_entry_t **entries_out)
{
    size_t count, i;
    ce_dir_entry_t *entries;

    *entries_out = NULL;
    if (len < CE_DIR_HEADER_SIZE)
        return -1;

    count = (size_t)data[6] | ((size_t)data[7] << 8);
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
    r = librescrs_read_file(card, CE_PKI_ROOT_DIR_FID, &dir_buf, &dir_len);
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
    r = librescrs_read_file(card, mscp_fid, &mscp_buf, &mscp_len);
    if (r < 0) goto out;

    mscp_count = ce_parse_dir(mscp_buf, mscp_len, &mscp_entries);
    if (mscp_count < 0) { r = SC_ERROR_INVALID_DATA; goto out; }

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
        r = librescrs_read_file(card, cmap_fid, &cmap_buf, &cmap_len);
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
               "key_fid=0x%04x key_size=%u",
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

/*
 * Read the raw (possibly compressed) cert file and return DER bytes.
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
    const u8 *data;
    size_t dlen;
    int r;

    *der_out     = NULL;
    *der_len_out = 0;

    r = librescrs_read_file(card, cert_fid, &raw, &raw_len);
    if (r < 0)
        return r;

    if (raw_len < 6) {
        free(raw);
        return SC_ERROR_INVALID_DATA;
    }

    /* Skip 2-byte CardFS length prefix. */
    data = raw + 2;
    dlen = raw_len - 2;

    if (dlen >= 4 && data[0] == 0x01 && data[1] == 0x00) {
        /* zlib-compressed DER */
        size_t uncompressed_len = (size_t)data[2] | ((size_t)data[3] << 8);
        uLongf dest_len;
        int zr;
        u8 *der = malloc(uncompressed_len);
        if (!der) { free(raw); return SC_ERROR_OUT_OF_MEMORY; }

        dest_len = (uLongf)uncompressed_len;
        zr = uncompress(der, &dest_len, data + 4,
                        (unsigned long)(dlen - 4));
        if (zr != 0) {
            sc_log(card->ctx,
                   "librescrs: zlib uncompress failed (ret=%d)", zr);
            free(der);
            free(raw);
            return SC_ERROR_INVALID_DATA;
        }
        *der_out     = der;
        *der_len_out = (size_t)dest_len;
    } else if (dlen >= 1 && data[0] == 0x30) {
        /* Uncompressed DER (ASN.1 SEQUENCE tag). */
        u8 *der = malloc(dlen);
        if (!der) { free(raw); return SC_ERROR_OUT_OF_MEMORY; }
        memcpy(der, data, dlen);
        *der_out     = der;
        *der_len_out = dlen;
    } else {
        sc_log(card->ctx,
               "librescrs: cert FID 0x%04x: unknown format (byte0=0x%02x)",
               cert_fid, data[0]);
        free(raw);
        return SC_ERROR_INVALID_DATA;
    }

    free(raw);
    return SC_SUCCESS;
}

static int librescrs_pkcs15_bind(sc_pkcs15_card_t *p15card,
                                  struct sc_aid *aid)
{
    sc_card_t      *card = p15card->card;
    cert_entry_t   *certs = NULL;
    int             ncerts, i, r = SC_SUCCESS;

    (void)aid;

    sc_log(card->ctx, "librescrs: pkcs15 bind");

    ncerts = librescrs_enum_certs(card, &certs);
    if (ncerts < 0) {
        sc_log(card->ctx, "librescrs: cert enumeration failed: %d", ncerts);
        return ncerts;
    }
    if (ncerts == 0) {
        sc_log(card->ctx, "librescrs: no certificates found");
        goto out;
    }

    /* Set card label. */
    free(p15card->tokeninfo->label);
    p15card->tokeninfo->label = strdup("Serbian CardEdge");
    free(p15card->tokeninfo->manufacturer_id);
    p15card->tokeninfo->manufacturer_id = strdup("CardEdge");

    /* Query PIN tries_left via card driver's pin_cmd. */
    {
        struct sc_pin_cmd_data pin_data;
        int pin_tries_left = -1;

        memset(&pin_data, 0, sizeof(pin_data));
        pin_data.cmd           = SC_PIN_CMD_GET_INFO;
        pin_data.pin_type      = SC_AC_CHV;
        pin_data.pin_reference = CE_PIN_REFERENCE;

        /* Best-effort: failure to query PIN status is not fatal. */
        if (sc_pin_cmd(card, &pin_data, &pin_tries_left) >= 0
            && pin_tries_left < 0)
            pin_tries_left = pin_data.pin1.tries_left;
        sc_log(card->ctx, "librescrs: PIN tries_left=%d", pin_tries_left);

        /* PIN auth object — must be registered before private keys
         * so auth_id links work. */
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
            auth_info.attrs.pin.flags         = SC_PKCS15_PIN_FLAG_INITIALIZED
                                              | SC_PKCS15_PIN_FLAG_LOCAL
                                              | SC_PKCS15_PIN_FLAG_NEEDS_PADDING;
            auth_info.path.aid.len = AID_PKCS15_LEN;
            memcpy(auth_info.path.aid.value, AID_PKCS15, AID_PKCS15_LEN);
            auth_info.auth_id.len      = 1;
            auth_info.auth_id.value[0] = 1;

            strncpy(auth_obj.label, "User PIN", sizeof(auth_obj.label) - 1);
            auth_obj.auth_id.len = 0;
            auth_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

            r = sc_pkcs15emu_add_pin_obj(p15card, &auth_obj, &auth_info);
            if (r < 0) {
                sc_log(card->ctx, "librescrs: add PIN obj failed: %d", r);
                goto out;
            }
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

        /* Private key object. */
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
         * Set only the AID on key_info.path (path.len stays 0).
         * This makes select_key_file() select the PKI applet via AID
         * before calling set_security_env(), without appending a file
         * path that would fail on CardEdge's non-TLV FCI.
         *
         * The key FID is passed via key_info.key_reference and
         * reconstructed in set_security_env() from the low byte.
         */
        key_info.path.aid.len = AID_PKCS15_LEN;
        memcpy(key_info.path.aid.value, AID_PKCS15, AID_PKCS15_LEN);

        strncpy(key_obj.label, certs[i].label, sizeof(key_obj.label) - 1);
        key_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
        key_obj.auth_id.len      = 1;
        key_obj.auth_id.value[0] = 1;

        r = sc_pkcs15emu_add_rsa_prkey(p15card, &key_obj, &key_info);
        if (r < 0) {
            sc_log(card->ctx, "librescrs: add prkey[%d] failed: %d", i, r);
            goto out;
        }

        /* Certificate object. */
        if (librescrs_read_cert_der(card, certs[i].cert_fid,
                                    &der, &der_len) < 0) {
            sc_log(card->ctx, "librescrs: could not read cert[%d] DER", i);
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
            sc_log(card->ctx, "librescrs: add cert[%d] failed: %d", i, r);
            free(der);
            goto out;
        }
        /* der ownership now belongs to p15card; do not free. */
    }

    sc_log(card->ctx, "librescrs: pkcs15 bind OK (%d certs)", ncerts);

out:
    free(certs);
    return r;
}

/*
 * sc_pkcs15_init_func_ex — exported symbol looked up by parse_emu_block()
 * in pkcs15-syn.c when a module with sc_driver_version >= 0.9.3 is loaded
 * under [framework pkcs15 / emulate <name> { module = ... }].
 *
 * parse_emu_block() calls sc_dlsym(handle, "sc_pkcs15_init_func_ex") and
 * invokes it directly.
 */
int sc_pkcs15_init_func_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
    return librescrs_pkcs15_bind(p15card, aid);
}

/*
 * OpenSC module entry points (required by load_dynamic_driver in ctx.c).
 *
 * sc_driver_version() must return the exact PACKAGE_VERSION string of the
 * OpenSC build this module was compiled against; OpenSC rejects mismatches.
 *
 * sc_module_init() returns a pointer to sc_get_driver so OpenSC can call
 * it to obtain the sc_card_driver struct.
 */

/* Forward declaration needed by sc_module_init. */
struct sc_card_driver *sc_get_driver(void);

const char *sc_driver_version(void)
{
    return sc_get_version();
}

void *sc_module_init(const char *name)
{
    (void)name;
    return sc_get_driver;
}

struct sc_card_driver *sc_get_driver(void)
{
    /* Save ISO ops for delegation, then override what we handle. */
    iso_ops = sc_get_iso7816_driver()->ops;
    librescrs_ops = *iso_ops;
    librescrs_ops.match_card         = librescrs_match_card;
    librescrs_ops.init               = librescrs_init;
    librescrs_ops.select_file        = librescrs_select_file;
    librescrs_ops.set_security_env   = librescrs_set_security_env;
    librescrs_ops.compute_signature  = librescrs_compute_signature;
    librescrs_ops.decipher           = librescrs_decipher;

    /* Set ATR table on driver struct (external drivers pass NULL initially). */
    librescrs_drv.atr_map = librescrs_atrs;

    return &librescrs_drv;
}
