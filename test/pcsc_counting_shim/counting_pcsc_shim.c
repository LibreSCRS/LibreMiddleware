/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* SPDX-FileCopyrightText: 2026 hirashix0 */

/**
 * @file
 * @brief A counting PC/SC provider, loaded in place of libpcsclite.
 *
 * OpenSC reaches PC/SC through a library it dlopens by name: the
 * `reader_driver pcsc { provider_library = ... }` block of the configuration
 * OPENSC_CONF points at. Pointing that at this file's shared object makes every
 * PC/SC call OpenSC performs observable, with no daemon, no reader and no card.
 *
 * It answers exactly enough to get OpenSC to enumerate a reader, connect to it
 * and start talking to a card, and then refuses every APDU with 6A 82. That is
 * deliberate: the invariant under test is which readers the PKCS#11 providers
 * open handles on while a secure channel is live elsewhere, and that question is
 * settled before any card is identified. A test that let the bind succeed would
 * need a card emulator and would measure the emulator.
 *
 * Configuration comes from the environment, because the configuration file this
 * library is named from is written by the same test:
 *   LIBRESCRS_SHIM_READERS  reader names, ';'-separated (default: one reader).
 *   LIBRESCRS_SHIM_ATR      the ATR every reader reports, in hex.
 *
 * The separator is ';' and not the NUL byte the PC/SC multi-string uses:
 * setenv() takes a C string, so a NUL in the value would end it. The
 * multi-string is built here.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

#include "counting_pcsc_shim.h"

#define SHIM_MAX_READERS 8
#define SHIM_MAX_NAME 128
#define SHIM_MAX_HANDLES 16
#define SHIM_MAX_ATR 33

struct shim_reader
{
    char name[SHIM_MAX_NAME];
    unsigned long connectCalls;
};

struct shim_handle
{
    SCARDHANDLE handle;
    int readerIndex;
};

static pthread_mutex_t shimMutex = PTHREAD_MUTEX_INITIALIZER;

static struct shim_reader shimReaders[SHIM_MAX_READERS];
static unsigned shimReaderCount;
static int shimReadersLoaded;

static struct shim_handle shimHandles[SHIM_MAX_HANDLES];
static unsigned shimHandleCount;
static SCARDHANDLE shimNextHandle = 0x5C00;
static SCARDCONTEXT shimNextContext = 0x5C10;

static unsigned long shimEstablishContext;
static unsigned long shimReleaseContext;
static unsigned long shimListReaders;
static unsigned long shimDisconnect;
static unsigned long shimStatus;
static unsigned long shimGetStatusChange;
static unsigned long shimTransmit;

/* ---- configuration ------------------------------------------------------- */

/* Reader names are read once per reset so that a test which changes the
 * environment between two calls -- the reader-set-change case -- must reset to
 * be believed, rather than getting a silent re-read it did not ask for. */
static void load_readers_locked(void)
{
    const char* spec = getenv("LIBRESCRS_SHIM_READERS");
    const char* cursor = NULL;

    shimReaderCount = 0;
    shimReadersLoaded = 1;
    if (spec == NULL || *spec == '\0')
        spec = "Counting Shim Reader 0";

    cursor = spec;
    while (*cursor != '\0' && shimReaderCount < SHIM_MAX_READERS) {
        const char* end = strchr(cursor, ';');
        size_t len = (end != NULL) ? (size_t)(end - cursor) : strlen(cursor);
        if (len > 0 && len < SHIM_MAX_NAME) {
            memcpy(shimReaders[shimReaderCount].name, cursor, len);
            shimReaders[shimReaderCount].name[len] = '\0';
            shimReaders[shimReaderCount].connectCalls = 0;
            ++shimReaderCount;
        }
        if (end == NULL)
            break;
        cursor = end + 1;
    }
}

static void ensure_readers_locked(void)
{
    if (!shimReadersLoaded)
        load_readers_locked();
}

static int find_reader_locked(const char* name)
{
    unsigned i;
    if (name == NULL)
        return -1;
    ensure_readers_locked();
    for (i = 0; i < shimReaderCount; ++i) {
        if (strcmp(shimReaders[i].name, name) == 0)
            return (int)i;
    }
    return -1;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* A structurally valid four-byte T=1 ATR: TS, T0 with TD1 and no historical
 * bytes, TD1 selecting T=1, and the checksum those two bytes require. Nothing
 * downstream should recognise it -- it only has to be well formed enough for
 * the reader layer to hand it on. */
static const unsigned char shimDefaultAtr[] = {0x3Bu, 0x80u, 0x01u, 0x81u};

static size_t shim_atr(unsigned char* out, size_t cap)
{
    const char* spec = getenv("LIBRESCRS_SHIM_ATR");
    size_t n = 0;

    if (spec == NULL || *spec == '\0') {
        n = sizeof shimDefaultAtr;
        if (n > cap)
            n = cap;
        memcpy(out, shimDefaultAtr, n);
        return n;
    }
    while (*spec != '\0' && n < cap) {
        int hi, lo;
        while (*spec == ' ' || *spec == ':')
            ++spec;
        if (*spec == '\0')
            break;
        hi = hex_nibble(*spec++);
        if (*spec == '\0')
            break;
        lo = hex_nibble(*spec++);
        if (hi < 0 || lo < 0)
            break;
        out[n++] = (unsigned char)((hi << 4) | lo);
    }
    return n;
}

/* ---- counter surface ----------------------------------------------------- */

struct LibrescrsShimCounts librescrs_shim_counts(const char* reader)
{
    struct LibrescrsShimCounts out;
    memset(&out, 0, sizeof out);

    pthread_mutex_lock(&shimMutex);
    out.establishContext = shimEstablishContext;
    out.releaseContext = shimReleaseContext;
    out.listReaders = shimListReaders;
    out.disconnect = shimDisconnect;
    out.status = shimStatus;
    out.getStatusChange = shimGetStatusChange;
    out.transmit = shimTransmit;
    out.openHandles = shimHandleCount;
    if (reader == NULL || *reader == '\0') {
        unsigned i;
        for (i = 0; i < shimReaderCount; ++i)
            out.connect += shimReaders[i].connectCalls;
    } else {
        int idx = find_reader_locked(reader);
        if (idx >= 0)
            out.connect = shimReaders[idx].connectCalls;
    }
    pthread_mutex_unlock(&shimMutex);
    return out;
}

unsigned long librescrs_shim_open_handles(void)
{
    unsigned long n;
    pthread_mutex_lock(&shimMutex);
    n = shimHandleCount;
    pthread_mutex_unlock(&shimMutex);
    return n;
}

void librescrs_shim_reset(void)
{
    pthread_mutex_lock(&shimMutex);
    shimEstablishContext = 0;
    shimReleaseContext = 0;
    shimListReaders = 0;
    shimDisconnect = 0;
    shimStatus = 0;
    shimGetStatusChange = 0;
    shimTransmit = 0;
    shimHandleCount = 0;
    memset(shimHandles, 0, sizeof shimHandles);
    shimReadersLoaded = 0;
    shimReaderCount = 0;
    pthread_mutex_unlock(&shimMutex);
}

/* ---- the PC/SC surface OpenSC resolves ----------------------------------- */

LONG SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
{
    (void)dwScope;
    (void)pvReserved1;
    (void)pvReserved2;
    if (phContext == NULL)
        return SCARD_E_INVALID_PARAMETER;
    pthread_mutex_lock(&shimMutex);
    ++shimEstablishContext;
    *phContext = shimNextContext++;
    pthread_mutex_unlock(&shimMutex);
    return SCARD_S_SUCCESS;
}

LONG SCardReleaseContext(SCARDCONTEXT hContext)
{
    (void)hContext;
    pthread_mutex_lock(&shimMutex);
    ++shimReleaseContext;
    pthread_mutex_unlock(&shimMutex);
    return SCARD_S_SUCCESS;
}

/*
 * Two-call convention, both branches. A caller may pass a NULL buffer to learn
 * the length, or a buffer of its own size; when that size is larger than what
 * is needed, the length written back must be the length of the data and not the
 * size of the buffer. A provider that echoes the caller's size back looks
 * correct to every caller that sized the buffer exactly, which is what tools do.
 */
LONG SCardListReaders(SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders)
{
    char multi[SHIM_MAX_READERS * SHIM_MAX_NAME + 1];
    size_t used = 0;
    unsigned i;

    (void)hContext;
    (void)mszGroups;
    if (pcchReaders == NULL)
        return SCARD_E_INVALID_PARAMETER;

    pthread_mutex_lock(&shimMutex);
    ++shimListReaders;
    ensure_readers_locked();
    for (i = 0; i < shimReaderCount; ++i) {
        size_t len = strlen(shimReaders[i].name) + 1;
        memcpy(multi + used, shimReaders[i].name, len);
        used += len;
    }
    multi[used++] = '\0'; /* the multi-string's own terminator */
    pthread_mutex_unlock(&shimMutex);

    if (mszReaders == NULL) {
        *pcchReaders = (DWORD)used;
        return SCARD_S_SUCCESS;
    }
    if (*pcchReaders < (DWORD)used) {
        *pcchReaders = (DWORD)used;
        return SCARD_E_INSUFFICIENT_BUFFER;
    }
    memcpy(mszReaders, multi, used);
    *pcchReaders = (DWORD)used;
    return SCARD_S_SUCCESS;
}

LONG SCardConnect(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols,
                  LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
{
    int idx;
    LONG rv = SCARD_S_SUCCESS;

    (void)hContext;
    (void)dwShareMode;
    (void)dwPreferredProtocols;
    if (szReader == NULL || phCard == NULL)
        return SCARD_E_INVALID_PARAMETER;

    pthread_mutex_lock(&shimMutex);
    idx = find_reader_locked(szReader);
    if (idx < 0) {
        pthread_mutex_unlock(&shimMutex);
        return SCARD_E_UNKNOWN_READER;
    }
    ++shimReaders[idx].connectCalls;
    if (shimHandleCount >= SHIM_MAX_HANDLES) {
        pthread_mutex_unlock(&shimMutex);
        return SCARD_E_NO_MEMORY;
    }
    shimHandles[shimHandleCount].handle = shimNextHandle++;
    shimHandles[shimHandleCount].readerIndex = idx;
    *phCard = shimHandles[shimHandleCount].handle;
    ++shimHandleCount;
    pthread_mutex_unlock(&shimMutex);

    if (pdwActiveProtocol != NULL)
        *pdwActiveProtocol = SCARD_PROTOCOL_T1;
    return rv;
}

LONG SCardReconnect(SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols, DWORD dwInitialization,
                    LPDWORD pdwActiveProtocol)
{
    (void)hCard;
    (void)dwShareMode;
    (void)dwPreferredProtocols;
    (void)dwInitialization;
    if (pdwActiveProtocol != NULL)
        *pdwActiveProtocol = SCARD_PROTOCOL_T1;
    return SCARD_S_SUCCESS;
}

LONG SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition)
{
    unsigned i;
    (void)dwDisposition;

    pthread_mutex_lock(&shimMutex);
    ++shimDisconnect;
    for (i = 0; i < shimHandleCount; ++i) {
        if (shimHandles[i].handle == hCard) {
            shimHandles[i] = shimHandles[shimHandleCount - 1];
            --shimHandleCount;
            break;
        }
    }
    pthread_mutex_unlock(&shimMutex);
    return SCARD_S_SUCCESS;
}

LONG SCardBeginTransaction(SCARDHANDLE hCard)
{
    (void)hCard;
    return SCARD_S_SUCCESS;
}

LONG SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition)
{
    (void)hCard;
    (void)dwDisposition;
    return SCARD_S_SUCCESS;
}

/* Two-call convention for both the reader name and the ATR, for the same
 * reason as SCardListReaders. OpenSC asks for the ATR here with a NULL name
 * buffer before it sends a single APDU. */
LONG SCardStatus(SCARDHANDLE hCard, LPSTR mszReaderName, LPDWORD pcchReaderLen, LPDWORD pdwState, LPDWORD pdwProtocol,
                 LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
    unsigned i;
    int idx = -1;
    char name[SHIM_MAX_NAME];
    size_t nameLen;
    unsigned char atr[SHIM_MAX_ATR];
    size_t atrLen;

    pthread_mutex_lock(&shimMutex);
    ++shimStatus;
    for (i = 0; i < shimHandleCount; ++i) {
        if (shimHandles[i].handle == hCard) {
            idx = shimHandles[i].readerIndex;
            break;
        }
    }
    if (idx < 0) {
        pthread_mutex_unlock(&shimMutex);
        return SCARD_E_INVALID_HANDLE;
    }
    memcpy(name, shimReaders[idx].name, sizeof name);
    pthread_mutex_unlock(&shimMutex);

    nameLen = strlen(name) + 1;
    atrLen = shim_atr(atr, sizeof atr);

    if (pcchReaderLen != NULL) {
        if (mszReaderName == NULL) {
            *pcchReaderLen = (DWORD)nameLen;
        } else if (*pcchReaderLen < (DWORD)nameLen) {
            *pcchReaderLen = (DWORD)nameLen;
            return SCARD_E_INSUFFICIENT_BUFFER;
        } else {
            memcpy(mszReaderName, name, nameLen);
            *pcchReaderLen = (DWORD)nameLen;
        }
    }
    if (pcbAtrLen != NULL) {
        if (pbAtr == NULL) {
            *pcbAtrLen = (DWORD)atrLen;
        } else if (*pcbAtrLen < (DWORD)atrLen) {
            *pcbAtrLen = (DWORD)atrLen;
            return SCARD_E_INSUFFICIENT_BUFFER;
        } else {
            memcpy(pbAtr, atr, atrLen);
            *pcbAtrLen = (DWORD)atrLen;
        }
    }
    if (pdwState != NULL)
        *pdwState = SCARD_PRESENT | SCARD_POWERED | SCARD_NEGOTIABLE;
    if (pdwProtocol != NULL)
        *pdwProtocol = SCARD_PROTOCOL_T1;
    return SCARD_S_SUCCESS;
}

/* Every configured reader reports a card present with the configured ATR; any
 * other name -- the PnP pseudo-reader OpenSC also watches, for instance -- is
 * unknown. */
LONG SCardGetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout, SCARD_READERSTATE* rgReaderStates, DWORD cReaders)
{
    DWORD i;
    unsigned char atr[SHIM_MAX_ATR];
    size_t atrLen;

    (void)hContext;
    (void)dwTimeout;
    if (rgReaderStates == NULL)
        return SCARD_E_INVALID_PARAMETER;

    atrLen = shim_atr(atr, sizeof atr);

    pthread_mutex_lock(&shimMutex);
    ++shimGetStatusChange;
    for (i = 0; i < cReaders; ++i) {
        int idx = find_reader_locked(rgReaderStates[i].szReader);
        if (idx < 0) {
            rgReaderStates[i].dwEventState = SCARD_STATE_UNKNOWN | SCARD_STATE_CHANGED;
            rgReaderStates[i].cbAtr = 0;
            continue;
        }
        rgReaderStates[i].dwEventState = SCARD_STATE_PRESENT | SCARD_STATE_CHANGED;
        rgReaderStates[i].cbAtr = (DWORD)atrLen;
        memcpy(rgReaderStates[i].rgbAtr, atr, atrLen);
    }
    pthread_mutex_unlock(&shimMutex);
    return SCARD_S_SUCCESS;
}

LONG SCardCancel(SCARDCONTEXT hContext)
{
    (void)hContext;
    return SCARD_S_SUCCESS;
}

/* 6A 82 to every APDU: no card is emulated here, and the invariant under test
 * is settled before any card would be identified. */
LONG SCardTransmit(SCARDHANDLE hCard, const SCARD_IO_REQUEST* pioSendPci, LPCBYTE pbSendBuffer, DWORD cbSendLength,
                   SCARD_IO_REQUEST* pioRecvPci, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength)
{
    (void)hCard;
    (void)pioSendPci;
    (void)pbSendBuffer;
    (void)cbSendLength;
    (void)pioRecvPci;

    pthread_mutex_lock(&shimMutex);
    ++shimTransmit;
    pthread_mutex_unlock(&shimMutex);

    if (pbRecvBuffer == NULL || pcbRecvLength == NULL)
        return SCARD_E_INVALID_PARAMETER;
    if (*pcbRecvLength < 2)
        return SCARD_E_INSUFFICIENT_BUFFER;
    pbRecvBuffer[0] = 0x6Au;
    pbRecvBuffer[1] = 0x82u;
    *pcbRecvLength = 2;
    return SCARD_S_SUCCESS;
}

/* Present so OpenSC takes its "correct API" branch, and refusing so no pinpad
 * or vendor feature is claimed. */
LONG SCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr, LPDWORD pcbAttrLen)
{
    (void)hCard;
    (void)dwAttrId;
    (void)pbAttr;
    (void)pcbAttrLen;
    return SCARD_E_UNSUPPORTED_FEATURE;
}

LONG SCardControl(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer, DWORD cbSendLength, LPVOID pbRecvBuffer,
                  DWORD cbRecvLength, LPDWORD lpBytesReturned)
{
    (void)hCard;
    (void)dwControlCode;
    (void)pbSendBuffer;
    (void)cbSendLength;
    (void)pbRecvBuffer;
    (void)cbRecvLength;
    if (lpBytesReturned != NULL)
        *lpBytesReturned = 0;
    return SCARD_E_UNSUPPORTED_FEATURE;
}
