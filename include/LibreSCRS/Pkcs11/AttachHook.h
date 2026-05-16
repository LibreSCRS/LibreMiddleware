/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 hirashix0
 *
 * AttachHook.h — process-local CardSession injection hook
 * for librescrs-pkcs11.so.
 *
 * Allows a host process that already holds a LibreSCRS CardSession (e.g.
 * for display) to share it with the PKCS#11 sign path, avoiding a second
 * PC/SC handle on the same reader.
 *
 * Lifecycle: call after C_Initialize succeeds and before C_GetSlotList.
 * The matching detach hook (or C_Finalize) releases the module-side
 * shared_ptr ref.
 */

#ifndef LIBRESCRS_PKCS11_ATTACH_HOOK_H
#define LIBRESCRS_PKCS11_ATTACH_HOOK_H

#ifdef __cplusplus
extern "C" {
#endif

/* Magic cookie identifying the v1 attach-token shape. */
#define LIBRESCRS_PKCS11_ATTACH_MAGIC_V1 0x4C53435253415431ULL /* "LSCRSAT1" */

/* v1 attach-token POD. Caller-owned; module reads only. */
typedef struct LibrescrsPkcs11AttachTokenV1
{
    unsigned long long magic; /* must equal LIBRESCRS_PKCS11_ATTACH_MAGIC_V1 */
    void* session_ptr;        /* opaque; module casts to its known type      */
    unsigned long flags;      /* reserved; must be zero in v1                */
} LibrescrsPkcs11AttachTokenV1;

/* Return codes. */
#define LIBRESCRS_PKCS11_ATTACH_OK 0
#define LIBRESCRS_PKCS11_ATTACH_BAD_MAGIC 1
#define LIBRESCRS_PKCS11_ATTACH_BAD_FLAGS 2
#define LIBRESCRS_PKCS11_ATTACH_NULL_PTR 3
#define LIBRESCRS_PKCS11_ATTACH_NOT_INITIALIZED 4
#define LIBRESCRS_PKCS11_ATTACH_OUT_OF_MEMORY 5

/*
 * Park session_ptr against reader_name for the next C_GetSlotList probe.
 * Re-attach for the same reader replaces the prior entry (its module-side
 * shared_ptr ref drops). Thread-safe; module-side mutex serialises with
 * the matching tryAdopt() in the probe path.
 *
 * Returns LIBRESCRS_PKCS11_ATTACH_OK on success or one of the codes above.
 * Never throws across the C boundary; internal exceptions are caught and
 * mapped to OUT_OF_MEMORY.
 */
int librescrs_pkcs11_attach_session(const char* reader_name, const LibrescrsPkcs11AttachTokenV1* token);

/*
 * Idempotent removal of the entry for reader_name. Releases the module-side
 * shared_ptr ref. No-op if no entry exists.
 */
int librescrs_pkcs11_detach_session(const char* reader_name);

#ifdef __cplusplus
}
#endif

#endif /* LIBRESCRS_PKCS11_ATTACH_HOOK_H */
