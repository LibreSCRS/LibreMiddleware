/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 hirashix0
 */

/**
 * @file AttachHook.h
 * @brief Process-local CardSession injection hook for
 *        @c librescrs-pkcs11.so.
 *
 * Allows a host process that already holds a LibreSCRS @c CardSession
 * (e.g. for display) to share it with the PKCS#11 sign path, avoiding
 * a second PC/SC handle on the same reader.
 *
 * @par Lifecycle
 * Call @ref librescrs_pkcs11_attach_session after @c C_Initialize
 * succeeds and before @c C_GetSlotList. The matching
 * @ref librescrs_pkcs11_detach_session (or @c C_Finalize) releases the
 * module-side @c shared_ptr ref.
 *
 * @par ABI versioning
 * This header defines the v1 token shape. Future incompatible token
 * layouts will add a new @c LibrescrsPkcs11AttachTokenV<N> struct and a
 * matching @c LIBRESCRS_PKCS11_ATTACH_MAGIC_V<N> constant; the v1
 * surface remains supported.
 *
 * @since 4.1
 */

#ifndef LIBRESCRS_PKCS11_ATTACH_HOOK_H
#define LIBRESCRS_PKCS11_ATTACH_HOOK_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Magic cookie identifying the v1 attach-token shape.
 *
 * Byte pattern spells out @c "LSCRSAT1" in ASCII.
 *
 * @since 4.1
 */
#define LIBRESCRS_PKCS11_ATTACH_MAGIC_V1 0x4C53435253415431ULL

/**
 * @brief v1 attach-token POD. Caller-owned; module reads only.
 *
 * Fields:
 * - @c magic — must equal @ref LIBRESCRS_PKCS11_ATTACH_MAGIC_V1.
 *   Validated by the module to detect ABI drift across host /
 *   module-version mismatches.
 * - @c session_ptr — opaque pointer; the module casts it to its known
 *   internal @c CardSession shared_ptr type. Caller must keep the
 *   referent alive until after the matching detach call.
 * - @c flags — reserved for future extension. Must be zero in v1; any
 *   non-zero value is rejected with
 *   @ref LIBRESCRS_PKCS11_ATTACH_BAD_FLAGS.
 *
 * @par ABI versioning
 * The struct layout is frozen for v1. New fields, if needed, will ship
 * as @c LibrescrsPkcs11AttachTokenV2 with its own magic constant.
 *
 * @since 4.1
 */
typedef struct LibrescrsPkcs11AttachTokenV1
{
    unsigned long long magic;
    void* session_ptr;
    unsigned long flags;
} LibrescrsPkcs11AttachTokenV1;

/**
 * @name Attach hook return codes
 * @{
 * @since 4.1
 */
#define LIBRESCRS_PKCS11_ATTACH_OK 0              ///< Success.
#define LIBRESCRS_PKCS11_ATTACH_BAD_MAGIC 1       ///< @c token->magic mismatch.
#define LIBRESCRS_PKCS11_ATTACH_BAD_FLAGS 2       ///< @c token->flags non-zero.
#define LIBRESCRS_PKCS11_ATTACH_NULL_PTR 3        ///< @c reader_name, @c token, or @c token->session_ptr is NULL.
#define LIBRESCRS_PKCS11_ATTACH_NOT_INITIALIZED 4 ///< @c C_Initialize not called yet.
#define LIBRESCRS_PKCS11_ATTACH_OUT_OF_MEMORY 5   ///< Internal allocation failure (also mapped from caught exceptions).
/** @} */

/**
 * @brief Park @c session_ptr against @c reader_name for the next
 *        @c C_GetSlotList probe.
 *
 * Re-attach for the same reader replaces the prior entry (its
 * module-side @c shared_ptr ref drops). Thread-safe; module-side mutex
 * serialises with the matching @c tryAdopt() in the probe path.
 *
 * @param reader_name Null-terminated PC/SC reader name. Must outlive
 *        the call.
 * @param token       v1 attach token; see
 *        @ref LibrescrsPkcs11AttachTokenV1.
 *
 * @return @ref LIBRESCRS_PKCS11_ATTACH_OK on success or one of the
 *         @c LIBRESCRS_PKCS11_ATTACH_* error codes.
 *
 * @note Never throws across the C boundary; internal exceptions are
 *       caught and mapped to @ref LIBRESCRS_PKCS11_ATTACH_OUT_OF_MEMORY.
 *
 * @since 4.1
 */
int librescrs_pkcs11_attach_session(const char* reader_name, const LibrescrsPkcs11AttachTokenV1* token);

/**
 * @brief Idempotent removal of the entry for @c reader_name.
 *
 * Releases the module-side @c shared_ptr ref. No-op if no entry
 * exists.
 *
 * @param reader_name Null-terminated PC/SC reader name.
 *
 * @return @ref LIBRESCRS_PKCS11_ATTACH_OK on success (including the
 *         no-op case), or @ref LIBRESCRS_PKCS11_ATTACH_NULL_PTR if
 *         @c reader_name is NULL.
 *
 * @since 4.1
 */
int librescrs_pkcs11_detach_session(const char* reader_name);

#ifdef __cplusplus
}
#endif

#endif /* LIBRESCRS_PKCS11_ATTACH_HOOK_H */
