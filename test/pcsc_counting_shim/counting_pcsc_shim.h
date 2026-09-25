/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* SPDX-FileCopyrightText: 2026 hirashix0 */

/**
 * @file
 * @brief Counters a counting PC/SC provider exposes, and the three functions
 *        that reach them.
 *
 * The shim is loaded by OpenSC, not by the test: OpenSC dlopens whatever
 * `provider_library` in the OPENSC_CONF it reads names, so the only way to see
 * what OpenSC did at the PC/SC layer is to ask the library OpenSC loaded. A
 * test reaches these three functions by dlopening the same path (the same
 * inode is the same mapping, hence the same counters) and dlsym-ing them.
 *
 * This header exists so the shim and its callers cannot disagree about the
 * shape of the struct that crosses that boundary.
 */

#ifndef LIBRESCRS_COUNTING_PCSC_SHIM_H
#define LIBRESCRS_COUNTING_PCSC_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Call counts, per reader where a reader is involved. */
struct LibrescrsShimCounts
{
    unsigned long establishContext; /**< SCardEstablishContext calls (global). */
    unsigned long releaseContext;   /**< SCardReleaseContext calls (global). */
    unsigned long listReaders;      /**< SCardListReaders calls (global). */
    unsigned long connect;          /**< SCardConnect calls for the reader asked about. */
    unsigned long disconnect;       /**< SCardDisconnect calls (global). */
    unsigned long status;           /**< SCardStatus calls (global). */
    unsigned long getStatusChange;  /**< SCardGetStatusChange calls (global). */
    unsigned long transmit;         /**< SCardTransmit calls (global). */
    unsigned long openHandles;      /**< Handles connected and not yet disconnected. */
};

/**
 * @brief Read the counters.
 * @param reader Reader name the @c connect count is asked about; NULL or an
 *               empty string totals every reader.
 */
struct LibrescrsShimCounts librescrs_shim_counts(const char* reader);

/** @brief Handles connected and not yet disconnected, across every reader. */
unsigned long librescrs_shim_open_handles(void);

/** @brief Zero every counter and forget every open handle. */
void librescrs_shim_reset(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBRESCRS_COUNTING_PCSC_SHIM_H */
