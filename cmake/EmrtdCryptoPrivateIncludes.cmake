# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# The PRIVATE include directories the EMRTDCrypto translation units need.
#
# Two places compile those translation units, and both must see the same
# directories: lib/emrtd-crypto (the library) and fuzz/ (three harnesses that
# pull the same .cpp files into an instrumented executable, because PRIVATE
# sanitizer flags do not arrive over a link). This list used to live in both
# files, hand-copied; one directory was then added to the library only, and
# three of the ten fuzz harnesses stopped compiling -- invisible in every
# ordinary build, because LIBRESCRS_BUILD_FUZZ defaults to OFF.
#
# Add a directory HERE, never to either consumer directly. The check at the
# end of the top-level CMakeLists.txt fails the configure if EMRTDCrypto ends
# up carrying a directory this list does not name.

set(LIBRESCRS_EMRTD_CRYPTO_PRIVATE_INCLUDES
    ${PROJECT_SOURCE_DIR}/lib/emrtd-crypto/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    # SecureChannel public + internal headers —
    # included via direct path rather than `LibreSCRS_SecureChannel` link to
    # avoid a circular target dependency: LibreSCRS_SecureChannel privately
    # links EMRTDCrypto for the BAC/PACE/CA protocol implementations. A
    # static<->static cycle is permitted, but a SHARED LibreSCRS_SecureChannel
    # cycle fails at generate time (LIBREMIDDLEWARE_BUILD_SHARED=ON / LibreKDE
    # consumer mode). All downstream targets that link EMRTDCrypto also link
    # LibreSCRS_SecureChannel directly, so no transitive surface is lost.
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/lib/SecureChannel/include
    # The shared internal Crypto headers (CleanseGuard, OpenSslPtr). Four
    # key-agreement paths in this library each wrote their own scope guard for
    # wiping key material; the one they share now lives there, beside the other
    # internal crypto RAII this repository already keeps in one place.
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
)
