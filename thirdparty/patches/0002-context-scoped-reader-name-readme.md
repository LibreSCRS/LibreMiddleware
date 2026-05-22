# 0002-context-scoped-reader-name

**Status:** vendored downstream patch, pending upstream submission to
github.com/OpenSC/OpenSC.

**Why we ship this.** OpenSC's `_sc_add_reader` enumerates every PC/SC
reader visible to pcscd and lets every loaded driver's `match_card`
transmit plain probe APDUs against each card. When a host process
holds a PACE-protected channel on reader A (via LM's own SecureChannel
stack) and then loads opensc-pkcs11.so to sign on reader B, libopensc's
probe sweep on reader A's card tears down reader A's card-side SM
context. The host-side `PaceChannel` state survives, the next wrapped
APDU returns SW != 9000, and the user-visible workflow fails at
`selectApplet`.

See the project's design notes for the empirical evidence motivating
this patch.

**What the patch does.**

1. Adds `sc_context_param_t::scoped_reader_name` (exact-match
   per-context reader whitelist).
2. Falls back to `OPENSC_SCOPED_READER` environment variable when
   the field is NULL.
3. Plumbs through `_sc_add_reader` (`ctx.c:75-83`) next to the
   existing `ignored_reader()` substring blacklist check.
4. Bundles an env-gated `[PCSC_TRACE_LIBOPENSC]` trace point in
   `sc_transmit_apdu` (`apdu.c`) for downstream cross-validation;
   zero runtime cost when `LIBRESCRS_PCSC_TRACE` is unset.

**LM-side use.** `LibreMiddleware/lib/opensc-pkcs11/src/opensc_card.cpp`
sets `OPENSC_SCOPED_READER` immediately before each
`sc_establish_context` call, restricted to the target reader name.

**Upstream PR.** Tracked separately; 4.2 ships with the vendored
version regardless of upstream merge status.
