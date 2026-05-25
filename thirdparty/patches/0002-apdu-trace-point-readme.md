# 0002-apdu-trace-point

**Status:** vendored downstream debug aid, not intended for upstream
submission.

**What the patch does.** Adds a `LIBRESCRS_PCSC_TRACE`-gated trace point
in `sc_transmit_apdu` (`src/libopensc/apdu.c`). When the environment
variable `LIBRESCRS_PCSC_TRACE` is set (and not `0`/empty), each APDU
transmission logs the reader name and APDU header
(`[PCSC_TRACE_LIBOPENSC] reader=... cla=.. ins=.. p1=.. p2=.. lc=.. le=..`)
to stderr. The check is cached in a static, so there is zero runtime
cost on the hot path when the variable is unset.

**Why we ship this.** Cross-validation tooling: when diagnosing
cross-reader / secure-messaging behaviour it is useful to see exactly
which reader each libopensc-issued APDU targets, independent of LM's
own host-side tracing. Used to confirm, e.g., that the opensc-pkcs11
provider issues zero APDUs to a reader holding a live SM session while
binding a different reader.

**History.** This patch previously also carried a
`scoped_reader_name` reader-whitelist
(`sc_context_param_t::scoped_reader_name` + `OPENSC_SCOPED_READER` env
+ `_sc_add_reader` filter). That half was removed once it was
superseded by the SessionPresence registry + per-reader bind
(opensc-pkcs11 defers on `hasLiveSm`; `OpenScCard::bind` targets a
single reader via `sc_ctx_get_reader_by_name` + `sc_connect_card`).
Nothing in LM/LC set the field or env, so it was dead code. Only the
trace point remains.
