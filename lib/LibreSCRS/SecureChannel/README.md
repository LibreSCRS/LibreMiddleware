# LibreSCRS_SecureChannel — test-mockability decision

This note records a foundational design decision for the upcoming
`LibreSCRS_SecureChannel` subdomain (`PlainChannel`, `PaceChannel`,
`BacChannel` behind an `ISecureChannel` abstraction owned by
`CardSession`). It can be removed once the subdomain is fully landed
and reviewed.

## Decision

Channel implementations will be parameterised on an abstract
`IConnection` interface (option **a**), not on a `PCSCConnection`
with `transmit()` made virtual under a testing macro (option **b**).

## Rationale

1. **Established LM precedent.** The smartcard subdomain already
   ships exactly this pattern for its other low-level dependency:
   `IPCSCScanProvider` (interface in `lib/smartcard/src/`) is
   implemented by the production `PCSCScanProvider` and the
   test-only `MockPCSCScanProvider` (under `test/`). Following the
   same pattern for the connection seam keeps the codebase uniform
   and avoids inventing a parallel mocking idiom.
2. **No `LIBRESCRS_TESTING` build-config bifurcation.** Option (b)
   would require introducing a new preprocessor switch and would
   make the test binary structurally different from the release
   binary (virtual dispatch present in tests, absent in release).
   LM has so far avoided that kind of split; option (a) keeps a
   single binary shape.
3. **Cleaner DI surface for channels.** `PlainChannel`,
   `PaceChannel`, and `BacChannel` are natural consumers of an
   abstract transmit seam — they don't depend on any concrete
   PC/SC behaviour and shouldn't carry a hard link to it. Taking
   `IConnection&` documents the dependency precisely.
4. **Minimal blast radius.** When `PCSCConnection` is later changed
   to inherit `IConnection`, existing callers that hold a
   `PCSCConnection&` keep working unchanged; only channel
   constructors take the new abstract type.

## Scope of this commit

This commit adds:

- this README, and
- a stub header `lib/smartcard/include/smartcard/i_connection.h`
  declaring the `IConnection` abstract base with `transmit()` and
  a virtual destructor.

It does **not** make `PCSCConnection` inherit from `IConnection`,
add any channel implementations, or touch the build system. Those
land in subsequent tasks.
