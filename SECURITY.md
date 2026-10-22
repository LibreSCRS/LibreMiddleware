# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately using GitHub Security
Advisories:

  https://github.com/LibreSCRS/LibreMiddleware/security/advisories/new

For non-GitHub correspondence, contact the project release signing
identity:

  librescrs@proton.me

We respond to security reports within five business days. Please give
us a reasonable disclosure window before publishing.

## Release verification

LibreSCRS releases ≥ 4.0 are cryptographically signed.

- **Git tags** are GPG-signed with the LibreSCRS Release Signing key
  (fingerprint `6B05889AC9A6A7188DF639B06F27A989C2031D16`). The CI
  release pipeline rejects any unsigned or wrong-fingerprint tag.
  See `KEYS` in this repository for the public key blob and the
  `gpg --verify` / `git tag -v` workflow.
- **Release artifacts** (binaries, plugins, archives) are signed via
  Sigstore cosign keyless using GitHub Actions OIDC. The SLSA
  provenance bundle (`*.sigstore.json`) ships alongside every release
  asset. See <https://librescrs.github.io/security/> for the
  end-to-end verification guide including expected OIDC issuer +
  identity values.

## PKCS#11 module deployment

The middleware ships a PKCS#11 module, `librescrs-pkcs11.so`, and it can be
deployed in one of two ways. The choice has security consequences, so it is
recorded here rather than left to the packaging.

**The supported desktop arrangement is the agent proxy.** The agent owns the
reader, collects the PIN in its own prompter behind an authorization prompt and
a lease, and is the single PKCS#11 provider a host sees. The direct module
collects the PIN inside whichever application loaded it. Registering both means
two independent security models for one card, and which one applies is decided
by whichever dialog the user happens to type into. The module is therefore
installed without a p11-kit declaration by default; see
`docs/SHARED-LIBRARY-CONSUMERS.md`.

There is a second, harder consequence of registering both, and nothing in the
code prevents it: the guard that stops one provider from binding a card whose
secure channel another holds is **process-local**. A direct module loaded into a
different process — a browser, a mail client, an agent of its own — sees an empty
guard, binds the card, and sends plain commands to a card whose contactless
session the LibreSCRS agent is holding. That ends the session card-side. Nothing
detects it and nothing re-establishes it; the user is asked for the card access
number again at the next operation. Keeping exactly one LibreSCRS provider per
host is what prevents this, and that is a property of the packaging, not of the
library.

On macOS the agent's hold on a card is exclusive at the system level: a card
session holds the card through CryptoTokenKit until it is closed, and the
direct module is not built for macOS.

**The direct module is exclusive with the agent on the same reader.** It is not
published as a package in 5.0 — it is built for tests and installed
unregistered — and a host that registers it by hand takes on this limit:

- It probes each reader exactly once for the life of the loaded module. Nothing
  watches for card removal — `C_WaitForSlotEvent` reports
  `CKR_FUNCTION_NOT_SUPPORTED` and the module runs no thread of its own — so a
  card swapped into the same reader is not re-probed until `C_Finalize`, and the
  slots the first card published stay surfaced. What stays surfaced is the first
  card's identity too: the token label, the serial number and the certificate a
  host reads back belong to the card that has gone. Two cards of the same family
  carry the same object identifiers, so the objects rebind silently and **a PIN
  collected for the first card is presented to the second**, spending its retry
  counter. Reload the module, or use the agent.

A signature made through the middleware's signing API does not load the module:
it signs through the card plugin on the session the caller already holds.

## Supported versions

| Version | Supported |
|---------|-----------|
| 5.x     | ✅ Active  |
| 4.x     | ✅ Active  |
| 3.x     | ❌ EOL     |
| 2.x     | ❌ EOL     |
