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

## Supported versions

| Version | Supported |
|---------|-----------|
| 4.x     | ✅ Active  |
| 3.x     | ✅ Active  |
| 2.x     | ❌ EOL     |
