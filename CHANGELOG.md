# Changelog

What changed in each release of birdcage, for the people who run it.
Newest first. The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and the version numbers follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- The dashboard no longer shows the self-test and maintenance buttons (#228).

### Fixed

- A plain `http://` visit to the dashboard's TLS port is now redirected to
  `https://` instead of failing (#212).
- The canary page's status pills show the right state again (#229).

### Security

- Built with Go 1.27.4 (#203), which also carries Go 1.27.3's `crypto/x509`
  fix (#194).
- `enrol` and the upgrade command refuse to make a new certificate authority
  once certificates have been issued from the current one, so existing
  canaries are not cut off (#214).

## [0.1.0] - 2026-10-03

### Added

- The first release. Six images -- birdcage, mockingbird, opencanary,
  nightjar, smb-lure and holder -- published by digest, each with a
  key-based validation attestation, and mirrored to GHCR.

[Unreleased]: https://github.com/tomlawesome/birdcage/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tomlawesome/birdcage/releases/tag/v0.1.0
