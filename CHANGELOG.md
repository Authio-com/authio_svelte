# Changelog

All notable changes to `@useauthio/svelte` are documented here. This
project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] — 2026-06-13

### Fixed
- **Package is now installable from npm.** `0.2.0` declared its
  `@useauthio/node` dependency as `file:./vendor/authio-node` (and did
  not ship the vendor directory in the tarball), so
  `npm install @useauthio/svelte` failed for every external user. The
  dependency now points at the published `@useauthio/node` (`^0.2.0`).
- Server-side `AuthioServerSession` now carries the `flags` array that
  `@useauthio/node@0.2.0`'s `Session` requires (surfaced from the token's
  `flags` claim), keeping the type build green against the real package.

## [0.2.0] — 2026-06-12

### Changed
- **Renamed npm package `@authio/svelte` → `@useauthio/svelte`.** The
  original `@authio` scope could not be claimed on npm, so every Authio
  SDK now publishes under the organization scope `@useauthio`. Install
  with `npm install @useauthio/svelte` and update imports accordingly.
  The old `@authio/svelte` name is retired; releases below this entry were
  published (or prepared) under the old name and are kept for history.

