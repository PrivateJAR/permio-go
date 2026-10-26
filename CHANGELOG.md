# Changelog

## Unreleased

### Added

- Package `permio` at the module root: the hand-written SDK beside the
  generated stubs.
  - `New(Options)` with local API key validation, `PERMIO_API_KEY` fallback,
    `DefaultEndpoint` / `DevEndpoint`, default project and `WithProject`,
    per-attempt timeout (default 10s), retry options and an injectable
    `grpc.ClientConnInterface`.
  - Checks: `Check`, `CheckAll`, `CheckAny`, `CheckDetailed`, `Assert`,
    `AssertAll`, `BatchCheck`, `BatchCheckDetailed`.
  - `ListAccess` (with `Allows`, `Prefixes`, `Patterns`, `RegexpSource`) and
    `WhoHasAccess`.
  - `Grant`, `Revoke`, `GetGrant`, `WhoAmI`, permission and role CRUD.
  - Groups via `Client.Groups()`; `GroupPrincipal`, `Resource`, `EncodeSegment`,
    `ValidateResourceURI`.
  - `iter.Seq2` iterators over every paginated listing, and `Collect`.
  - Typed errors: `*Error` with `Kind` (`errors.Is` with `ErrAuth`,
    `ErrPermission`, `ErrValidation`, `ErrNotFound`, `ErrUnavailable`,
    `ErrTimeout`, `ErrRateLimited`, `ErrDenied`, `ErrConfig`, ...).
  - Retries of idempotent reads on Unavailable / DeadlineExceeded, and of
    rate-limited reads after the server's RetryInfo / retry-after delay.
    Writes are never retried.
  - Raw clients: `Permissions()`, `Organisations()`, `Conn()`.
- Apache-2.0 LICENSE, CI and release workflows on Blacksmith runners.

## v0.0.18 and earlier

Generated stubs only, published by PrivateJAR/proto's release workflow.
