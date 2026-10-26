# Changelog

## v0.1.0

First release with the hand-written SDK package.

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
  - Groups via `Client.Groups()`; `GroupPrincipal`, `Resource` /
    `MustResource`, `EncodeSegment`, `ValidateResourceURI`.
  - `Resource()` with no segments (or an empty segment) is a validation error,
    never `"/"`.
  - `Groups.AddMembers` / `RemoveMembers` take at most 100 principals and send
    them in one write; more is a validation error rather than several writes
    that could partly fail.
  - `CreatePermission` and `CreateRole` are idempotent (the API upserts);
    `AlreadyExists` from the API (e.g. a rename onto a used name) maps to
    `KindAlreadyExists` with no extra calls.
  - `iter.Seq2` iterators over every paginated listing, and `Collect`.
  - Typed errors: `*Error` with `Kind` (`errors.Is` with `ErrAuth`,
    `ErrPermission`, `ErrValidation`, `ErrNotFound`, `ErrUnavailable`,
    `ErrTimeout`, `ErrRateLimited`, `ErrDenied`, `ErrConfig`, ...).
    `GRPCStatus()` never reports `OK`: denied errors carry `PermissionDenied`
    and config errors `FailedPrecondition`.
  - Plaintext (`Insecure` or an `http://` endpoint) is only allowed to
    localhost, `*.localhost` and loopback addresses, so the API key is never
    sent in clear over the network.
  - Listings fail with an error if the API repeats a pagination cursor,
    instead of ending quietly with a partial result.
  - Retries of idempotent reads on Unavailable / DeadlineExceeded, and of
    rate-limited reads after the server's RetryInfo / retry-after delay.
    Writes are never retried.
  - Raw clients: `Permissions()`, `Organisations()`, `Conn()`.
- Apache-2.0 LICENSE, CI and release workflows on Blacksmith runners.

### Retracted

- v0.0.1 to v0.0.18 are retracted in `go.mod`: they contained only the
  generated stubs, not the SDK package.

## v0.0.18 and earlier

Generated stubs only, published by PrivateJAR/proto's release workflow.
