# Rust basic manager compatibility preflight (TB-01 partial)

This source change is not a new release or native acceptance. Use the Windows
ZIP and Linux manager/frontend package from the same immutable integrated test
release, verify every asset hash, and configure the Windows guided **TLS,
non-renewal** enrollment domain. Rust basic collects CPU, physical memory,
system-volume capacity and uptime; it does not replace Go Read admin or grant
its extended scopes. Existing release bytes/tags are unchanged.

## Public contract, not authority

`GET /v1/windows/rust-basic-capabilities` returns at most 2,048 bytes of static
protocol/configuration metadata. It requires the actual TLS 1.3 operator listener,
exact Host, canonical path, no query/body/browser credentials, and the existing
bounded public-metadata admission budget. It exists only for a valid configured
Windows TLS non-renewal domain. No identity, invitation, bootstrap certificate,
telemetry, runtime state or secret appears in the response. It never creates a
challenge, pending record or approval and adds no operator/data access.

The strict nine-field response identifies:

- `tracebolt.rust-basic-manager-capabilities.v1`;
- `tracebolt.enrollment.v2`, `windows-inventory-v1`, `rust-windows-basic-v1`;
- `tracebolt.agent-telemetry.windows.v1` and `tracebolt.agent-receipt.v1`;
- exact enrollment and agent HTTPS origins;
- whether automatic Windows registration is actually configured.

Automatic mode requires that last capability; explicit invitation mode cannot
be selected as an implicit fallback. Advanced preprovided mode has distinct
legacy telemetry-origin semantics and is deliberately outside this preflight;
its behavior is unchanged, not newly accepted as compatible. The existing authorization
profile stays Windows inventory even though the Rust collector is basic-only.

## Ordering and safe diagnostics

`validate-config` remains a local-only parser check. Add `--check-manager` for the
network preflight; the installer supplies it for automatic/invitation enrollment
before `New-Service` or any target directory creation. Explicitly requesting this
capability check in preprovided mode fails closed without sending a request.
It sends only the fixed GET over existing selected
server trust: no endpoint key, CSR, invitation ID/token, cookie or credentials.
Redirects, environment proxies, plaintext HTTP and trust adoption stay disabled.
Connect timeout is five seconds; the entire request is bounded to ten seconds.
Unknown/duplicate JSON fields, wrong protocol/profile/origins, oversize data or an
old manager are rejected. A configured agent-origin pin is not overwritten.

`init` performs the same check before `Enrollment::open` for automatic/invitation
enrollment; the library enrollment initializer independently rechecks before the lock, DB,
key or CSR. Existing enrollment/telemetry retries, status and ledger reads do not
require this public endpoint and never recreate/reset used state.

- `MANAGER_PROTOCOL_UNSUPPORTED`: use matching manager/frontend and Rust basic
  artifacts with the required Windows TLS non-renewal configuration. No downgrade
  or replacement identity is attempted.
- `MANAGER_PREFLIGHT_UNAVAILABLE`: check the supplied address, selected TLS trust
  and network/server availability. TLS failures, rate limits and 5xx responses
  are not presented as proof of incompatibility. Raw responses/errors stay out of
  logs; no unbounded automatic retry is introduced.

The release-manifest writer records manager, frontend and agent source commits
separately (currently one source build), the Rust-basic profile, required protocol
and package hashes. The manager tar hash binds its included compiled frontend;
this is not independent attestation of installed bytes.

## Evidence and remaining gates

Portable Rust tests use disposable, authenticated loopback TLS and check strict
contract handling, selected trust/origin pinning, repeatable nonmutation, direct
library and CLI failure before new state, and no enrollment request. Go tests
exercise the real manager handler, configured service, guard failures, admission
limit and unchanged enrollment snapshots; the native Windows protocol fixture
advertises the same contract. These are not native Windows installation or a
real Windows-to-Linux-manager/dashboard acceptance result.

Manager/network availability can change after any preflight. A later failure
after valid preflight may retain disabled staging; no transactional installer or
TOCTOU-proof path/executable validation is claimed. Invitation-bootstrap content,
preprovided compatibility/credential validation, reparse/ACL/executable provenance/manifest
checks and an explicit offline-install mode remain TB-07/TB-08 work. Native
negative installation/file-preservation tests, supported OS/architecture gates,
freshly downloaded released-component acceptance and immutable release evidence
are still required. Keep #128/#134 open until their full acceptance is met.
