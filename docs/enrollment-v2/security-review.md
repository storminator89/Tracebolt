# Enrollment foundation: targeted security review

Review date: 2026-10-03. Scope: the isolated `enrollmentstate`,
`enrollmentcrypto` and `keyvalidation` packages, before runtime integration.
This is a targeted source and regression review, not an exhaustive audit or
deployment approval. Published manager/browser and native-sender evidence is
tracked separately.

This is the historical foundation checkpoint. Subsequent durable storage,
runtime integration and native-client acceptance are recorded in
[the durability review](durability-security-review.md) and
[the native-client review](native-security-review.md). The process-local scope
and integration prerequisites below describe this earlier checkpoint, not the
capabilities of the later combined candidate.

## Current boundary

The state engine is process-local and non-durable. It does not create an
invitation endpoint, authenticate an operator, generate credentials, invoke a
signer, install a service, transmit telemetry, or deliver a certificate. Public
snapshots are inspection data and cannot restore the private engine. Empty or
body-constructed proof flags cannot replace the concrete verified proof types.

The reviewed contract requires server-owned challenge and issuance context,
exact instance/origin/profile binding, one semantic claim, explicit approval,
fixed issuance metadata and a separate fresh activation proof. Returned public
key/certificate byte slices are copies. Secret-bearing diagnostics are redacted.

## Findings addressed during review

1. Engine diagnostic methods originally covered pointers without adequately
   protecting a dereferenced value. The engine now holds a shared private state
   behind a copyable handle, uses value-safe formatting/JSON redaction, and never
   copies a live mutex. Independent copied-handle concurrency and diagnostic
   tests pass under the race detector.
2. The original enrollment proof verifier accepted a degenerate Ed25519 public
   key as proof of possession. An independent rejection regression failed before
   the defensive change. The new shared key policy requires canonical encoding,
   a nonidentity point and membership in the prime-order subgroup. Ordinary
   generated-key compatibility and pure key-classification tests pass. The
   earlier failure was in unexposed enrollment code; it is not evidence of an
   unauthenticated exploit against the published manager.
3. Activation proofs now bind a digest of every immutable issuance-intent field,
   including claim/CSR and signing-request metadata. The certificate validator
   checks serial bounds before fixed-size conversion, avoiding an oversized
   serial panic. These owner fixes have focused package regressions.

The key policy uses pinned `filippo.io/edwards25519` v1.2.0 for curve operations
and retains Go's normal signature verification. The upstream API explicitly
allows noncanonical point encodings, so the additional byte roundtrip is
necessary. Cofactor projection followed by the inverse-cofactor roundtrip
checks the full subgroup condition, including mixed-order points.
[Upstream API documentation](https://pkg.go.dev/filippo.io/edwards25519@v1.2.0)

## Independent evidence

`tests/security/enrollment_state_boundary_test.go` exercises exported contracts:

- copied handles share one synchronized state; pointer/value diagnostics remain
  redacted; caller-owned snapshots cannot mutate the engine;
- empty opaque proofs cannot claim, issue or activate; unapproved state cannot
  produce a signing intent; unsupported renewal/recovery/migration fail closed;
- concurrent distinct terminal commands produce one CAS commit; terminal
  tombstones, verifier uniqueness and global capacity remain enforced;
- canceled or expired operations leave state unchanged; expiry requires an
  explicit valid transition;
- inspection JSON rejects duplicate/case-aliased/missing/extra fields, nulls,
  fractional revisions, invalid state combinations, trailing data and oversize.

Verified independently in the Linux development workspace:

- the five independent state groups, race detector, three repetitions: **pass**;
- full `internal/enrollmentstate` package, race detector, three repetitions:
  **pass**;
- pure `internal/keyvalidation` tests, race detector, three repetitions:
  **pass**;
- the five existing generated-key enrollment-crypto tests covering claim
  binding/JSON, fixed certificate policy and activation binding, race detector,
  three repetitions: **pass**;
- `go vet` on the three scoped packages and `go mod verify`: **pass**.

A fresh pinned `govulncheck` v1.8.0 scan on Linux/amd64 with Go 1.27.1
covered 29 root packages and 11 modules, including the new enrollment packages
and `filippo.io/edwards25519` v1.2.0. Source/module-file hashes were unchanged
during the scan. It reported zero reachable-symbol findings and zero
imported-package findings. The required `x/crypto` module still carries
[GO-2026-5932 for unused OpenPGP](https://pkg.go.dev/vuln/GO-2026-5932);
dependency inspection found only its Argon2 and blake2b packages imported. This
is a scoped advisory result, not a blanket guarantee of no vulnerabilities.

These checks do not establish installer/service operation, durable enrollment,
certificate delivery, trusted-TLS browser behavior or a deployed LAN system.
Existing-runtime weak-key exploit validation was not performed. The existing
manual certificate path requires a configured trusted issuer and explicit
operator approval; its defensive hardening and compatibility checks are a
separate change, not an inherited enrollment test result.

## Required before integration

- Use a trusted manager clock and server-owned challenge records. JSON decoding
  is not authority for client-supplied time, identity, issuer or approval.
- Atomically persist approval/revocation, intent, exact certificate DER, revision
  and delivery/replay metadata. Calling the in-memory engine and then writing a
  database is not an atomic persistence implementation.
- Add explicit external-signer idempotency/reconciliation, restart and rollback
  behavior, bounded challenge/rate limits, issuer custody, renewal/recovery and
  old-pending-frame migration tests before exposing enrollment.
- Preserve the separate TLS and disposable HTTP-test profiles. HTTP testing
  still provides neither confidentiality nor authenticated server/UI delivery.
- Complete final immutable-source aggregate/CI evidence before runtime
  integration. The checks above deliberately do not claim an existing-runtime
  exploit reproduction or a full changed-tree execution pass.
