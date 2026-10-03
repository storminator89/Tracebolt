# Linux guided enrollment client

The native `enroll-agent` command connects a public, operator-supplied enrollment
bootstrap to the existing `lan-agent` foreground sender. It does not install a
service, change OS trust, configure a firewall, renew credentials, or recover lost
keys. Windows/macOS builds return unsupported; runtime support is Linux only.

This page describes the implementation and disposable local fixture coverage.
It is not evidence of a real endpoint installation, reboot acceptance, or live
credential provisioning. Running it on a real endpoint generates persistent
endpoint credentials and requires the operator's authorization.

## Guided path

1. In the manager, create an invitation for Linux. Transfer the public
   `tracebolt.enrollment-bootstrap.v2` JSON to the intended endpoint through a
   trusted channel. The bootstrap contains no invitation secret or private key.
2. Build the native commands from the reviewed revision:

   ```sh
   go build -o /your/approved/bin/enroll-agent ./cmd/enroll-agent
   go build -o /your/approved/bin/lan-agent ./cmd/lan-agent
   ```

3. From the endpoint's controlling terminal, run:

   ```sh
   enroll-agent --bootstrap /absolute/path/bootstrap.json \
     --state-directory /absolute/path/new-private-device-directory
   ```

   The bootstrap must be a protected regular file with no symlink ancestors or
   writable-by-other ownership. Its public certificate material may be mode 0644;
   mode 0600 also works. The state directory must be absent or empty and mode 0700
   owned by the running UID. Its parent must already exist and be protected.
   Root/runtime-owned sticky ancestors such as `/tmp` are supported for fixtures.

4. Before the hidden invitation prompt, inspect the exact manager and agent
   origins, profile, manager/invitation IDs, collection profile, server CA
   certificate fingerprints and enrollment issuer/root certificate fingerprints.
   These are local bootstrap values, never trust learned from a network response.
   The command also prints its locally derived full SPKI SHA-256 fingerprint and
   context-bound 128-bit comparison value. It disables terminal echo before
   printing the prompt. No invitation argument, environment variable, URL,
   bootstrap field, stdin mode or downloadable secret file is supported.
5. Enter the invitation in the hidden prompt. Compare the complete locally
   printed fingerprint and comparison value against the manager's pending claim,
   then explicitly approve the intended device in the manager. The client waits
   cooperatively with bounded polling. Default timeout is 15 minutes; `--timeout`
   allows up to 30 minutes. Ctrl-C or timeout leaves the same identity for resume.
6. When enrollment and the private handoff are ready, run the exact command the
   client prints, equivalent to:

   ```sh
   lan-agent --config /absolute/path/new-private-device-directory/agent.json --foreground
   ```

   Foreground reporting stops when that command stops. There is no background
   installation or service startup. The existing sender's minimum interval,
   telemetry limits, pending-byte/sequence ledger and transport policy apply.

For the deliberately insecure test profile, also pass `--insecure-http-test`.
This acknowledgement is required each time. HTTP exposes the invitation and
reports, and its manager responses provide no server authenticity. The client
and ready metadata permanently identify this profile; even an `activated`
response is not described as verified server activation. There is no downgrade.

## Resume and failure rules

Re-run with the identical bootstrap and state directory after a normal interrupt
or uncertain network response. The local key, CSR, claim ID and semantic request
IDs are committed in a single private atomic ledger before any request. The
semantic claim hash is saved before transmitting the invitation-bearing claim;
the invitation and claim request bytes are never written to disk. Status uses a
fresh, purpose-bound challenge and the saved local key before deciding whether
invitation re-entry is needed. An uncommitted retry retains the same key, CSR,
claim ID and request ID.

After a definite authenticated TLS 400/401 claim rejection with the exact bounded
enrollment error envelope/code/message, the client saves a
rejection marker while retaining the old candidate hash. Re-running first checks
bound-key status. If the claim is still uncommitted, the operator can enter a
corrected invitation on the SAME key, CSR, claim ID and request ID. The corrected
candidate is atomically staged before sending. An uncertain response never
permits changing the candidate; status reconciliation remains mandatory. An
earlier unresolved candidate remains pinned even if a later retry receives a
definite rejection. Intermediary, malformed or unrecognized errors cannot enable
correction. Only matching bound-key status resolves the earlier ambiguity.

HTTP-test rejection is unauthenticated and cannot authorize correction. A
syntactically valid but wrong HTTP-test invitation can therefore pin an unusable
semantic claim. Preserve that state for inspection. The operator may need to
cancel the old invitation and issue a new authorized invitation for a NEW
dedicated directory. Do not delete/reset a ledger, change its bootstrap, or reuse
sender state to work around an error. Missing keys, tampered files, mismatched destinations,
foreign contents, interrupted write temporaries, missing ledgers and lost sender
domains fail closed. There is no automatic cleanup, lost-key recovery or renewal.

A terminated claim stops the client. A transport error alone is not treated as
revocation. Recoverable transport/401/409/429/503 outcomes are bounded by the
cooperative timeout; 429 respects a bounded retry delay. Invalid response
framing, changed context, invalid trust or a mismatched intent fail closed.

## Private files and readiness

The private directory contains only recognized mode 0600, single-link,
owner-controlled regular files and a separate mode 0700 telemetry directory:

- `enrollment.lock`: exclusive process lock
- `ledger.json`: local private key seed, CSR, fixed operation IDs and exact
  manager/origin/profile/issuer binding; later verified intent/certificate and
  activation/publication checkpoints. Treat this as private key material.
- `agent-key.pem`, `agent-cert.pem`, `server-ca.pem` (TLS only), `agent.json`:
  protected material and `tracebolt.lan-agent.v2` guided sender configuration
- `ready.json`: final handoff marker, written after files and directory fsync
- `telemetry/`: the sender's independent bound sequence/pending-byte ledger,
  initialized before any runnable sender configuration is published

TLS sender certificate files contain the leaf plus the dedicated issuer. The
HTTP-test sender accepts the leaf alone. No OS trust store is changed.

Publication validates every preexisting output against the local ledger before
network activity. Key/certificate/CA files are written first. A durable
sender-initialization-started checkpoint precedes the one-time initialization of
the exact bound sender ledger. Only after that succeeds is `agent.json` written,
then the handoff-prepared checkpoint is saved and the final ready marker appears.

On every initialized resume, the sender's explicit validation API acquires its
exclusive lock and validates the existing exact-bound ledger before enrollment
network activity. It does not create missing paths, locks or ledgers. Missing
sender state, an empty replacement directory, a wrong binding or an active
sender lock fail closed. Stop the foreground sender before asking enrollment to
validate the completed handoff. Enrollment does not reset sequences, change
pending bytes or clean up sender crash temporaries. It reads sender state only
through this explicit validation boundary.

An interrupted successful initialization can resume publication while preserving
its existing sender ledger. An interrupted initialization with missing/invalid
state cannot be retried as a fresh initialization. The final ready marker can be
republished only after prepared files and the valid bound sender ledger pass
validation. The v2 sender itself also requires existing state at runtime, so
starting it after state loss cannot create a new sequence domain. Existing v1
manual sender configuration retains its separately documented behavior.

This checks current binding and required state, not historical rollback. Restoring
a valid older backup with the same binding is explicitly outside rollback
detection; do not use a backup copy to reset or recover a live sender sequence.

Atomic writes use private exclusive temporary creation, file fsync, descriptor-
anchored rename and directory fsync. A crash temporary is retained and causes
rejection rather than being promoted or deleted. Same-UID/root compromise and
whole-directory removal are outside this filesystem boundary. In-memory secret
buffers are cleared when possible, but Go does not guarantee erasure of all
transient string/runtime copies. No invitation or private key is logged.

## Programmatic API and validation

`LoadBootstrap(path) (Bootstrap,error)` reads strict public bootstrap JSON.
`Run(ctx, Bootstrap, Options) (Result,error)` supplies a mandatory public-trust
`Display` callback and an in-memory `Secret` callback. The latter returns bytes,
which the client clears. `Notify` receives fixed phase strings and local public
comparison metadata. Callback errors are reduced to fixed safe errors. Generic private-handle
formatting and JSON serialization are redacted; only the explicit private ledger
codec can serialize persisted key material.

`Result` contains an existing `lanclient.Config`, its private configuration path,
local fingerprint/comparison values and `ServerAuthenticated` (always false for
HTTP-test). It does not return private keys, invitations or raw proof bodies.

The client reuses the shared exact-origin bootstrap transport: explicit server
roots, TLS 1.3, vetted/pinned addresses, no redirects, proxies, cookies, browser
credentials or compression. Response JSON is bounded and checked for exact
fields, duplicate/case aliases, nulls and malformed framing. Issuer/root policy
uses `enrollmentissuer.ValidatePublicAuthority`. Every delivered immutable intent
field is checked against local key/CSR/context and the previously checked public
snapshot, then DER is checked with `enrollmentcrypto.VerifyIssued`. Certificate
and intent commit before a fresh activation proof; lost activation responses
reconcile through the bound-key status route.

Focused checks:

```sh
go test -race ./internal/enrollmentclient ./cmd/enroll-agent
go vet ./internal/enrollmentclient ./cmd/enroll-agent
```

Fixtures create disposable generated keys and loopback HTTP/TLS servers. They
cover guided success, pre/post-commit claim loss, activation-response loss,
pending resume/cancellation, complete-intent mismatch, strict bootstrap/response
framing, local output and trust checks, private-first-write/locking, fail-closed
filesystem faults, initialized sender-domain loss/replacement, sender-lock
contention and exact pending-byte/sequence preservation. CLI tests reject secret
arguments without echoing their values. A synthetic PTY fixture sends input
immediately after the prompt and verifies echo suppression and terminal-state
restoration. Actual manager/enroller/sender binary
acceptance is a separate runtime integration check; this package's fixtures do
not prove real installation or persistent service operation.
