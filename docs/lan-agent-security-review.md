# One-shot LAN sender security review

Reviewed 2026-10-03. **Targeted source, regression and native Linux two-process checks passed.** This is a foreground sender milestone, not a service, real-LAN deployment or production-security approval. The earlier manager review is [lan-security-review.md](lan-security-review.md); the sender contract and runtime evidence are [lan-agent.md](lan-agent.md) and [lan-client-runtime-evidence.md](lan-client-runtime-evidence.md).

## Boundaries checked

- Linux-only protected configuration and state. The sender consumes preprovided client material, does not issue/enroll credentials, and performs one bounded collection/delivery attempt. Existing stdout-only and developer-preview commands retain their separate roles.
- TLS is the default, with explicit server CA trust, exact hostname/SAN verification, a current client-auth certificate and TLS 1.3. Loaded material is opaque and revalidated before use; zero/uninitialized material cannot fall back to ambient roots or anonymous TLS.
- HTTP test requires explicit acknowledgement, separate profile-bound state and an Ed25519 client leaf. Telemetry is signed for the exact configured origin and request contract. **It remains readable on the network; an impersonating HTTP server can forge an acknowledgement and cause the pending sample to be discarded.** This mode provides neither server authentication nor confidentiality.
- Destinations come from protected local configuration. All DNS answers are vetted before a literal address is dialed. Proxies, redirects, compression and automatic alternate-provider behavior are disabled. Metadata, link-local, unspecified, multicast and special transition addresses are rejected; HTTP test is restricted to private/loopback destinations. No network discovery occurs.
- A private single-writer lock spans the delivery attempt. State is bound to profile, exact origin, client certificate fingerprint and expected manager-assigned agent ID. Changes to those fields cannot redirect or reuse pending data. This is not a claim that every non-binding configuration field is immutable.
- Before transmission, one exact request and its consumed sequence are stored through a synchronized file, atomic rename and directory synchronization. An uncertain result retains the original bytes, digest, sequence and observation times. No new sample silently replaces an unresolved fresh request.
- A validated identity/sequence/time-bound receipt clears only its pending digest. Receipts require all six exact fields, correct types, supported content type, no encoding and a bounded body. Malformed, missing, oversized or untrusted responses retain the pending sample and produce static diagnostics.
- Expired pending observations are discarded without sequence reuse. Only a genuinely new collection can obtain the next sequence; old timestamps are never rewritten to appear fresh. The sequence domain matches the receiver's signed 64-bit maximum.
- State paths are descriptor-anchored, private and checked for replacement, unsafe ownership, symlinks and hardlinks. Fresh initialization requires a dedicated empty directory. Existing temporary work is cleaned only after the ledger's schema, body digest and exact binding are validated. Corrupt or incompatible state fails closed.
- Diagnostic formatting/JSON omits key material and retained telemetry. CLI status exposes only bounded outcome/profile/sequence flags and availability counts. State on disk is plaintext protected by filesystem permissions, not encrypted storage.

## Findings corrected before acceptance

1. **Premature temporary-file deletion.** Fresh, wrong-binding and corrupt-state paths could remove a preexisting `.state.tmp` before validating ownership of the logical store. Three independent synthetic regressions reproduced this. Initialization now rejects unrelated nonempty directories, and cleanup follows complete ledger/binding validation. All three preservation tests pass.
2. **Loaded-material trust boundary.** An exported material structure could be manually constructed with missing TLS settings. Material is now opaque and only accepted after explicit load/revalidation, preserving configured roots, name, client certificate, TLS minimum and verification.
3. **HTTP client certificate checks and receipts.** Local validation now checks current exclusive client purpose before collection; receipt parsing requires every field instead of accepting omitted values as defaults. Encoded receipts are refused.

## Independent execution evidence

- `go test -race ./... -count=1`, `go vet ./...`, and `go mod verify`: passed against the integrated source.
- `tests/security/lanclient_state_boundary_test.go`: independent directory-preservation regressions, writer exclusion, exact bytes across reopen, defensive copies, digest-bound acknowledgement, monotonic sequence and body-free diagnostics passed.
- Reviewed and executed the sender's focused tests for an actual committed manager observation followed by response loss, exact retry from a newly built CLI process, stale discard/new collection, changed binding, malformed/encoded receipts, redirects, cancellation and rejected trust material.
- Reviewed and independently executed `tests/lanclient/runtime_test.go`: separate built `lan-manager` and `lan-agent` processes passed both TLS/mTLS and signed HTTP-test profiles. Checks include empty/awaiting inventory, sequences 1→2→3, manager restart persistence and session invalidation, stale sequence rejection, revocation across another restart, unchanged last accepted data after denial, private modes and clean shutdown.
- The Go race command instruments the test harness; its child binaries are ordinary native builds. No race-instrumentation claim is made for those subprocesses.

All runtime checks used disposable loopback listeners, synthetic operator credentials and ephemeral certificates with normal verification. No global trust store was changed, raw observation values were published, or real deployment was performed. Opt-in/skipped container tests do not establish container execution.

## Advisory evidence

A fresh Linux/amd64 source scan used `govulncheck@v1.8.0` with Go 1.27.1 after the sender/state code was present. It covered 26 root packages, including the sender command and two-binary harness; source hashes were unchanged during the scan. Results: **zero reachable-symbol findings, zero imported-package findings, and one advisory in a required module**.

The remaining module-level entry is [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), affecting the unused, unmaintained OpenPGP packages in `golang.org/x/crypto`. The application uses Argon2 and does not import those OpenPGP packages. This is neither an observed reachable sender vulnerability nor a blanket claim that every dependency is advisory-free.

## Remaining limits

- No Windows/macOS sender-state/ACL/lifecycle acceptance, installation, signing/distribution, service recovery, reboot, uninstall or unattended scheduling is established.
- The buffer retains one recent sample, not offline history. Replay/state rollback after privileged tampering or unsupported recovery remains outside this process boundary.
- The CLI's 20-second context is a cooperative work budget; synchronous filesystem or output operations are not proven to obey a hard wall-clock deadline.
- Actual LAN routing, firewall/container configuration, real credential provisioning, server trust setup and deployment readiness need separate acceptance.
- Native observations are authenticated claims from the process environment, not hardware attestation, continuous liveness or whole-device health.

This review is targeted manual analysis with regression evidence, not an exhaustive formal security scan or certification.
