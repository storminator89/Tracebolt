# Native LAN sender: two-binary runtime regression

Run on Linux with the Go version declared by `go.mod`:

```sh
go test -count=1 -timeout=4m ./tests/lanclient
```

`go test -short` skips this subprocess test. It also runs as part of a normal
`go test ./...` invocation.

The test builds **both** `cmd/lan-manager` and `cmd/lan-agent` into a temporary
location. All telemetry comes from the separate native agent process. No
application handler, collector, trust registry, or sender-state implementation
is invoked inside the test process.

## Profiles and assertions

Both profiles use separate ephemeral `127.0.0.1` operator and agent listeners:

- Default TLS: both configuration profile fields are omitted; the manager uses
  TLS 1.3 and agent mTLS. The operator and agent trust only the test's explicit,
  temporary CA. An agent request without a client certificate cannot complete
  its TLS handshake.
- Explicit `http-test`: both configurations explicitly acknowledge plaintext.
  The actual agent signs using its disposable Ed25519 identity. The session API
  must expose the unencrypted-test warning. Plain HTTP is not server-authenticated.

The public operator API performs login, certificate approval with a checked
fingerprint, authenticated inventory reads, and cookie/Origin/CSRF-protected
revocation. The suite verifies:

1. Unauthenticated inventory is denied. Authenticated inventory is initially
   empty, and an approved but silent agent remains unknown with no measurements.
2. The first separate sender process submits sequence 1. Inventory has exactly
   its manager-assigned identity, operator-provided label, source `lan`,
   `synthetic=false`, null IP, and unknown overall health. Metric/evidence
   provenance and nullable percentage values remain consistent with the safe
   availability counts. No hostname, account, machine ID, serial number, or
   network-interface identifiers appear in the response schema.
3. The next sender process advances to sequence 2 and a new observation.
4. SIGTERM and restart preserve approval and the accepted observation. Operator
   sessions do not survive restart. A **separate disposable test state** attempts
   sequence 1 and is rejected without altering inventory, independently proving
   that the manager retained its replay floor. The original sender state then
   advances successfully to sequence 3.
5. Revocation rejects sequence 4 without changing the last accepted observation.
   The pending request remains retained. After another manager restart, retrying
   it is still rejected and inventory still displays revoked trust.
6. Managers terminate cleanly on SIGTERM. Fixture and generated state directories
   remain 0700 and files remain 0600.

Every process and readiness wait is bounded; cleanup sends SIGTERM and uses a
bounded kill fallback only on failure. No services, Docker containers, deployment,
real LAN interface, global OS trust changes, TLS-verification bypass, or permanent
credentials are involved. Test-only certificates, passwords and local observation
state are deleted with the temporary directory. Child logs and raw observations
are never printed. Failures report only fixed, safe diagnostic labels.

These are real bounded Linux observations from the test machine. A cloud sandbox
may expose shared-kernel or host-wide readings; the suite does not establish
physical-host identity, container limits, endpoint health, Windows/macOS runtime
acceptance, browser UI acceptance, or production deployment readiness.
