# Native LAN client runtime evidence

Verified on 2026-10-03 in a Linux cloud development sandbox.

## Result

**PASS** for both the default TLS/mTLS profile and the explicitly acknowledged
HTTP-test Ed25519 profile, using freshly built, separate `lan-manager` and
`lan-agent` executable processes.

The independent regression lives in
[`tests/lanclient/runtime_test.go`](../tests/lanclient/runtime_test.go). It uses
public CLI and HTTP contracts, with no in-process collector, sender, manager,
registry, or state calls. Its [run guide](../tests/lanclient/README.md) describes
the setup, assertions and scope.

| Check | Result |
| --- | --- |
| Build both actual binaries and start separate loopback operator/agent listeners | PASS |
| Default TLS with explicit ephemeral CA trust, TLS 1.3 and required client certificate | PASS |
| Explicit plaintext-test configuration, actual Ed25519 sender and visible warning metadata | PASS |
| Login, browser-cookie session, Origin/CSRF mutation boundaries and certificate approval | PASS |
| Empty/awaiting inventory before agent collection; no manager-generated sample | PASS |
| Real one-shot Linux agent observation in authenticated manager inventory | PASS |
| Manager-assigned identity, `source=lan`, `synthetic=false`, unknown overall health and null IP | PASS |
| Evidence provenance and available/unavailable percentage counts | PASS |
| Separate sender processes advance sequences 1, 2 and 3 | PASS |
| Manager restart preserves approval and observation while invalidating sessions | PASS |
| Fresh disposable sender state sequence-one replay is rejected after manager restart | PASS |
| Revoked sender rejected; last accepted observation unchanged | PASS |
| Revocation and rejection of retained pending request survive another restart | PASS |
| Clean SIGTERM manager shutdown; private 0700 directories and 0600 files | PASS |

## Commands

```sh
. scripts/env.sh
go test -count=1 -timeout=4m ./tests/lanclient
go test -count=5 -timeout=4m ./tests/lanclient
go test -race -count=1 -timeout=4m ./tests/lanclient
go vet ./tests/lanclient
```

All commands passed. The repeat run completed all five iterations for both
profiles. The race command instruments the test harness; the subprocesses are
normal native builds, not race-instrumented binaries.

## Privacy and acceptance limits

Only safe pass/fail test output was retained. No raw readings, certificate
contents, passwords, machine identifiers, fixture paths or state files are
included in this evidence. All trust material and passwords are disposable,
locally generated test fixtures. No global trust store is changed, verification
is never bypassed, and the listeners bind only ephemeral IPv4 loopback addresses.
No persistent service, Docker container or deployment is created.

The collector runs on the cloud Linux sandbox only. The readings may describe a
shared kernel or sandbox-visible filesystem; they do not establish a physical
host, container resource limits or endpoint health. This verifies native Linux
binary-to-binary integration. It does not verify Windows/macOS sender runtime,
real LAN exposure, browser interaction, signing/distribution, production audit,
retention, hardening or deployment readiness.
