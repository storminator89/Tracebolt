# Package reader, frame and sender review

Reviewed 2026-10-04 UTC on Linux/amd64 with the existing Go 1.27.1 toolchain.
This checkpoint is separate from the pure parser/DTO review recorded in
[contract-review.md](contract-review.md). It covers the isolated source reader,
v3 frame, v4 sender/configuration and operational clone-trimmer. API, durable
enrollment-store/quota, UI, real native package collection and whole-system
acceptance are not approved by this review. Their sources were still being
integrated and no full aggregate was run. Frozen archives were not changed.

## Decision and correction

No unresolved blocker was found in the final reviewed seams. One concrete
collector cancellation inconsistency was found and corrected by its owner:
cancellation during a failing provider constructor originally returned the
provider's unavailable/denied reason without checking the canceled context.
The corrected branch returns both sections unknown/timeout. Inert fixtures cover
permission-denied, read-failed and unsupported factory errors and verify slot
release. Final source-bound hashes are recorded below.

The initial new sender fixtures injected operational/package sources but still
used the existing basic `collector.Snapshot`. Those earlier runs therefore read
sandbox basic observations, including release and `/proc` data. They were not
new package-source acceptance. Before this review executed the new sender suite,
the owner added private per-attempt basic-source injection. All new package
collection tests now use synthetic basic, operational and package observations;
the only direct public `Run` calls in those owner fixtures fail on missing/wrong
ledgers before source work. Existing production and legacy-test wrappers remain
unchanged and their earlier basic-source evidence remains separately labeled.

## Source-reader boundary

Reviewed production `packagecollector` source and its inert-provider/disposable
descriptor fixtures. Production `Collect` and the system-root factory were not
called in these checks.

- Invalid generation, time or nil context fails before provider construction.
  A single atomic admission slot spans construction, source work, rechecks,
  cleanup and export. Busy calls perform no source work. No read goroutines are
  abandoned and no hard filesystem deadline is promised.
- Production paths are fixed. Each parent is descriptor-relative, no-follow,
  owned by UID 0 and not group/world writable. Tests supply an explicit private
  root and fixture UID through unexported per-instance seams.
- A regular `/etc/os-release` wins. Only its leaf ENOENT after validated `/etc`
  permits the fixed `/usr/lib/os-release` fallback. Two exact standard symlink
  spellings are allowed; arbitrary links, link chains and unsafe targets fail.
  Normal symlink permission bits are not mistaken for target write permission.
- O_PATH probing precedes nonblocking/no-follow read opens; regular-file,
  identity, mode/owner, size and modification checks detect ordinary replacement
  or mutation. Pinned parent/leaf/link and current-path identities are rechecked
  after both source attempts, including when the other source fails.
- Changed/failed sources clear their own dependent facts. Cancellation clears
  both sources. No parsed prefix, raw diagnostic or previous result is exported.
  File descriptors close synchronously. No network, process execution, APT,
  package refresh, credential/trust or persistent filesystem write is introduced.

This is not an atomic two-file snapshot, protection against a privileged OS
administrator, physical-host attribution, or isolation from OS-managed remote
mount behavior. Native Debian/Ubuntu reads remain a separate acceptance gate.

## Frame and sender boundaries

- Existing telemetry v1 retains exactly its original three members. Telemetry
  v2 retains its four-member operational shape. Even `packages: null` is rejected
  by older frame schemas. Neither old profile acquires package collection.
- Telemetry v3 requires the basic observation, unchanged operational-v1 baseline
  and package component. The durable profile matrix admits it only for
  `managed-operations-v2`; relabeling the contained operational profile fails.
- Both raw and canonical component reservations are enforced: 16 KiB basic,
  32 KiB operations and 16 KiB packages, under the unchanged 72 KiB outer cap.
  Strict shape, duplicates, null/types, decoded strings and package validation
  remain mandatory. A compact raw string cannot bypass canonical expansion.
- Package generation and collection time must equal the operational component;
  source age/skew and ordering against the basic bundle stay enforced. Managed
  sequence numbers remain within the existing JavaScript-safe integer domain.
- Sender config v4 requires the exact package profile and a distinct v4 ledger
  binding. It uses `OpenExisting`; missing or differently bound ledgers cannot
  create/reset/adopt state. Older config/profile combinations remain separate.
- New collection validates the operational snapshot, trims a clone to 32 KiB,
  validates the package result and shared capture identity, prepares the basic
  bundle, and validates the whole frame before staging. Cancellation or invalid
  components cannot consume a new sequence or create a pending frame.
- A pending frame is decoded under its original exact configuration and sent as
  the unchanged durable bytes. Wrong-schema pending data remains retained and
  does not trigger replacement collection. Explicit stale discard consumes no
  reused sequence and never refreshes old collection/signature timestamps.
- TLS and ordinary signed HTTP-test owner fixtures verify exact retry bytes;
  signature timestamps remain tied to original generation. The HTTP-test age
  limitation remains unchanged. Durable manager historical replay acceptance
  belongs to the separate store review, not the receipt stubs used here.

`TrimForPackageFrame` validates before trimming, deep-clones all slices/pointers,
keeps the original operational schema/profile/time/generation/counts, and marks
removed rows partial. The old 48 KiB standalone contract is unchanged. The final
JSON reconstruction contains no omitted row data through retained backing arrays.

## Independent regression work

Added `tests/security/linux_packages_transport_boundary_test.go`:

- wholly synthetic legacy/new exact-shape and profile matrix;
- generation/time/profile/sequence negatives;
- exact raw component/outer bounds, one-byte overflow, canonical expansion and
  exact age/skew edges;
- nested strict package decoding through the frame boundary;
- 32 KiB clone ownership across volume/network/process pointers and all section
  slices, preserved source counts, idempotence and invalid-tail rejection.

Added `tests/security/linux_packages_sender_boundary_test.go`:

- pre-staged, wholly synthetic, whitespace-preserving v3 frame sent through
  exported `Run` on an ordinary generated-key loopback TLS fixture;
- failed delivery, ledger close/reopen, exact retry, original receipt fields,
  acknowledgment and preserved sequence floor, all on the pending-only path;
- bidirectional old-profile/package-profile manager-marker isolation, with
  unchanged marker bytes after rejection and fresh explicit marker acceptance.

The pending-only handler is a bounded receipt stub, not an enrolled store or
real endpoint. No fresh collection path is reached by that independent test.

One existing review-owned unknown-profile fixture was repaired literally:
`managed-operations-v2` became `managed-operations-v99` in
`TestIndependentOperationalProfileConfigStrictAndImmutable`. Its rejection
assertion and all other cases remain unchanged. The former literal is now an
implemented profile; the separate new-profile marker checks preserve isolation
coverage instead of treating valid new configuration as an unknown value.

## Commands and outcomes

All commands used offline module settings (`GOTOOLCHAIN=local`, `GOPROXY=off`,
`GOSUMDB=off`) and the existing workspace toolchain/caches. Owner tests were
inspected before execution to verify their fixture-only paths.

```sh
go test -race -buildvcs=false ./internal/lanclient ./internal/lanstore ./internal/operational \
  -run '^TestPackage|^TestTrimForPackageFrame|^TestValidateGuidedHandoff' -count=1
go test -race -buildvcs=false ./tests/security \
  -run '^TestIndependentPackage(Sender|Frame|Operational|Profile)|^TestIndependentOperationalProfileConfigStrictAndImmutable$' -count=1
go vet -buildvcs=false ./internal/lanclient ./internal/lanstore ./internal/operational ./internal/packagecollector ./tests/security
```

These passed. Recorded package times were 1.896s sender, 1.321s frame/store package
focused tests and 1.360s operational trimmer; the final independent boundary run
reported 1.485s. No race diagnostic appeared. The separate reader reviewer also
reran its focused Linux package race tests and vet after the cancellation fix.
Reader Windows/amd64, Darwin/arm64 and Linux/arm64 fixture binaries were compiled,
not executed. No native package read, APT command, advisory/dependency scan,
forged-key investigation, real credential operation or OS/service change was
performed for this checkpoint.

## Reviewed source identifiers

The workspace has no Git metadata; no commit identity is claimed. These identify
the mutable-source checkpoint without changing the frozen candidate archives:

```text
f28809223f822aa4eb8e3894159419192111eafa23f429907415dbdfdb7499dd  internal/packagecollector/collector.go
e2a2840b269fd6d2401e6d73ba72262ba3c682e85e8bcd546b86b48291386e7f  internal/packagecollector/source_linux.go
3f137b49db665baeb5cda0573089a52dc0f26e29cd9557d1e23ae6656eb717bb  internal/packagecollector/source_other.go
88c20d0260da958b614566327d345ea55536ba0ecfb65074ecf55385fc602eb2  internal/packagecollector/collector_test.go
d755bf385bb04daca4aeccbc27550227a3d5deeba2bf102c49b85ba304751294  internal/packagecollector/source_linux_test.go
e3f2d976d44d7a8f063dbd48aaa36c5aee9916e9168c7f81786cd86c29ab7028  internal/lanstore/protocol.go
e4fd350d13cdfb099f78f3f2702de265e7be71f4da458a376a044cf72263989e  internal/lanstore/protocol_packages_test.go
2975bf8da8640a4a64bef1f87c0de1c02d67275e3339f9678c754c6926284d6e  internal/lanclient/client.go
b4b702761b0ec1d7ee126b51a972b86e7d73161d64e5f9fef94f1941b37ca575  internal/lanclient/config.go
8097a59de64e05a6170b4c78f78d09aef64d040462861c36e005c46c1c7362e3  internal/lanclient/frame_json.go
e2bdc1faf2993d20ea624b2acc1d9baae17d128b7a80501554e864ef8a72eff1  internal/lanclient/guided_state.go
82edac4e082689dcd755d861c5adecdce74cf047ef6d9f5e0285bd3c95bbd4fa  internal/lanclient/validate_handoff.go
240556eb9c77abd831bd071a8cff7385a57a6a024fd870fc0ba36b3a99624abd  internal/lanclient/packages_test.go
171e533c7a7677bda469c77f95c0708aaa3b8aff63a6251d15ef6c621d587c1b  internal/lanclient/validate_handoff_test.go
c8a23e893542612513559f87a4924a141313a1ffdf2c0dd3edf35bb87f5e10bf  internal/operational/package_frame.go
02fe79f706ed2e43f7dd84abfcad8b1278216dd075cc0923baf24d201bee8ffa  internal/operational/package_frame_test.go
3ba3c8fb73ba1044eda7ccdf4966e270758a749bd84798939b74c42c750b4fe9  tests/security/linux_packages_transport_boundary_test.go
f8cf4a883bc0e8222b33ec5bb517e0f28ecfa14af45fb47ab268a1a5d1ee20d1  tests/security/linux_packages_sender_boundary_test.go
d20cfaa2704bb138be008280cf3d052859101cc279b9c173da347c58675903fa  tests/security/operational_api_boundary_test.go
```

## Source-only native harness preflight

A later source-only review inspected the opt-in
`cmd/lan-manager/packages_process_test.go` harness and its existing fixture
helpers. This is a separate preflight, not an extension of the executed fixture
results or source hashes above. The enabled gate was not run by this reviewer;
no compiler-heavy check was run during the independent store timing window.

The environment guard precedes setup and process execution. If enabled, this
harness would run actual basic, operational and fixed package sources, send the
observations over private loopback fixtures and retain them in temporary state.
Existing operational collection can invoke its fixed read-only system commands.
There are two successful foreground samples per transport mode and another
collection attempt before the revoked one-shot delivery is rejected; scheduling
can allow an additional foreground attempt. Logs contain quality enums, selected
row counts and pass/fail statements, rather than raw metadata. A successful run
with unavailable package sources would validate explicit unknown propagation,
not positive Debian 13 or Ubuntu 24.04 inventory coverage.

The revised harness sets offline Go child-build settings; uses gate, build,
profile and rejected-command contexts; isolates owned subprocess groups; and
uses bounded cooperative-stop/kill waits. Rejected output is capped at 4 KiB
through a private buffer with only its checked `Write` method exposed, avoiding
a promoted `ReaderFrom` bypass. It must decode as exit code 1 with
`pending_retained`. The gate-only PTY helper
has its own deadline, bounded TERM/KILL reaping and a child parent-death signal.
Review caught and corrected a parent-death setup race: the expected Python
parent PID is now captured before `pty.fork`, then checked after installing the
signal in the child. The helper-exit wait is also bounded, with the cleanup flag
set only after receiving the wait result. The embedded Python script passed AST
parsing without being executed. Older process-test helpers remain unchanged.

No remaining source-level gate blocker was found after these corrections. This
preflight does not authorize or demonstrate a native run, durable store/API
acceptance, deployment, package refresh, advisory retrieval or healthy native
package coverage. Actual execution results must be recorded separately against
the final formatted source and exact opt-in test command. Cooperative process
cleanup is not a guarantee against an uninterruptible kernel I/O stall.
