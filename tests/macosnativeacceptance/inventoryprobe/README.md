# Gate A inventory evidence probe

Source preparation only. This package is a dedicated manual acceptance harness,
not an enrollment, runtime, installer, or release interface. Building it, running
its inert tests, and using `--check` do not approve a native read. A separately
reviewed exact-artifact approval and supervisor admission are required before
the native selector is used.

## Boundary and invocation contract

Build with the repository's exact Go 1.27.1 toolchain:

```
go build -trimpath -o TASK_ROOT/bin/inventory-probe ./tests/macosnativeacceptance/inventoryprobe
```

The executable accepts exactly one of these argument arrays:

- `["--check"]`: emits one content-free checked report, exits 0, and reads no host
  environment or provider. Import/package initialization has no provider calls.
- `["--native-inventory-once"]`: requires all of the guards below before selecting
  `macosinventory.CollectNative` exactly once. There is no retry or alternative
  provider. Unrecognized, repeated, combined, absent, or extra arguments fail
  closed, with exit 2 and a blocked report. No arbitrary commands, arguments,
  file paths, production consents, credentials, or grants can be supplied.

Native guards require compiled/runtime Darwin, exact Go `go1.27.1`, and this exact
environment marker set, deliberately supplied by the supervisor:

```
GITHUB_ACTIONS=true
GITHUB_EVENT_NAME=workflow_dispatch
GITHUB_REPOSITORY=storminator89/Tracebolt
RUNNER_ENVIRONMENT=github-hosted
RUNNER_OS=macOS
TRACEBOLT_NATIVE_GATE_A=enabled
TRACEBOLT_REPOSITORY_VISIBILITY=public
```

The only architecture combinations are:

- compiled/runtime `arm64`, `TRACEBOLT_RUNNER_LABEL=macos-15`, `RUNNER_ARCH=ARM64`
- compiled/runtime `amd64`, `TRACEBOLT_RUNNER_LABEL=macos-15-intel`, `RUNNER_ARCH=X64`

These markers are accident guards, not cryptographic host attestation or user
authorization. The supervisor independently verifies actual hosted context,
source/manifest, OS/image, current runner identity, approved selectors, private
task directory and public-artifact rules. It starts the probe as an owned
process group, incrementally enforces the 64-KiB output cap and external deadline,
discards stderr text, and waits/reaps the probe. The probe has no filesystem
output, account/identity lookup, network, enrollment, production state or grant.
Neither a successful source nor the current-runner guard proves non-admin access.

The collector receives only a recognizable fixed synthetic in-memory Request
and Consent. The fixed timestamp identifies an inert request, not a claimed
native capture time; it and all synthetic identity tokens are omitted from the
report. The native edge rejects non-Darwin again immediately before calling the
existing collector. The five commands, source parsers, product environment,
working directory `/`, one-second command budget, 200-ms pipe wait, two-second
provider budget, eight-second collection budget, byte and row limits are unchanged.

## Inert testing seam

`Run(context.Context, Provider) Report` invokes an explicitly injected trusted
provider once with synthetic inputs. It labels its result `inert_fixture` and
never selects the native provider. `Execute` additionally exposes the admission
boundary for tests with synthetic host markers and an inert provider. Tests
never call `main`, `nativeProvider`, `CollectNative`, a subprocess, or a native
API. They use literal parser fixtures and `CollectWithSources` only. Compiling
Darwin executables/tests establishes compilation only; do not execute them under
source-preparation approval.

## Exact report and exit semantics

The only output is one compact JSON object plus a newline, at most 65,536 bytes,
written once to stdout. There are no formatted errors or stderr diagnostics.
`Report`, `SourceResult`, `Limits`, and `validReport` in `probe.go` define the
closed schema; no unrecognized provider string is copied into any field.

- `schemaVersion`: `tracebolt.macos-native-inventory-evidence.v1`
- `gate`: `A`
- `mode`: `native`, `inert_fixture`, `check`, or `blocked`
- `status`: `passed`, `failed`, `checked`, or `blocked`
- `collector`: `macosinventory.CollectNative`
- `snapshotSchema`: `tracebolt.macos-read-inventory.v1`
- `collectionCalls`: 0 or 1; `collectionReturned`: boolean
- `collectionElapsedMilliseconds`: observed monotonic whole-call duration, or null
- `snapshotValidated`, `snapshotRoundTripValidated`: existing wire validation
  booleans, including in-memory encode/decode; no encoded content or hash escapes
- `snapshotBytes`: actual encoded snapshot length only when validation succeeds,
  otherwise null
- `sourcesObserved`: count 0–5; `commandMetricsAvailable`: always false
- `limits`: unchanged configured command 1000 ms, pipe wait 200 ms, provider
  2000 ms, collection 8000 ms, snapshot 524288 bytes, report 65536 bytes
- `sources`: fixed ordered array of the five source projections below

Source IDs, in order: `hardware_sysctl_v1`, `receipts_pkgutil_v1`,
`processes_ps_ucomm_v1`, `interfaces_ipv4_ifconfig_v1`,
`interfaces_ipv6_ifconfig_v1`. Each object has:

- `id`: only that fixed ID
- `availability`: `not_run`, `observed`, `denied`, or `unavailable`
- `reason`: `none`, `not_run`, `access_denied`, `source_unavailable`,
  `unsupported_platform`, `invalid_metadata`, `bounds_exceeded`, or
  `budget_exhausted`
- `parserPassed`, `validationPassed`, `passed`: booleans
- `rows`: observed row count, otherwise null; hardware is one source record,
  never a CPU count. Receipts may be observed-empty. The current product rejects
  empty process/interface row sets; the probe does not relax that requirement.
- `addresses`: observed family address count for an interface source, otherwise
  null. An observed interface can legitimately have zero addresses.
- `maxOutputBytes`: 4096 for hardware, 262144 for each other command
- `maxRows`: respectively 1, 2048, 4096, 128, 128
- `maxAddressesPerRow`: respectively 0, 0, 0, 16, 16
- `stdoutBytes`, `stderrBytes`, `elapsedMilliseconds`, `exitCode`, `childStarted`,
  `childReaped`: always null, because production does not expose these observations

Source validation checks each family independently with the unchanged product
wire validator. An invalid source is unavailable with no counts; successful
siblings remain visible. For an observed native source, `parserPassed` follows
the actual product adapter's parser success. In injected tests it is only fixture
evidence. `validationPassed` can also be true for a canonical unavailable/denied
source, but its `passed` remains false.

Native exit 0 requires all five sources observed and individually valid, and
successful complete snapshot encode/decode. Exit 1 is an unsuccessful gate,
including denied, unavailable, malformed, bounds, budget, cancellation, panic or
whole-snapshot validation failure. Valid siblings are retained where their
envelope matches this request. Top-level reasons additionally permit
`invalid_input`, `host_context_rejected`, `selector_required`, `toolchain_rejected`,
`provider_panic`, `collection_failed`, `snapshot_invalid`, and `provider_outcome`.
Report-write failure exits 1 without a retry or printing the error.

The product's fixed runner synchronously calls `cmd.Run`, with cancellation and
bounded pipe waiting. That is a reviewed static wait/reap contract, not a newly
measured per-child reap result. `collectionReturned` proves only that the call
returned; it must never be relabeled as individual child-reap evidence. The
supervisor separately reports its observed process reap. Source success does not
prove broader OS-service internal work, complete application/network coverage,
ordinary-user visibility, production operation, or installation acceptance.
