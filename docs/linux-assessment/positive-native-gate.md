# Positive Ubuntu 24.04 native acceptance gate

Status: implemented opt-in test candidate. Pure synthetic assertions and the
default skip are locally verified. Positive native execution on a standard,
disposable Ubuntu 24.04 runner remains a separate acceptance result; this document
does not claim that execution happened or authorize collection on another host.
No runtime, collection profile, source adapter or dependency is changed.

## What the gate exercises

`TestPackageUbuntu2404PositiveNative` uses the existing real three-binary
enrollment/foreground harness: `lan-manager`, `enroll-agent` and `lan-agent`.
It creates fresh disposable private fixture state, explicitly acknowledges the
existing `managed-operations-v2` privacy scope, and checks the authenticated
manager API after both scheduled sender samples in both TLS and signed HTTP-test
profiles. It keeps the existing consent, generation/time/sequence/receipt,
security-coverage, revocation and unchanged-receipt checks.
All four positive inspections must finish; skipped or filtered profile subtests
cannot silently satisfy required acceptance.

The added inspector consumes manager-delivered package and operational views.
It never calls a second collector, replaces a native report with synthetic data,
or runs a separate package inventory command. The existing general
`TestPackageThreeBinaryEnrollmentAndForeground` retains its independent
`TRACEBOLT_PACKAGE_RUNTIME_TEST=1` opt-in and unknown-compatible semantics.

Required positive evidence for every inspected sample:

- Fresh package/operational views for the same device, sequence and receipt;
  valid snapshots with the same generation and collection time, within existing
  component and managed-v2 operational reservation bounds.
- Healthy parsed release fields exactly `ubuntu`, `24.04`, `noble`. Derivatives,
  missing values, point-version substitutions and other releases fail this gate.
  The identifiers remain endpoint observations, not authenticated OS provenance.
- Healthy package inventory with exact, non-null, positive full-source observed
  and installed counts, positive selected rows, and at least one selected
  installed row. Selected rows retain the 128-row and 16 KiB component limits.
- Truthful package export completeness. A fully parsed source may export only a
  bounded prefix: `complete=false`, `truncated=true`, with `item_limit` or
  `byte_limit`. This is expected and passes. Full-source counts are never replaced
  by selected-row counts. Missing/failed sources and unknown counts fail.
- Healthy, positive bounded selected volume, network-interface and process rows
  from the same operational snapshot. At least one interface must have all
  traffic/error counters and at least one process must have parent/RSS/CPU/thread
  metrics. Measured-row counts are reported separately from selected counts.
  Other selected rows can retain explicitly unavailable metrics in partial
  sections. Zero-valued counters are legitimate; absent counters do not become zero.

Operational limits remain explicit rather than being misrepresented as failures
of unrelated source domains:

- Volumes establish discovered agent-visible mount rows, not complete disk
  coverage or necessarily positive disk-capacity measurements. Unsupported and
  unmeasured mounts sort first and can fill the selected-row cap.
- Network address counts stay null and the network section stays partial because
  the current provider deliberately does not enumerate addresses. Interface state
  can legitimately be unknown. No address collection or network probe is added.
- Bounded/partial process discovery is allowed with positive selected metrics;
  package source count exactness does not imply an exact process-directory count.
- Services and journal events remain schema-validated and may be partial,
  unknown, denied or empty as their contract permits. The gate never changes
  privileges, groups, ACLs, namespaces or services to make those reads succeed.
- Existing CVE/update projections must remain unknown. Ubuntu package rows are
  not evaluated with Debian rules; uploaded catalogs retain unverified authority.

## Explicit execution on an authorized disposable runner

Use a standard Ubuntu 24.04 runner, outside a container or altered namespace,
under its existing non-root account. The helper cannot prove host-wide visibility
or that an otherwise matching namespace is a standard runner; that is an
execution-environment requirement. Have the approved Go 1.27.1 toolchain on PATH,
an available locked dependency cache and Python 3 available. It does not install them.

After separately authorizing the existing managed-v2 native reads and loopback
fixture execution on that disposable runner:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
TRACEBOLT_PACKAGE_UBUNTU2404_TEST=1 \
go test -buildvcs=false ./cmd/lan-manager \
  -run '^TestPackageUbuntu2404PositiveNative$' -count=1 -timeout=8m -v
```

The general runtime opt-in is not needed. The explicit positive gate fails,
rather than skipping, for invalid nonempty opt-in values, privileged execution,
missing Python, build/fixture failures, unsupported release, unavailable package
facts or missing required operational evidence. With the variable unset, it skips
before building binaries or accessing collector sources. Do not set this variable
in broad local test runs or on a private developer host.

The existing harness includes basic/operational collection as well as package
collection, and may invoke its existing fixed bounded systemd/journal tools.
There is no APT/dpkg command execution, package refresh, installation, service
deployment, new account, external source lookup or host trust/network change in
this gate. Fixture credentials and state are temporary and private. It is not an
installer/systemd-service acceptance test.

## Evidence and local checks

Keep only fixed pass/fail status and validated count/quality/completeness output.
Do not print or upload raw responses, package fields, private paths, process
identifiers or names, credentials, runtime state, source data or subprocess logs.
The inspector returns fixed failure codes even for malformed source strings.
The shared harness does not forward child diagnostics to test output.

Pure local checks, with both native opt-in variables unset:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
go test -race -buildvcs=false ./cmd/lan-manager \
  -run '^(TestPackagePositive|TestPackageUbuntu2404PositiveNative$)' -count=1
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
go vet -buildvcs=false ./cmd/lan-manager
```

These tests use invented typed fixtures only. They cover strict opt-in selection,
unavailable/mismatched releases, null/inexact/zero inventory counts, incomplete
and empty selections, truthful partial exports, the actual pure export trim,
row/byte caps, provenance mismatches, mixed measured/unavailable operational rows,
all-unmeasured operational failure and evidence
privacy. Passing them plus the default-skipped native test is preparation for
native acceptance, not a positive native result. Existing source archives and the
held installer snapshot remain separate and unchanged.
