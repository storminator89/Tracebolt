# macOS Gate I interface diagnostics

**Source-only, default-off and not authorized for invocation by this document.**
Gate I is a narrow diagnostic adapter for a separately reviewed manual native
run. It is not an endpoint feature, profile, grant, installation or release.
Source tests and cross-compilation establish no native result. The interface
parser's accepted inputs and the production command runner remain unchanged;
this candidate adds finite rejection classification, not a permissive parser fix.

The shared [native evidence document](macos-native-acceptance.md) describes the
assembled A/B/I harness. This composition preserves the separately reviewed
log-v2 diagnostic source and its rejection behavior. Gate I introduces the
independent outer-v2 report and does not approve Gate B. Historical first-run
artifacts retain their original validators and are not rewritten. A later source
composition requires a new review and a newly derived source digest.

## Exact once-only interface scope

The tagged probe can invoke only these existing fixed commands, in order:

- `/sbin/ifconfig -a inet`
- `/sbin/ifconfig -a inet6`

Each family gets at most one command attempt. Each successful command result is
parsed exactly once by `ParseInterfacesWithDiagnostic`, then separately checked
by the existing canonical validator in a synthetic in-memory envelope. An
ordinary command or parser failure preserves the other family's independent
attempt. Cancellation stops remaining work and retains completed sibling
results; cancellation can still fail the overall gate after both families finish.
No complete inventory collection, hardware/receipt/process read, alternative
format, DNS query, network probe, shell, retry or discovery is introduced.

The production runner retains its one-second command deadline, 200-ms pipe wait,
256-KiB combined output cap, fixed environment and `/` working directory, closed
stdin, stderr rejection and direct wait/reap behavior. Parser bounds remain
128 interfaces, 16 addresses per interface and 4,096 bytes per source line.
An empty interface list remains rejected. Native values exist only in memory;
raw byte buffers are cleared after use and parsed values are not retained in
reports or written to disk.

The bridge is available only with Darwin and the explicit
`tracebolt_interface_diagnostics` build tag. Ordinary endpoint builds have no
native diagnostic bridge. Main requires the exact `--native-interfaces-once`
selector, supported Darwin architecture, Go 1.27.1 and matching one-attempt,
public GitHub-hosted manual-run source/commit markers. These are accident guards,
not authorization. The Python supervisor separately verifies reviewed source,
compiled-binary custody and executable hashes immediately before the gate.

## Closed evidence and failure truth

The dedicated inner schema is
`tracebolt.macos-native-interface-diagnostics.v1`, bounded to 16 KiB. It contains
exactly two ordered family records, fixed source IDs, declared limits, command
and parser call counts, finite outcomes/rejection codes, canonical-validation
results and pass booleans. Go and Python independently validate this projection;
unknown or duplicate JSON fields, unknown enums and inconsistent results fail
closed. A diagnostic rejection remains a failed family and failed gate.

No interface name, address, prefix, MTU, flags, raw native/error text, line/index
identity, input-content hash or native-value count is exported. The unchanged
runner does not expose per-command stdout/stderr counts, elapsed time, exit
code, child-start or child-reap measurements. All six remain `null` and
`commandMetricsAvailable=false`. Declared limits are not measured values.
An outer probe being reaped does not independently prove every internal command
child was reaped.

The supervisor's separate outer report has numeric `schemaVersion: 2` and
`scope: macos-native-evidence-v2`. It adds explicit Gate I selection,
`interfaceDiagnostics`, `interfaceProcess` and the interface-binary hash. This
outer-v2 change applies to reports from this assembled harness, including A/B
selections; Gate I does not change the separately reviewed log module's inner
`syntheticLog.schemaVersion: 2` contract.
Unselected gate fields remain empty. The supervisor separately measures its
owned interface-probe process with a 12-second deadline, 16-KiB stdout limit
and 1-KiB stderr limit. It accepts a validated failure projection only with a
coherent exit status, no stderr and proven outer-process reap.

## Preparation, public metadata and cleanup

Gate I uses the existing pinned `actions/setup-go` action with Go 1.27.1,
`token: ''`, `cache: false`, `check-latest: false` and no custom download URL.
This verifies the installed tool's version and executable hash after setup;
it is not a pre-execution archive-checksum gate. Normal public setup metadata
can appear in Actions output.

The task-owned preparation performs locked `go mod download` and `go mod verify`
through `proxy.golang.org` and `sum.golang.org`, with no direct/VCS fallback.
It then disables module networking and builds only the tagged interface probe
using `-trimpath -buildvcs=false`. Each module or build child is bounded to
240 seconds; each module output stream is capped at 1 MiB and each compile stream
at 64 KiB. Preparation text is discarded. Build scratch and caches stay in the
new protected task tree. Runtime probe code opens no network socket; preparation
and Actions artifact delivery are not an OS firewall sandbox.

A separate 120-second native supervisor budget begins after builds, within the
20-minute job limit. Gate I retains the four fixed metadata commands:
`sw_vers -productVersion`, `sw_vers -buildVersion`, `uname -r` and `uname -m`,
each bounded to five seconds and 128 bytes per stream. It also retains hashes of
the fixed sysctl, pkgutil, ps, ifconfig and log executables without invoking the
non-interface providers. The existing numeric real/effective UID/GID and up to
64 supplementary group IDs are observed; root or mismatched real/effective IDs
are refused. Admin membership is not queried and remains unknown. The current
UID's passwd home may be obtained internally but is never published. These
observations do not establish ordinary non-admin access.

Public output is one strict outer report per architecture, at most 64 KiB, in
public Actions artifacts retained for 14 days. Permitted metadata includes
bounded OS/build/image versions, architecture/runner label, numeric caller
identity, exact reviewed source/tree/tool hashes, observed outer-process
measurements and cleanup truth. Raw native output, arbitrary error text,
usernames/home paths, hostnames, interface identities, content and input hashes
are excluded. No binary, cache, task HOME or credential is uploaded. A prior or
stale report cannot authorize upload.

Cleanup terminates and reaps only owned children, then removes only the recorded
new task tree using descriptor-relative, no-follow checks. Unproven reap or
changed ownership/inode retains the tree and fails the run. Missing cleanup is
not reported successful. No global kill, OSLog erase, host service/account,
credential, enrollment, TCC, Full Disk Access or security-setting change occurs.

## Review and any future Gate I-only start

The manual workflow is `.github/workflows/macos-native-acceptance.yml` in public
`storminator89/Tracebolt`. All three gate inputs default to false. It accepts
only the first attempt on standard hosted `macos-15` (ARM64) and
`macos-15-intel` (X64); there is no caller-controlled runner, path or command.
Gate A plus Gate I is rejected in both workflow and supervisor. Gate B remains
an independently selected and separately approved write/read scope.

Before any new invocation:

1. Complete independent review of the exact complete commit and Git tree,
   including this document, separately reviewed log module, workflow and generated source
   metadata. Publication or merging is not permission to dispatch.
2. Derive `sourceSHA256` from that final checkout using only the inert command
   `python3 -B tests/macosnativeacceptance/run.py --check`. This hashes source;
   it does not build, inspect host identity or invoke providers. Any later
   included-source change requires a new digest and review.
3. Obtain fresh explicit approval for one Gate I-only attempt on both named
   standard hosted architectures, covering the two interface reads, preparation,
   bounded metadata observations, public reports and owned-task cleanup above.
   Previous approvals for other gates or revisions do not carry over.
4. Supply `gate_i=true`, `gate_a=false`, `gate_b=false`, `reviewed_commit` equal
   to the exact approved current 40-hex commit, and `reviewed_source_sha256`
   equal to its exact inert-check result. Both `GITHUB_SHA` and
   `GITHUB_WORKFLOW_SHA` must match that commit. A tree ID is not a commit ID.

This source candidate does not provide native permission, create a persistent
identity/profile, promise a parser pass, establish ordinary non-admin access or
accept a macOS release. Native enrollment/renewal, dedicated-account operation,
launchd lifecycle and reboot persistence remain separate gates.
