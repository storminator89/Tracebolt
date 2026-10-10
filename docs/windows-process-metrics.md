# Windows process CPU and working-set memory

This source candidate adds a separate default-off `windows-process-metrics-v1`
local capability to an activated `windows-inventory-v1` identity. Existing
inventory, event-header and volume grants do not cover process CPU/RAM. Original
identities, profiles, enrollment/sender manifests and sequence floors remain
unchanged. Source fixtures and cross-compilation are not native acceptance.

## Explicit scope

The owned stopped service can preview `windows-service --process-metrics-preview`.
The source enable operation is `--process-metrics-enable --apply
--process-cpu-memory`; disable is `--process-metrics-disable --apply`. Deliberate
HTTP-test additionally requires `--insecure-http-test` and the plaintext CPU/RAM
metadata disclosure. These are source command descriptions, not authorization to
run host changes. A create-only protected sibling store binds the grant to the
existing sender. Missing records in used stores, unsafe paths, foreign bindings,
and incomplete writes fail closed. Disabling preserves the record; re-enabling
creates a new grant. Configuration holds the existing exclusive sender lock.

The reusable upfront `WindowsCapabilityConsent` contract has a new v2 supporting
base inventory plus any explicitly selected combination of event headers,
volumes and process metrics. v1 keeps exactly its original scopes and rejects
process metrics. One acknowledgement covers all selected disclosures, including
HTTP risks where applicable. Activation and owned/stopped-service verification
remain required. No installer automatically calls this contract. Extension writes
are sequential; partial results report completed scopes and the possibly
indeterminate failed scope, without identity reset or automatic rollback.

## Measurement and bounded work

Only PIDs retained in the current bounded inventory are queried, at most 128.
There is no second enumeration, background loop, shell, debug privilege, process
memory-content access, executable-path lookup or owner collection. OpenProcess
requests only PROCESS_QUERY_LIMITED_INFORMATION; GetProcessTimes and
GetProcessMemoryInfo supply counters. Handles close synchronously. A cooperative
five-second budget is checked between calls; an in-flight API cannot be preempted.
No new host permissions are requested to turn denial into successful collection.

CPU is delta kernel+user CPU time divided by elapsed time, as percent of one
logical processor, so values can exceed 100%. Working-set RAM is resident bytes,
not private bytes, committed memory or a share of total system RAM. Uint64 byte
counts stay decimal strings throughout transport and UI. Genuine zero differs
from null/denied/unavailable. First observation and restart have null CPU with
first-sample quality. Counter/clock regression or changed process creation time
produces reset/null; impossible deltas are never clamped into plausible values.

Local CPU baselines use PID and creation time, are bounded to current PIDs and
are never persisted/exported. A process created after the original inventory
capture is withheld to avoid joining reused PIDs to older executable metadata.
Failed creation identity also suppresses RAM. Failed reads drop the old baseline;
grant replacement or disable resets it. Metrics reuse the ordinary reporting
interval. Pending retry never re-collects or updates capture/receipt times.

## Shared path and compatibility

A strict v4 Windows frame carries process metrics and optional independently
consented event/volume extensions. Without process scope, v1, event-only v2 and
volume-bearing v3 preserve their shapes. Each metrics snapshot carries at most
128 PID-sorted rows and 12 KiB. During a fresh, explicitly consented process-metrics
capture, an already-enumerated sender-process row is retained through the inventory
row/byte caps, the metrics cap and later network/startup frame refits. The sampler
reads that admitted process first within the unchanged five-second budget, then
the remaining PIDs deterministically; serialized rows remain PID-sorted. Trimming
removes the highest non-self PID. Ordinary inventory-only paths retain their
existing highest-PID trimming. Missing self is never fabricated, and an admitted
self row plus the minimum envelope that cannot fit fails closed. Original counts,
capture times, denied/unavailable values and partial labels remain truthful.
For a full frame, complete volume rows may additionally be trimmed enough to retain
the metrics envelope and admitted self row, followed by non-self metrics-row trimming. The whole frame remains 72 KiB. Unknown/duplicate fields,
wrong scopes/generation, unlisted PIDs, null extensions, contradictory values and
invalid timestamps fail closed. Updated managers are required before enabling;
never reset a sender ledger to bypass an older manager's rejection.

Actual adapter → signed sender → ingress → atomic durable store → authenticated
operator view is reused. The same sequence/generation/capture floors apply, with
an additional process-metric capture advance check. Replaced/revoked grants
prevent affected pending bytes from sending without resetting sequence. Consent
is checked before capture, afterward and immediately before transmission.

The existing Processes table adds CPU and working-set RAM with EN/DE labels.
Unconfigured, first-sample, reset, denied, unavailable, trimmed, stale and expired
states are explicit. Metric capture and manager receipt remain original; two-minute
staleness and 24-hour private-row expiry are independent of event/volume expiry.
Identity revocation and existing session/navigation/blur/clock protections hide
private data. Process measurements never enter basic observations or AI/provider
exports.

The Processes workspace can filter the captured process name or PID and sort by
name, numeric PID, CPU or working-set RAM in either direction. Missing CPU/RAM
measurements stay last; byte sorting preserves exact uint64 values. The default
remains ascending PID. Each page contains at most 25 of the existing maximum
128 captured process rows. Captured, matching, displayed and observed counts
remain distinct; sorting cannot find high-usage processes omitted from the
bounded collection. These controls neither collect more rows nor grant a scope.
Filter/sort changes return to the first page. A same-snapshot refresh keeps only
the view controls while the resource hides private rows during its reread.
Device or original-snapshot changes,
private-data clearing and leaving the Processes tab discard its view controls.
Metric expiry removes values independently while younger process rows remain.
English/German native controls stay outside the mobile-hidden table header;
fixture DOM/keyboard coverage is not rendered-browser or native acceptance.

## Remaining acceptance

Portable synthetic tests, mocked Windows API tests, TypeScript/DOM tests and
Windows cross-builds establish source behavior only. Separately approved native
acceptance must verify ordinary service-token access and denial, protected-store
ACLs, real counter/working-set values, PID reuse/restart/disable, bounded handle
lifetime, exact retry and actual Windows → Linux manager → shared browser data.
No service installation, native process read, security grant, provider export,
workflow dispatch or browser acceptance follows from this candidate.
