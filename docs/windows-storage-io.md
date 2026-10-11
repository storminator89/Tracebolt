# Windows aggregate storage I/O: source candidate

This default-off source increment adds private aggregate disk-I/O context. It is
not in the published preview. Native Windows 11/Server provider access under the
unchanged LocalService token, fresh Setup, real values and release acceptance
remain unverified. Source tests and cross-builds authorize no host reads, grants,
installation, provider enablement, account/ACL or service changes.

## Exact source and meaning

A local PDH query adds exactly eight English counters under
`\PhysicalDisk(_Total)\`: `Disk Read Bytes/sec`, `Disk Write Bytes/sec`,
`Disk Reads/sec`, `Disk Writes/sec`, `Avg. Disk sec/Read`, `Avg. Disk sec/Write`,
`Avg. Disk Queue Length`, and `Current Disk Queue Length`. There are no wildcards,
instance enumeration, user-supplied paths, remote machines or alternate providers.

Two samples at least one second apart record local query-call completion
timestamps and the elapsed sample window; these are not atomic per-counter
provider timestamps. Each attempt starts a new query, without a baseline reused
across attempts, grants or restarts. Throughput is bytes/second, operation rates are
operations/second, and average read/write latency is seconds per completed
operation. Average queue length is the provider's interval average; current
queue length is the second sample's instantaneous outstanding-request count,
including requests being serviced. They must not be
silently equated or summed. PDH formatting uses `PDH_FMT_DOUBLE | PDH_FMT_NOSCALE |
PDH_FMT_NOCAP100`; these metrics are not percentages.

This is PerfDisk's `_Total` aggregate over its visible provider population. It
never proves complete physical-disk coverage, a stable population across the
interval or an atomic disk snapshot. It has no per-disk identities and is never
joined to drive letters, volume GUIDs, storage-provider DeviceId, friendly names,
row positions or capacity. RAID, virtual disks and Storage Spaces retain these
limits. It is not paging-I/O attribution, a SMART result, saturation/health
verdict or a diagnosis.

A successful API return and counter `CStatus` of `PDH_CSTATUS_VALID_DATA` or
`PDH_CSTATUS_NEW_DATA` are both required before a value can be observed. Only finite nonnegative values are accepted. Missing, denied, reset,
invalid-timebase and invalid-data results stay finite unavailable states where
PDH distinguishes them; unknown errors are not guessed. Each counter retains
independent availability. An observed zero operation rate suppresses that
side's latency as idle/unavailable; an unavailable operation rate cannot prove
idle or authorize latency. Real zero throughput/operations/queue remains zero.
Missing values are never manufactured as zeros.

## Independent authority and fresh Setup

`windows-storage-io-v1` has an identity-bound protected `-storage-io` sibling
store, its own immutable manifest, lock and temporary file. Absence is off. It
requires explicit local scope acknowledgement; isolated HTTP-test additionally
requires the separate full plaintext-risk acknowledgement. Older grants never
expand, and the storage-capacity/provider grant does not authorize this read.

Fresh Read admin has exactly nineteen scopes: consent v12, outer receipt 10,
bodyless `/v1/windows/read-admin-setup-capabilities-v8`, and contract
`fresh-nineteen-read-admin-scopes-v1`. The concise Storage group and full details
name aggregate throughput, operations, latency, queues and sample timing.
Scope and HTTP-test acknowledgements start unchecked and clear on Back or
bootstrap replacement. Earlier consent sets, receipt bytes, advertisements and
historical development commands remain unchanged. No migration is required.

Every selected sibling must be genuinely absent for fresh creation. Setup keeps
the owned service disabled, checks the original activated identity and protected
phase before/after each grant, and verifies all eighteen extension digests before
startup. Partial evidence is retained without rollback, repair, re-enrollment or
automatic retry. Setup does not query counters to prove LocalService access or
change permissions to make a provider succeed.

## Worker, transport and privacy

The source runs in an isolated current-executable child with fixed dispatch and
bounded private IPC. Only opaque identity/grant/generation and original capture
bindings are supplied, never a counter path, configuration path, credential or
inherited environment. The child independently re-resolves the protected
installed service/parent identity and exact enabled grant before and after
collection. Changed identity or grant emits no snapshot. The worker retains the
existing token and cannot elevate it.

The provider worker has a two-second budget within the existing five-second
optional-scope budget and three-second primary-delivery reserve. Insufficient
time produces an unavailable result; the one-second sample interval is never
shortened and no global deadline is extended. Cancellation
kills and synchronously reaps the owned child. It does not promise to cancel
work internal to Windows provider services. There is no extra polling loop.
The canonical scope envelope is bounded to 2 KiB; the maximum measured fixture
is 1,385 bytes. Fresh v16 reserves a 26 KiB bounded base preview before
process/startup row bindings, allowing the new 2 KiB envelope without expanding
the frame. Historical v15 keeps its 28 KiB reservation. The conservative
composed residual allowance remains 73,472 bytes below the 73,728-byte ceiling;
fitting stops earlier when the actual frame fits. Sender and manager validators
independently enforce the frame ceiling. Wire v16 requires the separate
grant; earlier wire/retry bytes retain their exact meanings. Pending retry bytes and independent complete
process/service/software/network generations remain unchanged. The frame remains
72 KiB, the observation 16 KiB, and optional retained-context storage 80 KiB.

Only the authenticated private Windows Storage view exposes this context.
Original generation, grant, capture age and sample interval remain visible.
Latest failures remain current; a useful previous whole capture keeps its
original time and 24-hour expiry, without field merging or refreshed timestamps.
Revocation, missing/replaced grants, operator-session expiry, cancellation and
navigation clear access as applicable. Whole oldest captures may be evicted
from the shared retention budget. No data enters AI/provider export, basic
observations, health/alarm policies or service actions.

## Remaining native acceptance

Separately approve exact matching endpoint, Setup, manager and dashboard
artifacts on clean Windows targets after the remaining Admin-data work. Verify
unchanged LocalService PDH readability, absent/disabled/denied counters, idle and
active disks, invalid/reset/timebase behavior, RAID/virtual/Storage Spaces
semantics, cancellation/reaping, grant replacement, and fresh unchecked TLS/HTTP
setup through actual manager/browser display. No native result, installation,
reboot, ARM64 runtime, signing, release or host deployment is established here.
