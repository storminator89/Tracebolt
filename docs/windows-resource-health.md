# Windows CPU and physical-RAM policies

This source increment adds two independent, default-off manager policies in the
Windows Health tab. It evaluates only CPU and memory percentages already accepted
under the existing Windows basic inventory consent. It adds no collector, native
read, local grant, enrollment, credential, service action, AI export or alarm.
Published preview bytes do not include these newer manager policies. This is not
full Windows/Linux Health parity.

## Exact measurement scope

CPU is the existing `windowsinventory` interval percentage from two
`GetSystemTimes` samples: `100 * (deltaKernel + deltaUser - deltaIdle) /
(deltaKernel + deltaUser)`. Kernel time includes idle time. The collector validates
nondecreasing counters, a positive total, and consistent idle/kernel values.
The result describes the observed processor group; it is not a universal all-group
machine utilization claim. Each existing report samples an interval of about
250 ms. Repeated high reports spanning 60 seconds support a sustained sampled
threshold assessment, not proof that every instant between reports was high.
See Microsoft's [GetSystemTimes contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemtimes).

RAM is the existing `GlobalMemoryStatusEx` measurement:
`100 * (ullTotalPhys - ullAvailPhys) / ullTotalPhys`. It describes physical RAM
not immediately available. It is not process working-set usage, committed memory,
page-file usage, or the approximate `dwMemoryLoad` field. The available physical
memory field includes memory Windows can immediately reuse without first writing
it to disk. See Microsoft's [MEMORYSTATUSEX fields](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex).

The manager uses these already-measured percentages unchanged. Failed, missing,
partial, denied, malformed, stale or future CPU/RAM samples remain unknown. One
metric never substitutes for another. An unrelated partial inventory section does
not invalidate an independently healthy basic percentage.

## Separate policies, shared evidence rules

Each policy initially has `enabled=false`, threshold 90%, and revision zero.
Only a deliberate shared-administrator save enables that exact metric. Thresholds
are whole percentages from 50 through 99. No manager/schema upgrade, disk opt-in,
CPU opt-in, RAM opt-in, report, or GET enables a sibling policy. Named operators
may read these policies but may not change them.

Both metrics use the existing [capacity evidence state machine](windows-capacity-health.md):

- Confirmation needs distinct, advancing original captures spanning at least 60
  seconds at or above threshold, plus 60 seconds of continuous manager evaluation.
- Recovery needs distinct newer captures spanning at least 60 seconds at or below
  threshold minus five percentage points, plus continuous manager evaluation.
  For a 90% threshold, recovery requires 85% or below. Repeated polling of a
  single high or low sample never opens or recovers an incident.
- Original capture, accepted receipt, and manager evaluation timestamps are kept
  separate. Source/capture/receipt evidence must be at most 120 seconds old.
  Browser aging can only remove confidence. A newer unevaluated accepted tuple
  makes the current assessment unknown until the monitor evaluates it.
- Unknown never recovers an incident. Authority loss, restart, clock rollback,
  an evaluation gap over 90 seconds, or a failed evaluator resets confidence and
  waiting periods while retaining history and durable monotonic evidence floors.
- Disable/threshold change closes an open incident as `policy-changed`, with no
  recovery observation. Re-enable starts a new wait; identical saves are no-ops.
  Stale optimistic revisions fail. Each metric retains its own revision, sequence,
  receipt and capture floors, including through unknown/restart/policy changes.

The disk v1 API, persisted state and shared fixture remain unchanged. CPU/RAM use
separate canonical, metric-tagged records in `windows_resource_devices`, with a
composite device/metric key. Disk state cannot decode into that envelope. Each
metric retains at most 100 incidents, and the resource table permits at most 25
devices and 50 records. Closed incidents older than 30 days are pruned only during
an authorized evaluation or policy change. Reads never write/prune/repair state.
Corrupt state and failed writes fail closed without replacing retained bytes.
Engine incident IDs remain scoped to `(device, metric)`; they are not global IDs.

One coordinated production scheduler evaluates contact first, then all enabled
disk/CPU/RAM policies from a single accepted-source transaction. There are no
per-metric loops contending for enrollment admission. When all three policies are
off, the percentage evaluator performs zero enrollment-source reads. Linux
Health, investigations, AI and alarms remain separate.

## Operator contract and UI

GET `/api/devices/{id}/windows-resource/{cpu|memory}` is read-only. POST to the
same route plus `/policy` accepts exactly `enabled`, `thresholdPercent`, and
`expectedRevision`. The route binds the metric; body/query aliases are rejected.
Both use the same operator/session/certificate checks as disk, including current
authority and session rechecks immediately before writes and response release.
A replacement identity cannot inherit a previous identity's policy or history.

The closed `tracebolt.windows-resource-view.v1` response adds the required exact
`metric` discriminant to the existing bounded percentage view. Clients reject a
CPU response on a RAM request and vice versa, and never accept disk v1 as a
resource view. Responses remain bounded to 128 KiB and exclude identity hashes,
invitation IDs, evaluator epochs and durable transition/floor metadata.

The actual Windows Health view exposes independent EN/DE panels and collapsed
settings. The shared hook/parser/panel retain disk defaults. Resource keys bind
metric, device, session and protected-request epoch. Passive refresh preserves a
deliberate dirty draft but grants no stale edit authority. Revision changes,
navigation, device/session/logout and authority changes invalidate obsolete
results/drafts. Uncertain writes are reconciled read-only, never automatically
retried. A save does not itself evaluate a source.

## Verification and remaining gates

Portable fixtures cover per-metric default-off isolation, measurement selection,
source-spanning confirmation/recovery, same-sample polling, hysteresis, unknown
states, separate durable floors, restart/rollback, policy revisions, corruption,
failed writes, bounded storage, session/certificate/release checks and one source
read for 25 devices with 75 enabled percentage policies. An invented accepted
Windows report traverses the real enrollment store, scheduler, operator store and
authenticated API independently for CPU and RAM. The exact Go-generated shared
fixture is consumed by TypeScript tests.

Source/component/browser-fixture tests are not native Windows, installed-service,
real Windows-to-Linux interoperability, actual browser-rendering, or deployment
acceptance. Hosted browser and native acceptance remain separate reviewed gates.
No new PR, native scope, remote action, notification, AI admission or release is
implied by this implementation.
