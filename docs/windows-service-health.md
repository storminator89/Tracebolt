# Windows service checks

This source increment adds **Service checks / Dienstprüfungen** in the Windows
Health tab. A shared administrator can choose up to eight currently reported
services by readable display name, review the exact reported names, and explicitly
enable the expectation that those services should be running. This separate
manager policy starts disabled. It consumes existing accepted inventory only;
it adds no collector, host read, permission, local grant, transport/profile field,
service action, automatic restart, notification or AI export.

For a reviewed one-time configuration across exact existing group members, see
[group service checks](fleet-group-service-checks.md). Each member retains its own
exact service selection and source admission; membership alone enables nothing.

## What the evidence means

The existing native source is `EnumServicesStatusExW` for caller-visible Win32
services, including names, display names, state and PID. Enumeration can silently
omit services for which the caller lacks query-status rights. The managed report
carries at most 128 rows and a 48 KiB snapshot budget can trim further. Therefore:

- A **unique exact-name positive row** in a valid healthy or partial section can
  support that row's reported state. Partial/truncated metadata describes coverage;
  it does not erase a valid positive row.
- A missing row is always **unknown**, even when scoped `complete`/`countExact`
  fields are true. It never proves a stopped, removed or absent service.
- Duplicate exact names are ambiguous: the chooser withholds every occurrence and
  evaluation stays unknown. Case is preserved and never folded. The source
  contract does not establish equivalent spellings.
- `running` supports the selected expectation. `stopped` and `paused` violate the
  explicit should-be-running expectation. Neither establishes a crash, failure
  cause, executable identity or application health.
- `start_pending`, `stop_pending`, `continue_pending` and `pause_pending` stay
  unknown. There is no checkpoint, wait hint or exit-code evidence to establish a
  hung transition. PID and configured startup mode do not select or classify a
  service.
- History follows that exact reported name on the originally bound endpoint.
  Same-name removal/recreation cannot be distinguished. This is not full-host
  service coverage or continuity of a particular service instance.

The original inventory snapshot capture time is the service observation time.
Accepted receipt and manager evaluation time remain separate. The manager cannot
refresh service age with CPU timestamps, a new HTTP response or browser polling.
The caller-visible Windows enumeration contract is described in Microsoft's
[EnumServicesStatusExW documentation](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw).

## Confirmation, unknown states and retained history

An incident requires advancing accepted sequences and original captures spanning
at least **120 seconds**, plus 120 seconds of continuous manager evaluation while
stopped or paused. Recovery needs newer running captures spanning **60 seconds**,
plus 60 seconds of manager evaluation. Polling one sample never confirms or
recovers an incident. All current source/capture/receipt/evaluation evidence must
be at most 120 seconds old; four pending native states, missing/ambiguous rows,
denied/unavailable metadata and future/stale timestamps interrupt waiting periods.

Unknown never recovers an open incident. Restart, source/evaluation errors and
manager gaps over 90 seconds reset confidence; rollback fails closed. Durable
sequence, receipt and capture floors survive missing observations, restart and
policy changes. A newer accepted tuple makes the current UI check unknown until
the coordinated monitor evaluates it. Browser time aging only removes confidence.

Disable or a changed selection closes open episodes as `policy-changed`, with no
recovery observation. Every actual policy change starts a new wait; identical saves
are no-ops. Policy changes use optimistic revisions. Retained names can be removed
or disabled with live device/session authority even when their latest metadata is
stale or missing. New selections and re-enablement require a fresh, unique row.

The canonical tagged ledger is separate from disk, CPU, RAM and Linux Health in
`windows_service_devices`: at most 25 devices, eight selected checks per device,
100 total incidents per device, 30-day closed-history retention, and a 256 KiB
state bound. Reads never prune, repair or replace state. Transaction/write failure
leaves the prior durable bytes intact. Corruption fails closed. Device ID,
invitation and certificate bind policy and history; a replacement identity cannot
inherit them. Those private bindings, epoch and floors never enter the API view.

## API, scheduler and operator workflow

GET `/api/devices/{id}/windows-services` returns the closed, bounded
`tracebolt.windows-service-view.v1` contract (512 KiB maximum, including the
256 KiB ledger projection plus fresh bounded inventory). It includes selected checks, durable
history and a fresh chooser from the same authority read. The chooser carries
original capture/receipt/sequence and scoped quality/count/truncation metadata;
it exposes no PID. Null inventory means no fresh trustworthy chooser.

POST `/api/devices/{id}/windows-services/policy` accepts exactly `enabled`,
`services` and `expectedRevision`. It is shared-administrator-only, with same-origin,
CSRF, exact route/body validation and session/certificate authority checks before
mutation and response release. An enrollment-to-operator lease now freezes the
original identity, current leaf and revocation through each policy commit. The
transaction resamples the actual clock after SQLite waits, checks live operator
access, and repeats exact source/policy admission immediately before commit.
Failed guards roll back both policy and notification bookkeeping. This closes the
earlier fixed-time save gap after an operator-store wait; evaluator timing and
the strict v1 API are unchanged. Named operators have read-only access. A save
does not itself evaluate a report.

The production scheduler runs contact first, then all enabled disk/CPU/RAM/service
policies from one accepted-source transaction, with one admission lock and no new
competing loop. When all four opt-in policies are disabled, that evaluator performs
zero enrollment-source reads. The discrete service state machine does not encode
states as percentages or enter Linux Health/AI/alarm admission.

The EN/DE panel uses readable display names and exact-name secondary context.
Passive refresh preserves dirty drafts, while source/session/device/authority and
revision checks prevent stale mutation authority. Navigation and expiry discard
obsolete results. Uncertain saves are reconciled by read only and never replayed.
The operator can explicitly discard a draft; scope and evidence details stay in
collapsed explanations rather than obscuring the chooser.

## Verification and remaining gates

Synthetic Go tests cover every Windows state, positive partial rows, exact-case and
Unicode selection, duplicate/missing rows, original capture versus receipt,
repeated samples, source-spanning confirmation/recovery, independent default-off
policy, restart/gaps, monotonic floors, corruption, write failure, revisions,
storage limits and final session/certificate authority. A real accepted invented
Windows frame traverses enrollment storage, the coordinated monitor, durable
operator storage and authenticated API. A Go-generated shared fixture is consumed
by TypeScript parser and actual Health component tests; browser scenarios cover
EN/DE chooser, drafts, original timestamps, unknown history and policy closure.

These are source and synthetic fixture checks. Actual browser-rendering acceptance
must run in hosted CI because local Chromium cannot launch in this environment.
Native Windows service lifecycle, installed-service observations, real
Windows-to-Linux interoperability and deployment acceptance remain pending.
The published Windows preview does not include this newer manager policy. Service
actions, Windows AI/notifications and broader Linux feature parity are not added.
