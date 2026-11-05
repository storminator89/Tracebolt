# Linux process watches

Process watches are a default-off, manager-side source candidate. They reuse only
already accepted **complete process generations** from an activated Linux
`managed-operations-v3` endpoint with its existing complete-overview consent.
They do not enable collection, change an endpoint grant, install a helper, request
privilege, run commands or control a process. See
[complete overview](complete-overview-extension.md) for the original local scope.
Source and synthetic tests do not establish installed-host or release acceptance.

## Explicit opt-in and meaning

A shared administrator can review and save up to eight exact, case-sensitive
process names per device, selecting two or three consecutive missing-process
observations. Names are not patterns, command lines, paths or service names.
They retain their original spelling and whitespace, are sorted without locale
normalization, and are limited to 64 UTF-8 bytes each. An explicit acknowledgement
of local derived-history retention is required to enable or replace the policy.
Named read accounts can inspect the view but cannot change policy or acknowledge
incidents. Existing session, Origin, CSRF and source-authority checks still apply.

The dashboard offers already observed names from the existing private inventory,
with exact manual entry as a fallback. Opening the chooser reads stored rows only;
it does not request a capture or change collection consent. Each page contains at
most 100 process rows. Names are combined exactly within the page and selection,
without interpreting spelling, whitespace, case or wildcard characters. Whitespace
positions and Unicode codes distinguish literal choices and reviewed names for
sighted and screen-reader users, including whitespace-only names. Selection
is bounded to eight names. A name may match several processes, and Linux may
shorten names; choosing it does not identify one application. The existing
inventory search accepts printable ASCII; other names remain selectable by paging
or exact manual entry. Page choices are not global counts or health claims.

The chooser requires the same sequence, generation ID, manifest hash, original
capture times, completion receipt and coverage as the current fresh watch source.
It rejects newer failed or incomplete inventory attempts and rechecks the watch
source after each query. Inventory's 24-hour retention never substitutes for the
watch's under-120-second freshness. Pages, searches and private reads are bounded,
cancelable, and cannot renew the original watch-view lease. No policy write or
approval follows from a selection.

Editing an existing policy is explicit and starts with its saved names and
threshold. Normal view expiry keeps only the unconfirmed draft in the same
visible operator context. It removes evidence, chooser rows and approval and
requires an explicit refresh and a new unchecked review. Closing, navigating,
hiding, focus loss, logout, session expiry or source-identity replacement clears
the draft. A chooser read that proves source replacement or lost management
authority also clears the parent view and draft immediately. An uncertain write remains GET-only; it is never replayed.

A matching row in running, sleeping, disk-sleep, idle or parked state counts as
active. Stopped, tracing-stop, zombie and dead rows count as nonrunning. A watch
can confirm an incident only when a complete generation has zero active matches
and no unidentified rows that could conceal a match. A positive match remains
useful when unrelated rows are unidentified. These are discrete observations in
the agent's Linux namespaces, not proof of host-wide visibility, application
health, continuous uptime or a process's ability to serve requests.

Only captures **started after the current policy was enabled** can contribute.
The enabling snapshot is consumed as a baseline. Two confirmed active snapshots
recover an open incident. Acknowledgement records that an operator has seen an
incident; it does not change its process condition or establish recovery.
Disabling/replacing a policy or replacing its source identity ends existing open
incidents as `monitoring_stopped`, never as recovered.

## Freshness, missing attempts and restarts

The existing Linux health loop evaluates stored observations every 30 seconds,
independently of an open browser. No extra endpoint reads are scheduled. Both the
original capture start and manager completion receipt must be less than 120
seconds old, with a still-current enrolled credential and source identity.
A newer pending, failed or incomplete attempt suppresses an older complete
snapshot; a prefix or an empty nonterminal page never establishes absence.

Confirmation and recovery require increasing capture/receipt times and adjacent
process-source sequence numbers. A missing sequence, stale/unavailable source,
unknown name coverage or nonadvancing evidence breaks the corresponding streak.
Repeating a snapshot gives no additional credit. Process restarts and device-local
source failures require a newly consumed baseline; an unavailable device does not
invalidate healthy devices' confirmation. No historical backfill is performed.
An incident can remain open with an unknown current condition during an outage.

GET is read-only: it does not evaluate, enable, acknowledge or create a ledger.
It hides stale counts and pending confirmation credit. Source replacement can be
visible before the next background pass retires the old policy; such history is
marked noncurrent, and current checks are unknown. Browser response leases last
at most 30 seconds and never extend source freshness or credential validity.

## Local retention and bounds

Derived history contains selected names, matching counts, original generation
identifiers/times, confirmation/recovery proof and operator acknowledgement time.
It does not copy complete process rows, PIDs, command lines, usernames or process
content into the watch ledger. Nothing is sent to AI, external notification
recipients or endpoint actions by this feature.

Terminal incidents expire after 30 days from their close time, or their last
observation when clock rollback prevented a trustworthy close time. **Open
incidents do not age out merely because their source disappears.** Each device
is bounded to 128 incidents and a 192 KiB encoded ledger; byte pressure can evict
older terminal incidents earlier. Open incidents are preserved and omitted
history is explicitly counted. The store supports at most 25 used device ledgers.

A separate local retention-only pass runs before source reads, including for
disabled, revoked, expired or unavailable endpoints. It cannot add evidence,
change policy, recover incidents or create a default-off ledger. Clock rollback
never decreases durable floors or creates a fabricated closing timestamp.
Missing used-ledger markers, noncanonical records or storage integrity failures
fail closed rather than silently reinitializing monitoring.

## API and uncertain outcomes

Authenticated operator endpoints are:

- `GET /api/devices/{deviceId}/linux-process-watches`
- `POST /api/devices/{deviceId}/linux-process-watches/policy`
- `POST /api/devices/{deviceId}/linux-process-watches/acknowledge`

Writes require a unique request ID, canonical decimal-string expected revision,
and the reviewed source token. A policy request includes the complete sorted
name list, enable flag, confirmation count and retention acknowledgement.
Disable uses an empty name list, count zero and acknowledgement false, and can
succeed with an unavailable generation when device authority is still valid.
An acknowledgement names the exact incident. Bodies reject missing, duplicate,
unknown, null or wrongly typed fields; query parameters are not accepted.

The current enrollment/source lease is held through the bounded operator-store
transaction, with repeated source and session guards. Exact command replays are
idempotent; changed requests cannot reuse the same request ID. When a response is
lost or a write result is uncertain, read saved state and reconcile the original
request ID and revision before making a new deliberate review. HTTP 409 can also
follow a committed write whose final clock/freshness guard rejected its response;
it is not proof that the write was rejected. Do not infer
success, retry a write automatically, or reset stored state to recover it.

## Verification boundary

Focused tests cover complete multi-chunk sources and exact names; missing,
partial, stale, failed and corrupt generations; current authority and expiry;
post-opt-in captures; source-sequence gaps; replay, CAS and session/CSRF checks;
pure reads; browser-independent scheduling; per-device outage isolation;
retention without source authority; restart persistence; and byte-bound history
with unresolved incidents preserved. The API emits a Go-serialized lifecycle
fixture consumed by frontend validation tests. Native deployment, host collection
and external notification/action behaviour are not asserted by these fixtures.
