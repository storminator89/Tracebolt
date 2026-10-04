# Linux operational observation contract, candidate v1

This is a new read-only managed collection profile, `managed-operations-v1`, not a
silent expansion of `basic-readonly-v1`. The held installer and its real-systemd
acceptance candidate are unchanged. Fresh enrollment must explicitly bind the
selected profile through server config, public bootstrap, proof and certificate
intent. Existing basic identities/ledgers are not silently migrated.

## Collector seam

Package `internal/operational` owns the structs below, strict validation, bounded
Linux providers and provider tests. Export `Collect(context.Context, time.Time)
Snapshot`, `Validate(Snapshot) error`, `Empty(time.Time, Reason) Snapshot` and
`const SchemaVersion = "tracebolt.linux-operational.v1"`. The supplied time is a
trusted collection-window start, never a remote request value. Local filesystem
operations can outlive context cancellation; collection is sequential with at most
one in-flight attempt and no accumulating abandoned goroutines. The sender must
not stage/send after its context expires. No hard15s syscall bound is claimed. No function sends
network requests or accepts a command, arbitrary path or remote target.

Snapshot JSON fields:

- `schemaVersion`: exact version above
- `collectionProfile`: `managed-operations-v1`
- `generationId`: `sample_` plus32 lowercase random hex (observation label, not a credential)
- `collectedAt`: UTC RFC3339 timestamp
- `durationMs`: measured nonnegative integer up to Number.MAX_SAFE_INTEGER (not a hard deadline)
- `sections`: exact keys `volumes`, `network`, `services`, `processes`, `software`, `events`

Every section has `meta` and `items` (never null).
`meta` has exact fields:

- `generationId`: original sample generation; equals snapshot generation for fresh raw sections
- `quality`: `healthy`, `unknown` or `denied` from collector; API may age to `stale`
- `reason`: `none`, `source_missing`, `permission_denied`, `not_supported`,
  `timeout`, `invalid_source`, `read_failed`, `item_limit`, `byte_limit`,
  `remote_filesystem_skipped`, `tool_unavailable` or `not_implemented`
- `observedAt`: UTC timestamp (collection window start)
- `complete`: boolean; false for any missing coverage/truncation
- `truncated`: boolean
- `observedCount`: nonnegative count of discovered eligible records
- `countExact`: boolean; false if enumeration itself hit a bound
- `itemLimit`: fixed section cap

`healthy` means available values were successfully collected, not healthy device
security. Unavailable sections have empty arrays, an explicit reason and no green
coverage. Partial valid results may be healthy with complete=false. Unknown/null
metrics are never substituted with zero.

Items and initial caps:

- volumes, limit32: `id` (mount_ + bounded kernel numeric mount ID), `mountPoint`
  (max160 UTF-8 bytes), `filesystem` (max32), `kind` (`local`,`remote`,`virtual`,
  `unknown`), `totalBytes`, `availableBytes`, `usedPercent` (nullable),
  `measurementQuality`, `measurementReason`. Discover mount records visible in the agent's OS/mount namespace within a
  bounded source scan; measure only allowlisted local filesystems. Never stat a
  network/FUSE mount. Mark skipped/unmeasured entries and truncation explicitly.
  Redact usernames from /home and /run/user mount prefixes. Never export mount
  options, credential-bearing source strings, UUIDs or serials.
- network, limit32: `name` (max64), `state` (`up`,`down`,`unknown`), `mtu`
  (nullable), `rxBytes`, `txBytes`, `rxErrors`, `txErrors` (nullable), `ipv4Count`,
  `ipv6Count` (nullable). No MAC, IP address values, SSID, routes or active probe.
- services, limit128: `name` (max128), `loadState` (`loaded`,`not_found`,`masked`,
  `unknown`), `activeState` (`active`,`inactive`,`failed`,`activating`,
  `deactivating`,`reloading`,`unknown`), `subState` (`running`,`exited`,`dead`,
  `failed`,`other`,`unknown`). Failed units sort first. No descriptions or exec
  commands. A fixed absolute systemctl query may be used after trusted-binary
  validation, clean environment, timeout and output cap; never a shell.
- processes, limit64: `pid`, `parentPid` (nullable), `name` (max64), `state`
  (`running`,`sleeping`,`stopped`,`zombie`,`idle`,`unknown`), `rssBytes`,
  `cpuTimeSeconds`, `threads` (nullable). Sort by RSS descending. Read fixed
  procfs metadata only; no command lines, environment, CWD, user/account IDs or
  executable paths. Bounded process scanning reports whether count is exact.
- software, limit256: `name` (max128), `version` (max192), `architecture` (max32),
  `manager` (`dpkg`). Installed records only, deterministic name/architecture
  order. Reuse the existing assessment parser where appropriate. No package
  descriptions, maintainer data or file lists. Missing database is unknown.
- events, limit64: `source` (`systemd-journal`,`agent`), `unit` (max128),
  `priority` (integer0..7), `messageId` (empty or32 lowercase hex), `count`,
  `firstSeen`, `lastSeen` (UTC). At most a15-minute metadata window. Never export
  MESSAGE text, raw logs, command lines, environment or arbitrary OS error strings.
  Nonprivileged journal denial is reported; no group/ACL/security-setting change.

All strings must be valid UTF-8 without controls. Numeric counters must be finite,
nonnegative and at most Number.MAX_SAFE_INTEGER; percentages are0..100. Nullable
values mean unknown. The snapshot JSON ceiling is48KiB; trim lowest-priority
records deterministically to this ceiling and mark byte_limit/truncated/counts.
Do not silently discard high-priority failures or call a bounded sample complete.
The complete authenticated telemetry frame stays capped at72KiB.

Resource/OS/CPU/RAM/uptime fields remain in the existing basic observation so the
UI does not obtain contradictory parallel readings. Operational data is not added
to model/AI evidence packets by this profile.

## Operator read API

`GET /api/devices/{opaqueId}/operational` uses existing operator authentication and
exact Host rules. It performs no collection, process execution or provider calls.
Unknown device=>404; invalid operator session=>401.

Response `tracebolt.operational-view.v1`:

```
{
  "schemaVersion": "tracebolt.operational-view.v1",
  "deviceId": "agent_...",
  "status": "not_configured | awaiting | fresh | stale | revoked | unavailable",
  "serverNow": "RFC3339 UTC",
  "receivedAt": null,
  "sequence": null,
  "maxAgeSeconds": 120,
  "snapshot": null,
  "lastGood": {
    "volumes": null, "network": null, "services": null,
    "processes": null, "software": null, "events": null
  },
  "assessments": {
    "updates": {"quality":"unknown","reason":"not_implemented"},
    "vulnerabilities": {"quality":"unknown","reason":"not_implemented"}
  }
}
```

`snapshot` is null or the collector Snapshot. Each `lastGood` value is null or the
corresponding typed section, retaining its original observedAt; it is shown only
as explicitly retained/stale evidence when the current section is unavailable.
Server freshness uses collection and receipt times. An unavailable section must
not replace its last successful section with an apparently healthy empty list.

Transport/storage integration belongs to backend, not collector/UI workers.
The new body schema v2 retains exact bytes/retry sequence and the existing body
signature boundary, and is authorized only for a matching activated operational
profile in the same durable transaction. Old manual/basic agents remain v1.
Responses are bounded; tables display bounded samples and their observed counts,
not fictitious pagination beyond records actually received. Device revocation,
malformed snapshots, schema mismatch, replay and timeout remain explicit errors.

## Frontend ownership

An isolated `web/src/operational.tsx`, `operational-types.ts` and tests may be built
against this read contract. Show collection time, per-section coverage and caps,
latest failure plus last-good data, and source/profile. Do not call data fresh
from browser wall-clock guesses. Use serverNow + monotonic elapsed time. Page/BFCache or focus restoration invalidates
freshness until a new server anchor is fetched. The
existing protected401 boundary clears private views. Fixed local error copy;
never render raw errors as HTML. English default plus German labels. No synthetic
fallback, invented installer link, command execution or green missing CVE data.

## Explicit privacy/retention policy for review

Metadata names and mount paths can themselves reveal personal or secret-like
labels. This profile is not anonymous or guaranteed secret-free. The direct
account/cmdline/environment/message fields listed below are excluded, and the
operator/endpoint consent display must explain that operational names remain.

All listed item fields are default-on **only in a freshly selected
managed-operations-v1 enrollment**. They are default-off for the existing basic
profile. Operator and endpoint trust display must name these categories before
accepting the invitation; changing manager configuration does not rebind existing
identity, consent or pending telemetry.

| Section/fields | Fixed source | Privacy/default policy | Retention/export |
| --- | --- | --- | --- |
| Existing CPU/RAM/uptime/OS metrics | Existing basic collector | Existing bounded policy, unchanged | Existing device observation; no wider AI packet |
| Volume mount ID, redacted mount point, filesystem, kind, utilization | Bounded /proc/self/mountinfo, local-filesystem allowlist for Statfs | New-profile on; exclude options/source credentials/UUID/serial; skip remote/FUSE measurement | Latest + last-good section, operator-only |
| Interface names/state/MTU/counters/address counts | Fixed procfs/netlink metadata | New-profile on; address values, MAC and SSID remain off | Latest + last-good, operator-only |
| Service unit name and enumerated states | Fixed trusted systemctl argv | New-profile on; descriptions/exec commands off | Latest + last-good, operator-only |
| PID/parent PID/comm/state/RSS/CPU time/threads | Fixed bounded numeric proc entries | New-profile on; account IDs, cmdline/env/CWD/executable paths off | Latest + last-good, operator-only |
| Installed package name/version/architecture/manager | Fixed dpkg database/parser | New-profile on; descriptions/maintainers/file lists off | Latest + last-good, operator-only |
| Event source/unit/priority/message ID/count/window timestamps | Fixed metadata-only journal query or typed agent events | New-profile on; raw MESSAGE and other text bodies always off; denied read stays denied | At most15-minute sampled window + last-good, operator-only |

The snapshot cap is48KiB; the authenticated frame cap remains72KiB. Initial
runtime capacity remains25 retained device identities, including tombstones.
At most one current and one last-good value per section per device are retained,
not an unbounded event/history store. Operational snapshot data has a global
logical quota of4MiB (latest + retained observations) and a per-device quota of
128KiB; reject without refreshing age on a quota violation. Retained sections preserve their own original generation/time; mixed generations
are never labeled as one fresh snapshot. Expiry and quota evaluation are atomic
with durable observation admission. Last-good sections older than24 hours are
pruned by the trusted-clock transaction before serving the read model, which
returns an explicit unavailable state. No broader historical retention is implied
by this first read model; expiry tests must establish the actual pruning behavior.

No operational field is exported to an external model/provider, analytics,
GitHub artifact or support bundle by adding this package. An external export or
AI allowlist is a separately reviewed policy. Native tests publish only fixed
pass/fail/count evidence. The all-volumes/services/software UI must label bounded
coverage; it cannot manufacture pages for records the client did not send.

The hardened systemd unit creates a filesystem namespace. Volume/process/network
views describe what the agent can see, not guaranteed complete physical-host
inventory. Keep the sandbox and report restricted visibility. The current schema
and implementation remain Linux-only despite the neutral consent-profile ID.
The latest authenticated raw frame remains for replay validation until replaced;
24-hour pruning applies to the last-good cache and operational read visibility,
not a promise of physical deletion of every copy of that latest frame.

## Explicit invitation acknowledgement and server policy

On a freshly configured managed instance, authenticated `GET /api/enrollment`
adds `collectionProfile: "managed-operations-v1"` and
`collectionPrivacy: "metadata_labels_may_be_sensitive"`. Only this profile's
invitation POST requires the additional exact boolean
`collectionAcknowledged: true`. Omission, false, null, strings and duplicate keys
are rejected before creating state. The established basic profile omits these
response fields and retains its original two-field request. A request cannot
select a different profile; the immutable instance configuration is authoritative.
The Linux endpoint displays the same profile/privacy scope before hidden invitation
input. The public bootstrap never contains the invitation secret.

The first runtime uses one collection profile per manager instance and cannot
adopt existing basic state. Its AI export guard therefore rejects case analysis
for the whole managed instance before loading case titles, summaries or evidence.
Persisted case/evidence provenance is an additional defensive check, not client-
selected authority. This slice creates no operational-derived cases or AI packet
fields. Future mixed-profile instances need a separately reviewed device-to-case
export policy before this conservative instance-level restriction can change.

Ingress retains the existing two-request global work bound. Normally verified TLS
peers reserve at most one identity-specific request; signed HTTP reserves that
slot only after proof of possession succeeds. Public certificate headers alone
cannot reserve an identity slot. Busy responses are fixed429 with Retry-After15.
Operational reads admit one active read per shared store handle, reject excess
requests with fixed429/Retry-After2, and remain subject to existing operator auth.
These bounds limit queued work; they are not a claim of denial-of-service immunity.

A SQLite `BUSY`/`LOCKED` result at the initial `BEGIN IMMEDIATE` is classified
separately as retryable `storage_busy` (HTTP429). The existing five-second SQLite
busy timeout is unchanged. No transaction/authority read or mutation has started
in that case. API read Retry-After is2 seconds; enrollment and ingress use15.
Cancellation, invalid/corrupt storage, validation failures, and write/commit
uncertainty never become this retryable category. There is no internal authority-
transaction retry. A sender's later retry still preserves its exact pending bytes
and original observation times. This is separate from global/identity ingress
admission (`ingress_busy`) and the operator read concurrency guard.
