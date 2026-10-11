# Complete caller-visible Windows process inventory

This source slice adds a separate default-off `windows-complete-processes-v1`
local grant. It captures the complete caller-visible Toolhelp process snapshot
under the existing LocalService identity. Fresh Read admin explicitly includes
it as the sixteenth scope. It does not expand the old inventory or process-metrics
grants, and a manager update cannot enable collection.

## Snapshot fields and exclusions

One `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` handle supplies snapshot PID,
snapshot parent PID, executable name and thread count through `Process32FirstW`
and `Process32NextW`. No process handle is opened. PID zero is a valid snapshot
identifier. Duplicate names remain separate rows; duplicate PIDs fail the attempt.
Names that are empty, malformed UTF-16, unterminated or path-like remain unavailable
on their original PID row rather than being guessed or silently removed.

PIDs are identifiers within this snapshot, not durable process identities.
Processes may have exited and parent PIDs may have been reused. The UI never joins
these rows to another generation, network observation or retained CPU/RAM sample.
The existing separately consented metrics sample remains bounded to 128 base rows,
with its unchanged PID-plus-creation-time validation and CPU accounting. Full CPU
or working-set coverage is not implemented or implied by complete basic inventory.

No command lines, environments, executable paths, process-owner credentials,
usernames, process memory contents, filesystem contents, thread enumeration,
modules, heaps, elevation, debug privilege or host changes are requested. Rows
remain private operator data and never enter basic observations, AI/provider
exports, alarms or notifications.

API semantics follow Microsoft's [snapshot documentation](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot),
[PROCESSENTRY32W fields](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w)
and [Process32NextW termination](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw).
Only explicit end-of-enumeration succeeds, including a genuinely empty snapshot.

## Bounded complete-generation contract

- At most 32,768 rows and 8 MiB of canonical row JSON, ordered by numeric PID.
- Names retain at most 259 UTF-16 units / 1,036 UTF-8 bytes, without truncation.
- One OS-owned snapshot handle and one fixed caller-owned native entry buffer.
  There are at most 32,769 enumeration reads, including the terminal probe; fixed
  entry-buffer work is bounded by 32,769 × 1,024 bytes across supported layouts.
- Capture has a cooperative 15-second deadline including snapshot creation.
  Windows owns the snapshot's opaque allocation and an in-flight native API
  cannot be hard-canceled. The caller does not claim a hard OS-memory or wall-clock
  ceiling, does not abandon a goroutine, and closes the handle synchronously.
- Up to 512 immutable chunks, each at most 128 rows / 64 KiB including its envelope;
  a frozen pack is at most 12 MiB, below the unchanged protected-file ceiling.
- Independent bursts permit 64 operations / 20 seconds. Captures are at least
  one minute apart and retain their original 24-hour expiry. Exact pending bytes
  drain over later bursts without recapture or refreshed timestamps.
- Manager storage reserves at most 48 MiB per device, with a 128 MiB global budget
  shared with full services/software and existing metadata. Existing physical
  database/WAL caps remain enforced. Maximum-sized devices are not promised to
  fit simultaneously.

A cutoff, denied read, duplicate PID, interrupted enumeration, clock regression
or timeout fails the complete attempt. Its prefix is discarded, never promoted
as complete or empty. A previous completed generation stays available only for
its original lifetime, alongside the distinct latest failed-attempt reason.
A missing first generation is unavailable/awaiting, not zero processes.

## Consent and durable state

Fresh Read admin uses exact consent v9, outer receipt 7 and the V5 capability
contract. Earlier consent/receipt bytes retain their original scope sets.
The preserved source-only local administration interface requires an activated
existing identity and the owned stopped service:

- `windows-service.exe --full-processes-preview`
- `windows-service.exe --full-processes-enable --apply --complete-process-inventory`
- `windows-service.exe --full-processes-disable --apply`

HTTP-test additionally requires `--insecure-http-test` and explicit plaintext
process-inventory disclosure. These examples are not permission to execute them.
No installer, service action, native read or persistent grant follows from source
or fixture checks.

First enable durably writes an irreversible process-used bit in primary sender
record v4 before creating its protected sidecar. Existing service/software bits,
sender identity, telemetry counter and exact pending bytes/digest are preserved.
Unchanged v1/v2/v3 records retain their exact encoding. Process, software and
service grants/revisions/capture floors remain independent; enabling either
older extension after processes cannot downgrade v4.

Missing used sidecar/sender/pack state, interrupted initialization, foreign
bindings or a missing used marker fail closed. They are never recreated as fresh
or repaired by resetting floors. Disable retains state and sends only its scope
status on a later run. Reenable creates a new local grant/revision; dormant rows
cannot acquire new timestamps, lifetime or authority. Scope status is the last
acknowledged endpoint decision, not an immediate remote erasure guarantee.

## Private search and paging

Read-only protected POST `/api/devices/{id}/windows-full-processes/query` uses
the current operator session, Origin and CSRF guards. Search text and cursors
stay in request bodies. Requests contain `search`, `sort`, `limit` and `cursor`.
Literal Unicode case-insensitive search covers captured name, snapshot PID,
parent PID and thread count. Sorts are `pid`, `name`, `parentPid` or `threads`
with `-asc`/`-desc`; default is `pid-asc`. Missing names sort last in both
directions, with numeric PID as the stable tie-breaker.

The validated whole generation supplies full matching count. Pages contain at
most 100 rows / 256 KiB. Cursors bind the exact device, grant/revision, generation,
manifest, query/sort/limit, offset, operator session and original expiry. A changed
or expired generation/authority produces restart-required, never mixed pages.
Current identity, session and original lifetime are rechecked after serialized
waits and again at response time. No view or search creates endpoint consent.

The Processes tab shows the complete inventory and its concise counts/search/
filter/sort/paging controls, with source and original capture details on demand.
The old preview/metrics sample remains separately labeled and available when no
complete generation exists. Pending requests, device/tab/session changes,
visibility/focus loss, untrusted time and original expiry clear private rows and
cursors. Latest attempt failure is distinct from retained inventory age.

## Verification boundary

Portable inert fixtures cover more than 128 processes, PID zero, maximum rows,
invalid names, finite cutoffs, exact retry/restart, independent used-state floors,
private complete search/pages and authority/session/expiry fences. Windows cross-
compilation establishes compilation only. No source test invokes native process
collection, installs software or grants access. Native LocalService visibility,
actual OS snapshot resource behavior, installed fresh consent and real Windows
endpoint-to-manager-to-browser acceptance remain separately approved gates.
The public five-scope preview is unchanged.
