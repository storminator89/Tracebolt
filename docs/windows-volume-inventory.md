# Caller-visible Windows volume inventory

This source candidate adds a default-off `windows-visible-volumes-v1` capability
under an activated `windows-inventory-v1` identity. Existing inventory consent
still covers only the system-volume metric; neither it nor event-header consent
grants this extension. No released installer, native installed-service run or
real Windows → Linux manager → browser acceptance is established by these tests.

## Explicit local approval, compatible identities

The owned stopped service supports `windows-service --volumes-preview`,
`--volumes-enable --apply --visible-volumes`, and
`--volumes-disable --apply`. HTTP-test additionally needs
`--insecure-http-test` and the plaintext-volume warning. These are source
commands, not instructions to run them on an unapproved host. Activation,
service ownership, stopped status, exact transport and original sender binding
are checked. Preview cannot grant anything. The protected sibling store is
create-only; a missing record inside existing state is a failure, never a fresh
grant. Disabling retains the record; re-enabling issues a new grant identifier.
Old enrollment/sender manifests, identities and sequence floors are unchanged.

`WindowsCapabilityConsent` is a reusable versioned upfront local approval
contract for a future fresh installer. It lists exactly the selected metadata,
event-header and/or volume scopes, requires the base inventory profile, and
requires one explicit acknowledgement of all selected disclosures. The reusable
configuration function runs only after activation and requires its caller to
verify the owned service is stopped. It does not create an identity, perform
manager approval or auto-grant on upgrade. Current install/enroll does not invoke
it. Selected extension writes are sequential, not atomic; partial results name
completed scopes and the possibly indeterminate failed scope. Never recover by
resetting identity, deleting grants or enabling unselected scopes. Future
installer integration must retain the upfront approval through activation and
keep this failure truth, rather than inventing permanent additional prompts.

## Scope, capacity truth and resource bounds

Native source uses FindFirstVolumeW/FindNextVolumeW to enumerate caller-visible
local volume GUID roots, including volumes with no drive letter. It does not
query volume labels, serials, mount paths, files, remote connections or network
shares. Supported local drive types are fixed, removable, CD-ROM and RAM disk;
unknown/unsupported types remain visible as unavailable without a capacity query.
The GUID is still identifying metadata value covered by consent. This is
bounded visible-volume coverage, not all physical disks, partitions or
whole-machine storage. Virtual/iSCSI-backed local volumes are not distinguished
from other local volumes by this API.

Each row keeps its GUID, drive type and observation quality. Successful capacity
has three decimal uint64 strings:

- `totalBytes`: total bytes available to the calling identity, quota-aware
- `availableBytes`: free bytes available to that identity, quota-aware
- `freeBytes`: physical volume free bytes, which may exceed the caller's total

No physical used/total percentage is inferred by subtracting physical free from
quota-aware total. Denied/unavailable reads carry null capacity, never zero.
A successful zero-capacity read remains an actual zero observation. The shared
Overview's system-volume percentage and history keep their original semantics;
this extension does not turn them into an all-disk aggregate.

Enumeration is capped at 128 native rows, with a cooperative five-second budget
checked between synchronous native calls. Windows cannot preempt an in-flight
volume API call here; no detached worker or unbounded goroutine is used. The
normal sender interval is reused; there is no additional polling loop. Transport
carries at most 64 rows and 12 KiB, with deterministic complete-row trimming.
The whole frame remains at most 72 KiB; additional trimming to its remaining
budget preserves original capture, observed count and exact/lower-bound count.
At the native cap, the count is a lower bound and completeness is not claimed.
Enumeration quality is distinct from each row's capacity quality: an exact,
complete enumeration may contain denied rows. Partial and unavailable latest
observations replace old successful data.

## Full shared path and compatibility

The sender uses `tracebolt.agent-telemetry.windows.v3` when volume scope is
active, optionally alongside independently consented event headers. With events
only it emits the unchanged v2 shape; with neither it emits unchanged v1.
The same signed Windows ingress, identity profile, durable store transaction,
resource history and authenticated operator API are reused. Unknown/duplicate
members, null extensions, foreign scope/generation, contradictory quality,
noncanonical values and invalid capture times fail closed. Latest volume capture
must advance alongside the existing frame/generation replay floors. Pending
retries retain exact bytes and original receipts through restart. Revocation or
replacement of either local grant discards affected pending bytes without
resetting sequence. Consent is checked after capture and again before sending.
Old managers cannot accept v3; upgrade the manager before explicit enable, and
do not downgrade a sender or reset its pending ledger to bypass incompatibility.

The existing Windows Inventory tab gains a concise Storage subtab in EN/DE.
It shows quota-aware total/available and physical free separately, with individual
denied/unavailable states, enumeration counts and truncation. Original volume
capture and manager receipt are retained. Capture/receipt staleness after two
minutes and private-row expiry after 24 hours remain explicit. Independent event
and volume expiry does not hide a younger sibling capability. Session loss,
clock regression, blur/navigation, request interruption and frozen response
refresh protections apply equally to volumes. Revoked identities hide data.
Volume GUIDs/capacities never enter basic evidence or AI/provider export.

## Evidence boundary and native gate

Synthetic tests exercise actual collection adapter → signed sender → production
ingress → durable store → authenticated shared operator view, exact restart
retry, independent disable, replaced/revoked grants and strict version rejection.
Contract/native-API-injection tests, DOM tests and Windows cross-compilation are
source evidence. Hosted invented browser fixtures are UI-only and must run on
the final composed source before screenshot acceptance is claimed. No local
browser, real volume read, consent activation, service installation, security
change or native workflow dispatch is implied.

Before native acceptance, separately approve and verify: matching Windows
binary/source and manager, owned stopped service and protected sibling-store
access; caller-visible GUID enumeration including no-drive-letter volumes;
quotas, denied/offline/removable/CD-ROM observations; finite handle lifetime;
service restart/pending retry and disable; and actual Windows values in the
same Linux manager and browser. Never widen host rights or repair ACLs merely
to make a read succeed.

API references:
- [GetDiskFreeSpaceExW quota and physical-free semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw)
- [FindFirstVolumeW volume enumeration](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstvolumew)
- [GetDriveTypeW types](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew)
