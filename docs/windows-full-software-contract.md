# Windows machine software generations

This default-off source extension captures caller-visible registrations beneath
HKLM `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` in both explicit 64-bit
and 32-bit registry views. It does not establish every installed program.
Per-user registrations, other profiles, MSIX/Store, portable and unregistered
applications are excluded. No executable path, registry path, uninstall command,
license key, credential or provider/AI export is collected or transmitted.

## Source and identity

The existing LocalService identity uses read-only enumerate/query rights. One
OS thread owns the registry handles. Fixed ancestors and registration keys open
with REG_OPTION_OPEN_LINK; link target bytes are never read. A linked required
root is unsupported; a linked registration remains an unavailable-field row. Every returned subkey remains a row,
including registrations with missing names and unavailable optional values.
The fields are an opaque registration ID, view, display name, display version
and publisher. Optional fields distinguish observed (including an empty string)
from unavailable; missing, denied, oversized, malformed or non-REG_SZ values are
unavailable. Environment strings are never expanded.

The registration ID is SHA-256 over a scope-specific domain, explicit registry
view, and the exact native UTF-16 subkey bytes. It identifies that source key,
not an application across reinstalls or renames. Duplicate product names and
registrations in separate views remain distinct. No generic Unicode folding is
used for registry identity. Duplicate exact IDs within a capture fail it.

Root counts and last-write values are checked before/after enumeration, with
per-registration last-write checks around value reads. Disappearance, detected
mutation, enumeration denial, malformed key identity, cancellation or exhausted
limits fail the complete attempt. No prefix is promoted. Missing roots are
positive empty-view evidence. Successful enumeration is scoped and non-atomic;
these consistency checks cannot prove that concurrent registry activity never
occurred. A denied subkey query retains its enumerated ID with unavailable fields.

API assumptions follow Microsoft's [RegEnumKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw),
[RegQueryInfoKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw),
[RegOpenKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw)
and [RegQueryValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw)
documentation. String data is checked independently for termination and valid
surrogate pairs; Windows does not guarantee terminated registry strings.

## Coherent resource limits

- At most 32,768 registrations and 8 MiB of canonical row JSON.
- Optional text: 512 UTF-16 code units and 2,048 UTF-8 bytes; no truncation.
- Native key buffer: 256 UTF-16 units; value buffer: 1,026 bytes.
- At most 262,176 native read/query/open operations and 128 MiB cumulative
  fixed name/value-buffer work. Mandatory handle cleanup is bounded by opens.
- One synchronous 15-second cooperative capture budget, including root opens.
  No goroutine is abandoned; an in-flight Windows API cannot be hard-canceled.
- At most 512 chunks, each 128 rows / 64 KiB including the complete envelope.
- The 12 MiB frozen pack remains below the unchanged 16 MiB protected-file cap.
  Rows occupy at most 8 MiB and each chunk reserves 4 KiB of envelope room, so
  the 512-chunk maximum plus pack wrapper remains below 12 MiB.
- Each independent burst is 64 operations / 20 seconds. Pending packs drain over
  later bursts without recapture, new timestamps or new expiry. Minimum capture
  interval is one minute; original retention is 24 hours.
- Manager reservation: 48 MiB per device, 128 MiB globally shared with complete
  services and existing metadata. Lower quotas or bytes may bind before row
  count. They reject admission, never promise all maximum-sized devices fit.

Rows, chunks, sender phase, grant revision and capture floor are separate from
old bounded telemetry. Exact lost-ack retry bytes and original receipt times are
retained. A failure consumes one capture sequence and leaves the prior completed
generation with its original age plus a separate latest-attempt status.

## Explicit consent and used-state fence

The source CLI requires an already activated existing identity and stopped owned
service:

- `windows-service.exe --full-software-preview`
- `windows-service.exe --full-software-enable --apply --complete-machine-software`
- `windows-service.exe --full-software-disable --apply`

An HTTP-test identity also requires `--insecure-http-test` and the complete
plaintext disclosure. These commands document source behavior, not permission to
run them on a host. The current fresh GUI Read admin profile includes this inventory and separately
discloses [derived change history](windows-software-history.md); its history
retention requires the additional explicit history scope. The published preview
still has the historical five-scope GUI. Service inventory consent does not imply
software or history consent, and a manager upgrade grants none of them.

First software enable writes an irreversible software-used marker into version
3 of the existing mandatory primary sender record before creating its sidecar.
Untouched v1 and service-only v2 records preserve their exact encoding. The
transition preserves sender binding, telemetry counter, exact pending bytes and
digest. The existing protected primary file schema and 128 KiB cap are unchanged.
Software and services have independent bits, sidecars, consent revisions and
capture floors. Enabling services after software must retain version 3.

A missing used sidecar, missing marker with existing sidecar, missing used
sender/pack, interrupted initialization or invalid version is an error requiring
preserved-state diagnosis. Never recreate it as fresh, reset floors, re-enroll or
recapture a consumed attempt. Disable retains state; reenable creates a new local
grant/revision without refreshing a dormant capture. Older binaries fail closed
on the new primary version; do not downgrade or reset it.

## Operator search and pages

Protected read-only POST `/api/devices/{agent_id}/windows-full-software/query`
uses the current authenticated operator, Origin and CSRF guards. Private search
text and cursors stay in bodies. Request fields are search, sort, limit and
cursor. Sorts are name/version/publisher/view with asc/desc suffixes. Literal
Unicode case-insensitive search covers captured display name, version, publisher
and view; version ordering is text, not upgrade order. Missing values sort last;
opaque registration ID provides stable ties.

The complete generation is validated before full matching count/search. Pages
are at most 100 rows / 256 KiB. Cursors bind exact device, grant/revision,
generation/manifest, query/sort/limit, offset, session and original expiry. Changed
or expired authority/generation returns restart_required, never silently joins
replacement rows. Current identity/grant and original lifetime are rechecked at
response time. Missing/failed data is not a successful empty inventory.

The UI is compact: coverage badge, useful counts, search/sort, registration table
and paging. Full scope/age details are on demand. Pending requests, session/tab/
device changes, visibility or focus loss, untrusted time and original expiry
clear private rows and cursors. No UI read creates consent or collects host data.

## Verification boundary

Portable fixtures exercise bounded registry enumeration and UTF-16 parsing,
large complete generations, independent markers, exact retry, source and sender
failure, and protected manager pages. Windows cross-builds prove compilation
only. Actual LocalService registry visibility, protected Windows ACL storage,
installed CLI consent and shutdown remain a separately approved disposable
Windows gate. Browser execution and final hosted CI must be reported separately.
No native read, persistent host grant, service control, installation, release or
remote publication follows from this source task.
