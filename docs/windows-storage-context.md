# Windows storage context: source candidate

This slice adds useful storage context to the existing compact Storage view. It
is not in the published Windows preview. Unchanged LocalService access, native
Windows 11/Server provider coverage and fresh Setup acceptance are unverified
and explicitly deferred until the missing Admin-data work is complete. Source
fixtures, cross-compilation and invented browser screenshots authorize no host
read, installation, service change, ACL grant or release.

## Exact sources and meanings

- GetLogicalDrives supplies the fixed 26 assigned drive-letter candidates.
  GetDriveTypeW excludes mapped network drives before any volume-GUID query.
  GetVolumeNameForVolumeMountPointW receives only a generated local root such as
  `C:\`, with a fixed 50-unit output buffer. No caller-selected path, folder mount
  path, file, network share, volume label or serial is read. The returned GUID is
  canonicalized; inaccessible/unknown local candidates retain an unavailable row.
  Mapping is a caller-visible API observation, not an atomic topology guarantee.
  Letter/GUID values can change during or after capture. Mapping is displayed in
  a compact independent drive-letter panel alongside
  volume capacities. The volume collector records its own later capture time,
  so no mapping is attached to capacity rows and no timestamp is rewritten.
  Retained mappings stay separate. Unlettered volumes keep their original GUID
  display from the independent visible-volume scope.
- One fixed local `Root\Microsoft\Windows\Storage` query selects only DeviceId,
  FriendlyName, HealthStatus, OperationalStatus, BusType, MediaType and Size from
  MSFT_PhysicalDisk. DeviceId is a provider address/identifier; FriendlyName is a
  provider-supplied, user-editable label. Both are explicitly disclosed identifying
  metadata. No SerialNumber, UniqueId, PhysicalLocation, arbitrary properties or
  WMI methods are requested. The displayed index is capture-local enumeration
  order, never a stable device ID or OS disk number.
- HealthStatus and OperationalStatus are the storage provider's high-level
  reports. A reported Healthy value is not a SMART result, self-test, physical
  health proof or guarantee against failure. Unknown/null/future values are not
  converted to healthy. Bus/media values are source reports. RAID, iSCSI, virtual
  disks and Storage Spaces can abstract or hide backing devices; the visible
  rows are not an all-physical-disk inventory. No volume-to-physical-disk join is
  inferred from DeviceId, order, size, drive letter or any other heuristic.
- The existing volume total/available remain quota-aware; physical volume free
  is separate. PhysicalDisk Size is provider-reported device size, never a volume
  capacity, used-space or free-space measurement.

I/O throughput and latency, SMART attributes/self-tests, temperature, wear,
reliability counters and topology joins are deferred. They need separate
source/interval/identity semantics; no value is invented from capacity or status.

Official API references:
[GetLogicalDrives](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getlogicaldrives),
[GetDriveTypeW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew),
[GetVolumeNameForVolumeMountPointW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumenameforvolumemountpointw),
[MSFT_PhysicalDisk](https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-physicaldisk).

## Consent, workers and bounds

`windows-storage-context-v1` is independent and default-off. Its protected
`-storage-context` sibling grant is identity-bound and create-only; old grants,
identity records, receipt bytes and sender sequence floors retain their meanings.
The fresh fourteen-scope Read admin profile uses consent v7, outer receipt 5 and
the separate bodyless capability-v3 route. The initially unchecked combined
acknowledgement explicitly names drive letters/GUIDs and provider identifiers and
friendly labels. HTTP-test additionally discloses their plaintext risk. No extra
manual per-feature setup or migration is required, and Setup does not query or
repair providers to establish access.

Drive mapping and disk-provider reads each run in a separate current-executable
worker, under the existing token. Bounded private IPC has only opaque identity,
grant, generation and original-capture bindings. The child independently verifies
its installed parent and enabled grant before and after reading. There are no
caller-selected executable/query/configuration paths or inherited environment.
WMI activation retains the existing locked-thread, no-impersonation and
High/System-integrity verification. This check never elevates the token.

Each source has a one-second ceiling, sharing the existing five-second optional
source budget with fair remaining time and pipe/reap reserve. Cancellation kills
and synchronously reaps the owned child; it cannot promise to stop internal WMI
provider-service work. The sender's existing optional-source rotation and
three-second send reserve include this scope; no extra polling loop is added.

The disk enumerator uses fixed semisynchronous forward-only WQL, at most 64 Next
calls and at most 32 retained rows. Reaching 64 is a lower-bound count, never
complete coverage. String BSTR lengths are checked before copying (DeviceId 64,
FriendlyName 128 UTF-16 units), invalid UTF-16 rejected, and operational-status
SAFEARRAY dimensions/type/bounds validated before at most 16 element reads.
Scalar null/invalid fields remain unavailable rather than zeros. Enumeration
coverage is distinct from nullable row fields. The whole scope is at most 16 KiB;
complete-row trimming retains counts, grant, generation and original capture.

## Private transport and freshness

Wire v13 requires storage context and permits earlier independently granted
siblings. Earlier v1-v12 wire meanings and exact pending retry bytes remain
unchanged. Strict sender/manager validators reject foreign binding, duplicate
scope grant IDs, noncanonical JSON, impossible coverage and unbounded fields.
All scopes fit the existing 72 KiB frame without dropping base identity or a
granted envelope. Revoked/replaced authority discards pending affected bytes
without resetting sequence; capture and pre-send authority are rechecked.

Only the authenticated private Windows inventory view exposes these rows. Latest
failures stay visible. A prior useful whole capture can be retained with its
original grant/generation/capture time, clearly separate from the current
snapshot. Known fields, a real mapping or an observed complete empty enumeration
count as useful. Unknown, Other, reserved and unrecognized enum-only observations
stay visible in the current capture but cannot refresh or replace useful retained
data. Health 0/1/2, bus 1–13 or 15–17, media 3/4/5 and documented operational
status 2–18 count as meaningful status values. Grant omission/replacement and
identity revocation remove access.
Current/prior captures expire after 24 hours; two-minute staleness remains
explicit. The existing 80 KiB optional retention table is unchanged; if full
siblings exceed it, the oldest whole capture is evicted, never merged/refreshed.
Session loss, cancellation, clock regression and navigation clear private views.
No AI/provider export, basic evidence, alarms or service actions are added.

## Remaining acceptance boundary

Native acceptance still needs separately approved exact source/binaries and
matching manager: unchanged LocalService reads, denied/missing Storage provider,
removable/offline/no-letter media, multiple letters, quota semantics, RAID/virtual/
Storage Spaces coverage, source timeouts, fresh Setup and restart retry/disable,
and actual values in the Linux manager and browser. Do not install drivers,
providers or grant privileges merely to obtain a result. Windows ARM64 runtime,
release signing/publishing and host deployment remain separate gates.
