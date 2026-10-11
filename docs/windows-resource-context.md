# Windows CPU and memory context: source candidate

This default-off scope is source-only and is not in the published Windows
preview. Native reads under the unchanged LocalService token, provider coverage,
fresh installation and GUI acceptance remain unverified. No host read, install,
grant, credential/trust change, release or remote write is authorized by source
fixtures, cross-compilation or browser tests.

## Fields and meanings

- `Win32_Processor`: fixed local model/name, architecture, core count and logical
  processor count properties. Counts are labeled with their source. Complete
  reported rows may supply a source total; missing counts stay unknown. This is
  the caller-visible provider's view, including virtualization limits, not a
  claim of physical topology or CPU utilization across processor groups.
- `GetPhysicallyInstalledSystemMemory`: SMBIOS-reported installed RAM, converted
  from KiB to bytes with overflow checks. Firmware absence or invalid data stays
  unavailable. Installed RAM is separate from memory Windows can actually use.
- `GetPerformanceInfo`: OS-usable total and available physical RAM, current
  committed bytes and current commit limit, with a checked page-size conversion.
  Remaining commit capacity is current limit minus current committed bytes from
  the same valid capture. It is not a guarantee that a future allocation will
  succeed. Commit use is not pagefile use, and neither equals installed RAM.
- `EnumPageFilesW`: aggregate count, allocated capacity and current in-use bytes
  across the bounded successful enumeration. Pagefile names and paths are never
  copied, persisted or sent. Per-pagefile peaks are not summed or reported.
  A successful empty enumeration is distinct from unavailable/denied data.

Primary Microsoft contracts: [Win32_Processor](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor),
[installed RAM](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getphysicallyinstalledsystemmemory),
[performance information](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-performance_information),
and [pagefile enumeration](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumpagefilesw).

The sources retain independent status and the original capture time. There is
no inferred join between processor counts from independent providers, no
substitution of installed RAM for OS-usable RAM, and no conversion of missing
values to zero. Exact byte counts are represented as canonical unsigned decimal
strings. Commit remaining capacity and aggregate pagefile use are context,
not paging-I/O activity, thrashing, memory pressure or a health verdict. The
existing CPU utilization sampler remains unchanged: it returns unavailable when
there is more than one active processor group and samples only when exactly one
active group is reported. New Win32_Processor model and core-count configuration
can remain independently available; it does not add multi-group utilization
coverage. The separate bounded process CPU/working-set sample is unchanged.

## Explicit authority

`windows-resource-context-v1` has its own protected `-resource-context` sibling
store, immutable manifest, lock and temporary filename. It is off when absent.
Enable requires explicit local acknowledgement of this scope and, for isolated
HTTP-test only, the separate full plaintext-risk notice. The ordinary sender
and enrollment manifests and all historical grants remain unchanged.

This scope introduced the exact eighteen-scope Read admin profile with consent v11,
outer receipt 9 and a new bodyless capability-v7 route:
`/v1/windows/read-admin-setup-capabilities-v7`, returning contract
`fresh-eighteen-read-admin-scopes-v1`. Current fresh Setup uses the separately
current [fresh Read admin profile](windows-read-admin-setup.md). Earlier advertisements, consent scope sets
and receipt bytes remain exact; no older grant is promoted. The full scope
checkbox and HTTP-test risk checkbox start unchecked and clear on Back or
bootstrap replacement. No manual feature command or migration is required.

Fresh creation rejects any present, malformed, incomplete or denied sibling
store rather than adopting it. The existing stopped/owned/disabled service,
protected phase receipt and original activated identity guards run before and
after each selected scope operation. All seventeen extension grant digests must
match before startup. Partial writes preserve evidence; no automatic repair,
rollback, reset, re-enrollment or replacement authority follows.

See [Read admin setup](windows-read-admin-setup.md) for phase and receipt rules.
Collection and retry authority must reject absent, disabled, replaced or foreign
grants and changed/unactivated installed identities. Native source workers use
only fixed local read operations under the existing token. Provider failures
remain explicit; setup does not test provider access or change permissions.

## Bounded collection and transport

Four fixed sources run as isolated current-executable children with bounded
private request/response pipes. Each receives only opaque binding/grant/generation
and original capture time. The child checks current protected installed identity
and the exact grant before and after reading. Workers inherit the existing token;
no credentials, arbitrary query, configuration path or inherited environment is
passed. Cancellation kills and synchronously reaps the owned child; it cannot
stop work internal to a Windows provider service.

The CPU source accepts at most four Win32_Processor rows and 128 UTF-16 units per
name. The fifth row makes the entire CPU source unavailable/bounds; no clipped
prefix is presented as complete, and valid memory siblings remain available.
At most 32 pagefiles are aggregated. The canonical snapshot is at most 5 KiB;
the maximum mixed-failure fixture is 4,932 bytes. Each source has at most a
one-second provider budget, within a five-second parent scope budget and the
existing primary-delivery reserve. Missing, denied, timed-out and unsupported
sources remain distinct finite unavailable states where the API identifies them.

Wire v15 requires this separately granted context and permits earlier explicitly
granted envelopes. The frame remains at most 72 KiB, the observation 16 KiB and
the optional retained-context cache 80 KiB. On fresh granted-v15 captures, the
sender reserves a truthful 28 KiB bounded base preview before process/startup
row bindings are formed. Self-PID, original counts and truncation evidence remain
intact. After all permitted whole-row fallbacks, the conservative composed residual
allowance is 73,472 bytes, below
the unchanged 73,728-byte frame ceiling. It includes full event/hardware/resource
envelopes, the 16 KiB observation, fixed source fields, original failure/count
metadata and the protected self-process metric. Fitting stops earlier whenever
the actual frame fits, so a successful frame may be larger than this residual
allowance while remaining at or below 73,728 bytes. Sender encoding/decoding and
manager validation independently enforce that ceiling. Earlier wire v1–v14 bytes,
pending retries and independent complete
process/service/software/network generations are unchanged.

Known historical v14 availability limit: an admissible maximum composed-frame
fixture can fail fitting when existing bounded base/context envelopes coexist
with a synthetically padded 16 KiB observation. The padding is not built-in
collector output, so this is not proof of native reachability. No v14 wire or
retry behavior is changed here. Fresh v15's pre-binding base reservation avoids
this composition overflow; it does not claim a general native performance result.

The authenticated private Windows view retains original source/grant/generation
and capture age. A useful previous scope capture expires at 24 hours; latest
failures remain visible. Missing/replaced grants or revoked identity clear
access. The shared 80 KiB cache evicts whole oldest captures when needed, never
merges fields or refreshes old capture times. Operator-session expiry and
cancellation also apply to current and retained context.

## Privacy and limits

CPU model labels and source-labeled counts, installed SMBIOS RAM, OS-usable RAM,
commit current/limit/remaining and aggregate pagefile allocated/in-use capacity
are explicitly disclosed in both scope and HTTP-test notices. These fields are
private operator metadata, excluded from AI/provider exports, notifications and
basic observation projection. HTTPS remains the default; HTTP-test carries the
metadata in plaintext and cannot authenticate manager responses.

No CPU identifiers/serials, raw SMBIOS, RAM-module serials, pagefile names or
paths, process owners/paths/commands, pagefile configuration changes, remote WMI,
PowerShell, arbitrary queries, provider/driver installation, privilege expansion,
account/ACL changes, paging-I/O rates or automatic remediation are added.

Native acceptance must later use the exact matching endpoint, Setup, manager
and dashboard artifacts with separately approved clean Windows targets. Include
unavailable/denied providers, virtualized counts, installed-versus-usable RAM,
empty/large pagefile enumeration, grant changes and cancelled workers. Synthetic
source tests never establish any of those native results.
