# Windows Update cache inspection candidate

**Default-off source candidate, 10 October 2026. Native Windows acceptance is
pending.** This collector now has a separate [runtime/manager/UI source path](windows-update-runtime.md).
It is not in the published Windows preview, does not establish Linux feature
parity, and is not a CVE evaluator or update-installation mechanism.

[Windows status](windows-status.md) · [Read-observation consent](windows-read-observation-setup.md)

## Implemented source boundary

`internal/windowsupdates` defines a separate consent and a bounded inspection
contract. The sender invokes it only inside an independently verified, bounded
owned worker after the new local grant. The ordinary service does not make a
synchronous WUA call. Existing Windows five-scope approvals and service-startup
consent do not grant this scope; Setup, provider/AI and action paths remain excluded.

The Windows source creates a local in-process Windows Update Agent (WUA) session
through COM on one locked OS thread. Before a single fixed search it sets and
reads back both `Online=false` and `CanAutomaticallyUpgradeService=false`.
Failure or an unexpected enabled value stops inspection; there is no online or
shell fallback. The only search criteria are:

```text
IsInstalled=0 and IsHidden=0 and Type='Software'
```

These are observations from the caller-visible cached WUA software-update result,
with the configured WUA source left unchanged. They omit installed, hidden and
driver updates; WUA's default supersedence behavior still applies. The adapter
verifies each inspected row's type, installed flag and hidden flag. It does not
register an offline CAB, change update policy, enable a service, retrieve update
history, request detection, download content, accept EULAs, install updates or
reboot. Only the two per-searcher safety properties are written. COM/WUA can
initialize local components and perform internal bookkeeping; this is not a
claim that Windows performs zero internal side effects.

The returned fields are update GUID and revision, sanitized title, KB numbers,
MSRC severity and the existing `IsDownloaded` flag. No descriptions, URLs,
paths, release notes, error prose, machine accounts or arbitrary COM properties
are returned. Severity is a vendor label attached to the update, not proof of
an exploitable vulnerability or complete CVE coverage. `Downloaded=true` means
WUA reports content already cached; the adapter does not request a download.

## Freshness, counts and errors

- `source` is always `wua-cache`; `cacheFreshness` is always `unknown`. There is
  no trustworthy cache-generation timestamp in this contract.
- `collectedAt` is the original inspection/base-generation capture time. It is
  not the time of an online scan or metadata refresh. Fitting a frame and retrying
  must retain the original value.
- Empty successful cached results do not mean the machine is fully patched,
  protected, online-current or compliant. A fresh inspection can observe a stale
  or incomplete cache.
- `observedCount` is the WUA collection count for this fixed cached search, before
  row validation and retention limits. `countExact=true` is allowed only for
  WUA `orcSucceeded`. `orcSucceededWithErrors` remains `partial` and the count is
  a lower bound on the requested cached search, including when it is zero.
- `countExact` does not promise all row metadata was readable. Failed row reads,
  invalid identities, malformed strings and duplicate identities produce a
  `partial` snapshot; the original result count remains visible.
- `truncated` means the cached result count exceeds retained rows. Rows may be
  missing because of bounded traversal, row/byte budgets or failed row reads.
  A row's `metadataTruncated` independently marks shortened titles or capped KB
  enumeration.
- Failures before a usable result become `denied` or `unavailable`, with fixed
  public reason codes. Non-Windows platforms explicitly report unsupported.
  Raw HRESULT messages, exception descriptions and arbitrary source errors never
  enter snapshots. Caller cancellation returns an error and no snapshot.

## COM activation trust boundary

A fixed update-session CLSID avoids ProgID resolution but does not itself pin a
provider DLL. Microsoft documents per-user COM class configuration precedence,
LocalService's own HKCU hive, and in-process activation of the DLL selected by
class registration. Those facts alone do not establish that this worker is
vulnerable: Microsoft's [COM per-user configuration restriction](https://learn.microsoft.com/en-us/previous-versions/bb756926(v=msdn.10))
states that, starting with Vista/Server 2008, processes above Medium integrity
ignore per-user COM configuration and use per-machine configuration.

The native source makes that precondition explicit. After locking its OS thread
and before COM initialization or activation, it requires no thread impersonation
token and queries its current process token with `TOKEN_QUERY` only. A bounded
two-call `TokenIntegrityLevel` query, capped at 4 KiB, must contain a valid mandatory-label SID
whose pointer and complete bytes remain inside the returned buffer. Only High
(`S-1-16-12288`) and System (`S-1-16-16384`) are accepted. Medium, Medium Plus,
unknown or malformed labels, token/query errors and impersonation all fail
closed before WUA activation. The adapter never raises integrity, adjusts a
token, impersonates, overrides registry mappings or changes registry/security
settings. The ordinary worker identity, grant and parent-verification gates
remain separate requirements.

Activation continues through documented `CoCreateInstance` with the fixed CLSID
and `CLSCTX_INPROC_SERVER` only. It does not call `DllGetClassObject` directly;
Microsoft's [caller guidance](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-dllgetclassobject)
explicitly discourages that bypass. The existing system-DLL loader is retained
for `ole32.dll` and `oleaut32.dll`. This trusts the operating system, protected
machine registration and installed executable; it is not a claim to validate
every later DLL/dependency load or isolate all services sharing LocalService.
Machine-registration/system compromise and arbitrary code already inside the
worker are outside this narrow guard.

## Bounds and synchronous-call limitation

The source examines at most 128 updates from WUA's native result order, sorts the
validated inspected rows by GUID/revision, and retains at most 64 rows in a
24 KiB canonical JSON snapshot. This is a sorted bounded prefix observation, not
a guarantee that the globally lowest 64 GUIDs or highest-severity updates were
selected. It copies at most 2,048 UTF-16 code units per native string; individual
identifier, severity and KB fields have smaller limits. Strings beyond their
native limit fail the row. Titles retain at most 256 UTF-8 bytes after removing
control/format characters and collapsing whitespace. At most eight KB entries
are read per inspected row; retained KB values are canonicalized, sorted and
deduplicated. Invalid UUIDs, KB numbers, severity values and UTF-16 are rejected.

The 15-second collection budget is **cooperative**. The adapter checks context
before and after COM work, but synchronous WUA search/property calls and cleanup
cannot be forcibly interrupted. WUA may allocate its complete result collection
before bounded traversal begins. Therefore the source does not establish a hard
wall-time bound, a cap on WUA's own memory, or service-stop responsiveness. It
spawns no abandoned background worker to pretend cancellation completed.

The [runtime adapter](windows-update-runtime.md) isolates this source in the
current installed executable's fixed worker mode. Its parent enforces a process
deadline and reaps the child; a child-only watchdog also covers parent loss.
That limits the owned client process, not WUA service-internal work or memory.
The exact LocalService/COM behavior, termination and ordinary-reporting continuity
still require separately approved native Windows measurement before release.

## Consent and contracts

- Scope: `windows-cached-update-inspection-v1`
- Consent schema: `tracebolt.windows-update-inspection-consent.v1`
- Snapshot schema: `tracebolt.windows-update-inspection.v1`
- `Consent` carries an independent random grant ID, exact sender binding and
  explicit enabled state. `EncodeConsent` / `DecodeConsent` enforce canonical
  bytes, exact schema/scope, field set and binding; no legacy scope is promoted.
- `Collect(ctx, Request)` validates enabled consent, independent sender binding,
  generation ID and UTC capture time before opening the source. It does not
  persist, authenticate or create a grant. A future runtime caller must first
  authenticate an existing durable local receipt and activated identity.
- `CollectWithSource` exercises the same coordinator with synthetic sources.
- `Encode`, `Decode`, `Validate` reject extra/duplicate/noncanonical fields,
  inconsistent counts and quality, invalid metadata and oversized snapshots.
- `ValidateBinding` ties a snapshot to the exact base generation, grant and
  original capture. `FitBudget` drops complete rows without changing those
  bindings, source freshness, count or quality semantics, and owns its copied
  row/KB slices.

The collector itself does not write consent or sender state. The separate
[runtime adapter](windows-update-runtime.md) adds protected create-only consent
and explicit source CLI commands; [v7 manager admission](windows-update-manager.md)
retains exact pending bytes and original capture/replay boundaries. Documentation
or source compilation is not a runtime grant.

## Separate end-to-end source path

- [Local consent and isolated sender](windows-update-runtime.md): stopped-service
  preview/enable/disable, independent grant, pre/post/send rechecks, bounded owned
  worker and exact pending-byte retries. No promotion of old identities or grants.
- [Protocol, durable manager and operator view](windows-update-manager.md): new
  v7 with required update snapshot, optional old siblings, unchanged 72 KiB frame
  budget, exact base generation/capture binding, original receipt, capture floor,
  revocation and 24-hour private expiry. Old v1-v6 frames remain accepted.
- [Shared Updates dashboard](windows-update-dashboard.md): bounded cached rows,
  original inspection time, unknown cache freshness, truthful empty/partial/denied
  states, local search/sort/page and explicit session/navigation/expiry clearing.
  Refresh reads the accepted manager snapshot and never triggers a native scan.

Portable tests and synthetic browser fixtures cover those contracts. They do not
prove native WUA visibility under the installed token, actual offline behavior or
Windows-to-Linux production interoperability. The published preview's five-scope
native subset does not cover this new capability.

Update/CVE mapping and selected update installation remain separate future work
requiring their own trustworthy applicability/feed data and mutation consent,
plan, consume-once and reboot/failure handling. This package does not grant them.

## Verification and remaining native gate

Portable fixtures cover offline control order/readback, denied or disabled scope,
identity/capture binding, cancellation, partial/empty/failed searches, large
counts, bounded native-row traversal, output fitting, sanitized metadata and
error reasons, UTF-16 rejection, canonical serialization and unsupported hosts.
Windows-only tests inspect COM ABI layouts, pointer-union access and HRESULT
mapping without opening WUA. Portable synthetic integrity-label fixtures cover
both pointer widths, allowed/rejected levels, malformed/truncated records and
out-of-buffer pointers. Injected token-API fixtures cover open/query failures,
impersonation, null handles, size/fill growth or truncation, bounded allocation,
no retry and handle closure, including a close failure overriding success.
Source-order fixtures pin the no-impersonation/query-only API surface, pre-COM
trust gate and OS-thread cleanup. These fixtures never query a real token or
initialize COM. A portable source-boundary test guards the
reviewed DLL/API/property surface. Cross-builds are compilation evidence only.

Run the focused portable checks with the repository's Go version:

```sh
go test -race -count=1 ./internal/windowsupdates
go vet ./internal/windowsupdates
GOOS=windows GOARCH=amd64 go vet ./internal/windowsupdates
GOOS=windows GOARCH=amd64 go test -c -o /tmp/windowsupdates-amd64.test.exe ./internal/windowsupdates
GOOS=windows GOARCH=arm64 go test -c -o /tmp/windowsupdates-arm64.test.exe ./internal/windowsupdates
GOOS=windows GOARCH=386 go test -c -o /tmp/windowsupdates-386.test.exe ./internal/windowsupdates
```

No native WUA search was executed during source development. A future native gate
needs an exact reviewed source/binary, explicit VM/scope approval, controlled
cached data, disabled/unavailable-WUA cases, stale and empty cache cases, denied
caller rights, repeated cancellation/cleanup, resource measurements and traffic
observation proving no online scan by this client. Do not use fixtures or an
unsigned cross-build as permission for a real host read or a new persistent grant.

Activation acceptance must also record the exact child process's LocalService
identity, owning service SID, existing High/System integrity label and absence
of thread impersonation before COM activation. Microsoft says system services
ordinarily receive System integrity; that is not a measurement of this child.
Verify the actual loaded provider/dependency provenance and the protected
per-machine registration, along with successful denied/allowed gate behavior and
balanced COM/thread cleanup. Do not modify host registration, permissions,
identity, privileges or integrity to make this gate pass. A failed trust gate
must remain a denied observation with ordinary reporting still available.

## Microsoft references

- [WUA Online property](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-get_online)
- [Automatic WUA upgrade property](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-get_canautomaticallyupgradeservice)
- [Synchronous Search and criteria](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search)
- [OperationResultCode](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/ne-wuapi-operationresultcode)
- [MSRC severity](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-get_msrcseverity)
- [Update session CLSID assignment](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/e839e7e0-1795-451b-94ef-abacd6cbecac)
- [IDispatch invocation and property-put convention](https://learn.microsoft.com/en-us/windows/win32/api/oaidl/nf-oaidl-idispatch-invoke)
- [VARIANT layout](https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ns-oaidl-variant)
- [COM class configuration precedence](https://learn.microsoft.com/en-us/windows/win32/com/classes-and-servers)
- [LocalService account and its HKCU hive](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account)
- [Merged HKEY_CLASSES_ROOT view](https://learn.microsoft.com/en-us/windows/win32/sysinfo/merged-view-of-hkey-classes-root)
- [COM process-integrity restriction on per-user configuration](https://learn.microsoft.com/en-us/previous-versions/bb756926(v=msdn.10))
- [Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [Integrity RID constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
- [TOKEN_MANDATORY_LABEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label)
- [GetTokenInformation query contract](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
- [OpenThreadToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [CoCreateInstance and class-factory lifetime](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
- [CLSCTX in-process selection](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [DllGetClassObject caller restrictions](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-dllgetclassobject)
- [LoadLibraryEx directory/dependency search](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
- [DLL search order and redirection](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [COM thread initialization and balanced cleanup](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex)
