# Windows Update cache inspection candidate

**Source-only candidate, 10 October 2026. No native Windows acceptance or runtime
integration is established.** This package is a first read-only Windows Update
slice, not Linux feature parity, a CVE evaluator or update installation support.

[Windows status](windows-status.md) · [Read-observation consent](windows-read-observation-setup.md)

## Implemented source boundary

`internal/windowsupdates` defines a separate consent and a bounded inspection
contract. No current CLI, Setup flow, installed service, sender, manager API,
dashboard, provider or telemetry path imports or invokes it. Existing Windows
five-scope approvals and service-startup consent do not grant this scope.

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

Before installed-service integration, choose and test a bounded isolation/lifetime
strategy that does not let a slow native call stall reporting or service shutdown.
Do not enable this source in the current main agent loop without resolving that
gate and measuring native behavior on separately approved disposable Windows VMs.

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

No consent sidecar, persistent generation ledger or wire version is introduced by
this slice. The consent and HTTP warning strings are contracts for a future
explicit local approval flow, not a new supported command or a runtime grant.

## Planned separate end-to-end slice

1. Add create-only, identity-bound local preview/enable/disable handling in
   `internal/lanclient` with protected persistence and explicit disclosure of
   update titles/identifiers, unknown cache freshness and HTTP-test exposure.
   Retain disabled receipts and independent durable generation/retry floors.
2. Resolve the synchronous source lifetime gate; then add opt-in collection in
   the Windows sender. Never activate from a manager request, schema upgrade,
   Setup receipt or an older profile. The fresh five-scope coordinator stays as-is.
3. Add a new backwards-compatible Windows wire version in
   `internal/windowsmanaged`, leaving v1-v6 accepted bytes unchanged. Bind the
   optional update snapshot to the base generation, grant and original capture;
   enforce the complete frame budget and durable exact retry bytes.
4. Extend admission, consumption/replay and private manager persistence in
   `internal/enrollmentservice`, `internal/enrollmentstore` and `internal/store`.
   A manager schema change must not grant endpoint collection.
5. Add an operator-only bounded API and dashboard view in `internal/api` and
   `web`. Preserve stale/partial/unavailable truth, private expiry and the unknown
   cache-freshness label. No "up to date" inference from zero rows. Keep update
   evidence excluded from provider packets and public health summaries.
6. Test consent-negative, cross-generation, replay, exact-retry, disabled/stale
   retention, old-frame compatibility, malformed metadata, UI escaping, budgets
   and provider exclusion before separately approved native acceptance.

Update/CVE mapping and selected update installation remain separate future work
requiring their own trustworthy applicability/feed data and mutation consent,
plan, consume-once and reboot/failure handling. This package does not grant them.

## Verification and remaining native gate

Portable fixtures cover offline control order/readback, denied or disabled scope,
identity/capture binding, cancellation, partial/empty/failed searches, large
counts, bounded native-row traversal, output fitting, sanitized metadata and
error reasons, UTF-16 rejection, canonical serialization and unsupported hosts.
Windows-only tests inspect COM ABI layouts, pointer-union access and HRESULT
mapping without opening WUA. A portable source-boundary test guards the reviewed
DLL/API/property surface. Cross-builds are compilation evidence only.

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

## Microsoft references

- [WUA Online property](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-get_online)
- [Automatic WUA upgrade property](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-get_canautomaticallyupgradeservice)
- [Synchronous Search and criteria](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search)
- [OperationResultCode](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/ne-wuapi-operationresultcode)
- [MSRC severity](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-get_msrcseverity)
- [Update session CLSID assignment](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/e839e7e0-1795-451b-94ef-abacd6cbecac)
- [IDispatch invocation and property-put convention](https://learn.microsoft.com/en-us/windows/win32/api/oaidl/nf-oaidl-idispatch-invoke)
- [VARIANT layout](https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ns-oaidl-variant)
