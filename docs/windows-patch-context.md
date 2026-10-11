# Windows patch context

Source candidate, 11 October 2026. The existing Updates tab now has a separate
opt-in read-only patch-context path: Windows edition/release/build revision,
bounded retained update history, and three machine-wide reboot indicators.
The published preview and native acceptance are unchanged.

## Local approval

`windows-patch-context-v1` is independent and default-off. Neither cached-WUA
consent, the five-scope Setup coordinator nor any existing receipt grants it.
With the activated, receipt-owned inventory service stopped, the source supports:

- `windows-service --patch-context-preview`
- `windows-service --patch-context-enable --apply --windows-build-history-reboot`
- `windows-service --patch-context-disable --apply`

These are source interfaces, not authorization to execute them. Preview does not
write. Enable prints the complete disclosure before dispatch. An existing
HTTP-test identity additionally needs `--insecure-http-test` and its plaintext
warning; production remains HTTPS. A protected create-only `-patch-context`
sibling binds the scope to the existing sender identity. The sender lock spans
configuration. Missing used state and unsafe/foreign state fail closed. Disable
retains state; explicit re-enable creates a fresh grant. No migration, service
restart, ACL change, enrollment or setup promotion occurs.

## Fixed local sources

The machine reader opens only fixed HKLM keys with query-value access and the
64-bit view. It reads `EditionID`, `DisplayVersion`, `CurrentBuildNumber` and
DWORD `UBR` from `Windows NT\CurrentVersion`. Each value uses one fixed 130-byte
buffer, no allocation/retry based on registry size. String metadata is restricted
to short ASCII version/edition labels; build/revision are canonical uint32 decimal
strings. Missing, denied, malformed and unavailable values stay distinct. These
registry labels can be absent or stale and are not Windows support-lifecycle proof.
No ProductID, registered owner, user hive, path, key enumeration or recovery key
is read.

WUA uses fixed local in-process COM activation behind the existing locked-thread
High/System-integrity and no-impersonation guard. Both `Online=false` and
`CanAutomaticallyUpgradeService=false` must be set and read back. No `Search`
call occurs. `GetTotalHistoryCount` and exactly one `QueryHistory(0, min(count,64))`
read the latest retained installation/uninstallation events. The count is checked
again; a changed/failed count or short collection is partial with only the returned
collection count as a lower bound. Invalid rows are omitted with partial quality.
No history paging loop or recapture occurs.

At most 64 rows and 24 KiB are retained: capture-local index, update GUID/revision,
sanitized title (256 UTF-8 bytes), UTC event time, operation, result and hexadecimal
HRESULT. Events are ordered by their source index and descending time; duplicates
of an update across separate events remain legitimate. Titles may include KB
numbers, but history is not a current installed-update inventory, an online
availability check, a complete audit log or a compliance/CVE verdict. WUA retention
may be cleared; zero events proves none of those claims. Application identities,
URLs, descriptions and error prose are neither requested nor retained.

The three reboot indicators are independently known or unknown:

- WUA `ISystemInformation.RebootRequired`: updates waiting for restart
- CBS `RebootPending`: fixed machine key presence, no values read
- `PendingFileRenameOperations`: REG_MULTI_SZ type/size only, with a null data
  pointer. Payload paths are never allocated or read. A nonempty-looking value is
  an indicator, not an urgency or correctness claim; empty-looking or malformed
  metadata stays unknown because the payload was not inspected.

Missing CBS/PFRO markers mean only those indicators were not set. Access/query
failures remain denied/unavailable. Three negatives never establish that every
Windows component has no reboot pending; computer rename, domain join, installer
and vendor-specific reasons are outside this slice. No reboot or remediation
operation is provided.

Microsoft references: [QueryHistory](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-queryhistory),
[UTC history timestamps](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/81f33109-ff5f-4c51-8a1c-412f49c47bab),
[WUA reboot property](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-isysteminformation-get_rebootrequired),
[registry query bounds](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw),
[pending file-operation semantics](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexa),
[CBS indicator](https://learn.microsoft.com/en-us/windows-server/manage/windows-admin-center/virtualization-mode-known-issues).

## Worker, transport and private display

The current executable's fixed patch worker receives only a bounded 1 KiB
canonical identity/grant/generation/capture request, never a path, query,
credential or environment override. It uses the existing protected service-token,
actual live SCM-parent, executable hash, creation-time and activated-identity
checks before/after capture. It independently reloads the new protected receipt.
The parent enforces 15 seconds, kills/reaps its child and bounds inherited-pipe
waits to 100 ms; the existing 20-second self-watchdog covers parent loss. No native
COM goroutine remains running in the service. These bounds cover the owned
process, not WUA's internal service memory or scheduling. With patch context
selected, the sender additionally caps each cache/patch child to five seconds and
reserves three seconds from the remaining parent deadline for staging/delivery.
Insufficient time skips that optional source with a finite unavailable/budget
result; genuine parent cancellation still stops the attempt. Cache-only behavior
and the outer attempt deadline remain unchanged.

Wire `tracebolt.agent-telemetry.windows.v9` requires `windowsPatchContext` with a
separate visible grant. v1-v8 encodings/retry bytes stay unchanged without this
scope. The new section uses the exact base generation and conservative original
report-window capture time; the sources are not an atomic snapshot. The 72 KiB
frame limit remains. Fitting drops complete optional rows while preserving base
rows, protected self metrics, grant, age and counts. Consent is checked before
capture, after capture and before send; replacement/revocation suppresses pending
data. Retry/restart retains exact bytes and original receipt/capture. The durable
base capture floor also covers later scope-absent reports.

Only the authenticated operator Windows inventory view exposes `patchContext`.
Existing current identity authority, stale status and 24-hour privacy expiry apply.
No public/basic, provider/AI, health policy or action permission is expanded.
The EN/DE Updates panel shows a compact build line and checked reboot status;
source reasons and retained history are available in collapsed details.

## Verification boundary

Portable tests cover exact consent, disclosure failure, bounded/partial sources,
canonical Go/browser shape, old-scope compatibility, TLS/HTTP-test admission,
private-view expiry/revocation, exact retry/restart and isolated-worker lifecycle.
Cross-builds are compilation only. Synthetic production-UI browser captures are
not native telemetry or installation evidence.

A separately authorized disposable Windows gate must establish LocalService
registry/WUA visibility, actual offline network behavior, native history retention
and dates, mixed reboot indicators, worker responsiveness, protected consent,
replacement/disable/re-enable and Windows-to-manager-to-browser operation. No host
read, grant, installation, scan, download, update, reboot or security-setting
change is authorized by these source tests.
