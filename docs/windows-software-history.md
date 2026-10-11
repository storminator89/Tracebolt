# Windows machine-software change history

Current development source adds a separate, explicit, default-off
`windows-machine-software-history-v1` grant. Fresh Read admin Setup discloses it
as the twentieth scope. The published five-scope Windows preview does not contain
this feature. No native collection, privilege, service-control, AI, export or
health-policy authority is added.

## What a change means

The manager compares two complete HKLM 32/64 Uninstall registration generations
from the existing [machine-software source](windows-full-software-contract.md).
Both must have been captured after the current history grant, under the same
activated identity, sender binding, source, coverage, software grant and revision.
Both retain their original 24-hour inventory lifetime at comparison time. Only
consecutive successful capture sequences with ordered, nonoverlapping observation
windows are comparable. A failed, incomplete, missing, expired or interrupted
baseline produces a baseline/gap status, never synthetic registration removals.

Rows match by exact opaque registration ID and registry view. The change kinds
are registration added, registration removed, and observed metadata changed.
Name, version or publisher differences count only when both values are observed;
unavailable-to-observed is not an observed version change. Duplicate display
names remain separate registrations. A version comparison is literal text and
has no upgrade/downgrade semantics.

Before/after times are original capture-finished observation times. They are not
actual installation/uninstallation times. A registration identifier does not
identify an application across reinstalls, and history does not infer
maliciousness, compliance or complete installed-program coverage. Changes that
happen and reverse between captures are not observed.

## Explicit authority and unchanged transport

The stopped-owned-service source CLI offers `--software-history-preview`,
`--software-history-enable --apply --machine-software-history`, and
`--software-history-disable --apply`. Ordinary complete software inventory must
already be enabled. HTTP-test requires its separate plaintext acknowledgement.
These are source interfaces, not permission to run them on a host.

History is an optional exact `historyScope` field in the existing software
consent. Absent history preserves legacy consent and message bytes. History
enable/disable rotates the software grant and revision; the existing durable
software sender discards an old pending pack while preserving sequence floors.
No old baseline is reused. Scope and chunk bodies carry the exact consent through
the existing signed/mutual-TLS transport and receipts bind exact request hashes.
No new telemetry frame version, provider, worker or generic orchestration is used.
The old inventory grant alone never authorizes derived history.

## Retention, quotas and gaps

Only newly consented derived change rows have seven-day retention. Each expires
at the earlier generation's original capture-start plus seven days; retries,
queries and later captures cannot renew it. Original inventory generations still
expire after 24 hours. History and baseline are cleared on a scope/grant change.
Current identity expiry/revocation and operator-session authority remain required.

History reserves 1 MiB per enabled device inside the unchanged 48 MiB software
per-device and 128 MiB shared global inventory ceilings. The reservation covers
the entire canonical history record, including consent, counters and comparison
metadata. At most 1,024 derived change rows are retained. Every software/service/
process/network-context admission and transaction budget counts that reservation.
The schema permits at most 25 authorized software devices; no global ceiling is
raised. Enabling history can be refused when this existing budget is unavailable.

At complete promotion, the whole bounded difference is counted. Either every
change from that comparison fits or none of its change rows are retained, with
an explicit `resource_limit` gap and exact omitted-change count. This never
presents a prefix as a complete comparison. A full history buffer does not block
promotion of an otherwise admissible current inventory. The next complete
capture is the next baseline. Existing changes keep their original expiry;
normal retention pruning reports an expired-change count. Gap and omission
counters describe this grant epoch, not all machine history.

The existing 32,768-row / 8 MiB generation, 64 KiB per signed software request,
512-chunk, 12 MiB protected pack and 256 KiB page limits remain unchanged. Chunk
construction sizes the complete history-authorized envelope before splitting.
No new data enters the ordinary telemetry frame.

## Private Software UI

Protected read-only POST
`/api/devices/{agent_id}/windows-software-history/query` uses the authenticated
operator, current session, Origin and CSRF guards. Its body is
`{"search":"","sort":"observed-desc","limit":100,"cursor":""}`. Search is
literal Unicode case-insensitive over retained before/after metadata, exact
registration ID, registry view and change kind. Newest after-observation time
sorts first, with exact change ID ties. Counts/search inspect the entire bounded
history; pages contain at most 100 rows / 256 KiB.

Cursors are separately domain-signed and bind device, exact grant/revision,
history digest, query/limit, operator session and original deadline. Deadline is
the earliest of 15 minutes, identity/session expiry and the earliest retained
row/comparison expiry. A changed snapshot, grant, session or deadline requires
restarting; pages never splice history. Store and final HTTP response guards
recheck current authority and original lifetime after waits and preparation.

The bilingual Software view keeps a compact current-inventory/history switch,
summary, search and table, with full before/after details on demand. Baseline,
latest failed/pending attempt, comparison gaps, quota omissions and expiry remain
separate. Focus/visibility, session, device/tab changes and expiry clear private
rows and cursors. Reading the UI does not grant collection or history.

## Verification boundary

Portable tests cover consent byte preservation, grant rotation, exact retries,
post-consent baselines, unknown metadata, failure/partial gaps, complete-diff
quota rejection without blocking inventory, private search/paging and response
authority. Shared-budget and escaped-text frame fixtures exercise actual bounds.
Fresh setup/source builds and hosted screenshot registration are separate checks.
Local browser execution is not run in this environment; screenshots must come
from the registered hosted gate. Windows native provider/service-identity and
installation acceptance remain deferred until the Admin-data work is complete.
No fixture or cross-build establishes a host grant, native run or published release.
