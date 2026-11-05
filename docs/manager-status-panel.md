# Operator manager status panel

The authenticated LAN **Investigations** work queue includes a compact **Manager
status** panel in English and German. It starts closed. Opening it reads the
existing private `GET /api/manager/readiness` once; **Refresh manager status**
deliberately reads it again. There is no background polling or automatic retry.
The panel does not change the manager, endpoint, credentials, grants or settings.

## Readiness and certificate evidence

The panel displays the existing [bounded readiness contract](manager-readiness.md):
core store reads, loaded public-authority checks and the original completion time
of each configured inventory/Health worker. `ready` is shown as **Recorded checks
passed**, never an overall endpoint, fleet, deployment or production verdict.
Absent optional components remain **Not configured**. Starting, stopped, failed,
timed-out, stale and busy evidence remain distinct from successful work.

HTTP 503 with the exact versioned unavailable response is useful evidence. Its
component rows and loaded certificate dates are displayed rather than discarded
as a generic network failure. Busy and missing-source fallbacks cannot become an
empty successful roster. Malformed, partial, unknown-field, contradictory or
oversized responses are withheld. Other HTTP error bodies are never displayed.

The three loaded public certificate roles are the presented server chain,
enrollment issuer and enrollment root. Their original validity intervals and
30-day/seven-day warnings are shown separately from the readiness checks. The
server-chain interval is the intersection of its loaded certificates. Missing
certificate reporting is **Current validity unknown**, not **Not configured** or
no warnings. Dates do not prove trust, connectivity, a TLS handshake, possession
of a private key, credential reload or successful renewal.

The expanded limits list the five areas the API does not assess: full store
integrity, write capacity/durability, complete maintenance sweeps, optional
provider workers and native/release acceptance. One successful inventory step is
not a complete sweep or proof that another failed domain recovered.

## Original times, age and access

The original manager read and component completion timestamps are never restamped
by rendering, refreshing an unchanged manager clock or closing/reopening the
panel. Successful snapshot evidence becomes stale after five seconds, or sooner
if a worker's original freshness bound expires. Certificate confidence becomes
unknown after five seconds; its original dates remain visible as historical
metadata. Passage of time cannot turn a not-yet-valid certificate into an
accepted current certificate. A fresh manager read is required.

The client carries a conservative elapsed-time floor across reads and remounts
within the existing protected request epoch. A stalled or slowly advancing
manager clock cannot renew old confidence. Manager rollback or browser
wall/monotonic-clock disagreement withholds evidence. Retained snapshots are
cleared at two minutes, or sooner at the session's original expiry.

Reads use one exact same-origin path, session cookies, no-store, no redirects, a
32 KiB streaming byte cap and a ten-second client deadline. Only valid HTTP
200/ready or 503/unavailable schema pairs are accepted. The server continues to
authorize each request, including its final session check after slow reads.

Closing the panel aborts its read and clears its values. Access invalidation,
logout intent, navigation, blur, page hiding and visibility loss also clear the
snapshot and prevent delayed responses from restoring it. Returning focus or
restoring a page permits deliberate refresh, without an automatic new read.
Changing actor/session/route retains the existing work-queue remount boundary.
No local storage, download, export, provider call or external delivery is added.

## Focused verification

From `web/`:

```sh
npm run typecheck
npm run test:environments
npx vitest run src/manager-readiness-model.test.ts src/manager-readiness-panel.test.tsx src/incident-timeline.test.tsx --maxWorkers=1
npm run build
```

These are model/transport/DOM component fixtures and production compilation, not
browser or native acceptance. They cover exact contracts, unavailable source
evidence, original times and certificate boundaries, streaming byte limits,
session/epoch invalidation including in-flight bodies, close/remount, manual
refresh, stalled/rollback clocks, source aging, visibility/navigation and EN/DE
states. They neither establish deployment nor waive the existing release gates.
