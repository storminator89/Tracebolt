# Linux network counter interval investigation

The existing device **Inventory → Preview → Network** panel includes a read-only
**Network counter interval** investigation in English and German. It uses the
already-authorized Linux operational source and its existing protected GET. It
adds no endpoint collection, background poll, grant, API, persistent history,
notification, AI transfer, export or action.

## Choose and compare original observations

1. Choose **Use current network observation as baseline**. This copies only its
   bounded network rows and original source references into component memory.
2. After a later ordinary agent report, use the existing **Refresh observations**.
   A repeated original sample waits instead of manufacturing another interval.
3. Review matched interface names, original capture and acceptance times,
   generation and sequence, each observation's original coverage/reason/count/cap,
   and the interval between their original source timestamps.
4. Replace or clear the baseline deliberately. Filter names with literal,
   case-insensitive text, limited to 160 characters. These controls make no
   requests, start no capture and write no storage.

The current observation must be a fresh, strict-validated latest snapshot with
healthy network rows and unique names. The native source deliberately does not
collect interface addresses/counts and therefore reports **partial coverage**;
this remains usable without being relabeled complete. Capped/truncated source
rows remain bounded samples. Retained `lastGood`, denied, stale, unknown,
unsupported and missing latest sections never supply current comparison evidence.

Matching names and counters describe only the received rows. A name present in
one observation alone is not proof of addition/removal, even with complete
visible-namespace coverage. No whole-host count, network total or all-clear is
inferred. Both observations retain their original coverage independently.

## What the arithmetic means

For each name present in both observations, received/sent bytes and RX/TX errors
are subtracted only when both endpoint counter values are known. Zero remains
zero. A missing endpoint value remains unknown. Any decreasing counter withholds
all differences for that name; a changed MTU does likewise. No wrap/reset or
replacement is guessed. Each row exposes both original counter endpoints in a
local disclosure so the arithmetic and unknown values can be checked. Up/down/unknown states describe each endpoint observation,
not the intervening interval.

The source has no boot ID or immutable interface ID. A name match does not prove
continuity, even with positive counters and unchanged MTU. Reboot, reset, rename
and replacement cannot be excluded. Changes per second divide byte differences
by the original observation-timestamp interval; timestamps identify the source
snapshot, not individual interface read instants. Rates are rounded to six
significant digits. They are arithmetic comparisons, **not verified throughput,
bandwidth utilization, continuous activity, packet loss or a health verdict**.

The original interval must be between one second and one hour, inclusive.
Nanosecond source precision is retained for ordering, bounds and displayed UTC
references. Subsecond intervals withhold rates. Nonadvancing or inconsistent
sequence, generation, original capture/receipt or device references clear the
baseline. Every new response is also checked against the most recent eligible
source, so a regression cannot hide behind an older baseline. An expired interval
requires selecting a new baseline, without an automatic replacement.

## Clock, session and privacy boundaries

Freshness includes conservative request latency and an advancing monotonic
manager-time floor across successful reads. Repeated or slowly advancing manager
timestamps cannot repeatedly renew old confidence. Nanosecond future/expiry
bounds are checked independently of millisecond display helpers. Regressing or
invalid manager/monotonic clocks withhold the network investigation for that
mounted device session. Reopen the device view after resolving a clock problem;
repeated refreshes do not repair the comparison automatically.

An ordinary explicit refresh keeps the baseline but withholds comparison while
its current source is unavailable. Source read failure, invalid response,
denial, duplicate names, stale current evidence, navigation, session/device
change, authentication loss, hidden/background suspension and page exit clear
the baseline. Late interrupted responses cannot restore it. Current evidence
aging out clears the baseline; refreshing before that point can compare later
fresh observations without making the baseline itself a current-state claim.
Nothing survives the mounted device/session scope or enters browser storage.

## Focused checks

Run from `web`:

- `./node_modules/.bin/vitest run src/network-interval-model.test.ts src/network-interval.test.tsx src/operational.test.tsx src/operational-security-review.test.tsx`
- `npm run typecheck`
- `npm run test:environments`
- `npm run build`

Model and React DOM tests use synthetic strict DTOs matching native partial
coverage. They cover original times, nanosecond edges, bounded rows, null/zero,
counter resets, MTU changes, partial coverage, literal/inert text, repeated
refresh/replace/clear, request interruption, source/session loss, clock floors
and original-source regression. These are not browser/native acceptance or
end-to-end installed-service/deployment evidence. No browser tests are required
or run for this feature.
