# Windows accepted-contact history

This source-only slice adds a separate manager evaluator and a read-only Windows
Health panel. It does not generalize Linux health inputs, investigations, AI
exports, or device-level health claims. Existing Windows system-volume readings
remain neutral and quota-aware; event headers retain their separate sample,
consent, quality, capture, and expiry boundaries.

## Evidence and lifecycle

The source is the authenticated manager's original accepted report receipt and
sequence for one current guided Windows identity. Inventory capture time, GET
time, retry time, endpoint clocks, ping, and live reachability are not contact.
A repeated GET or duplicate telemetry retry never renews acceptance.

- A receipt age at most 120 seconds is recent.
- An older receipt begins a pending period. Sixty seconds of continuous manager
  evaluation opens one overdue-report incident.
- Once open, fresh accepted reports must stay recent for 60 seconds of continuous
  evaluation before recovery. The incident retains its original opening receipt
  and sequence, last overdue confirmation, and separate recovery receipt,
  sequence, and resolution time.
- No accepted report is unknown. Missing authority, manager restart, clock
  rollback, or a gap over 90 seconds resets transition waiting periods. A stale
  evaluator (over 120 seconds) makes current state unknown. Unknown never means
  recovered and does not close an incident.
- The store retains at most 100 incidents. Recovered incidents are retained for
  30 days; an open incident is retained until recovery. Source-only storage tests
  do not establish deployed persistence or installed-service acceptance.

There is no offline determination, Windows disk threshold, new native read,
automatic alarm delivery, notification, acknowledgment, maintenance workflow,
AI call, investigation creation, or remediation in this slice.

## Narrow operator read

GET `/api/devices/{id}/windows-contact` is isolated from Linux health APIs. It
requires current operator authorization and matching guided Windows authority.
The API rechecks authority after reading history. A changed guided identity or
certificate binding fails closed before history is exposed; there is no automatic
history transfer, identity replacement, or renewal. Its closed response contains:

- `schemaVersion: tracebolt.windows-contact-view.v1`, `deviceId`, `serverNow`
- `status`: `unknown`, `recent`, `pending`, or `overdue`
- `lastAcceptedAt` and numeric `sequence` (null and zero when none)
- independent nullable `evaluatedAt` and future `certificateExpiresAt`
- bounded `incidents` with `wcontact_` plus 16 hexadecimal digits for ID,
  `kind: overdue-report`, `openedAt`, `lastConfirmedAt`, original
  `lastAcceptedAt` and numeric `sequence`, nullable `resolvedAt` and
  `recoveryAcceptedAt`, and numeric `recoverySequence` (zero while open)
- recovered rows alone include `closedReason: reports-resumed`

Current source acceptance can be newer than the last evaluator pass. That tuple
is shown with unknown current state until evaluation catches up. The frontend
requires a usable future certificate expiry and rejects nullable expiry rather
than borrowing authority from an old inventory response.

## Browser protection and display

The endpoint is requested only from the selected Windows Health tab for a real
LAN device, one supported manager-owned identity capability, guided certificate
metadata, and an authenticated timestamped session. Metadata refresh/failure or
access loss hides the private history. The dedicated GET has a 64 KiB response
limit, a 10-second timeout, and one request at a time; visible reads poll at 15
seconds. Query parameters, filters, and action submissions are unnecessary.

The EN/DE panel shows the original receipt and sequence separately from manager
evaluation time. An open row can remain visible with unknown current state while
current read authority is valid. Browser aging only removes confidence: it never
opens or resolves a durable incident. If a recent receipt passes 120 seconds
before a new evaluation arrives, current state becomes unknown.

Strict parsing rejects mismatched IDs, unexpected fields, impossible dates,
future times, invalid sequences, malformed incident lifecycles, and excess rows.
Request-start elapsed time includes response delay. An isolated, bounded,
in-memory clock map retains only time watermarks across refresh, failure, blur,
and remount. Frozen/tiny manager-clock progress cannot renew observations; wall
and monotonic clock divergence or manager rollback fails closed. No private
history is cached in that map or browser storage. Session/certificate expiry,
refresh errors, abort, blur, hidden pages, and navigation discard visible data;
late responses cannot restore it.

## Verification boundaries

Portable tests use explicitly invented manager records, including EN/DE states,
original-time boundaries, pending/open/recovered/no-report cases, stale evaluator
history, delayed responses, repeat GETs, remount, clock regression, metadata
failure, expiry, access loss, and the separate volume/event composition.

`tests/e2e-review/windows-contact-history-browser.mjs` supplies one bounded,
source-only hosted-browser case for an existing authorized loopback fixture. It
covers EN/DE at 1440/390 pixels, repeated original receipts, evaluator expiry,
retained open history, and denied-read clearing; writes/external requests and
unexpected device routes are rejected. Its companion Node tests validate the
invented fixture and source safeguards without launching a browser. The bounded case is composed into the existing Windows browser runner, with
its existing login, write/external-request rejection, and finite stage reporting.
No browser case was run in this source-only slice. Browser/native Windows/deployment acceptance remain
separate gates. No publication or permission change is authorized by these tests.
