# Windows incident notifications

This source-only manager increment connects existing Windows contact, system-volume
capacity, CPU, physical-RAM and selected-service episodes to the **already configured
public HTTPS webhook**. Recipient setup remains in Settings → Alarm setup. No
recipient, credentials, host grant or external delivery is provisioned by this change.
Linux Health, AI admission and their v1 alarm/status contracts stay unchanged.

## Explicit source approval

The collapsed fleet **Windows notifications** panel shows retained Windows delivery
counts and one device/check selector. A shared administrator reviews the exact
original identity, check, current destination host and bounded payload, checks an
initially unchecked approval, then confirms. Named accounts can read, including
named alarm administrators; their existing capability does not grant this separate
Windows source permission. Source approval never enables a health policy, collector,
service action or destination. Every source starts off.

Approval binds the original device ID, invitation, immutable issued-certificate
anchor, exact domain and current destination binding. Same-identity leaf renewal
preserves it. A replacement identity inherits neither policy nor queue. Changing or
re-enabling the recipient produces a fresh destination binding; old Windows source
approvals become ineffective until explicitly reviewed again. Source revisions
advance on every successful change. Disable consumes queued work; no pending work
is transferred to another recipient or resurrected by re-enabling.

Enabling never scans or broadcasts retained episodes. Only newly created evaluator
transitions can create delivery intents, in the same SQLite transaction as the
unchanged source ledger. Disk, CPU and RAM may all use the same local incident ID;
original identity, domain, incident and original opening time are included in the
opaque episode key, and the transition distinguishes opening from recovery. Seen
acknowledgements never enqueue, close or recover an episode.

## Payload and outcomes

The transport uses `tracebolt.windows-alarm-event.v1` with the existing bounded
payload shape: event, device and local incident IDs; `windows-contact`,
`windows-disk`, `windows-cpu`, `windows-memory` or `windows-service` rule; fixed
source target or the exact selected service name; warning severity; opening or
recovery, fixed reason, original observation and manager transition timestamps.
No raw telemetry, logs, inventory, hostname, IP, free-form text or identity anchors
are exported. Contact observation time is the original accepted report receipt;
its recovery means **reports resumed**, not endpoint health.

- A recovery requires an opening accepted by the provider under the same source
  revision and destination. An in-flight opening must finish first.
- Genuine reasons are `reports-resumed`, `within-policy`, and `running`.
  `policy-changed` is closure, never recovery.
- An opening that closes before sending is consumed. Unknown or stale evidence
  never proves recovery; an opening waits for a current qualifying evaluation.
- The dispatcher rechecks exact current enrollment under the existing enrollment
  lease, including the exact accepted report sequence/receipt, source policy revision,
  destination, retained episode, source evidence and
  trusted manager clock before claiming. Startup requires a fresh opening evaluation.
- HTTP begins only after the claim commits and releases storage/enrollment locks.
  A later disable, maintenance start or revocation cannot recall that request.
  Accepted and uncertain outcomes remain truthful; definite retry is stopped by
  an intervening source-policy or maintenance change.

`provider accepted` means HTTP 2xx, never human receipt. Windows counters are
separate from the unchanged Linux/test alarm status: pending, accepted, suppressed,
failed, uncertain and durable dropped gaps. Details are on demand; reads do not
prune, evaluate, send or change a policy.

## Maintenance really suppresses Windows dispatch

The existing bounded maintenance contract remains unchanged. Its current exact
original identity and either all domains or one matching domain now suppress newly
eligible Windows notification dispatch. Start also consumes queued matching work
atomically, and records a stop-retry fence for in-flight work. Opening/recovery
transitions during the window are retained as suppressed notification intents;
incidents, acknowledgements, source policies and evidence keep their original truth.
An early end or expiry never releases a backlog. A genuine recovery occurring after
the window can still notify for an earlier provider-accepted opening. The current
maintenance label has its original immutable deadline and ages away locally.

Maintenance does not affect Linux notifications or stop Windows collection,
evaluation, host activity or source history. It is not a recurrence calendar,
notification channel manager or generic automation framework.

## Bounds, storage and transaction guards

Policies are separate canonical records, at most 125 retained device/domain
records. This is a record bound, not a 25-identity storage bound; the private
projection offers five domains for each of at most 25 currently admitted identities.
Capacity exhaustion fails visibly without eviction. Policies never alter old v1
ledger bytes. The Windows outbox
is independent: at most 500 pending/in-flight and 1,000 total records. At capacity,
a durable dropped counter commits with the source transition rather than blocking
health evaluation. Terminal records may be pruned after 30 days during a new source
transition; accepted opening dependencies survive while their exact episode is
retained or their recovery is pending. Reads never prune, even when disabled.

The existing webhook worker/transport provides verified public HTTPS, public-address
checks, pinned DNS, no redirects/proxies, ten-second attempts, bounded definite
retries, terminal uncertainty and no automatic replay. The existing global two-second
send spacing is shared with Linux/tests; Windows adds a ten-minute opening cooldown
per exact identity/domain and a 24-hour queue lifetime. Startup marks in-flight
Windows work uncertain. The independent queues each retain their own existing-sized
bounds; their combined maximum is 2,000 records, 1,000 pending/in-flight.

GET `/api/fleet/windows-notifications` accepts no query/body and exposes only a
closed, bounded projection with a maximum 120-second authority deadline. POST
`/api/fleet/windows-notifications/policy` accepts exactly `key`, `revision`,
`enabled`, `destinationBinding`, `payloadAcknowledged`. Enable requires the current
binding and true acknowledgement; disable accepts neither. Both private API and
browser guard current sessions, same-origin JSON, CSRF, exact revisions, original
identity and clock. Recipient changes and send attempts are serialized against
source changes. The enrollment lease precedes the operator transaction; guards run
after connection waits and immediately before commit. Dispatch rechecks original
source freshness and queue expiry after its final SQL writes. Failed or uncertain saves
require a readback, never an automatic repeated write. Browser suspension, navigation,
logout or expired authority clears private data and pending review.

## Verification boundary

Essential fixtures cover default-off/no-backfill, independent colliding metrics,
contact/service recovery meanings, accepted-opening pairing, maintenance before and
during send, exact source/destination revisions, identity replacement, final authority
failure, restart uncertainty, durable capacity gaps and unchanged Linux/AI/v1 state.
Authenticated API and EN/DE component checks cover explicit review, read-only named
access, request guards, interrupted private views and no uncertain POST replay.

Source and fake-transport checks establish no actual webhook delivery, native Windows
collection, installed service, credentials, host action or browser pixels. Ordinary
hosted CI/screenshots and separately authorized live recipient acceptance remain
separate gates. Restore older databases with delivery disabled and reconcile the
receiver before re-enabling; the outbox cannot prove restore-safe external deduplication.

## Complete-generation service source

The separately opted-in [complete-service notification bridge](windows-complete-service-notifications.md) adds a compact explicit Complete source choice. It reuses this Windows outbox and transport with separate canonical approval and tagged v2 episode/payload identities. Existing preview source approval, five-domain v1 API and old keys remain unchanged.
