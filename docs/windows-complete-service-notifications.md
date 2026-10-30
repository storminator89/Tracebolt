# Complete-generation Windows service notifications

This source-only manager feature extends the existing collapsed **Windows
notifications** panel with an explicit **Preview / Complete** source choice.
Complete notifications remain separately off until a shared administrator reviews
one original Windows identity, its current complete-service check names, the
configured public HTTPS recipient and the bounded payload, then checks the
initially unchecked sharing consent. Named operators can read only.

The complete health policy, endpoint collection grant and recipient setup remain
independent. The manager never grants endpoint collection or service control, and
existing preview notification approval never enables complete notifications.
There is no new delivery worker, recipient or channel.

## Exact approval and transitions

A separate canonical policy table retains at most 25 original identities. Approval
binds original device/invitation/issued-certificate identity, complete local grant
and revision, the reviewed complete-health policy revision, and recipient binding.
Same-identity leaf renewal preserves approval, while the active leaf is still
checked for each operation. A new grant, changed monitored names or any new health
policy revision requires a fresh review. Destination changes require fresh
recipient-bound approval. Replacement identities inherit no approval or history.
Records are not silently evicted when the identity limit is reached.

Enabling never scans retained incidents or broadcasts history. The existing health
transaction captures only newly created complete-service transitions. The episode
key is the complete inbox's separate v2 identity, including the opening grant,
original identity, incident ID and original opening time. The outbox also pins the
opening health policy revision. No v1 ledger, key or decoder is widened.

An opening needs fresh post-startup attention for that exact service. Recovery
requires an opening accepted under the same complete notification revision and
recipient, an actual running recovery under the same local grant, and a currently
fresh complete generation with a matching, freshly evaluated running check.
Recovery also waits for a post-startup evaluation. Unknown source never proves recovery. Policy changes
close health episodes without reporting recovery. Disabling consumes queued work;
re-enabling cannot release an old backlog.

## Shared queue, transport and maintenance

Complete and preview notifications share the existing Windows outbox: at most
500 pending/in-flight and 1,000 total records. The existing public HTTPS worker
provides global send spacing, verified HTTPS/public-address checks, no redirects
or proxies, bounded attempts and persistent uncertainty. Complete outcomes return
to the Windows counter/receipt path, never Linux alarm completion.

The v2 payload uses `tracebolt.windows-alarm-event.v2` and the
`windows-service-complete` rule. It includes only the existing bounded event,
device and incident IDs, exact selected service name, fixed reason, transition,
severity and original observation/transition times. Grant IDs, certificate
anchors, generation IDs, manifests and other inventory remain private. Exact
native names retain their 256 UTF-16-unit / 1,024 UTF-8-byte limit without
normalization. The existing 2,048-byte payload limit remains enforced; any
unrepresentable payload records a durable dropped gap rather than blocking
health evaluation.

Whole-device maintenance and the existing **service** maintenance scope both
suppress complete-service notifications at transition capture and claim. Starting
maintenance consumes queued matching work in the same operator transaction. An
in-flight request cannot be recalled: accepted or uncertain outcomes remain
truthful, while definite retries stop. Ending maintenance never releases backlog
or changes incident truth. Accepted openings remain retained dependencies while
their exact complete incident remains retained, including incidents open longer
than the ordinary 30-day notification retention.

## Final authority and private API

The claim adapter selects only the queued service's exact complete row and uses
the actual complete-service enrollment lease. The inbox acknowledgement lease is
insufficient because it deliberately permits unavailable source. Original identity,
current leaf, exact local grant, current complete generation/manifest and original
capture/receipt stay pinned through the operator transaction. Source freshness is
five minutes, evaluation freshness is 120 seconds, and actual clocks are checked
after SQL waits and final writes. No storage lock spans HTTP I/O.

Missing fresh source waits conservatively. A bounded 30-second queue deferral lets
other eligible Windows work proceed without creating a retry or extending the
original 24-hour queue lifetime. No unavailable evidence becomes recovery.

- GET `/api/fleet/windows-notifications/complete` has no query or body and returns
  `tracebolt.windows-complete-notifications.v1`.
- POST the same route plus `/policy` accepts exactly `key`, `revision`, `enabled`,
  `destinationBinding`, `payloadAcknowledged`.

The closed projection has at most 25 source-qualified targets with exact current
service names, health-policy revision, grant/revision, source actionability,
recipient and retained delivery counts. Original identity anchors remain private.
A changed scope receives a new opaque review key but retains the independent
notification revision. The old approval is visibly ineffective until deliberately
reviewed again. Retained approval can be disabled even when source is unavailable.
Reads never evaluate, enqueue, prune or enable anything.

Same-origin JSON, CSRF, live shared-administrator session, exact revisions,
current enrollment and bounded final clocks guard changes. The enrollment lease
precedes the operator transaction. The browser clears review on navigation,
logout, source switching or expired authority. Uncertain saves reconcile through
GET only; they are never automatically repeated.

## Verification boundary

Essential source fixtures cover independent approval/no-backfill, health/grant/
identity replacement, actual complete-source dispatch routing, final authority
failure, genuine accepted-opening recovery, maintenance, durable uncertainty,
shared capacity/retention and Go JSON payload bounds. Recorder API fixtures use
temporary SQLite and synthetic authority only. EN/DE components consume a
Go-generated closed wire fixture. Hosted synthetic changed-view capture remains
a separate CI gate. These checks do not authorize or establish real notification
delivery, recipient credentials, Windows native collection, host installation,
service grants, ACL changes, deployment or release.
