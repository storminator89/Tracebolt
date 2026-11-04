# Opt-in local application incidents

This manager-side source feature turns existing completed HTTP/HTTPS, DNS and TCP
checks into a separately enabled local incident workflow. It performs no extra
probe, changes no destination permission, and sends no external notification or
AI request. It is not endpoint Health, proof of application correctness or an
uptime/outage-duration report.

## Complete operator workflow

Open **Local application incidents** in the existing Application checks panel.
Only opening or explicitly refreshing reads saved local status; there is no
polling, one-shot check, network test or automatic write retry.

An existing shared administrator or named `manage_application_checks` operator
can select one or more currently enabled check IDs, choose two or three
consecutive completed failures, review the exact current source, and explicitly
approve local retention. Ordinary named read access receives redacted status and
history but cannot enable, replace, disable or mark incidents seen. Enabling local
incidents never enables or changes the underlying probes.

The workflow supports both browser-managed configuration and an explicit startup
configuration file. The latter still controls the probes as a read-only startup
snapshot; local incident policy does not modify or override it.

A qualifying failure sequence creates one open incident per selected target.
Two consecutive successful completed observations confirm observed recovery.
**Mark seen** only records acknowledgement. It does not recover, repair or hide
an incident. **Disable local monitoring** ends its open incidents as **monitoring
stopped**, never recovered. Replacing/re-enabling a policy deliberately ends the
previous monitoring period, retires its open incidents and starts confirmation
again from fresh samples. The review discloses that consequence.

## Evidence and missing data

Failures are the existing fixed HTTP status, TLS verification/handshake or network
failure outcomes. HTTP 2xx, a permitted DNS resolution or a successful TCP connect
is only that check's observed success from the manager. A failed check can reflect
manager DNS, routing, firewall or trust rather than a target fault. Verified
certificate-expiry labels remain the separate existing TLS observation; an
approaching expiry alone is not an availability failure.

Only the original fully completed, uncancelled check result can count. Status
reads, recent-history reads and manager restart never replay samples or earn
confirmation. Start/completion timestamps retain their original meanings;
confirmation occurs at the final qualifying completion. No response body,
destination, address, port, certificate subject or arbitrary error text enters
this ledger.

Unknown/blocked destinations, stale or repeated samples, frozen/regressed clocks,
missing observations and gaps reset pending confirmation. They never recover an
existing incident. Freshness is measured from the original observation **start**
using the unchanged probe freshness formula, not from later persistence or API
reads. A legitimate completed result queued behind a newer read is checked using
a fresh trusted clock after serialized storage admission, not rejected merely
because that read advanced the durable clock floor.

Current observations are separate from retained incidents. After restart current
state is unknown and confirmation counters restart, while an existing approved
policy may resume only for the identical source definition. The original open
incident survives until actual confirmed recovery or a monitoring-end decision.

## Source identity and lifecycle

Human check IDs alone do not identify a source. The private binding includes the
manager/origin/profile, exact immutable configuration and, for managed settings,
the saved generation. External startup mode uses an exact configuration digest,
not the literal word "external". The digest and destinations are never returned
to read clients. An opaque per-monitor runtime token plus policy revision fences
every control review, including mark-seen requests.

A saved configuration change or disabled probes retires the previous local
policy. Same-named replacement targets cannot inherit its pending samples or
open incident. Retained rows explicitly identify whether they belong to the
current source. Disabled sources do not disclose their saved-but-never-enabled
target list to read clients.

Completion persistence runs synchronously in order after the original probe and
outside monitor/status/settings locks. It has a two-second local-write budget;
stop/disable joins that bounded work. It opens no storage transaction during
DNS, TCP, TLS or HTTP I/O. Local persistence may delay later sequential work, but
never lengthens original evidence freshness, adds a catch-up burst or retries a
probe. With no enabled local policy, per-result storage work is skipped.

## Persistence, bounds and uncertainty

A separate bounded ledger in the existing protected `operator.db` stores only
policy metadata and fixed incident evidence. Untouched installations persist no
incident row until an explicit local control. Constructors and reads cannot
silently opt in. Existing probe settings/audit, device incidents, AI approvals and
alarm outboxes remain separate.

At most 128 incidents are retained. Open incidents are protected. Terminal
history expires after 30 days, with oldest terminal rows also removed when
capacity is needed; omissions are explicit. If clock rollback made a monitoring
end time unknowable, it remains null and eventual retention uses the last
original completed evidence. No fabricated closure time is written.

Corrupt/noncanonical data, genuine storage failure or an uncertain commit blocks
only local incident persistence until a manager restart validates saved state.
A singleton used-marker committed with the first control detects a missing
ledger row across restart; row/marker mismatch is unavailable, not a fresh setup.
Restoring an entire older database/VM snapshot is not cryptographically detected
and requires operator review. It never silently resets known state or starts
another probe. A cancelled read or
hook that never entered a write does not permanently fence the component.
Underlying separately authorized checks retain their own normal lifecycle.

Writes carry an exact source token, revision, request ID and operation-specific
fields. The browser sends each once. An exact saved last request can reconcile
its outcome; absent evidence is not proof of failure. A later verified revision
or changed source token can fence a delayed old submission without claiming its
original result is known. A new action still needs a distinct explicit review.
Changing session, hiding, blurring or leaving removes private snapshots/reviews.

## API and verification

The authenticated operator-only `GET/POST /api/application-checks/incidents`
uses separate `tracebolt.application-incidents.v1` metadata. Existing status v1/v2
and recent-observation history contracts remain unchanged. Controls preserve
existing administrator capability, same-origin, CSRF, active-session and source
leases. Reads may normalize source retirement, runtime gaps and retention, but
never create an incident from a read or trigger a check.

Focused tests cover source fingerprints/runtime tokens, no added probes,
completion ordering and stop/join, original-start freshness, threshold/recovery,
unknown/gap/clock behavior, corruption rejection, capacity/retention, durable
restart, CAS/reconciliation, cancelled DB admission and blocked storage. Real
loopback TLS API tests cover permissions, framing, source changes and privacy.
EN/DE component tests include actual Application-panel integration and the real
Go DTO fixture. These fixtures do not establish browser, deployed-manager,
real-target or external-provider acceptance.
