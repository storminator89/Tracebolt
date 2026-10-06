# External alarm delivery: default-off pilot slice

This optional manager-side slice sends a small JSON event to one explicitly
configured **public HTTPS webhook**. It is a generic Tracebolt protocol, not a
Slack/Teams adapter. No recipient, credential or external service is provisioned
by an upgrade. SMTP, per-rule maintenance and event replay remain unimplemented.

## Browser setup and activation boundary

Settings contains a collapsed **Alarm setup** panel beside the retained read-only
**Alarm delivery** counts. Browser setup is available only on the Linux guided
manager with the complete collection profile. A new installation starts disabled:
construction, status reads, saving and startup validation perform no DNS lookup,
provider contact or automatic test. Once enabled, the existing worker may send
future qualifying health transitions. Existing incidents are never backfilled.
The development and manual-v1 managers have no alarm sender or setup authority.

The existing shared administrator can configure alarms. Named accounts require the
new explicit `manage_alarms` capability; `read`, update and service-action grants do
not imply it. Named readers can still inspect sanitized settings and status.
No upgrade modifies an operator file, creates an account or grants a capability.
All writes use the current session, exact Origin/Host, CSRF token, strict JSON and
an expected settings revision. Stale approvals and changed destinations are rejected.

- **Add/replace destination:** enter the complete new URL (up to 4096 ASCII bytes)
  and explicitly approve the bounded payload below, then save and enable. The URL
  is write-only, with a password-style field, no browser persistence and no response
  echo. Only the destination host is displayed afterward. Blank input cannot erase
  or reuse a destination. This MVP has no bearer-token entry field.
- **Disable:** explicitly confirm. The saved URL remains private for later use;
  queued work is suppressed. Messages already accepted cannot be recalled.
- **Enable:** review the retained host and explicitly approve future payload sharing
  again. Replacing or re-enabling creates a fresh generated destination generation;
  old unsent work and unpaired recoveries are not redirected to it.
- **HTTP-test:** the separately opted-in isolated test profile additionally requires
  an explicit acknowledgement that entering the URL exposes it and any embedded
  secret on the browser-to-manager plaintext connection. Public webhook requests
  still use verified HTTPS. Production HTTPS remains the supported default.

Managed settings live in `alarm-settings.json` under the existing protected manager
state directory, mode 0600, with trusted ancestors and no symlinks/hardlinks. This
uses the existing writable state volume, including standard read-only-root Compose
setups; it never writes under the read-only `/run/tracebolt` configuration mount.
Atomic temporary-file write, file sync, replacement and directory sync happen before
outbox activation. Settings changes and send attempts are serialized; an in-flight
attempt returns a busy response to changes, and every attempt is followed by a full
two-second idle window. No session mutation gate is held during provider I/O or a
request-body read. A failed/uncertain persistence step stops dispatch and marks the
controller blocked. A bounded best-effort emergency stop also suppresses queued
work; it does not invent an approved disable or modify the saved file. The status
API cannot report delivery enabled while the controller is blocked. Review the
state before restarting: startup reconciles whichever file was durably published
and may resume that previously approved delivery choice.
A missing managed file starts disabled; malformed or insecure files fail startup.

Only fixed action, server-derived actor, revision and time enter the bounded local
settings audit (latest 200 records). The protected file retains the last mutation
and enabling approval. Startup idempotently reconciles that mutation with the
outbox/audit transaction, including after a crash between file and database commit.
Neither audit nor public settings/status contains URL paths, queries, bearer values,
provider response bodies or raw errors. Protect backups containing this private file.

## Existing CLI configuration and precedence

Supplying `--alarm-config` takes precedence, even when that file explicitly disables
alarms. Its configuration remains externally managed and read-only in the browser;
UI changes and test sends are unavailable. The manager does not edit that supplied
file or any optional bearer-token file. Restart to change an external file.

The CLI override leaves a previously saved browser configuration untouched.
**Removing the flag resumes that saved browser choice, which may be enabled.**
Removing it is therefore not a universal disable command. To keep delivery off
while switching modes, retain an explicitly disabled CLI override, or explicitly
disable browser-managed delivery after switching in an appropriately controlled
maintenance window. With no saved browser destination, removing the flag starts off.

An administrator must separately approve the exact CLI destination and outgoing
data before provisioning private configuration and optional bearer-token files.
Explicit `enabled: true` and `payloadSharingAcknowledged: true` are still required.

The startup flag is `--alarm-config /absolute/protected/alarm.json`. A safe,
minimal disabled file contains:

```json
{"schemaVersion":"tracebolt.alarm-delivery-config.v1","enabled":false}
```

An enabled file additionally requires:

- `payloadSharingAcknowledged`: true only after approval of the payload below
- `managerInstanceId`: exact existing enrollment manager ID
- `profile`: exact existing `tls` or explicitly acknowledged `http-test` profile
- `destinationId` and `generation`: distinct administrator-chosen identifiers,
  one to 80 ASCII letters, digits, underscores or hyphens
- `endpoint`: exact HTTPS URL, port 443 only, without user information or fragment
- Optional `bearerTokenFile`: absolute path to separately provisioned token material

The configuration and token files must satisfy existing LAN protected-file
ownership, ancestor and no-symlink rules with private permissions (0600/0400).
The endpoint can itself contain a secret. Do not put it or token material in
source control, logs, chat, screenshots or diagnostics. Configuration formatting
is redacted; URLs and secrets never enter the outbox or status response.

Only public addresses are allowed. Loopback, private LAN, link-local, multicast,
unspecified and special-purpose ranges are rejected, including DNS responses
containing a mixture of allowed and blocked addresses. Private relays require
separate future design; there is no implicit private-network exception. Each
attempt validates DNS once, pins the dial to one numeric address and verifies TLS
against the original hostname using normal trusted roots. Environment proxy
settings and redirects are ignored/blocked. An HTTP-test manager still sends
alarms only over verified HTTPS. No production TLS bypass exists.

## Payload and meaning

`tracebolt.alarm-event.v1` contains event/device/incident IDs; rule and target
(agent, root filesystem or exact monitored service name); fixed `warning`
severity; `opened` or `recovered` transition; event state and fixed reason;
original observation time and manager transition time. IDs are generated from
manager/destination binding, device, incident and transition. There are no raw
logs, process/package dumps, hostname/IP inventory, free-form notes or credentials.
Times describe the event, not a promise about current endpoint state.

Health state and its new delivery intent commit in the same SQLite transaction.
Exact evaluator transitions are captured before bounded UI-history pruning.
Enabling delivery never broadcasts existing incidents or historical recoveries.
Repeated observations and acknowledgement do not create another message.

- A queued opening that recovers before a definite send is suppressed.
- A recovery is sent only for an opening accepted by the provider. If recovery
  happens during an in-flight attempt, it waits for that attempt's result.
- An uncertain opening remains uncertain; its recovery is not automatically sent.
- Removing a monitored service suppresses an unsent opening. It does not fabricate
  a recovery or send a closure message.
- Existing device-wide maintenance continues suppressing new local incidents.
  Queued openings are suppressed during maintenance. An accepted opening can
  still produce one genuine recovery. Expiry starts normal confirmation from fresh
  observations; no maintenance-history broadcast is created.
- Missing/stale observations or lost authority block queued openings; they never
  fabricate a healthy recovery. Existing health debounce/hysteresis is unchanged.

## Delivery states and bounds

`provider_accepted` means an HTTP 2xx response was received. It does **not** mean
that a person received, read or acted on the event.

A worker claims one immutable record, releases the database transaction, sends,
then commits a result bound to that attempt. There is at most one request in
flight per worker, a ten-second request deadline, a persisted global minimum
spacing of two seconds and a ten-minute opening cooldown per device/rule. A
continuing latest outage can send after cooldown; recovered intermediate flaps
are suppressed rather than flushed.

Definite pre-send DNS/connection/TLS failures and an explicit HTTP 429 rejection
can retry with one-, two-, five- and fifteen-minute delays, up to five attempts.
Unanswered requests after a TLS connection was handed to HTTP, HTTP 408/5xx and
restart with an in-flight claim become terminal `uncertain`. No implicit replay
of uncertainty, automatic HTTP retries, redirect resend or receiver-idempotency
promise exists. Other 4xx and redirects are terminal failures. Response bodies
are discarded with bounded reads and never saved as diagnostics.

Queued work expires after 24 hours. At most 500 pending/in-flight and 1,000 total
records are retained. Terminal records older than 30 days can be pruned, except
accepted-opening dependencies still needed by incident history or queued
recoveries. At capacity, health evaluation continues and a durable `dropped`
counter is committed with the health change. This is an explicit delivery gap,
not successful queuing. There is no automatic gap replay or remediation.

Authenticated `GET /api/alerts/status` returns only enabled and state counts,
including `inFlight`, `providerAccepted`, `failed`, `uncertain`, `suppressed` and
`dropped`. Named read accounts can inspect it. POST is not a send operation.
Counts include synthetic tests and retained previous destination generations. No URL, token, provider
body or raw error is exposed.

Settings also exposes a compact read-only **Alarm delivery** panel for authenticated
LAN accounts, including named read accounts. It shows retained provider acceptance,
pending (queued plus in flight), failed and uncertain counts; nonzero dropped gaps
remain separate. Disabled delivery stays quiet, while retained counts remain
visible. Details explain the individual states and retained-history limits.
Provider acceptance is never described as receipt by a person. These aggregate
counts cannot confirm any individual opening or recovery event.

The panel performs only the existing status GET on entry, explicit refresh, or
a confirmed local settings/test mutation. A local notification carries no state;
the panel cancels an older pending read and fetches actual counts through its
existing session, visibility and cancellation guards. No optimistic On/Off, polling,
automatic retry, send or configuration action is introduced. A failed follow-up
read keeps the prior snapshot marked previous with current status unknown. Loading time is
labelled using the browser clock, because the API has no server observation time.
A failed refresh keeps the last valid snapshot visibly marked as previous, with
its original loading time and unknown current status. Session loss, navigation or
page suspension clears the snapshot and cancels its read; returning requires a
fresh read. Unknown or malformed responses never become zero counts.

Changing the exact endpoint, manager/profile, destination ID or generation changes
the binding. Old unsent jobs are suppressed, never redirected. Bearer rotation
alone preserves the destination binding. If a bearer change also changes the account
or intended recipient behind the same URL, the administrator must change
`destinationId` or `generation` as well; the manager cannot infer that provider
relationship from a token. Ordinary restart with the same enabled
binding preserves definite queued retries; uncertain work remains terminal.

## Explicit synthetic test and settings API

`GET /api/alerts/settings` returns only the settings schema/version, mode
(`managed`, `external`, `unavailable`), revision, configured/enabled/blocked flags,
destination host and last test ID/state/time for the current destination generation.
Unavailable surfaces return an empty disabled view; they have no write authority.
No polling occurs. Closing, navigation, suspension or session loss clears drafts and
invalidates pending responses. Any uncertain write requires an explicit fresh read;
there is no automatic retry after failure or reauthentication.

`POST /api/alerts/settings` accepts exactly `expectedRevision`, `operation`
(`replace`, `enable`, `disable`), `endpoint`, `payloadSharingAcknowledged` and
`plaintextAcknowledged`, with a 6144-byte body cap. Only replacement accepts a
nonempty endpoint; disable accepts neither acknowledgement. Fields never select
manager identity, profile, actor, token file or storage path.

**Test destination** opens a separate payload/destination confirmation. Its explicit
confirmation posts `expectedRevision`, a generated 128-bit `requestId` and
`testAcknowledged: true` to `/api/alerts/test` (512-byte body cap). It requires enabled
managed delivery. It queues one `tracebolt.alarm-test.v1` record using the existing
outbox, transport, bounds, retry and uncertainty rules. A repeated request ID resolves
to the same retained record. No endpoint URL is stored in that record. Only one
outstanding test and one new test per minute are allowed, globally across destination
changes; a full queue declines the test without dropping a real health event.

The test contains a generated event ID and timestamps, with fixed `synthetic`
device/incident markers, `delivery-test` rule, `configured-webhook` target, `info`
severity, `test` transition/state and `operator_requested_test` reason. It contains
no live device information. The claim path revalidates this exact synthetic shape;
it cannot submit a custom message or imitate an actual incident. Tests appear in
the aggregate delivery counters. Read their individual latest result with explicit
refresh; queued/in-flight is pending, and **provider accepted is not human receipt**.
Failed/uncertain/suppressed remain distinct, and uncertain tests are not replayed.

## Verification and separate live gate

Deterministic fake transports and in-memory connection fixtures cover atomic
rollback, disabled/no-outbound behavior, restart, browser configuration/secret redaction and permissions, explicit synthetic
test deduplication/rate limits, crash/audit reconciliation, deduplication across devices,
destination changes, bounded retry/rate/capacity, recovery ordering, long-lived
incidents/history pruning, maintenance, stale/unknown evidence, SSRF, redirects,
redaction, protected files and unchanged authenticated read-only access. These
tests do not establish provider compatibility, actual recipient delivery or host
installation.

Before live use, separately authorize one destination and its bounded payload,
provision required material securely, then approve a controlled synthetic
acceptance check and verify what the intended recipient observed. This repository
change itself performs none of those actions.

**Restore limitation:** restoring an older database cannot prove that newer events
were already accepted externally. Start restored managers with alarm delivery
disabled and reconcile with the receiver before re-enabling. Do not claim
restore-safe replay or exactly-once recipient delivery from this outbox alone.
