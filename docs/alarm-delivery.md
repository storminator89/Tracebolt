# External alarm delivery: default-off pilot slice

This optional manager-side slice sends a small JSON event to one explicitly
configured **public HTTPS webhook**. It is a generic Tracebolt protocol, not a
Slack/Teams adapter. No recipient, credentials or external service is provisioned
by an upgrade. SMTP, browser recipient administration, test-send/replay actions,
per-rule maintenance and a delivery UI remain unimplemented.

## Activation boundary

Omitting `--alarm-config` means no alarm worker, DNS lookup or external request.
The existing health evaluator, authentication and collection permissions stay
unchanged. Enabled delivery requires guided enrollment with the complete Linux
collection profile and the configured manager identity. The development manager
and manual-v1 manager have no alarm sender.

An administrator must separately approve the exact destination and the outgoing
data, then provision a private local configuration and optional bearer-token
file. Configuration requires an explicit `enabled: true` and
`payloadSharingAcknowledged: true`; existing operator login, acknowledgement or
maintenance permissions do not enable sending. There is no send/configuration
HTTP endpoint. Restart the manager to change or disable configuration; removing
the startup argument disables delivery and suppresses unsent queued work.

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
Counts include retained previous destination generations. No URL, token, provider
body or raw error is exposed. UI presentation and per-event reconciliation remain
pending; operators must inspect the authenticated status during this pilot.

Changing the exact endpoint, manager/profile, destination ID or generation changes
the binding. Old unsent jobs are suppressed, never redirected. Bearer rotation
alone preserves the destination binding. If a bearer change also changes the account
or intended recipient behind the same URL, the administrator must change
`destinationId` or `generation` as well; the manager cannot infer that provider
relationship from a token. Ordinary restart with the same enabled
binding preserves definite queued retries; uncertain work remains terminal.

## Verification and separate live gate

Deterministic fake transports and in-memory connection fixtures cover atomic
rollback, disabled/no-outbound behavior, restart, deduplication across devices,
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
