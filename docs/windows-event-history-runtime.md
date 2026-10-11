# Bounded Windows event-history runtime

Source candidate only. This change does not authorize native host reads, local
scope grants, service operations, privileges, installation or release acceptance.
The existing recent-header sample and selected sampled-message scope keep their
original encodings and authority.

## Separate explicit local authority

The new scope is `windows-application-system-event-history-v1`. Its independent
`tracebolt.windows-event-history-consent.v1` requires both historical-header and
selected historical-message risk acknowledgement. HTTP-test also requires the
plaintext content warning. Messages may contain credentials, personal information
and other secrets. There is no Security channel, free-form query, source paging,
subscription, remote Event Log session or native permission expansion.

The source CLI uses the existing owned, stopped, activated inventory service:

    windows-service --event-history-preview
    windows-service --event-history-enable --apply --application-system-event-history-and-messages
    windows-service --event-history-disable --apply

An HTTP-test identity additionally needs `--insecure-http-test`. Preview is
nonmutating. Complete scope and HTTP warnings must be written successfully before
any enable operation. No operation starts or restarts the service.

The create-only protected sibling `-event-history` has a purpose-specific root
manifest and consent plus separate `reports` and `consumption` stores. Both
ledgers initialize before enabled consent. Missing used child records,
ambiguous writes, foreign identity, denied access and partial initialization fail
closed. Disable retains identity and replay floors; explicit re-enable rotates
only its grant. Existing sampled-content or twenty-scope setup receipts cannot
be decoded or promoted into this scope.

## Fresh Setup receipt12

Fresh Read admin now uses exact consent v14 with 21 ordered scopes and outer
receipt 12. Its new seventh disclosure group explicitly covers bounded
Application/System history and sensitive selected historical messages. The
approval checkbox remains initially unchecked and names the sensitive-message
risk. Separate HTTP and automatic-renewal approvals remain unchanged.

A new compatibility route `/v1/windows/read-admin-setup-capabilities-v10` returns
`fresh-twenty-one-read-admin-scopes-v1`. Every older advertisement, ordered scope
set, consent and receipt encoding remains exact. In particular v13 remains its
historical twenty scopes and receipt11. No existing installation or used
extension root is adopted. Before writes, fresh Setup checks all 19 extension
roots, including `-event-history`, for actual absence. The service stays disabled
until its activated original identity, all 20 extension grants and their exact
digests have been verified. The history digest verifies both independent ledgers,
not just consent. The existing protected receipt, identity and stopped-service
guards surround each scope operation. Interrupted setup retains evidence and
does not reset, regrant or start automatically.

## Serialized request and isolated worker

The current one-shot and foreground Windows sender runs a bounded history stage
with capability, peek, claim, isolated worker and result delivery. This stage has
its own monotonic capability sequence and exact pending metadata. It adds no
historical rows or message text to ordinary telemetry or sender diagnostics.

The parent durably records its non-content claim attempt before requesting a
manager grant. The child validates actual creator PID/creation time, fixed owned
SCM identity, restricted LocalService token/service SID, protected executable and
configuration. It independently rereads original activated identity and exact
history consent, verifies the parent attempt, commits its independent consume
floor and successfully closes storage before the first source read. The creator
and local authority checks repeat around capture. Lost claims/results and process
restart never authorize another read.

The fixed private worker argument is `--internal-windows-event-history-worker`.
It uses the existing Windows creator guard and self-only orphan watchdog, no new
host token or source access. Parent deadlines, output caps, cancellation,
kill/reap, sanitized environment and bounded inherited-pipe cleanup retain the
selected-content worker contract.

Search selects one Application/System channel and one UTC interval of at most
seven days within thirty days before original creation, with optional numeric
level/event ID. Results are bounded to 100 headers and 256 KiB; an observed empty
result remains distinct from unavailable. Up to 16 exact accepted rows may be
selected once for message capture. The search receipt, original query and all
six event-header fields bind follow-up selection. Follow-up creation and all
retries keep the original fifteen-minute expiry. Source truncation and retention
loss remain explicit; this is not proof of complete retained history.

## Memory, renewal and verification

At most one canonical result is held in endpoint process memory until its
original expiry. Result retries use exactly retained bytes, never source rereads.
Disable, replacement, terminal rejection, expiry, backwards time and shutdown
clear the slot. Metadata floors contain no native headers or messages.

The local sender binding and certificate authority remain the original immutable
renewal anchor. Transport uses the current activated leaf. Renewal neither adds
history to an earlier profile nor refreshes query, result, capture or receipt
ages. Actual activation joins the foreground sender and its worker; interrupted
memory-only results keep consume-once/result-lost behavior.

Focused portable fixtures cover new/old consent separation, missing used state,
ambiguous commit, independent exact retries, claim and result loss, restart,
empty search, selected-message original expiry, creator substitution, renewed
current leaf versus stable original authority, fresh receipt12 and failed scope
setup. These are synthetic source tests, not native Windows or installed-service
acceptance. A separately approved exact-artifact native gate is still required.

## Manager and private Logs flow

The independent `/v3/agent/windows-event-history/` capability, peek, claim, result
and status routes use their own proof domain and protected ledgers. The manager
stores only bounded request metadata and digest receipts in independent history
tables. An immutable per-credential used marker rejects missing used tables or
rows. It does not rewrite the old event-content application marker or grants.

Administrators use `/api/devices/{id}/windows-event-history`: GET status and
explicit POST `/create`, `/messages`, `/query`, `/cancel`. Create accepts one
channel and typed UTC bounds plus optional numeric filters. Messages accepts the
exact accepted search receipt and 1–16 selected channel/decimal-record pairs.
The same-session cache resolves all six accepted header fields, and the final
transaction independently checks the original receipt/report digest before
creating the next one-use request. New telemetry cannot reinterpret that search.
The followup preserves its original search creation and expiry exactly.

Manager admission resamples its trusted clock inside the SQLite transaction and
checks live credential, original expiry and server-derived session again before
commit. Current TLS leaf resolution preserves the immutable enrollment anchor,
local grant and durable floors. Maintenance uses the current credential without
substituting it into scope identity. Receipt publication precedes private memory;
exact delivery retry cannot repopulate lost bytes or create a new native read.

The compact English/German Logs search form explicitly names UTC. Status, row
count, captured-only filter and ten-row paging use accepted memory. Only a
separate checkbox selection and sensitive-message acknowledgement triggers
historical messages. Row details do not trigger reads. Navigation, visibility,
logout, identity replacement and original expiry discard private state; an
interrupted message-create cleanup cancels the exact predecessor search and
reconciles any replacement without resubmitting creation.

An exhausted or empty query is not retained-log completeness. Cap/partial,
denied, budget, stale, unavailable and lost-result states remain explicit. No
record-gap, unchanged-log, health or security conclusion is inferred.

The registered hosted browser runner is
`tests/e2e-review/windows-event-history-runner.mjs`. It requires eight genuine
production-UI screenshots: search and selected messages, English/German,
1440/390 pixels. Its intercepted invented transport is disclosed; screenshots
are UI fixture evidence, not manager-store or native Windows acceptance. Local
browser execution is not part of this source validation. Native Windows
Application/System reads, installed identity, publisher rendering, lifecycle,
and actual endpoint-to-manager acceptance remain separately authorized gates.
