# Exact Windows incident service review (source candidate)

The Windows incident inbox offers **Review service / Dienst prüfen** beside a
selected-service episode. A compact disclosure keeps the original incident in
view and reuses the existing selected-service controls. Opening it does not choose
an operation, create an action preview, approve an action, acknowledge the incident,
collect more data or grant endpoint permissions.

The disclosure separates retained incident lifecycle/times from the current
exact-name service observation. Recovered and policy-closed episodes keep their
original meanings. Unknown, absent, duplicate or stale current rows never mean
stopped. Current capture and accepted receipt timestamps remain original; browser
aging only withholds confidence. A reported service name cannot establish
continuity of the same SCM instance after same-name removal/recreation, executable
identity or application health.

## Identity proof and bounded read

GET `/api/fleet/windows-incidents/{opaque-key}/service-review` returns the closed
`tracebolt.windows-service-incident-review.v1` projection. The existing opaque key
binds device ID, original invitation, original issued-certificate anchor, source
domain, incident ID and opening time. The server resolves the retained episode,
verifies its complete original identity against current enrollment, and compares
the exact service name with the existing action binding. CPU, RAM and disk ID
collisions cannot become service targets. A same-ID replacement cannot inherit a
review; renewal retains the original certificate anchor but requires fresh current
credential admission.

Control is matched only for the existing named-operator Windows service control
capability and a separately configured, currently ready broker grant. Shared
administrator acknowledgement authority and observation consent do not confer
service-control authority. Missing grants, mismatched exact targets and unavailable
broker authority stay visibly blocked. Private invitation/certificate fields are
not added to the incident API, and unrelated grants are not exposed as matches.

The server uses the existing source-authority lease and final session/time checks.
The action status read is outside that lease because it owns a separate enrollment
transaction. This read may advance the existing durable action clock floor; it
creates no preview, job, permit, grant or host action. There is no new durable
review ledger. The response lease is bounded by current authority, 120 seconds,
and, when matched, the broker report's original readiness expiry.

## Preserve the proof through deliberate control review

An optional, single canonical `X-Tracebolt-Windows-Service-Review` header restricts
existing service-action status GET and manual-preview POST to the projected full
binding digest. The digest is SHA-256 over the domain
`tracebolt.windows-service-review-binding.v1` followed by a zero byte and canonical
JSON of the entire existing action binding. Endpoint, original incarnation,
manager/key, broker installation, grant, target and target digest are all pinned.
Malformed/duplicate headers or use on another route fail closed.

The server compares the expected digest inside the existing enrollment action
transaction before reading status or creating the independently requested preview.
A prior successful GET is not sufficient: replacement or binding drift before the
manual preview fails. The UI also compares the returned preview's full binding to
the pinned context before displaying approval. Existing strict v1 request bodies
and response schemas are unchanged, as are ordinary requests without the header.

The service selection remains initially unselected; the contextual operation
chooser is blank until the operator selects Start, Stop or Restart. Approval still
uses the existing exact preview ID/digest, named actor, original deadline and
initially unchecked confirmation. No incident header is accepted on approval: the
existing immutable preview contract owns that step. A status read never restores
an old preview or extends the incident-review lease. Generic saved-history reads
are not automatically opened from this contextual disclosure.

Closing, changing rows/filters, refreshing the inbox, navigation, visibility/session
loss, clock rollback or context expiry discards the private review. An expired
review must be deliberately reopened from a currently admitted incident. Nothing
is saved to browser storage, URLs, AI inputs or notifications. Local evidence age
and action authority remain separate.

## Source verification boundary

Focused inert Go fixtures cover opaque-key resolution, exact original identity,
renewal/replacement, binding pins, unsupported headers, source/authority expiry,
and the absence of preview/action creation on entry. The Go-produced wire fixture
is consumed by the TypeScript parser and component tests. EN/DE DOM fixtures cover
manual blank operation selection, independent approval, blocked grants, original
timestamps, stale/late responses and contextual status/preview constraints.

These are source and synthetic fixture checks. No browser, listener, native SCM,
service installation, credentials, permission change, grant, notification, deployment
or remote repository operation is established or authorized. Actual browser/layout
and native acceptance remain separate gates.

## Explicit complete-source v2 review

Complete-service inbox rows now offer the same deliberate **Review service /
Dienst prüfen** entry, through a separate GET
`/api/fleet/windows-incidents/complete/{opaque-key}/service-review` and closed
`tracebolt.windows-service-incident-review.v2` response. The old v1 route, decoder,
body, identity and behavior remain unchanged. V2 resolves only a retained
`service-complete` target; its opaque key includes the opening observation's
original local grant/revision in addition to the original enrollment and episode.
A legacy or sibling-domain key cannot cross into this route.

The current observation is read from the already-consented complete generation
for that exact historical name, even when a later policy no longer selects it.
Its original grant/revision, generation, digest, sequence, capture start/end,
final receipt, retention expiry and full row count remain visible in collapsed
provenance. This read neither evaluates nor writes service/incident/seen state.
A missing, stale, partial/failed or absent current source retains the episode with
an unknown observation; unavailable state fields are explicitly unknown. Missing
or duplicate rows never establish stopped or removed. The observation does not
assert continuity of the same SCM service instance or application health.

The read pins current original identity, active leaf and the present full
snapshot or explicit absence through the existing enrollment source lease.
Future-source absence is rejected rather than becoming eligible during a wait.
The actual post-wait and final trusted clock, operator session, credential, source
and broker deadlines must all hold before response release. Present-source age
is capped at five minutes from both original capture and receipt; the review
itself is at most 120 seconds and, when matched, the broker's original one-minute
readiness deadline. The action status read remains outside the source lease.

Full native names remain readable under their existing 256 UTF-16-unit /
1,024 UTF-8-byte contract. Control remains restricted to the unchanged 1–128 ASCII
application-service target contract and its critical-prefix exclusions. Unsupported
names return `unsupported_target`, expose no binding and do not call the action
manager. A supported target still needs named operator permission, a separately
configured ready grant, exact device/original certificate incarnation/name match
and the same immutable expected-binding status/manual-preview guard as v1.

Unknown observation intentionally does not invalidate an independently ready,
exactly matched service-control grant. It remains clearly unknown while the
operator may separately choose an operation, create a preview and explicitly
approve it. No operation is preselected and approval starts unchecked. The
incident creates no action permission, preview, job, permit or grant. There is
no automatic action or notification response.

Focused direct-recorder/temporary-SQLite fixtures and EN/DE DOM tests cover the
v2 handoff, native target rejection, current-source loss, renewal/replacement,
final lease boundaries, strict v1 isolation and separately approved preview.
The Go-exported wire fixture is consumed by the UI and hosted-only changed-view
capture source. Local `--check` performs in-memory bundling and fake route checks;
no browser is executed. Rendered browser, native Windows, release and deployment
acceptance remain separate gates.

The shared hosted Windows action gate asserts all five v2 states (read, selected
with no operation, preview with unchecked approval, unknown observation and
unsupported control target) in EN/DE at desktop/mobile sizes. Its canonical matrix
retains eight representative fixed-viewport images at normal text size. Every
request is intercepted: only one deliberately selected synthetic preview per
matched context is allowed, and approval is never sent. Focused PR and full
Validate tiers require the same exact source commit/tree, Go DTO, full compiled
input inventory, lock-bound dependency metadata, assertion manifest and exact PNG
names/dimensions/hashes. These contracts do not establish that hosted screenshots
or native acceptance have passed.
