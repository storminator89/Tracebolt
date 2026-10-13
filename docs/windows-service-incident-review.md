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
