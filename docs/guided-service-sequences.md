# Guided reusable Linux service sequences

This frontend source increment reuses the existing default-off
[service try-restart workflow](service-action-workflow.md). It does not provision
or enable a helper, grant, key, operator or host. Its synthetic tests establish
neither native service execution nor a released deployment.

## One device, deliberate steps

The named operator can arrange up to eight distinct services from the existing
action controller's permitted service list. Adding, removing and reordering steps
does not send requests. The inventory is not used to invent eligible targets.

**Check and save sequence** deliberately requests one existing preview for the
first selected service. The response must still match every selected service's
original policy and, for v2, its exact affected-service set. It pins the preview's
device, actor, protocol/scope, root policy, command key, incarnation and transport.
The preview is then discarded, with no approval. This is temporary selection and
binding metadata, not a permit, durable runbook or source of authority.

**Review this step** requests a new preview using the same existing controller.
The pinned bindings and current service policies must match before the ordinary
review appears. The existing interruption warning, v2 effect scope, original
expiry and initially unchecked approval remain mandatory for every step. The
request and approval bodies are unchanged: `{unit}` and
`{previewId, previewDigest}`. Backend and root-local checks remain authoritative.

An attempted step tracks its exact preview ID, service and actor. Only a matching
`operation_completed` result with `outcome=completed` offers the next step, and
**Review next step** still requires a separate click. This means reported command
completion, not a verified restart, healthy service or transaction success.
Approved and claimed states wait. An expired, not-started, unknown, foreign or
intervention-required result stops the sequence; it neither skips nor retries.
The existing saved status and history controls remain available for reconciliation.

After all steps report matching command completion, **Start a new reviewed run**
reuses only the selected services and original bindings. Every new step needs its
own fresh preview and unchecked approval. Binding drift requires a newly checked
sequence rather than silently rebinding an old one. There is no aggregate consent,
automatic advance, rollback, schedule, background execution or arbitrary script.

## Privacy and interruption

Only one sequence lives in component memory for the current device, named actor,
session expiry and transport. It is not written to localStorage, sessionStorage,
a file, manager database, URL or external service. Reloading, leaving the view,
blur, page hiding, navigation, authentication/context changes, original session
expiry or an unreliable clock discards it. An interrupted step never resumes
automatically. A manual selection outside the active step detaches the sequence
and remains subject to the ordinary independent review.

The local deadline uses the existing controller's request-start timing evidence,
including response latency. Later status responses may shorten, but never renew,
that deadline. The original wall/monotonic clock is checked before new evidence
is incorporated; a new response cannot conceal an earlier clock discontinuity.

Discarding a sequence does not cancel an approved action or erase the existing
durable action ledger. Uncertain submissions continue to use that controller's
GET-only reconciliation and blocking behavior. The per-view completion references
are temporary UI context, not a second job ledger or complete audit trail.

## Verification boundaries

Fixture tests exercise multi-step execution through the real frontend resource
and API validation, separate consent, exact result correlation, policy/identity
drift, repeated clicks, interruption, late responses and memory cleanup. The
existing API, controller and history suites remain regression gates. Native
root-helper/systemd acceptance and complete hosted/browser checks remain separate.

Durable shared recipes, APT composition, conditional remediation, generic scripts
and unattended execution are separate future designs. They must not inherit
authority from this sequence or from read-only inventory.
