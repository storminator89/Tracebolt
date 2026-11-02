# Device capabilities and navigation (TB-20)

This is an operator-UI contract, not a new endpoint profile, host permission,
collection, native Windows acceptance or deployment. Capabilities describe
support/profile scope; independently validated source status describes local
configuration, accepted observations and failures. Neither is a grant command.
The public [Rust compatibility contract](rust-manager-compatibility.md) likewise
advertises compatibility, not Basic-only credential authority; TB-21 remains
separate. Existing Go Windows identities and versioned wire/consent bytes are
unchanged.

## Missing data is not one state

The Capabilities view has five separately named explanations in English and
German, each with a next step, and uses a cause only when the source establishes
it:

| Cause | Evidence and next step |
| --- | --- |
| Not supported | Explicit unsupported capability/source result. Check platform/profile/source support; selecting a capability cannot add it. |
| Not granted locally | Explicit reported disabled local scope/policy. Review only the needed new local scope, with unchecked consent. |
| Not yet collected | Explicit awaiting-first-generation or `not_collected` result. Check the existing agent/report; do not create another identity or replay a write. |
| Stale | Original capture/freshness/retention evidence, including elapsed time. Check existing connectivity; reading cannot refresh the capture. |
| Technical failure | Failed source/transfer or failed status read. Inspect the source-specific view and read status again; failure is not zero/empty/healthy. |

Permission denial remains separate from missing consent: an operator access or
OS/provider permission error does not prove that a local grant is absent.
`not_configured` can mean absent manager/profile setup and is **not** relabeled
as a missing local approval. Unknown/malformed status never proves an empty
inventory, support, consent or health. Pending transfer and partial field coverage
also remain distinct. Fixed help text never interpolates raw source errors.

The existing bounded, status-only readers keep original observation and session
deadlines. Refresh does not extend a stalled server clock or expired session.
The shared sequential-read deadline marks only unfinished sources as timed out;
a slow sibling cannot overwrite a completed source observation, denial or invalid
response. Retained observations still age from their original capture time, and
late responses to an aborted batch cannot replace its result.
The profile-scope label explicitly separates advertised support from local
approval and current collection. Existing private inventory views retain their
own source/grant/field coverage; the guide is not a claim that every listed cause
occurred on this device.

## Navigation preserves operations, not stale consent

Local Devices section jumps retain the original mounted modules, active controls
and uncertain enrollment dialog. Device/inventory source navigation can still
unmount private readers and cancel reads: no hidden inventory polling or retained
checked preview is introduced.

Windows service approval now records a bounded memory-only uncertainty fence
**before** submitting. It is keyed to device, actor, original session and
transport. Returning to Services reads status; only the original job ID,
sequence, actor, target and operation can reconcile it. Idle, unrelated or
unreadable status cannot enable a replacement approval. A late response after
unmount cannot overwrite the current view. Auth invalidation clears private UI
context. This fence does not survive a full page/process restart, is not durable
server authority and does not claim to recall an already delivered permit.

Package-update recovery intents retain their original request IDs while visiting
other devices in the same actor/session/transport context. The bounded store
never evicts uncertain work to create room for a new operation. Intent metadata
contains no token, full preview or source provenance; the manager's job remains
authoritative. Different actor/session/transport or auth invalidation clears that
context. Existing exact-not-found readback rules still govern an explicit
same-ID retry; generic 404/failed reads do not authorize replay.

Journal and selected Windows event-content requests also retain bounded,
memory-only uncertainty metadata across remount. This metadata holds only the
original durable compare-and-set floor or exact cancellation identity and session
binding: no units, selected event/provider labels, messages, queries or checked
consent. Unchanged idle status cannot clear an in-flight create. A validated
advanced durable floor proves that the old create precondition can no longer
commit; it does **not** attribute another operator's request to this UI. A cancel
needs its exact terminal request or a newer floor. Content stays cleared and is
not queried while cancellation is unresolved. Event-content disclosure cleanup
still attempts the existing bounded cancellation, without treating a failed
cleanup as success or allowing old cleanup to overwrite a newer fence.

Linux service control, Windows update/software jobs and managed-MSI worklists
keep their existing independent saved-status/fence contracts. These durable
mutation jobs are not cancelled or repeated by a capability display or navigation.
Private event-content/history captures instead keep their intentional disclosure
lifecycle cancellation on navigation; until its outcome is established, the
original request remains visibly uncertain rather than silently forgotten.
Unsubmitted
selections and checked consent are intentionally cleared when their scope is
invalidated; preserving those would be unsafe, not operation recovery.

## Existing reads and exact new consent

Reading already accepted inventory or a retained permitted capture does not
require another collection approval. New requests retain their specific existing
review: journal unit/window/severity, package identities and immutable plan,
service target/operation, or the exact independent local category. A new
acknowledgement is unchecked; changing target/source/operation or going Back
clears it. Capability display never sends a consent or action mutation.

Fresh Windows Read admin still uses **one combined approval for 21 scopes in
seven readable groups**, not 21 new dialogs. For that fresh-only installer the
whole explicitly listed set is new; existing installations/grants are never
adopted. Later optional categories/actions use their own exact opt-ins and keep
old receipts/scopes unchanged. The historical read-admin reconsent CLI previews
each existing scope and retains enabled hashes; this work does not add a general
GUI migration/scope-upgrade planner.

## Regression and integration evidence

| Acceptance | Source regression evidence |
| --- | --- |
| Five distinguishable causes and useful next steps | `capability-observations.test.ts`, `device-capabilities.test.tsx`: EN/DE labels, explicit disabled versus absent config, waiting versus unknown, safe failure display, elapsed freshness and session expiry. |
| Active/uncertain operations survive navigation | `devices-workspace.test.tsx`; `windows-service-actions.test.tsx` including actual Services → Hostname → Services pending approval and exact-job reconciliation; `package-update-workflow.test.tsx` including A → B → A recovery; `journal-api.test.tsx` and `windows-event-content-api.test.tsx` including unresolved remount/cleanup; existing service/update/software/managed-MSI recovery suites. |
| Capability display grants nothing | Capability UI read-only request assertions; `internal/enrollmentservice/capabilities_test.go`; `internal/api/rust_basic_capabilities_test.go`; existing independent authorization negatives. |
| Existing reads without reconsent; exact unchecked new scope/action | `journal.test.tsx`, package/service workflow tests, `enrollment-windows.test.tsx`; `internal/windowssetupui/read_admin_test.go`, `internal/lanclient/windows_capability_consent_test.go`, `windows_event_history_setup_test.go`, and `cmd/windows-service/read_admin_reconsent_test.go`. |

PR #113's head `ee941c81a1881378555ef4636157acd2488c7b88` is already an
ancestor of base main `f53f5cccd8c9613008bfecab5412475b872e0092`; its read-first
inventory and active-control implementation is integrated despite the stale open
draft metadata. Do not merge its old predecessor branch again. This increment
preserves those fixed inventory/control slots and their existing regressions.

The existing capability, package-update, journal, Windows service-action and
event-content/history browser recipes also exercise these display/remount paths.
They use explicitly synthetic DTO/transport faults, wait for completed status
reads before asserting a retained fence, and keep existing no-write/no-external
guards. Their normal automatic PR browser job must pass on the reviewed source;
inert fixture/source checks are not a substitute for executing those recipes.
No extra runner, workflow dispatch, screenshot requirement or relaxed timeout is
introduced by these amendments.

Source/DOM tests, real Chromium with explicitly synthetic API fixtures, native
endpoint execution and real Windows ↔ Linux manager ↔ browser acceptance are
different evidence classes. TB-19 onboarding measurements and native endpoint
gates are not established by this UI change; no release or host operation follows.
