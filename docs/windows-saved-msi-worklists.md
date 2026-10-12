# Saved exact MSI worklists and deliberate batches

Source candidate only. Existing grants, signed permits/reports, native execution,
retirement and shared mutation-owner checks remain authoritative. No MSI, NTFS,
SCM, host service, key, permission, ACL or installation acceptance is established.

## Save, then choose each stage

A freshly initialized reusable-v3 manager can save one active worklist for the
current completed reviewed payload. Save freezes its full review, content identity
plus custody occurrence, exact registered target bindings and descriptive group
snapshot. Device names and group membership confer no authority. A changed
identity or A → B → A payload occurrence cannot replace the saved references.
Existing matching assignments are captured on Save; a separately delivered later
assignment is not silently adopted. Save and reopen issue no permits.

Each deliberate stage previews and enumerates its own eligible individual requests:

- Deliver authorizes separate delivery requests to the listed original bindings.
- Review records a separate package/terms, LocalSystem/custom-action, synchronous
  action and bounded maintenance review for each listed imported assignment.
- Approve pins each listed assignment's exact fresh readiness digest and deadline
  and authorizes one installation there. It never approves a later-ready device.
- Review package cleanup pins each listed settled result and authorizes removal
  of only that endpoint's app-owned package copy through the existing retirement
  permit. Its fresh unchecked acknowledgement is separate from installation and
  from Close batch, which only stops unsent requests.

One clear confirmation covers the enumerated requests in that stage. The browser
sends them sequentially in the foreground through the existing per-device API.
It never starts the next stage, retries an installer, refreshes readiness or resumes
a confirmed list after reload. The same actor, initiating session, original
session expiry, original binding/grant/current leaf, stage acknowledgements and
exact occurrence/transfer/grant-wide job sequence remain required at issuance.

The batch expires at most 60 seconds after confirmation and no later than its
original item deadlines or session. Readiness remains 60 seconds; maintenance
remains at most ten minutes. All 25 approvals may not fit one readiness window.
Review the remaining eligible devices again explicitly when their previous
readiness request has expired. Previously confirmed acknowledgements never become
standing or deferred permission.

Cleanup eligibility requires an attempted known-return result: success, verified
restart-required (3010), busy (1618), or known failure. Unknown return, 1641,
not-attempted, uncertain registration and unverified 3010 remain excluded. The
exact signed shared-owner status must be active, unblocked and idle, with capture
age less than 60 seconds. The cleanup batch deadline uses the original grant,
current time and that reviewed status's freshness, never an old install permit's
expiry. Issuance still rechecks current authority and all original retirement
guards. Each item pins its exact result digest, original binding, transfer,
grant-wide job sequence and payload occurrence. Other stages omit the new
retirement-only digest, preserving their canonical bytes and confirmations.

## Stop and uncertainty

Stop sending remaining requests serializes through the same enrollment-store
transaction as issuance. If an item committed first its exact permit and job link
remain; if Stop committed first a late item is rejected. Stop never cancels an
issued permit, a claimed installer or native work. A foreground interruption stops
further requests. Reopening reads the journal and existing evidence; it does not
resume or close a batch automatically. An unconfirmed POST is reconciled with GET,
not retried. Close the remaining open batch deliberately before a new confirmation.

The journal and existing MSI job mutate atomically. There is no separate execution
ledger, worker, scheduler or package cache. Each row distinguishes not dispatched,
permit issued, claimed/unconfirmed, result recorded and payload retired. Native
result and registration truth remain separate: 0 requires verified registration;
3010 is restart-required; 1618 and known failures are consumed non-success outcomes;
1641, unknown return, lost result, registration/cleanup uncertainty and unresolved
shared ownership remain attention states. Historical outcomes cannot make an
unavailable or revoked device currently successful. Missing retained exact
transfer/job evidence is unavailable, never reconstructed from a package hash.

Archiving changes presentation only. It neither closes an open batch nor retires
payloads. Batch cleanup uses the existing explicit per-device result-bound
retirement. Shared payload retirement remains a separate unchecked control,
available only after all assigned exact jobs have signed retirement reports.
Failed and restart-required results remain visible after endpoint cleanup; cleanup
does not turn them into successes. Abandoned imported work can still strand the single payload slot under
the original contract; this feature adds no native cancellation or cleanup path.

## Create-only state and bounds

Fresh reusable-v3 setup initializes a versioned protected manager metadata row and
an immutable reciprocal setup marker in the existing enrollment database. Existing
singleton/v2 and older v3 metadata are not migrated or promoted. An old unmarked
registry remains on its prior per-device path. A marked registry with missing or
contradictory worklist state fails closed; startup/GET never rebuild it.

The manager retains at most nine worklists, one active and eight archived, with
at most 25 targets and nine batches per worklist. Each saved record is at most
256 KiB; the aggregate metadata body is at most 2.25 MiB plus 4 KiB envelope within
the unchanged 192 MiB database ceiling. At capacity, archival/save can discard the oldest archived list only when every
assigned exact job has verified retirement evidence. New stage confirmation may
compact a closed batch only when its issued requests are reconciled by the exact
signed MSI records: imported delivery, reported or safely superseded readiness,
or retired installation. A cleanup batch additionally requires its exact signed
retirement evidence and reviewed result digest, or the same result and signed
retirement digest retained by the existing job ledger. Permit issuance or a
settled result alone never permits cleanup-batch compaction.
Target references and every execution/replay ledger stay
unchanged. Missing or uncertain evidence blocks compaction. Revisions never reset,
pruned IDs fail closed, and no native cleanup or automatic archival occurs. These
are retention bounds, not lifetime operation limits.
The unchanged payload limits are one 128 MiB manager copy and one separate
128 MiB copy per delivered endpoint, with at most 25 configured devices.

## Private API

- GET /api/windows-managed-msi/worklists lists existing records and availability.
- POST /worklists/save freezes reviewed current metadata and target bindings.
- GET /worklists/{id} reconciles one exact saved worklist.
- POST /worklists/{id}/preview reads eligibility without issuing a permit.
- POST /worklists/{id}/batches records one explicit exact stage confirmation.
- Existing reusable per-device delivery/review/approval/retirement bodies may add the strict
  batch reference: worklistId, batchId and zero-based item, in that canonical order.
- POST /worklists/{id}/close requires current revision and exact batch ID.
- POST /worklists/{id}/archive requires current revision and no open batch.

All routes are private named-operator HTTPS endpoints with existing session/CSRF
fences. Stage dispatch still requires the separate delivery or install capability.
Old per-device request and signed wire formats remain unchanged. Hosted synthetic
EN/DE desktop/mobile captures and source tests are not native runtime acceptance.
