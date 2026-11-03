# Read-only manager readiness evidence

Source candidate alongside the lean roadmap's first epic. This does not replace
`manager-setup doctor`, change startup, or establish deployment/native acceptance.

`GET /api/manager/readiness` uses the existing operator session boundary on the
configured LAN operator surface. Shared sessions and named read accounts can read
it. TLS (or the separately acknowledged HTTP-test profile), exact Host/Origin,
canonical path, session lifetime/revocation and no-store rules remain unchanged.
No anonymous, development, agent-ingress, HEAD or mutation route is added.
`/api/health` remains its independent static process-liveness response.

## Exact scope

The versioned response identifies its scope as
`core_reads_and_last_worker_steps`. HTTP 200 / `status: ready` means only that all
**configured checks in this bounded view** currently have the following evidence:

- The restore-quarantine boundary permits inspection. This is not proof against
  restoring an old, structurally valid database or replacing an entire host.
- Existing operator/trust/enrollment core tables can be read through the actual
  open pools. Protected path identity is checked, including before/after reads, against
  the identity captured during source preparation (enrollment: store opening).
  These checks do not decode every retained row or validate the whole ledger.
- Every certificate in the already-loaded presented server chain is in its
  validity interval. The configured enrollment issuer/root pass the existing
  pure public-authority validator at the current time. No private-key access,
  signing, credential issuance, filesystem reload or TLS handshake is attempted.
- Each configured Linux/Windows/macOS inventory loop completed a recent bounded
  maintenance **step** successfully. These components use `state: succeeded`, not
  whole-worker healthy. Linux selects one dynamic device/domain slot; Windows
  has subwork that runs only every fifth tick. Success in another slot does not
  prove that an earlier failed domain recovered or that a complete sweep passed.
- Each configured Linux/Windows health monitor completed a recent full iteration
  without an evaluation error. This says the evaluator ran, not that endpoints
  are healthy, their retained evidence is fresh, or an incident recovered.

The response also lists unassessed areas: full store integrity, write capacity
and durability, complete maintenance sweeps, optional provider workers, and
native/release acceptance. External alarms, application checks and proactive AI
retain their existing dedicated status/authority contracts. This endpoint does
not call providers, inspect targets, grant scopes, or make those systems ready.

Absent optional stores/workers are `not_configured`, not successful observations.
Configured workers are `stopped` before entry/after exit and `starting` until an
actual completion callback. Errors, including busy/deadline results suppressed by
warning throttles, produce `failed`. Successful later steps are reported only as
steps, without a claim that other slots recovered. Original completion times are
retained; GET never refreshes them. Future/old completion evidence is `stale`.
Inventory-step age limits are 5 seconds (Linux/Windows) and 2 minutes (macOS);
health-iteration age limits are 90 seconds. Any configured unknown, starting,
stopped, stale, failed, busy or timed-out check produces HTTP 503 / unavailable.
Missing readiness wiring also produces unavailable, never a default green result.

## Read-only and shutdown bounds

Each admitted request uses one shared 500 ms context budget for existing SELECTs.
There is one nonwaiting probe slot per manager. Concurrent callers receive busy;
there are no background probes, detached timeout goroutines, canary writes,
writer-admission transactions, schema initialization, maintenance calls, repairs,
new credentials, listeners, permissions, metrics exports or host changes.

A database driver or filesystem operation can overrun cancellation. The budget
is a cancellation request, not a hard OS interruption guarantee. The occupied
slot stays occupied until that synchronous operation returns. The existing HTTP
request drain retains stores and the manager writer lease during an unfinished
handler, including cancellation/shutdown. No readiness-probe join is inserted
before bounded HTTP shutdown. The session is checked again before returning a
slow result; expiry/revocation cannot receive that result.

Only fixed component/state labels and check times are returned. Device, actor,
path, target, fingerprint, SQL error, telemetry, provider and secret values are
not included. No repair action is available from this status read.

## Verification boundary

Focused local unit/API/component tests cover SELECT-only behavior, missing/closed
tables, private-state byte preservation, path replacement, issuer exact expiry,
authentication/revocation/canonical paths, single admission, cancellation and
request-drain ownership, real loop completions/errors and stale worker evidence.
No browser, native endpoint, load/scale, deployment or release acceptance is
implied. The minute-long macOS step remains unexercised by the lean tests; its
cancellation and configuration boundaries are covered.
