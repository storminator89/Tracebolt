# Linux selected health checks and incident history

This manager-side slice uses observations already accepted for an activated
Linux `managed-operations-v3` enrollment. It requires no new endpoint collection,
permissions, service account, shell command or agent-side consent. Existing
endpoint collection limits remain unchanged. It is not a full health assessment.

## What it checks

- **Contact:** no newly accepted telemetry for more than two minutes starts a
  one-minute pending period. A device with no accepted observation stays unknown.
  Duplicate delivery does not refresh contact. Recovery requires one minute of
  fresh contact while the manager is evaluating.
- **Root filesystem `/`:** the existing agent-visible `statfs(/)` allocation
  percentage opens an incident after advancing fresh samples at or above 90%
  span two minutes. Recovery requires samples at or below 85% spanning one
  minute. This is root-filesystem allocation, not every mount, physical-disk
  health, or available space including reserved-block behavior.
- **Explicit services:** the operator may name up to eight `.service` units.
  Fresh complete service observations with an observed `inactive` or `failed`
  state open an incident after two minutes; observed `active` for one minute
  recovers it. Missing units, unknown runtime state, failed collection and stale
  generations remain unknown. Merely being enabled does not mean running.

The fixed 30-second manager loop runs even when the dashboard is closed. Pending
transitions require consecutive evaluation and advancing original measurement
samples. Confirmation starts when the manager first evaluates the condition;
delayed samples cannot credit an earlier maintenance or disabled period. Transport
delay and the 30-second tick can lengthen confirmation. Re-reading one snapshot
does not earn duration. A manager gap longer
than 90 seconds, a clock rollback, or unknown data resets pending transitions.
Existing open incidents remain unresolved until recovery is actually observed.
Events missed while the manager is stopped cannot be reconstructed. These
selected checks do not change the existing device contact badge into overall
health.

## Operator controls

The device's **Health & history** tab shows check state and original observation
times, current and recovered incidents, and acknowledgements. Acknowledgement
records that the incident was seen; it neither resolves nor repairs it. Each
condition has at most one open incident; a later new failure starts a new one.

Maintenance windows are bounded to 15 minutes, one hour or four hours and can be
ended early. They suppress new incident openings; existing incidents remain
visible and can recover from measured good data. Suppressed time does not earn
alert duration after maintenance expires. Removing a monitored service closes
its incident as **monitoring stopped**, never as recovered.

Health state is persisted in the existing protected `operator.db`, separately
from enrollment credentials and telemetry. History retains at most 100 incidents
per device; resolved history older than 30 days is removed on evaluation. Open
incidents are preserved. At most the existing 25-device pilot limit is stored.
No external notification, automatic remediation, update installation or agent
command is sent. There is no timeseries archive of raw telemetry.

## API and authority

Only the authenticated operator surface exposes:

- `GET /api/devices/{id}/health`
- `POST /api/devices/{id}/health/acknowledge` with `incidentId`
- `POST /api/devices/{id}/health/maintenance` with `minutes` (0, 15, 60, 240)
- `POST /api/devices/{id}/health/services` with an explicit `services` array

Mutations retain same-origin, session lifetime and CSRF checks. Reads and writes
check current activated device authority. Revoked/expired devices expose no
health history through this surface. Source/storage errors preserve the last
persisted incident history; a stopped evaluator becomes unknown in the view.

## Acceptance and limits

Automated tests cover duration, repeated samples, hysteresis, one-open-incident
behavior, acknowledgement, recovery, source failure/staleness, explicit services,
maintenance expiry, manager/clock gaps, durable reopen, concurrent mutation,
current enrollment authority and operator session/CSRF boundaries. UI tests cover
validation, controls, interrupted reads, device/session changes and failures.

A useful target-host acceptance, when separately authorized, is to observe fresh
normal readings; stop and restore a deliberately monitored disposable service;
verify one incident, acknowledgement and measured recovery; then verify a bounded
maintenance window. Do not fill a production filesystem to test this feature.
Native deployment, VM/systemd acceptance, unattended fleet behavior and external
notifications are not established by source/fixture tests.
