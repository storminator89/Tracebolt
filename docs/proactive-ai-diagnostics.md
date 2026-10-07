# Proactive health diagnostics: first bounded increment

This is a **default-off, manager-side** workflow for existing activated Linux
health incidents. It adds background AI suggestions from narrowly scoped stored
health evidence. It does not yet search or export logs. No production provider,
customer telemetry, API key, endpoint permission or host action was used to
validate this change; tests use invented fixtures only.

## Operator experience

1. Configure the existing OpenAI-compatible provider. Saving does not contact it.
   Literal loopback servers remain supported; a loopback URL does not prove that
   inference stays local. Public providers require the existing exact HTTPS
   origin/credential rules. Optionally choose protected restart-safe storage as
   described in [AI settings persistence](ai-settings-persistence.md); saving a key
   requires its own explicit storage choice.
2. Expand **Proactive AI diagnostics**, select enrolled devices, review the exact
   saved URL/model and data categories, and explicitly approve future analyses.
   Only the authenticated shared LAN administrator can change this first scope;
   named read/maintenance accounts cannot grant AI export.
3. New eligible health incidents can trigger one background analysis without an
   open browser. Existing incidents from before approval are not backfilled.
4. Investigations show saved suggestions and original evidence times. Reloading,
   paging or opening a result never runs inference. Hypotheses remain unconfirmed;
   an evidence reference validates identity, not causal or logical support.
5. Disable the scope to cancel current work and stop future runs. Changing or
   clearing the provider, model or key also invalidates the scope. Provider and
   scope settings reset to off after manager restart in memory-only mode. With
   explicit protected provider storage, the approved scope survives an ordinary
   restart with its original approval time. Historical local findings
   remain subject to current device authority and retention.

## Explicit data boundary

The new `health-summary-v1` permission is independent of manual case analysis,
local agent collection approval and alarm destination approval. It covers only:

- A stored deterministic health incident: rule kind, event ID and original times
- Its typed check snapshot at admission: selected service unit name (where
  applicable), root-filesystem percentage or missing-contact state, source/time
- Fixed explanatory text and server-owned read-only runbook suggestions

The two evidence IDs are `health-event` and `health-snapshot`. Event confirmation
is **not** an archived series of raw readings. The snapshot is the observation
available when the attempt is admitted, not necessarily the opening sample.
Offline report timestamps stay old and are labeled stale.

No device name/ID/IP, free-form operator note, journal message, process command
line, dump content, unrelated telemetry or user-controlled prompt is copied.
Credential-like service-name markers are masked defensively; this is best-effort
pattern masking, not anonymization or a comprehensive secret detector. Service
names can expose application information and are explicitly disclosed in scope.

The existing `BuildPacket` rejection of managed operational profiles is unchanged.
`AnalyzeHealth` uses a separate typed builder; it does not relabel managed evidence
as basic telemetry. All model inputs remain untrusted data. Model output has no
permission to fetch context, invoke tools, issue shell commands or remediate.

### Raw logs require a separate future increment

The disabled raw-log option explains that existing local journal consent does
not authorize sending contents to an AI provider. A future implementation needs
an independently reviewed, exact provider/model/device/unit/time-window grant,
retention and redaction policy, bounded query/result contract and cancellation
revalidation. It must preserve the endpoint's original local journal grant and
cannot silently enable collection, widen service allowlists, convert dump access
into log access or reuse this `health-summary-v1` approval.

## Bounds and durable behavior

- One global active AI call, shared with manual analysis
- At most six background attempts per rolling hour; at least 60 seconds between
  attempts; 30 minutes per-device/rule cooldown for later incidents
- At most one attempt per device/incident, independent of provider changes,
  readbacks, failures or restart; no automatic retry/fallback
- Existing 24 KiB packet, 64 KiB request, 16 KiB findings and 1,024 requested
  completion-token limits; default provider timeout 15 seconds, maximum 30
- At most 250 locally stored attempts, 32 KiB public record each, 30-day evidence
  read retention, with local cleanup at startup and at least hourly while the
  health worker runs; an old open incident keeps its private consumed-attempt marker
- Bounded investigation response: 50 cards and at most 2 MiB, with the original
  final enrollment-authority and session rechecks

Expired results are hidden immediately from reads. Routine SQLite cleanup is not
secure erasure of filesystem snapshots, backups or previously retained WAL pages.

The SQLite claim commits before contacting the provider. A crash leaves an
interrupted attempt after restart, not an automatic replay. Provider errors and
invalid citations are explicit states without invented findings. Reads are
SELECT-only. The model loop is independent of health evaluation, so provider
latency cannot stall deterministic checks or recovery tracking. Current enrollment
authority is checked before export and again before publishing the result;
expired/revoked scope and provider changes discard the result. Already transmitted
bytes cannot be recalled. Client cancellation does not prove upstream inference
or billing stopped, and request caps do not guarantee a provider's price.

Recovery is recorded atomically with the health incident, without another model
call. Monitoring stopped is never called recovery. Existing alarm delivery sends
its already approved opened/recovered **health-event** payload only. AI prose and
log content are not added to an existing webhook permission. AI completion is
visible in the dashboard; this increment does not add a separate external
AI-result notification destination.

## API

Authenticated LAN only:

- `GET /api/ai/proactive`: current session-only or explicitly saved scope, exact configured provider,
  available device IDs, hard limits and `logsAllowed:false`
- `POST /api/ai/proactive`: exact revision/config revision, enable/disable, selected
  device IDs, exact approved URL/model, `dataScope:"health-summary-v1"` and an
  explicit acknowledgement; same-origin/CSRF and administrator checks required
- Existing `GET /api/investigations`: optional durable `analysis` on each card

No API request may supply replacement evidence, prompts or an inference URL.
Disabling remains possible when the device data source is unavailable. A repeated
or stale settings write conflicts rather than replaying approval. The scope is
not a production persistent-access grant made by a repository update. Optional
restart-safe storage requires the separate explicit choice above.

## Verification limits

Go fixture tests cover explicit scope, authority loss, provider changes, default
inertness, durable claim/rate/cooldown/restart behavior, recovery, redacted input,
strict evidence IDs and SELECT-only reads. Frontend tests cover current settings,
explicit confirmation, stale/uncertain writes and durable citation rendering.
These checks do not establish actual model quality, real provider compatibility,
customer log diagnosis or a deployed manager/agent acceptance result.
