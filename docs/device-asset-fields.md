# Device asset fields

The Windows device Overview includes a compact **Asset details** card for three
manually maintained values: asset tag, location and warranty end date. They are
manager-owned organizational information, not endpoint telemetry. This fills a
small part of the manual device-information use case described in Datto RMM's
[user-defined fields documentation](https://rmm.datto.com/help/en/Content/3NEWUI/Devices/UserDefinedFields.htm).
It does not implement Datto's agent population, script variables, fleet targeting
or arbitrary user-defined field types.

These current structured values are separate from chronological handover notes.
No hardware identifier, location or warranty date is inferred or collected from
the device. A date is a manually entered civil date, not verified warranty
coverage, an expiry alert or a device-health verdict.

## Simple explicit editing

- Read the saved values in the device Overview. An empty field is **Not set**.
- A shared administrator selects **Edit**, changes the fields, and explicitly
  saves the complete form. **Cancel** discards only the unsaved draft.
- **Clear fields** empties the draft. Saving is still required. This clears the
  current values, not their retained previous revisions.
- Do not enter passwords, credentials or other secrets. Existing authenticated
  readers of the manager can read these values; customer labels are not tenants.
- The asset tag accepts at most 80 UTF-8 bytes and location at most 160 UTF-8
  bytes. The optional date must be a real calendar date in `YYYY-MM-DD` form.
  Values are not silently trimmed or truncated. Control and format characters
  are rejected.

The current slice applies to admitted Windows inventory original identities.
Linux, macOS and manual-certificate profiles are not supported by this slice;
separate Rust Basic compatibility is not established.
It reuses existing Windows authority and cross-source identity-exclusion leases;
it does not change enrollment, host permissions, collectors or local consent.

## Private manager boundary

`GET/POST /api/devices/{agent_id}/asset-fields` is an authenticated, no-store
resource. POST requires a live shared-administrator session, Origin/CSRF checks,
the exact reviewed revision, an expiring session-bound review and a unique
operation ID. Named operators remain read-only under the existing route rules.
No authorization allowlist is expanded.

The separate store binds data to the manager, transport/profile and original
issued device identity. Hostname changes and valid same-identity leaf renewal do
not reset the record. A replacement, revoked, expired, ambiguous or unavailable
identity cannot inherit or expose it. Admission does not assert that an endpoint
is online.

At most 100 original identities and 100 accepted changes per identity are
retained. Each change retains the complete previous/current revision chain and
immutable operation receipt in a canonical record, bounded to 256 KiB including
JSON escaping. There is no automatic eviction or quota recovery. Old field
snapshots remain private store data; this slice does not provide a history or
restore screen. Field contents are never added to telemetry, global Device
summaries, cases, exports, support bundles, AI inputs or notifications.

## Interrupted and concurrent changes

Concurrent saves use exact revision comparison so an old form cannot overwrite a
newer change. A failed request may already have saved its change. The explicit
**Check saved result** action performs a read only, never a replay. A matching
operation receipt confirms completion. Before the original review deadline,
receipt absence is still uncertain and further writes remain blocked.

After that deadline, a deliberate authorized read can establish absence under
the single-writer manager contract. Reads and mutations share the original
identity authority lease and a monotonic manager-clock floor tied to the lifetime
of the process-random signing key. A late writer cannot commit behind a terminal
negative read. A restart invalidates old review tokens. This is not a guarantee
for independent managers sharing a store or signing key.

The browser keeps only the pending operation ID, original identity correlation
and original deadline in session storage. Field values and draft contents stay
in component memory. Storage failure disables writes. Session, identity,
navigation, focus and visibility changes clear private views and drafts; ordinary
view expiry can preserve an unsent draft for an explicit same-identity refresh.
An uncertain submitted form is never restored as a new editable request.

Views have at most a 60-second original lease, bounded by credential and session
expiry. There is no polling or automatic write. Final identity, clock and session
guards remain required after waits and immediately before output.

## Verification boundary

Focused source tests cover strict values and civil dates, roles and routes,
identity replacement/renewal, expiry/revocation, revision conflicts, lost-response
reconciliation, bounded storage and multilingual editing. Browser automation,
native host execution, deployment and release acceptance are not part of this
source change. The existing capture-verifier regression is not modified or waived.
