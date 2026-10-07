# Optional restart-safe AI settings

The manager can now keep an explicitly saved provider and its separately approved
`health-summary-v1` scope across an ordinary restart. This applies to the existing
complete Linux enrollment manager only. Defaults remain off and memory-only;
upgrading or loading the UI does not migrate an old configuration, save a key,
contact a provider, or grant data access.

## One-time setup

1. In AI provider settings, choose the exact URL/model and explicitly select
   **Keep provider configuration on this manager after restart**.
2. A nonempty API key requires a separate explicit choice to save that key on this
   manager. Keyed persistence requires the HTTPS operator profile. The separate
   HTTP-test profile supports only keyless loopback persistence. Enter keys through
   the authenticated settings UI/approved secure handoff, never chat, CLI arguments,
   repository content or browser storage.
3. Saving does not contact the provider. Configure the separate proactive scope:
   select specific devices and approve the displayed provider/model/data categories,
   including continuation after restart. This is not a log-content grant.
4. Ordinary restart restores that exact validated configuration generation and
   original approval timestamp. It does not manufacture a new approval, backfill
   pre-consent incidents, replay interrupted attempts or test connectivity.

Leaving the persistence choice unchecked retains the original session-only mode.
Saving a memory-only replacement first durably removes the old saved provider and
scope, so an earlier saved configuration cannot reappear on restart. Any provider,
model or key replacement invalidates the proactive scope and requires a new data
approval. Clear removes the saved provider/key and scope; disable durably stops
only the proactive scope, leaving the explicitly saved provider available.

## Storage and integrity

`internal/aiconfig` uses the existing private manager state directory and a distinct
`ai-settings.json` file. It validates owner/mode/type/path protections and uses
0600 files under a 0700 directory, atomic replacement and file/directory sync.
This is filesystem protection, **not encryption at rest**. The manager account,
privileged administrators and backups may access stored credentials. Clearing a
file is not secure erasure of backups, snapshots or previous filesystem blocks.

One bounded versioned record contains provider configuration, credential generation,
exact manager/profile binding, selected device IDs, data scope and approval audit.
Provider and scope have private consistency bindings. They detect accidental
mismatches, not a malicious same-UID actor who can rewrite both data and bindings.
Credentials and bindings are never included in public readback, logs, ordinary
formatting, SQLite case/finding records, localStorage or sessionStorage.

A create-only protected pending-write marker precedes mutations. Interrupted or
uncertain writes retain a blocker; the next startup refuses to adopt the record.
There is no automatic marker clearing or adoption. A storage failure is visible,
blocks exports, and requires administrator repair/review before restarting. If the
filesystem cannot persist even the marker, no durable-revocation claim can be made;
a failed disable must not be treated as a successful one. Do not delete markers
merely to make an enabled configuration load.

Missing settings initialize off. Corrupt, insecure, unresolved, instance/profile
mismatched or externally changed settings fail closed. Snapshot reads validate
protected bytes before export and publication; provider/scope changes cannot race
publication. Current device authority and original certificate deadlines are still
checked independently. A persisted selection never grants enrollment or endpoint
collection rights. Existing rate/cooldown and consume-once attempt ledgers survive
restart unchanged.

## API delta

- `GET /api/ai/config` adds `persistenceAvailable` and `persistentKeyAllowed`;
  `storage` is `memory-only` or `protected-file`, and `resetsOnRestart` reflects it.
- `POST /api/ai/config` remains the exact original seven-field session-only request.
- `POST /api/ai/config/persistent` uses those seven fields plus the explicit boolean
  `acknowledgeKeyStorage`. The route itself requests persistent provider storage.
- `POST /api/ai/config/clear` also clears protected saved settings.
- Existing proactive settings keep the same schema; `resetsOnRestart:false` means
  this provider can retain the explicitly approved scope after restart.

All mutations retain authenticated administrator, same-origin, CSRF, exact revision
and strict typed-body checks. Named read/maintenance capabilities do not gain AI
configuration authority. Development/basic managers have no persistent settings
controller and cannot enable this route.

## Validation boundary

Only synthetic keys/providers/records and local fixtures were used. Tests cover
key-storage acknowledgement, protected files, exact provider/scope binding, pending
fences, disable/forget, restart-preserved original approval, consumed incidents and
file drift. No real key was entered, no provider was configured for a user, no
external inference was called, and no endpoint or host permission was granted.
Real provider compatibility, model quality and deployed host acceptance remain
separate checks.
