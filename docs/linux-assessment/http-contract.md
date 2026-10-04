# Package observation API integration contract

In-progress candidate for a fresh `managed-operations-v2` manager/store. No
migration of an existing profile, marker, certificate or sender ledger occurs.

## Enrollment consent

`GET /api/enrollment` advertises the exact pair:
`collectionProfile: managed-operations-v2` and
`collectionPrivacy: package_source_metadata_may_be_sensitive`.
The existing v1 managed pair remains unchanged, and basic still omits both.
Managed-v2 invitation creation requires the existing explicit
`collectionAcknowledged: true` in addition to requestId/platform. The immutable
manager configuration chooses the profile; a request cannot change it. Creation
responses must match the acknowledged profile. Any profile/clock/auth/config
change invalidates prior consent and selected one-time material.

Consent includes the existing operational metadata plus exact selected OS release
identifiers, binary/source package names and versions, mapping basis and install
state. Metadata can reveal applications or sensitive labels. No account data,
commands, environment, descriptions, maintainers, repository URLs, APT execution,
package changes or AI export is added. Rows are bounded and may be partial. Latest
frame bytes persist until replaced, including after revocation; age does not
claim deletion. It requires a fresh store/enrollment; no silent state reset.

## Device package view

Authenticated `GET /api/devices/{id}/packages`, no query parameters, same existing
operator surface. Known old-profile/development devices return not_configured;
unknown IDs return404. It performs no source collection, package command or
matching. Fixed429 storage_busy with Retry-After2 covers bounded contention;
other storage faults remain fixed500 and do not become missing data.

Exactly:

```json
{
 "schemaVersion":"tracebolt.package-view.v1",
 "deviceId":"agent_...",
 "status":"not_configured|awaiting|fresh|stale|revoked|unavailable",
 "serverNow":"UTC RFC3339",
 "receivedAt":null,
 "sequence":null,
 "maxAgeSeconds":120,
 "snapshot":null
}
```

A present snapshot is the exact strict `linuxpackages.Snapshot` defined in
package-contract.md: schemaVersion/scope/generationId/collectedAt/durationMs,
release quality/reason/three nullable fields, inventory quality/reason/complete/
truncated/countExact/two nullable full-source counts/items. It is at most16KiB and
128 ordered rows. No incoming target/authority/assessment field is accepted.

The view has no package LastGood member. An unknown new source replaces prior
package facts, while the unrelated operational LastGood policy remains intact.
Stale/revoked views may retain their historical snapshot. At24h the API hides it
as unavailable; durable frame bytes still exist for replay/lifecycle consistency.
Snapshot source quality describes collection validity and is never changed to
"stale"; top-level status and trusted time determine current usability. A fresh
receipt with unknown inventory is not a successful inventory. Derive effective
age from serverNow plus monotonic elapsed time, validating both collection and
receipt timestamps. After lifecycle/clock uncertainty, clear the view until a
new server anchor is read. No client-wall-clock-only freshness assertion.

## Security coverage compatibility

The existing coverage DTO remains conservative. For the new profile its four
reason codes use `source_package_mapping_not_assessed` and
`client_release_not_assessed` in place of the unavailable variants. This says
that the current assessment projection has not evaluated the separately reported
facts; it does not claim confirmed CVEs or offered updates. Catalog authority and
artifact-origin reasons stay unchanged. The original profile keeps its exact
unavailable reason pair. UI accepts either coherent pair, never a mixture or an
invented numeric CVE/update zero. Future candidate matching is a separate gate.

## UI

Show the package details lazily under the authenticated eligible device Security
view, with exact release, selected rows/full-source counts, partial/truncation and
source failure reasons. Use English/German labels, inert escaped text and bounded
response parsing. No filename, raw errors, repository link or inventory storage
outside the authenticated view. Closing, device/session replacement, authentication
loss, pagehide/hidden/BFCache and uncertain clock clear data/cancel pending reads;
late results cannot reinstate an old view. Current source archive and published
UI remain separate from this in-progress candidate.
