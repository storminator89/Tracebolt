# Offline security coverage, first integration contract

This is a separate candidate after the frozen Linux operations source backup.
It introduces no network access, package/update execution, client scope expansion,
or definitive CVE result from missing provenance. Current client observations do
not contain source-package mapping, exact structured release or verified artifact
origin. Existing observed binary metadata must not be reinterpreted as those facts.

## Offline catalog

Only an authenticated managed-operations instance enables this slice. Development,
manual/basic profiles return `enabled:false`; imports are unavailable there.
One active normalized Debian 13/Trixie catalog is held in server memory. It resets
on restart; failed parsing/CAS/cancellation preserves the previous catalog.
At most 2 MiB and 10,000 rules/covered sources are accepted. Exactly one import body
may be read/parsed at a time. The existing fixed parser is reused, with explicit
root fields, booleans, arrays and supported release checks added at this boundary.
No URL is followed, signature claimed, comparator run or source data sent outside
the self-hosted manager. Operator upload is not vendor authentication.

`GET /api/security/catalog` returns:

```
{
 "schemaVersion":"tracebolt.offline-catalog.v1",
 "enabled":true,
 "serverNow":"RFC3339 UTC",
 "revision":"revision_<32 lowercase hex>",
 "storage":"memory-only", "resetsOnRestart":true,
 "catalog":null,
 "limits":{"maxBytes":2097152,"maxRules":10000,"maxInFlight":1}
}
```

A loaded `catalog` has exactly:
`id` (`catalog_` +32hex), `sha256` (64hex), `format`
(`debian-tracker-normalized-1`), `provider` (`debian-security-tracker`),
`declaredRelease` (`trixie`), `importedAt` (trusted server timestamp),
`publishedAt` (null), `freshness` (`unknown`), `originAssurance` (`unverified`),
`synthetic` (boolean), `byteCount`, `ruleCount`, `coveredSourceCount`.
Provider/release identify the accepted interchange scope, not proven authorship.
Import time never becomes vendor publication/fetch time. No raw rule/name/file
content or user filename is returned by this catalog metadata endpoint.
Disabled views use empty revision and null catalog; other fields remain explicit.

`POST /api/security/catalog` accepts the raw normalized JSON file body, exact
Content-Type application/json, the existing single Origin/CSRF headers, and one
`X-Tracebolt-Catalog-Revision` header containing the current revision. Profile,
origin trust, timestamps, public URL and verification booleans are never accepted
as authority from the body. The normalized root is exactly schema,synthetic,
coveredSources,rules. Every rule must target trixie. The parser's existing finite
bounds/known-field/duplicate rejection remain mandatory. Success 200 returns the
new catalog view. Parsing happens before the short operator mutation lease;
active session and revision are rechecked at commit. No save-time side effects
beyond the in-memory replacement occur.

`POST /api/security/catalog/clear` accepts exactly `{"expectedRevision":"..."}`
under the same operator lease/CSRF policy, returning the new empty view.
Catalog-specific failures use fixed codes/messages: 400 invalid_catalog/unsupported_catalog_release,
409 catalog_changed, 413 catalog_too_large, 429 catalog_busy, 404 catalog_unavailable.
Common session, framing and typed-body guards retain the existing API codes (including invalid_json and body_too_large for the clear request). No raw errors, file content or snapshot data appear in diagnostics.

## Per-device coverage

`GET /api/devices/{id}/security` reads the existing authenticated operational view.
It never substitutes the manager's package database for a client and never runs a
package command or matching operation from a GET. Response:

```
{
 "schemaVersion":"tracebolt.security-coverage.v1",
 "deviceId":"agent_...", "serverNow":"RFC3339 UTC",
 "maxAgeSeconds":120, "receivedAt":null,
 "collectionStatus":"not_configured|awaiting|fresh|stale|revoked|unavailable",
 "inventory":{
   "coverage":"unknown|partial|observed", "freshness":"unknown|fresh|stale",
   "reportedItemCount":null, "installedCount":null,
   "observedCount":null, "countExact":false, "truncated":false,
   "collectedAt":null, "generationId":null,
   "scope":"reported-installed-binary-packages",
   "originAssurance":"unverified"
 },
 "catalog":{"configured":false,"revision":"...","sha256":null,
   "originAssurance":"unverified","freshness":"unknown"},
 "offeredUpdates":{"coverage":"unknown","offeredCount":null,
   "reason":"native_update_adapter_unimplemented"},
 "vulnerabilities":{"coverage":"unknown","affectedCves":null,
   "reviewCandidates":null,"reasonCodes":["advisory_snapshot_unavailable",
     "source_package_mapping_unavailable","client_release_unverified",
     "installed_artifact_origin_unverified"]}
}
```

Available software metadata can have an observed/partial inventory and non-null
reported counts while updates/CVEs remain unknown. Only an exact complete binary
enumeration yields installedCount; partial results never become a full total.
Current failed software collection may show a retained section explicitly stale,
keeping its original generation/time. Revoked and expired source data is never
fresh. A configured catalog replaces advisory_snapshot_unavailable with
advisory_authority_unverified; it never fabricates package matches or zero CVEs.

## UI

English default and German translation. Add a lazy Security coverage view on LAN
Linux/unknown devices and an offline-catalog settings card. Use real API responses,
explicit memory-only/reset, format-vs-origin distinction and unknown counts.
Show source gaps and partial/stale together. No green "secure" badge, invented
update offer, external link built from imported text, model export or install
button. Configuration errors/401/logout/BFCache invalidate visible data and
cancel in-flight mutations. The selected file stays in memory only and is cleared
on cancellation/logout/uncertain outcomes; no browser storage, URL, filename or
raw content is exported. Invalid refresh cannot leave an older import form usable.

## Next native adapter gate

A separately reviewed wire/schema extension can add exact os-release ID/version/
codename and dpkg Source package/version with independent freshness/privacy.
This would enable review-candidate matching without inventing origin assurance.
Bounded read-only cached APT candidates must remain separate from advisory fix
versions and installation/activation. No apt update or package installation is
part of that path. Debian 13 CVE matching is explicit; Ubuntu 24.04 inventory/cache
support must not imply Debian advisory applicability or a completed Ubuntu CVE
adapter. Each vendor adapter needs its own ordinary fixture corpus and native
acceptance. Trusted artifact/repository evidence remains a distinct future gate.
