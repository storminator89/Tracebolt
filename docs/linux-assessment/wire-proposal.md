# Package observation transport proposal

Status: the release/source-package portion is implemented as a local candidate.
The earlier operational and offline-catalog archives retain their exact bytes.
Frame-v3/sender-v4 and fresh managed-operations-v2 are reviewed separately from
future cached APT and catalog matching, which remain proposals.

## Narrow next milestone

Use a new, explicit `managed-operations-v2` collection profile and a versioned
agent frame, while continuing to accept v1/basic and v2/operations frames under
their original profiles. The first new profile is Linux-only. A manager must not
silently widen an existing invitation, certificate, sender ledger or pending
frame. Newly selected consent names release identification, source-package
mapping and cached package-candidate metadata. The existing TLS and explicitly
selected HTTP-test warnings still apply.

The selected profile is `managed-operations-v2`, frame is
`tracebolt.agent-telemetry.v3`, and sender config is `tracebolt.lan-agent.v4`. A
fresh manager/store directory plus fresh enrollment is the narrow pilot
compatibility boundary; each store remains bound to exactly one profile. Legacy
binary support does not imply mixed profiles in one store. An existing mode
marker or ledger must never be adopted under a changed profile. An eventual managed
upgrade needs a separately designed key/profile/sequence transition. No automatic
re-enrollment, reset or replacement of a pending frame is permitted.

## Proposed bounded shape

A new frame carries the existing basic observation and the unchanged operational-v1
subdocument as an explicitly contained baseline scope, plus one separate `packages` snapshot using `tracebolt.linux-packages.v1`. It must bind
its original collection time and generation exactly to operational.CollectedAt and
operational.GenerationID respectively. Generation labels match by equality;
collection timestamps must precede or equal basic Bundle.GeneratedAt and pass
the existing age/skew rules. The basic bundle has no generation field. Keep
the existing 72 KiB total frame ceiling, 25-device pilot limit and request
admission policy. For this new frame only, both raw and canonical subdocuments
are limited to 16 KiB basic observation, 32 KiB operational baseline, and 16 KiB
packages. The total raw and canonical frame remains at most 72 KiB. Collection
uses an explicit validated row-trim budget before staging and marks partial
counts/provenance; it fails without staging if minimal valid envelopes cannot
fit. Existing v1/operational-v2 limits remain unchanged.

A standalone package snapshot has a 16 KiB export cap
and at most 128 deterministically ordered rows. These are export bounds, separate
from the larger bounded dpkg input parser. A valid inventory larger than the
export budget has an exact observed count and explicitly partial/truncated rows;
it must not acquire a complete-coverage or global zero-CVE assertion.

Selected release fields are exact ID, VERSION_ID and VERSION_CODENAME, preserving
missing versus empty values. The parser may recognize Debian 13/Trixie and Ubuntu
24.04/Noble only; other combinations remain unsupported. No display name,
ID_LIKE, package suffix or client-supplied trust boolean selects vendor authority.
Package rows include binary name/version/architecture, installation state, source
name/version and whether the mapping is explicit or the documented binary
fallback. These metadata labels can reveal installed applications and are not
anonymous or guaranteed secret-free. Maintainers, descriptions, file lists,
account data, environment, command lines and repository URLs remain excluded.

Cached APT observations, once their adapter is separately reviewed, remain a
separate section keyed to the same selected binary identity. They can report a
configured-cache candidate version and comparison, held-state knowledge and
cache availability/freshness. They do not claim downloadability, dependency
solvability, vendor authentication, installation, activation or reboot state.
Advisory fixed versions never create an offered-update row.

## Server and UI behavior

- Profile, schema and platform must be checked inside the existing atomic
  observation/replay/revocation transaction. Raw JSON retains strict known-field,
  duplicate, type, UTF-8, byte and timestamp validation.
- Require a package snapshot in every new-profile frame, including an explicit
  unavailable snapshot on failure. Retain it solely in the latest exact frame.
  There is no package LastGood merge; a new unknown snapshot replaces prior
  package facts. Latest-only limits cardinality, not lifetime: the exact frame
  remains durably retained until replaced, including for a revoked identity.
  Existing 24-hour LastGood pruning and freshness aging do not delete these
  latest-frame bytes. Consent and UI must not imply such deletion.
  Logical retained bytes are canonical operational snapshot plus
  canonical existing LastGood plus canonical package snapshot. Keep the
  existing 128 KiB/device and 4 MiB global quotas; operational plus package
  reservations together remain at most the old 48 KiB snapshot allowance. A
  retained LastGood combination that no longer fits is rejected atomically,
  preserving every prior identity/replay/frame/cache byte and receipt. Do not
  silently evict a section to force admission. This needs an exact-cap
  reload/ingress/operator-concurrency measurement before enablement. Source times are never refreshed by receipt or retry.
- The old operational endpoint remains compatible. A separate package DTO can
  feed the Security view; legacy/basic clients remain unknown for these facts.
- Imported catalogs remain unverified. Exact source-name matches may become
  bounded review candidates, with the actual declared catalog revision/digest,
  observed package/source versions and conservative reason codes. Unverified
  authority/origin must never become confirmed affected/fixed/not-affected.
- Synthetic catalogs must not be applied to real observations. Ubuntu inventory
  must never use Debian advisory rules. No-match in partial rows means only no
  candidate among the evaluated rows, never zero vulnerabilities on the device.
- Managed-derived package/candidate text remains excluded from AI packets until
  separately allowlisted and consented.

Exact pending-byte retry applies only within the current sender freshness policy.
The sender still discards an expired pending observation without reusing its
sequence; it does not refresh its collection or signature timestamp. Manager
exact historical retries preserve their original receipt. The HTTP-test signed
request age window remains independently enforced.

## Required gates

Before release/source-package implementation: review the precise DTO, profile
consent and retention/accounting formulas. Cached APT subprocess support and the
immutable catalog-to-observation matching bridge are separate later code gates;
they do not block the smaller release/source-package observation slice. Before enabling:
legacy parser/retry compatibility; new raw-wire negatives; 25-device dense-byte
budget; revoked/cross-profile/old-generation rejection; receipt-preserving exact
retry; consent and UI unknown/partial/stale semantics; and actual Linux process
workflow using ephemeral fixtures. Native nonprivileged package/cache reads need
an appropriate supported Debian/Ubuntu environment. They imply no service,
credential, OS trust, repository or package changes.
