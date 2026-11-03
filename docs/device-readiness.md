# Per-device readiness facts

The device's **Capabilities** tab starts with a compact, read-only summary of
evidence already shown on that page. It is a source feature, not a native or
release acceptance claim, and it does not calculate a readiness score.

## What the summary proves

- **Accepted report capture:** the original `Device.lastSeen` capture time from
  the accepted report. It is not the manager receipt time or the latest metadata
  refresh. A valid capture no more than 120 seconds old is labeled recent;
  older captures remain stale. An unset Go timestamp means no report recorded.
  Malformed/future captures or a missing validated manager clock mean age unknown.
- **Certificate validity:** uses the already validated manager-owned certificate
  check time plus elapsed time in this view. It distinguishes unknown, more than
  48 hours remaining, expiring, expired and explicitly revoked renewal state.
  Certificate validity does not establish a local collection grant, connectivity,
  renewal success or device health.
- **Reported agent version:** the exact version label supplied in device metadata.
  It is not a verified binary hash, package identity or proof of native execution.
- **Profiles from validated source status:** distinct nonempty `collectionProfile`
  identifiers from the existing system, complete-overview and complete-package
  status validators. These are source-status facts, not an inferred universal
  enrollment profile. A missing identifier is shown as not supplied. Other
  platforms/sources without those status reads are not assigned a guessed profile.
- **Capability status rows:** counts match the existing capability rows exactly.
  Supported/profile scope, collected, configured, denied, stale, failed, pending
  and unknown remain distinct. Advertised profile-scope count is separate from
  actual collection. Configured journal access does not count as collected content.
  These are neither fleet counts nor inventory record totals.

The summary never infers consent from a profile or a successful GET. Partial,
denied, unsupported and missing evidence cannot become an overall ready/healthy
label. Exact artifact verification, native acceptance and release gates remain
unestablished by these metadata reads and are stated in the evidence limits.

## Time, access and side effects

The existing visible-page render tick ages evidence. This component adds no
request, timer, storage, export, capture or mutation. The collection-status reader
keeps its existing bounded GETs, source validators, original ages, session checks
and visibility behavior.

Unchanged manager times retain their original local clock anchor. Slower
advancing manager time carries forward elapsed age rather than renewing an
unchanged capture. Backward manager time or a browser wall/monotonic-clock
disagreement makes age and certificate validity unknown for this mounted view.
Moving to another device starts a separate clock. A new metadata read does not
restamp the report's capture time.

When operator access ends, the summary removes prior values and status counts.
It is displayed for nonsynthetic LAN device pages only. It neither grants scopes
nor issues actions, permits, retries, enrollment, external notifications or AI
requests. Existing per-source workflows remain authoritative.

## Source verification

Focused model/component regressions cover original capture and zero-time
semantics, freshness boundaries, malformed/future timestamps, missing manager
time, clock stalls/rollback, certificate warning/expiry/revocation, distinct
state counts, both locales, access loss and no additional requests. The
integration test compares summary counts with the actual rendered capability
rows and retains the existing GET-only assertion.

Run from `web/`:

```sh
npm run typecheck
npm run test:environments
npx vitest run src/device-readiness-model.test.ts src/device-readiness.test.tsx src/device-capabilities.test.tsx --maxWorkers=1
npm run build
```

These checks are source fixtures and production compilation. They do not
establish browser/native, deployed-manager, enrollment or release acceptance.
