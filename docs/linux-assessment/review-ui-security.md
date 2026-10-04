# Independent conditional review UI boundary

Review date: 2026-10-04 UTC. Scope: `web/src/advisory-review*`, its minimal
mount in `security-coverage.tsx`, and alignment with the exact read-only HTTP
envelope and `offlinecatalog.ReviewResult` contract. Verification used synthetic
unit/JSDOM responses, TypeScript, and a local production build on Linux x86_64
with Node v24.19.0/npm 11.9.0. It did not use a real browser, network advisory
feed, actual package inventory, native collection, elevated privileges,
publication, or screenshots. No deployment or installed-host assessment is
claimed.

## Result and corrections

No unresolved blocker remains in the reviewed UI slice. Independent tests found
two related impossible-envelope consistency gaps; the implementation owner
corrected both before the final checks:

1. Multiple advisory rows for the same binary/architecture identity could carry
   different reported source package, source version, or source-mapping basis.
   The core copies those facts from one unique validated package row. The UI now
   requires identical source facts for that identity across its advisory rows.
2. Different binaries referencing the same source/advisory rule could carry
   different declared status, fix version, or ordered qualifications. The core
   copies those declarations from one immutable normalized rule. The UI now
   rejects such contradictions across every occurrence of that rule.

These were client fail-closed validation gaps for inconsistent manager output,
not demonstrated bypasses of manager authentication or findings about a live
host. Six independent negative regressions now pass. Positive regressions also
prove that different architectures may retain different exact source versions,
and different advisory rules may retain different declarations. The reviewer
edited only its independent test file and this document; the implementation
owner made the validator corrections.

## Contract and presentation

- The lazy disclosure performs only the same-origin authenticated selected-device
  `GET /api/devices/{id}/security/review`. It adds no request body, query,
  imported-content destination, mutation, package collector, update action, case,
  or AI export. The enclosing device view retains its existing eligibility and
  authentication boundaries.
- The real protected request helper streams and counts the entire response,
  accepts at most 65 KiB (66,560 bytes), rejects invalid UTF-8, and rejects
  oversized bytes even if `Content-Length` is missing or falsely small. The
  independent test accepts exactly 65 KiB and rejects one additional byte.
  The parsed review has an independent canonical 64 KiB limit. As with the
  existing manager DTO clients, this is parsed-key/shape validation, not a
  replacement for the raw catalog/agent-ingress duplicate-key decoder.
- Exact envelope/nested keys, identities, schema/scope, nullable fields, enums,
  safe integer counts, unknown/unverified qualifiers, and timestamp grammar are
  checked before display. The client rejects any non-null affected-CVE or
  offered-update count, synthetic live rows, unavailable live rows, oversized
  fields, invalid basis/reason combinations, and unsorted/duplicate row
  identities. Work counters must be feasible against inventory/rule counts and
  returned compared rows.
- Core limits stay 128 candidate rows, 4,096 inspected package/rule pairs,
  1,024 comparisons, and 65,536 canonical result bytes. Their fixed labels,
  partial status and omission reasons are visible. Byte-trimmed counters remain
  work performed, not a count of the remaining row prefix.
- Every displayed row is a review candidate. Completion refers only to selected
  scope. Catalog origin is unverified; catalog freshness/publication and
  installed-artifact origin are unknown. Core snapshot freshness is unknown and
  remains distinct from the manager's package collection window.
- Zero candidate rows, including complete empty selected inventory and synthetic
  catalogs, never become zero affected CVEs, zero offered updates, a secure-host
  verdict, or a green success indicator. Declared fix versions are explicitly
  unverified and do not establish installable updates. The unchanged coverage
  cards continue to say unknown.
- Release ID, version ID and codename retain their exact values, with absent and
  explicitly empty fields distinguished. Only the exact Debian/13/trixie triple
  can accompany a non-unavailable review. Unsupported Ubuntu/24.04/noble facts
  remain visible in an unavailable result without live candidate rows. Source
  versions preserve epochs, leading zeros, revisions and rebuild suffixes;
  the UI neither compares versions nor substitutes binary versions.
- Catalog IDs/hash/revision, observation generation, original receipt/sequence,
  collection time and manager time remain visible. A hash is described as a
  content identifier, not a signature. All imported/package values are inert
  React text. Accepted URL-like tokens are not links; markup fails validation.
  No raw error diagnostics, source URLs, remediation commands, HTML injection,
  inventory persistence or private result storage are introduced.

## Private lifecycle and freshness

The disclosure/session/device keys destroy old resources. Close, unmount,
identity/session changes, auth loss, pagehide, hidden visibility, blur and
navigation invalidate displayed data and abort outstanding work. Focus,
visible restoration and BFCache restoration require a new response; they cannot
restore the old rows. Hidden or auth-locked views do not issue restore reads.
The protected request helper also checks its session epoch after fetching and
after parsing a held response stream. Superseded/late replies cannot reinstall
old data, including when a new disclosure has already produced a newer result.

The maximum display lease is strictly 60 seconds from request start, rather
than response arrival. Request latency is also deducted from both the remaining
receipt and collection windows. Both server-relative ages must be at most 120
seconds, including RFC3339 nanosecond boundaries; no client wall-clock value can
establish server freshness. Negative/nonfinite monotonic time or a wall versus
monotonic discontinuity greater than 1.5 seconds invalidates the anchor. Pending
reads time out at 10 seconds. Refresh clears previous rows before a new read;
invalid output, HTTP 409/429/401, failure or expiry retain no prior candidates.

AuthBoundary remains responsible for the actual operator-session lifetime and
private epoch. The existing profile/configuration logic is unchanged by the
mount: legacy profiles may return `not_configured`, and the disclosure cannot
activate managed-operations-v2, enroll a device, or grant expanded collection
consent. Operator integration tests exercise the existing Security tab and auth
boundary without changing those semantics.

## Verification

The final independently executed commands from `web/` passed:

```
npm test -- --reporter=dot src/advisory-review-independent.test.tsx \
  src/advisory-review-types.test.ts src/advisory-review.test.tsx \
  src/advisory-review-api.test.tsx src/advisory-review-integration.test.tsx
# 5 files, 80 tests passed; 21 are independent regressions.
npm run typecheck
npm run build
# TypeScript and production Vite build passed.
```

The independent suite covers exact/over-limit wire bytes, false length headers,
inert URL-like text, exact missing/empty/unsupported release evidence, complete
empty-result caveats, nanosecond boundaries, the six consistency rejections and
their two positive compatibility cases, request-latency lease/freshness
accounting, protected epoch invalidation, private-session replacement, late
responses and BFCache restoration. Owner suites add all collection states,
synthetic suppression, DTO/core caps, partial reasons, EN/DE copy, clock/timeout
events, HTTP errors, DeviceDetail eligibility and AuthBoundary integration.

The owner separately reported 177 existing package/security regression tests
passing. This document does not treat that report as an independent full-suite
run. Go aggregate checks, full application regression and immutable-candidate
capture remain the coordinating task's gates. Real browser/visual acceptance
was not run and is not implied by JSDOM or a successful production build.

## Exact reviewed source

The mutable source directory has no Git metadata. SHA-256 identities below pin
the final reviewed implementation and contracts; a later change requires the
affected checks to be rerun. Test/build-generated output is not a source
publication.

```
a8777237106accf22681ec6bb41e7dc82a4bb2c59782948598b3401da23c2a79  web/src/advisory-review.tsx
969e9be9185c1e12d9d0fa9fd627c06e68299aa7d8c39bc60c37cd0a11438ce8  web/src/advisory-review-types.ts
1a7f00f30a759085d82d94b3aa679b12e4706f0ba5fe11acd476606ced9cd903  web/src/advisory-review.css
a5ab40969cc0d163dcd99b7e0912896ca5c6a1ec15bf86d8692b16ab5a0d3c6a  web/src/advisory-review-fixtures.ts
00312700a2f03177f28d306d92ad18cacc0763bfb26a59adb4f7a3b72dab9f90  web/src/advisory-review-independent.test.tsx
b09f5035af7447a72792923f9ab66b57c560a99dfac90a03b608beace5e73492  web/src/advisory-review.test.tsx
8a6cfb62f78800c4812a349b7c001e9b7a02c9c15fb5eaf605342be8e24f5101  web/src/advisory-review-types.test.ts
5d1506c8b5215933096fd02b21c12e3813de8956fb5ea54d42be98fd220b3f5f  web/src/advisory-review-api.test.tsx
df1105f21e5e9b71aea9a23bdb8c399992691fe70e0f79782f76fa9cd8ca64db  web/src/advisory-review-integration.test.tsx
bfddd01fb8c43f86d56624207d13410e8bfb76cc50512951c9fb5369064d721a  web/src/security-coverage.tsx
6a53f2f1785e2e7f0337af05844b2f75b755ad77cc7eafc4170290d5abe22241  web/src/api.ts
2338fd8513f127a1cb6284de6d897d48c77856ad76c3972cf791766631ffe8c6  internal/api/security_review.go
d39020eebc856ddd2047712c64358b4d3c084a0c118d942df9f434b352c5d890  internal/offlinecatalog/review.go
5761e844b74bb0deb2aae84e6fe90c114138e393cee1c6f8f4e627fdc2f7b3a7  docs/linux-assessment/review-http-contract.md
```
