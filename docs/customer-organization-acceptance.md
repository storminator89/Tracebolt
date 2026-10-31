# Customer organization boundary: acceptance evidence

This is the bounded manager-only acceptance record for **TB-17 / #144**.
Customers organize one manager's workspace; they are not tenants, authentication
principals, collection grants or action/export permissions. Confidential customer
boundaries require independently provisioned manager instances as described in
[customer records](customer-records.md#customer-separation-requires-separate-manager-instances).

## Scope and dependencies

The earlier disclosure change (#165) added the same EN/DE explanation to both
customer panels and documented separate identities, trust, state and backups.
This follow-through checks those statements against actual request handling,
CSV output and two independent Linux manager processes. It introduces no new
production capability, role, tenant protocol, installer or state migration.

TB-06 / #133 remains a separate personal-administration task. It does not have
to be silently implemented or bypassed to establish this organizational boundary:
the current catalog/assignment mutation still needs shared administration;
named accounts remain denied those operations. Completion of TB-17 does not
claim personal-account administration, MFA, common audit, tenant isolation or
completion of any other dependency's acceptance criteria.

## Acceptance matrix

| TB-17 criterion | Executable or reviewed evidence |
| --- | --- |
| No visible surface promises server-side customer isolation | Review of README, current release/download and installation guidance, proposed onboarding, and the EN/DE customer panels; `CustomerOrganizationNotice` is mounted in both panels. Existing disclosure tests require the access-control, collection/action, API/export and separate-instance warnings in both languages. |
| Separate instances, identities and backups are documented | The linked checklist requires distinct origins, manager/TLS/issuer identities, operator/provider credentials, protected configuration/state/volumes and backup sets; it explicitly excludes isolation from a shared host administrator. |
| Assignment or a display selection grants no data/action rights | `TestCustomerOrganizationAssignmentPreservesDataAndAuthority` performs the actual acknowledged assignment, rejects injected authority fields and compares inventory, capabilities, session, enrollment and trust before/after. `TestCustomerOrganizationMetadataCannotPromoteNamedOrAnonymousAuthority` retains direct API, collection, service-action and AI-export denials with customer IDs in bodies/headers. Unsupported customer query parameters fail canonical-path validation. |
| Display filters are not API or export access control | `customer-devices.test.tsx` keeps both customers' rows visible without another request. `customer-organization-export.test.tsx` mounts the real App/Auth/request/assignment/CSV code in EN/DE, reads the actual generated CSV Blob and requires identical allowed rows/bytes before selection, after either customer selection and after the explicit assignment. Export makes no request; only the intended acknowledged assignment POST is sent. Customer labels/IDs, identity digests and CSRF canaries are absent from this CSV. |
| Two separate instances share no keys, trust, state or backups | `TestCustomerSeparateManagerProcesses` runs the actual Linux `lan-manager` binary twice with separate temporary TLS/issuer/operator/configuration/state roots. It exercises own and foreign authentication/trust, independent catalogs, disjoint stopped-process backup copies and independent restart. |

## Reproduce

Use the exact source revision's Go 1.27.1, Node 24 and unchanged npm lockfile.
Run from the repository root:

```sh
go test -race -count=1 -timeout=6m ./internal/api \
  -run '^(TestCustomer|TestNamedAdministrationContract|TestNamedReadRoutes)'
go test -race -count=1 -timeout=6m ./cmd/lan-manager \
  -run '^TestCustomerSeparateManagerProcesses$'
go test -race -count=1 -timeout=4m ./internal/store -run '^TestCustomer'
(cd web && npm exec -- vitest run src/customer-organization-export.test.tsx \
  src/customer-organization-notice.test.tsx src/customers.test.tsx src/customer-devices.test.tsx)
(cd web && npm run typecheck && npm run build)
```

The final change record must identify the tested source tree/commit, Linux
architecture, tool versions, actual commands and pass/fail/skip results. Local
checks do not reclassify unrelated failed/cancelled hosted checks as successful.

## Recorded local result — 31 October 2026

Base: `a15d2dd98d9a49ac641520bc8afb7167c6af3fe7`; Linux amd64,
Go 1.27.1 and Node 24.22.1. Production sources, dependency locks, protocols,
stored authority, workflows and security settings are unchanged.

- Customer/named-boundary API race selection: **19 test roots passed**; final
  run 9.622 seconds. Customer-store race selection: **12 roots passed**, 2.927 seconds.
- Actual two-manager subprocess regression: **three race-harness repetitions
  passed**, 10.431 seconds; both manager processes exited cleanly each time.
- Actual-App CSV and adjacent customer component regressions: **27 tests in
  four files passed**, including both languages and no skipped tests.
- Complete frontend aggregate: **283 files / 7,611 tests passed**, 457.86 seconds
  with two workers. Discovery guard: **25 tests passed**, every file selected once.
- TypeScript check, production frontend build, API/manager vet and the native
  Linux manager source build passed. The existing large-chunk build warning remains.
- The unchanged canonical Go inventory derives identically twice: **5,990 roots**,
  retaining all prior **5,987**, with only the three new regression roots added.
  Reporter checks passed normally and optimized; **140** inert release tests and
  the documentation entrypoint checks passed. No failure vocabulary or gate was relaxed.
- Independent source/acceptance review found no blocker. Relative document links
  and whitespace checks passed. Exact commit/tree and hosted results belong to
  the integrating PR; local results are not a claim of all-CI success.

## Evidence boundaries

The subprocess test uses only disposable private files and bounded loopback
listeners. It installs no service, changes no OS trust, uses no user credentials,
collects no endpoint telemetry and grants no persistent host authority. A backup
copy is checked for disjoint file identity and preserved own bytes; it is not a
general backup/restore or freshness-reconciliation acceptance result.

The App CSV test uses synthetic responses and component DOM execution, not a
Chromium or Windows acceptance run. CSV is a local copy of already authorized
observations; it is not a server-enforced customer export policy. Authorized
readers can copy received values regardless of a UI filter.

Two managers under the same operating-system administrator are not hostile-tenant
isolation. Real deployments must independently verify approved origins, trust,
storage, credentials and exposure. Windows installation, real endpoint/native
provider acceptance, production hardening and separate-host isolation remain
outside TB-17's organizational-truth claim.
