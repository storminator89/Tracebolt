# Named-administration route and actor matrix (TB-06, inventory slice)

Source baseline: `f70de9291803dd7e26f8907c11de821244e307b8` (2026-10-31).
Reconciled with main `1dd1c4fed3f3368a8b968af1305bca054f012514` after
#166/#167. The added public Rust compatibility route is included below;
operator grants and the shared-only administration rows remain unchanged.
The test inventory is derived from the combined Go tree.
This is the first slice of [TB-06 / #133](https://github.com/storminator89/Tracebolt/issues/133):
an inventory and regression contract, **not implementation or acceptance of
personal-account administration**. No permission, role, account, stored record,
session policy or endpoint grant is changed. TB-02 / #129 remains a separate
dependency; its work is neither included nor published by this slice.

## Reading the matrix

- **R**: reads existing state; **W**: changes authority/configuration or invokes
  work; **P**: creates a process-local review/permit, not a passive read.
- **Shared** means an authenticated v1 shared-password session. Its human
  `ActorID()` is empty. Existing legacy administrative route access is independent
  of the displayed `read` capability; that display is not a complete grant list.
- **Named/read** means an authenticated v2 named session with its required,
  explicitly configured `read` grant. **Denied** also applies to a named account
  holding *all fourteen* currently defined capabilities. There is no admin,
  wildcard, role inheritance or shared-password fallback.
- **Allowed** is route admission only, not guaranteed success. Correct profile,
  current device/issuer authority, feature configuration, revision, typed body,
  acknowledgement and existing expiry/consume-once rules still apply. Feature
  absence can return 404/409/503. Anonymous `/api/` requests require login (401),
  except the exact auth bootstrap/login routes below. Native/public rows have
  their own credential boundary, not operator-account permission.
- **N/S**: a named read request has a server-derived human actor available in its
  session; shared requests have no human actor. These views do **not** create a
  per-read actor audit record. **S/no actor**: currently shared-only mutation;
  its called service/store and retained record do not bind a human actor.
  **AI sentinel**: saved settings/approvals use `shared-administrator`, not a
  person. A session ID used for cancellation is not a human audit identity.

The LAN boundary in `internal/api/operator.go` first checks actual transport
(TLS 1.3, or separately configured HTTP-test), exact Host/Origin, canonical paths,
framing and session expiry/revocation. Except separately capability-gated typed
action/alarm/application-check endpoints, it then denies named non-read requests
with `403 operator_capability_required`. The `namedReadRoute` classifier admits
GET/HEAD and a finite list of read-only POST queries; **classifier admission does
not make HEAD supported**. The routes below implement GET, not HEAD, and must
not be described as GET/HEAD APIs. Unsupported methods/paths do not acquire rights.
JSON writes retain same-origin, CSRF and bounded strict-body requirements.

The current capability inventory is `read`, `plan_updates`, `execute_updates`,
`restart_service`, `manage_alarms`, `manage_application_checks`,
`windows_service_control`, `windows_update_install`, `windows_update_download`,
`windows_update_schedule`, `windows_software_install`,
`windows_managed_msi_deliver`, `windows_managed_msi_install` and
`windows_managed_msi_schedule` (`internal/operatorauth/operators.go`). Only
`read` admits the named reads below. The other thirteen grants are for separate
typed maintenance/alarm/application-check routes, **not** any shared-only row
in this matrix. In particular, composing all thirteen does not confer account,
customer, enrollment, trust, AI or export administration.

## 1. Enrollment administration (four independent domains)

`{E}` is a finite expansion over these four literal prefixes, not an arbitrary
path: `/api/enrollment`, `/api/windows/enrollment`, `/api/macos/enrollment`,
`/api/macos-inventory/enrollment`. `{invite}` is a valid nonzero `invite_` ID.
Every row applies separately to **each** prefix. Windows/macOS wrappers rewrite
only the path and retain the original authenticated context; domain/profile
selection never manufactures a grant or platform scope.

| Method and route | R/W | Shared | Named/read | Actor binding / effect |
| --- | --- | --- | --- | --- |
| `GET {E}` | R | Allowed | Allowed | N/S; snapshots, configured platform/profile and public metadata only |
| `GET {E}/{invite}/renewal` | R | Allowed | Allowed | N/S; current renewal status; requires configured domain |
| `POST {E}/invitations` | W | Allowed | Denied | S/no actor; creates invitation and returns secret once; profile acknowledgement remains separate |
| `POST {E}/automatic-bootstrap` | P | Allowed | Denied | S/no actor; random public bootstrap ID, no invitation row; only configured TLS self-registration |
| `POST {E}/{invite}/approve` | W | Allowed | Denied | S/no actor; exact fingerprint/revision approval, not a request-supplied actor |
| `POST {E}/{invite}/disable-renewal` | W | Allowed | Denied | S/no actor; preserves original identity and renewal revocation boundary |
| `POST {E}/{invite}/terminate` | W | Allowed | Denied | S/no actor; only `canceled`, `rejected`, `revoked`, with existing request/revision fences |

Evidence: `internal/api/enrollment.go`, `windows_inventory.go`,
`macos_enrollment.go`, `macos_inventory_enrollment.go`;
`internal/enrollmentservice/{service,renewal}.go` and
`internal/enrollmentstate/types.go`. Enrollment snapshot approval/termination
fields contain request IDs, endpoint identity/fingerprint and times, **not the
approving human's actor ID**. Endpoint key identity is not an operator identity.

### Native enrollment and public compatibility/bootstrap boundary

These routes are listed to avoid mistaking native proof or public support
metadata for an administrator grant. `{C}` expands only to `/v2/enrollment`,
`/v2/windows/enrollment`, `/v2/macos/enrollment`,
`/v2/macos-inventory/enrollment`. A configured domain is required. All native
POSTs reject browser Cookie/Origin/CSRF and authorization/forwarded credentials;
an operator login is not a substitute for enrollment proof.

| Method and route | R/W | Admission / actual identity |
| --- | --- | --- |
| `POST {C}/challenge` | W | Bounded native peer/challenge budget; no human actor or operator grant |
| `POST {C}/claim` | W | Exact invitation/key/CSR/challenge proof; endpoint identity, not human actor |
| `POST {C}/self-claim` | W | Explicit TLS self-registration policy plus exact proof; no browser/admin grant |
| `POST {C}/self-bootstrap` | R | TLS self-registration, validated public ID and budget; no secret or human actor |
| `POST {C}/status` | W/status | Exact signed native proof; can progress approved/intent state through certificate issuance; endpoint identity, not a passive read |
| `POST {C}/credential` | W | Exact proof and existing issuance/envelope state; endpoint identity; not an ordinary read |
| `POST {C}/activate` | W | Exact proof and activation state; endpoint identity |
| `POST {C}/renewal/challenge` | W | Fresh TLS same-key renewal policy, bounded peer/challenge; no human actor |
| `POST {C}/renewal/status` | R | Exact renewal proof (challenge consumed), original identity/expiry/revocation; endpoint identity |
| `POST {C}/renewal/issue` | W | Exact renewal proof plus existing durable issuance fences; endpoint identity |
| `POST {C}/renewal/activate` | W | Exact renewal proof plus activation floors; endpoint identity |
| `GET /v2/enrollment/bootstrap/{invite}` | R/export | Public *primary-domain* bootstrap, no existence lookup/secret/status; credential-free bounded request |
| `GET /v1/windows/rust-basic-capabilities` | R | Public compatibility metadata only; exact valid nonrenewable Windows HTTPS bootstrap/domain, credential-free request and shared public budget; no account or enrollment grant |
| `GET /v1/windows/setup-capabilities` | R | Public static compatibility only; Windows domain required |
| `GET /v1/windows/read-admin-setup-capabilities` | R | Public static compatibility only; Windows domain required |
| `GET /v1/windows/read-admin-setup-capabilities-v2` through `-v10` | R | Nine exact versioned public compatibility routes; no wildcard or grant |
| `GET /v4/system/capabilities` | R | Public static support only; configured primary enrollment required |
| `GET /v3/journal/capabilities` | R | Public static support only; configured primary enrollment required |
| `GET /v4/journal/capabilities` | R | Public static support only; configured primary enrollment required |

Public GETs use `admitPublicMetadata`: no body, cookies, Origin, credentials,
conditional/range requests or forwarded identity; no GET-to-HEAD promotion.
Public/native availability does not prove endpoint installation or native
acceptance. Evidence: enrollment handlers above, `bootstrap_download.go`,
`windows_setup_capabilities.go`, `socket_owner_capabilities.go`,
`journal_capabilities.go`, `rust_basic_capabilities.go`.

## 2. Manual trust

| Method and route | R/W | Shared | Named/read | Actor binding / effect |
| --- | --- | --- | --- | --- |
| `GET /api/lan/agents` | R | Allowed | Allowed | N/S; public trust descriptors, not keys |
| `POST /api/lan/agents/approve` | W | Allowed in manual mode only | Denied | S/no actor; exact certificate fingerprint confirmation, trust policy |
| `POST /api/lan/agents/{agent}/revoke` | W | Allowed in manual mode only | Denied | S/no actor; retains revocation tombstone |

Guided enrollment disables both manual writes (`manual_identity_unavailable`);
named capability denial happens before this feature guard. No current capability
grants trust administration. `lantrust.Agent` persists public certificate
identity, times and revocation, not a human actor. Evidence:
`operatorHandler.agentMutation` in `operator.go`, `internal/lantrust/registry.go`.

## 3. Customers and organizational associations

| Method and route | R/W | Shared | Named/read | Actor binding / effect |
| --- | --- | --- | --- | --- |
| `GET /api/customers` | R | Allowed | **Denied** | Shared-only catalog, no per-read actor audit |
| `POST /api/customers` | W | Allowed | Denied | S/no actor; create with expected revision zero |
| `POST /api/customers/{customer}` | W | Allowed | Denied | S/no actor; rename with exact positive expected revision |
| `GET /api/customer-windows-assignments` | R | Allowed | **Denied** | Shared-only current identity/customer projection |
| `POST /api/customer-windows-assignments` | W | Allowed | Denied | S/no actor; create-only exact activated Windows identity/customer association |

Both handlers explicitly reject named sessions even on GET; the broad read
classifier is not sufficient. There is no GET customer-detail, delete, move or
tenant-authorization API here. Customer metadata/membership grants no tenant
isolation, enrollment, endpoint scope or account access. Revision, manager,
identity, issuer and transaction leases remain authoritative. Evidence:
`customers.go`, `customer_windows_assignments.go`,
`internal/store/{customers,customer_windows_assignments}.go`.

## 4. AI settings, execution and outbound export

| Method and route | R/W | Shared | Named/read | Actor binding / effect |
| --- | --- | --- | --- | --- |
| `GET /api/ai/config` | R | Allowed | Allowed | N/S; public provider/destination/model metadata, never key |
| `POST /api/ai/config` | W | Allowed | Denied | AI sentinel for durable forget of former saved provider; otherwise process memory |
| `POST /api/ai/config/persistent` | W | Allowed | Denied | AI sentinel in provider/last-change record; separately approved protected storage |
| `POST /api/ai/config/lan` | W | Allowed | Denied | Explicit destination approval, new provider memory-only; AI sentinel if forgetting former saved settings |
| `POST /api/ai/config/lan-private-ca` | W | Allowed | Denied | Exact reviewed CA fingerprint and HTTPS, new provider memory-only; AI sentinel if forgetting former saved settings |
| `POST /api/ai/config/clear` | W | Allowed | Denied | AI sentinel when forgetting persisted provider/scope; no silent recovery |
| `POST /api/ai/test` | W/export | Allowed | Denied | Session-ID cancellation owner; only fixed synthetic test packet, explicit provider/revision approval |
| `POST /api/cases/{case}/analyze` | W/export | Allowed | Denied | Session-ID cancellation owner, not durable human actor; exact stored case evidence; managed-profile export stays blocked |
| `GET /api/ai/proactive` | R | Allowed | Allowed | N/S; complete-profile health source required |
| `POST /api/ai/proactive` | W/export approval | Allowed | Denied | AI sentinel for saved approval/last change; exact provider/model/devices/health-summary scope |
| `GET /api/ai/journal` | R | Allowed | Allowed | N/S; complete Linux journal/health source required |
| `GET /api/ai/journal/source/{agent}` | R | Allowed | Allowed | N/S; existing source-policy review, not permission to capture/export |
| `GET /api/ai/journal/{agent}/{incident}` | R | Allowed | Allowed | N/S; existing bounded analysis result with original source expiry |
| `POST /api/ai/journal` | W/capture + export approval | Allowed | Denied | AI sentinel in enabled receipt; exact local policy, saved provider and separate capture/export acknowledgements |
| `POST /api/ai/network-review/preview` | P | Allowed | Denied | Process-local permit binds actual session ID, current observation and provider; not passive read |
| `POST /api/ai/network-review/run` | W/export | Allowed | Denied | Consumes exact session-bound permit; explicit one-time export; session-ID cancellation owner |

Background health and service-log export run under their exact existing saved
approval, provider/device/source authority, rate limits and durable attempt
floors, not the account currently reading settings. Revoking a scope does not
claim to recall bytes already sent. A later named-grant slice must separately
decide how actor removal/revocation affects standing approvals; this inventory
does not silently change those contracts.

Evidence: `ai.go`, `ai_provider_test_route.go`, `ai_persistence.go`,
`proactive_ai.go`, `journal_ai.go`, `ai_network_review.go`,
`internal/aiconfig/settings.go`. `aiSettingsActor` has a named-ID branch, but
current LAN route admission denies those named writes: that branch alone is
**not evidence of personal-account AI administration**.

Concurrent #151 work is outside this baseline: its candidate adds
`POST /api/cases/{case}/analyze-preview` (process-local session-bound preview,
not `read`) and binds analyze confirmation to a single-use exact packet/provider
review. It preserves named administrative denial. Revalidate the final combined
revision and its added denial test before treating that candidate as implemented;
the 38-route baseline count below deliberately excludes it.

## 5. Accounts and session lifecycle

| Method and route / operation | R/W | Shared | Named | Actual identity / current boundary |
| --- | --- | --- | --- | --- |
| `GET /api/auth/session` | R | Anonymous or current session view | Same | Anonymous discloses no names/grants; authenticated named actor comes from immutable server configuration |
| `POST /api/auth/login` | W/session | Password-only in v1 | Exact username/password in v2 | Strict schema cannot supply actor, role or capabilities; named login never falls back to shared |
| `POST /api/auth/logout` | W/session | Allowed | Allowed | Current actual session only; Origin/CSRF, revocation and admitted-work drain; does not revoke other sessions |
| Protected `operatorAuthFile` provisioning/replacement + manager restart | W/account | Local explicitly authorized administration, **not HTTP** | Same | v1/v2 mutually exclusive; static grants; restart invalidates old memory sessions |
| Account listing/create/update/delete, password reset, grant edit, live reload, per-account session revocation, shared-to-named migration API/UI | W/account | **Absent** | **Absent** | No route or capability exists; do not invent a path or imply availability |

Evidence: `operator.go`, `internal/operatorauth/{auth,operators}.go`,
`internal/lanconfig/operators.go`, [named authentication](named-operator-auth.md).
Account configuration is read from the protected file; loaders do not provision
users, rewrite credentials or edit host permissions. Actual server-derived actor
identity is available for named sessions, but session metadata is not an audit
trail for every success.

## 6. Local file exports (distinct from external AI transmission)

| Method / operation | R/W | Shared | Named/read | Actual actor / export boundary |
| --- | --- | --- | --- | --- |
| `GET /api/devices` then browser **CSV export** | R + local export | Allowed | Allowed | N/S at read; CSV is generated from already fetched filtered device rows in `App.tsx`, no export API/grant/server event |
| Browser invitation bootstrap JSON download | Local export after W admission | Allowed after authorized invitation creation | Cannot create invitation | Previously returned public bootstrap only, not invitation secret; originating mutation has no human actor |
| Browser automatic-bootstrap JSON download | Local export after P admission | Allowed after authorized bootstrap request | Cannot request automatic bootstrap | Public bootstrap only; originating request has no human actor |
| `GET /v2/enrollment/bootstrap/{invite}` | R/public export | No account credentials accepted | Same | See public boundary above; no secret, lifecycle lookup, or human actor |
| Dedicated CSV/report/support-bundle server export route or export capability | Export | **Absent in the inspected API** | **Absent** | Do not confuse JS `export` declarations or package/update downloads with a data-export permission |

CSV currently contains device name, OS, status, source label, CPU/memory/disk
values and last-seen time. The separately retrieved endpoint-identity projection
is kept outside `model.Device`, general CSV and AI packets; reading it does not
authorize its export. Permission to read already delivered values cannot prevent
a client from locally copying them. A future export policy must distinguish
server-generated exports, local copies and AI transmissions, rather than
claiming an export button alone enforces an authorization boundary.
Evidence: `web/src/App.tsx` (`exportCSV`), `web/src/enrollment.tsx` (bootstrap-only
downloads), `internal/api/fleet_endpoint_identity.go`, `bootstrap_download.go`.

## Next-slice decisions and acceptance gates

This document deliberately assigns **no new capability names or bit positions**.
A reviewed follow-on must explicitly choose independent read/write grants for
enrollment, trust, customer catalog/associations, provider settings, each AI
execution/standing-export scope, accounts and any server export. Existing
maintenance/alarm/application-check capabilities must not imply any of them.
Customer reads and AI destination/settings reads need explicit product decisions;
the current legacy/read asymmetries above are facts, not permission proposals.

Before granting a new route, bind the immutable server `ActorID()` through
admission, approval, downstream service/store, durable audit and response where
appropriate. Reject request-supplied identity and recheck current authority at
dispatch; preserve logout, expiry, revision, replay, revocation and original
approval floors. Define static-restart and standing-job revocation behavior and
version any necessary records without adopting/relabeling older authority.

TB-06 remains open until **two separately named administrators plus a restricted
user** actually administer the reviewed surface without a common password,
direct requests lacking the exact grant fail server-side, every successful
administrative operation records the actual human actor, and positive/negative
route-grant and replay/revocation tests cover the final implementation. Three
fixture logins that are all denied administration do not meet that criterion.

## Verification scope

`internal/api/named_administration_contract_test.go` adds direct real-TLS-listener
contracts for 38 method/route denials: twenty enrollment writes across four
domains, two manual-trust writes, five customer reads/writes and eleven AI
settings/invocation routes. They cover anonymous requests, read-only identity,
and two distinct identities holding all current grants; forged body authority
cannot turn a denial into body/feature handling. Positive existing read admission,
missing-feature truth, actual login actor and unsupported HEAD are separate.
The fixtures configure no real provider, endpoint, enrollment issuer or customer
source and grant nothing on a host.

Recorded source-fixture verification on 2026-10-31: the focused command below
passed with the official Go `1.27.1 linux/amd64` toolchain and race detector
(`ok localrmm/internal/api 2.553s`). `gofmt`, diff whitespace, static parity of
all 38 documented denial rows and all 14 source-defined capabilities, and local
documentation links were checked. No full suite, real provider, installed
endpoint, browser E2E or production acceptance was run in that local check.
Automatic PR CI is separate exact-head evidence; a passing source fixture does
not waive failed UI/browser gates or establish native acceptance.

Focused check:

```sh
go test -race ./internal/api -run '^TestNamedAdministrationContract' -count=1
```

Run existing `internal/operatorauth` tests and the named route/capability tests
as regression checks before accepting a grant implementation. Compilation/source
fixtures are not native installation, account migration, browser E2E or production
acceptance. This slice's implementation report must state which checks actually
ran; a command shown here is not a claim of a passing execution.
