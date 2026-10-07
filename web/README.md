# Tracebolt Web

English-default React/TypeScript admin UI for the Tracebolt prototype, with a German language switch. Source labels distinguish synthetic demonstration devices from the actual sandbox collector; no API failure is replaced with fixtures.

## Run

From `web/`:

```sh
npm ci
npm run build
```

From the repository root, start the Go manager using the project README. It serves `web/dist` at the same loopback origin as the API (default `http://127.0.0.1:8787`).

For changes, run `npm run dev` in `web/` (build and watch), keep the manager running, and refresh the browser. There is deliberately no permissive Vite API proxy: strict same-origin and CSRF checks remain intact. `npm run preview` is only an asset preview, not the supported API-integrated application.

## Checks

```sh
npm run typecheck
npm test
npm run build
npm audit --omit=dev
npm audit
```

All fonts/icons are installed dependencies served locally; no CDN or remote font request. The explicit language preference (English unless German is chosen), dark/light theme and one saved inventory view persist in local browser storage. UI labels, errors, status and dates are localized; collected evidence, notes and model output retain their original text. CSV export neutralizes formula-leading cells. Notes validate the backend's 2000 UTF-8 byte limit. Dynamic strings are rendered as React text, not HTML.

### Selected package-update workflow: simulation only

The Updates workspace now connects detected cached-candidate rows to a bounded
selection, independent preparation, immutable review, explicit confirmation and
saved status/results. Select at most 32 exact package name + architecture pairs;
selection and acknowledgment reset when the device, inventory source or operator
session/access scope changes. No arbitrary package or command entry is offered.

The independent `tracebolt.package-update-workflow.v1` contract is read from
`GET /api/devices/{deviceId}/package-updates`. Preparation sends only a new stable
request ID and canonical sorted identities to `/prepare`. The server's separate
adapter supplies exact versions, source package/version, source label, suite,
component, archive SHA-256, total download bytes, expiry, actor and transport.
Cached row versions are never submitted or converted into verified plan evidence.
The English/German review retains the server's immutable preview throughout its
saved job history.

Named `plan_updates` and `execute_updates` capabilities are independent and are
revalidated before their respective writes. Confirmation sends only the original
request ID and preview digest, and is enabled only for a nonexpired, actor-bound
`preview_ready` job after acknowledgment that package scripts may restart
services, no reboot happens automatically and rollback is not guaranteed.
Successful status requires every approved identity and exact version to have
matching verification evidence; a saved approval alone never displays success.

Lost write responses do not create another operation or automatically replay a
POST. Recovery reads the exact durable
`GET /api/devices/{deviceId}/package-updates/jobs/{requestId}` record. Only its
explicit `package_update_not_found` response can open a missing-prepare recovery
path: fresh named plan access and current simulation admission are rechecked,
and the original intent is retained. Generic 404 or unreadable status cannot
open that retry gate. An explicit retry preserves the same request and identity set or approval digest. A bounded,
nonsecret recovery intent in session storage contains only device/actor/session
scope, request ID, selected identities or approval digest. It contains no token,
full preview or source provenance, and is cleared on access invalidation or a
different device/actor/session scope. The manager's saved job remains authoritative.

Only the explicit simulation adapter can provide an available workflow in this
source candidate. Its UI is conspicuously labeled **SIMULATION ONLY** and all
package/result evidence is synthetic. Production remains
`executionMode: unavailable`, `available: false`, `native_adapter_unavailable`,
with null preview/job and disabled preparation/confirmation. This work does not
ship a protected native adapter, run a host update, or establish native/release
acceptance. Existing complete and limited cached-inventory readers keep their
separate local-consent and provenance boundaries.

## Screenshots

`node scripts/capture-screenshots.mjs` captures actual rendered UI against the running manager with Playwright. Install the official browser with `npx playwright install --with-deps chromium` on a supported development or CI runner. Optional environment variables:

- `TRACEBOLT_BASE_URL` (default loopback port 8787)
- `TRACEBOLT_SCREENSHOTS` (output directory)
- `CHROMIUM_PATH` (an existing browser executable)

The capture script explicitly selects German and uses only synthetic-device inventory, case, and drawer views. The workspace is viewport-bounded: content scrolls independently of the navigation and header. Gallery captures use viewport framing, not stitched full-document images of fixed navigation. The overview screenshot is deliberately cropped above the mixed-source table, excluding actual sandbox telemetry. It fails if synthetic inventory contains a real-source row, mobile pages overflow, or JavaScript errors occur.

Browser evidence is produced by the hosted CI runner against the compiled UI and a disposable local manager. Screenshots are associated with their exact source commit. The first reviewed UI snapshot was `594e88e`; newer UI changes require a new browser run and captures.

## Optional AI diagnosis

Settings includes a native OpenAI-compatible provider panel: base URL, model and a password field for a freshly entered API key. Configuration and credentials are kept only in manager memory, cleared by restart, and never read back into or stored by the browser. Changing the destination clears the entered key and remote-evidence consent. Saving configuration does not contact or verify the provider.

An investigation can request one bounded analysis after showing the exact destination and obtaining explicit operator review. Case title/summary and selected evidence text are sent without automatic secret redaction; review them first. A loopback endpoint may itself relay externally. There is no automatic provider request, periodic analysis, command execution or remediation in this version.

Model hypotheses stay separate from the deterministic rule finding. Citation buttons open the exact analyzed evidence snapshot. Missing/stale evidence and unconfirmed root cause remain visible. Configuration races, superseded responses, navigation and cancellation cannot install an old result into the current view. AI results are transient and disappear on reload.

## Operator access

The UI first reads the manager's explicit `/api/auth/session` contract. Development mode remains clearly unauthenticated. LAN mode loads protected data only after confirmed operator access, with no automatic replay of interrupted writes. Passwords and CSRF/session tokens are never placed in browser storage. Sign-out clears visible private state, aborts pending requests and broadcasts invalidation to other tabs. A non-secret pending-sign-out marker protects reloads when server confirmation is unavailable; if neither storage mechanism works, the UI explicitly warns about that limit. Hidden/BFCache-restored workspaces are concealed and the actual session is revalidated before showing their contents.

HTTPS is the normal LAN transport. Explicit HTTP LAN test mode keeps a persistent warning on the login and workspace surfaces: passwords and data can be read on the network. Declared LAN transport must match the actual browser protocol, otherwise access fails closed. No trust is inferred from forwarded headers or a hostname.

Auth and language component checks run with the app's unit suite. Real browser acceptance belongs to the exact source commit recorded by the hosted CI; prior gallery results do not validate a newer source snapshot.

## Conditional device enrollment

LAN inventory includes an enrollment panel backed by `/api/enrollment`. Creating an invitation requires the manager to explicitly report enabled Linux support; unconfigured, failed and capacity-limited states keep creation disabled. Development/demo mode does not show an enabled enrollment flow. Windows and macOS enrollment are unavailable in this version, and no installer or native-client download is claimed. Runtime issuer/client integration and real-handler browser acceptance are separate gates.

The creation response contains a one-time invitation secret. It is masked by default and retained only in the open dialog's memory. Reveal and clipboard copy require separate explicit clicks. Closing, navigating, hiding the page, claiming the invitation or losing operator access removes it from the UI; this is not a secure-memory zeroization guarantee. Explicitly copied clipboard contents remain the operator's responsibility. An uncertain creation is never automatically replayed; the operator checks the current record, cancels if needed and creates a replacement.

Only a whitelisted public bootstrap schema can be downloaded, on an explicit click. It contains exact destinations, profile, public trust material and the invitation ID. Secret-bearing downloads are unsupported. The UI rejects extra bootstrap fields, private-key material and mismatched destinations/identity before enabling export. The compatible native client must independently validate that public trust and take the invitation through its hidden prompt; no invitation is placed in a URL, command argument or browser storage.

Approval requires the operator to compare both the complete SHA-256 key fingerprint and context-bound comparison value on the device. Confirmation is bound to the displayed key, comparison value and revision. Lifecycle mutations carry that revision, require CSRF, do not automatically replay, and cannot replace newer revoked state with a delayed older response. Cancel/reject/revoke actions are phase-specific and require a visible final confirmation. Issued/activated identity states do not establish online status, ongoing collection, an installed service or device health. Deadlines use the validated server clock plus monotonic elapsed time, with a conservative request-duration allowance; browser wall-clock changes cannot extend an invitation. Expired approval stays disabled and the displayed secret is removed at its deadline. Hiding or leaving the page invalidates the clock anchor; approval waits for a fresh server response and a new comparison after return. The 25-record cap includes retained terminal records.


### Device diagnosis navigation

The full-width overview presents compact icon-labelled Last report, Warnings and Updates
cards above CPU, memory and disk observations. Contact is the last accepted report,
not a live reachability test. Optional interpretation is available through the
keyboard- and touch-accessible **Details → About these values** disclosure. Main
views keep meaningful labels and explicit warning states without repeated explanatory
subtitles or source promises. Warnings cover the existing selected Health checks;
unknown checks never become zero warnings. Updates use only the existing complete
cached-candidate ledger, with original age, stale/unknown cache freshness and partial
comparisons visible. Counts are not an installability or security assessment.

Overview reads are cancellation-aware and serial: existing identity metadata, then
one metadata-only update read, then one Health read when supported. Summary readers
add no polling, update-page query or collection. On restoration they wait for a fresh
identity read again. Full Health/Updates subviews retain their existing behavior.
Software inventory, full certificate/identity information and measurement sources
are in **Details**. Certificate expiry warnings remain on Overview. Metadata refresh
preserves the current subview, drafts, disclosures and scroll position. The selected inventory panel separately checks its first page every 15 seconds, atomically replacing only validated complete generations. Paging and unsubmitted search/filter edits pause those checks; captures keep their original times. See [inventory refresh boundaries](../tests/e2e-review/INVENTORY_LIVE_REFRESH.md).

For journal-compatible service units, **Open logs** in Services or Health opens the
existing Logs tab with only the exact-unit draft filled in. It does not create or
cancel a capture, grant local access, or acknowledge content/plaintext consent.
Existing captures keep their own service and query labels. Repeatedly selecting
Logs and refreshing device metadata preserve the current form instance and draft;
leaving the tab or device discards the handoff.

The hosted journal and v3 browser cases include service handoff/back navigation and
responsive overview checks. They also capture the rendered desktop/mobile device
overview with clearly synthetic fixture data as `synthetic-v3-device-overview-{desktop,mobile}-en.png`. These are required
on the final published source; source tests alone do not establish browser acceptance.

### Operational device inventory candidate

The authenticated device drawer exposes an **Inventory** tab for Linux LAN devices
and LAN identities whose platform has not yet been observed. Selecting it performs
the protected operational GET; the server explicitly distinguishes a basic profile,
awaiting data, current/retained observations, and errors. Synthetic/local demo devices
do not gain operational fixtures. Leaving the tab, changing device, losing operator
access or restoring a suspended view clears/refreshes the observation state.

For fresh `managed-operations-v1` enrollment, the manager must advertise the matching
`metadata_labels_may_be_sensitive` privacy value. The dialog names all six collection
categories, warns that names/mount paths may be personal or sensitive, and requires
an unchecked affirmative checkbox. Only this profile sends
`collectionAcknowledged: true`; basic enrollment retains its existing request body.
The returned snapshot/bootstrap must match the acknowledged profile, and confirmed
profile changes close the invitation dialog. Failed or malformed current-configuration
reads also invalidate the clock, consent and open dialog. In-flight writes are
aborted, older responses cannot restore a token, and an already-submitted request
remains explicitly unconfirmed until its server state is checked. Recovery requires
a fresh unchecked acknowledgement. Consent is not stored in the browser.
Direct command lines, environment variables and raw message bodies remain excluded;
namespace/permission coverage is bounded and operational observations are excluded
from AI evidence by the server policy. This integration does not migrate identities,
install a service, or turn unknown update/CVE assessment into a health claim.

Component and integration checks are local. Real-handler Chromium and safe synthetic
viewport captures must be run against the exact publication candidate separately.

### Compact service-log workspace

Logs use a service chooser, fixed-reference period presets and a Fetch logs action.
Advanced retains manual unit entry, exact UTC times and severity. Fetch only opens
an exact request review with the existing unchecked content and HTTP consent; final
Capture logs is the sole creation action. Dismissal clears review consent. Draft
edits invalidate an older review, and same-device metadata refresh preserves it.
Policy freshness, reported scope, session, paused/uncertain state and active-request
checks remain unchanged. Selecting a service or time never collects logs.

Permission status remains visible; verbose source/limit explanations are in native
accessible disclosures. Pending requests and captured results keep their original
service/window independently of draft edits. The resource/API/collector protocol
and local permissions are unchanged. The hosted journal runner validates real
rendering and produces exact-source desktop/mobile workspace and review captures.

### Alarm delivery status

Authenticated LAN Settings includes a compact read-only alarm panel using the
existing aggregate `/api/alerts/status` contract. Provider acceptance, pending,
failed, uncertain and dropped gaps stay distinct; Details breaks pending down
into queued/in-flight and explains suppression and retained-history scope.
Acceptance never proves receipt by a person. Disabled configuration stays quiet
without hiding retained failures. English is the default, with German labels.

Entry and explicit refresh read saved counts only. There is no polling, automatic
retry, sender control, destination editor or event replay. Failed refreshes retain
the previous snapshot with its original browser loading time and unknown current
status. Losing access, navigating away or suspending the page clears it and aborts
late reads. These source/component checks do not establish real webhook delivery.

### Capability source states

The capability view separates the manager-selected collection profile (`scope`)
from current source observations. Profile declarations are neutral; they never
prove a completed installation, successful read or healthy device. Endpoint
observation bundles still reject the manager-only `scope` value.

For complete-profile devices, visible authenticated capability views read the
existing bounded system, complete-overview, package and journal status endpoints
at a 15-second cadence. They do not fetch inventory rows or journal bodies,
start captures, or change grants. The original capture time remains authoritative;
retention and repeated reads cannot refresh old data. Hidden views, lost sessions,
invalid data and interrupted requests cannot retain a successful live status.

Denied access, collection/transfer failures, missing configuration, stale data,
unknown data and unsupported sources are distinct. New failures remain visible
even when an older complete generation exists. Expected process exits and
not-applicable filesystem capacity fields do not become source failures. Socket
collection and privileged owner-source provenance are separate; per-connection
attribution gaps remain in Connections. An enabled journal policy means
Configured, never proof of successful content access. The legacy automatic
journal-metadata preview is separate from the read-admin on-demand log helper.

Read-admin onboarding still uses one combined local approval for its supported
read scopes. This UI does not ask for additional grants or normalize missing
permission for an approved supported read. Technical source explanations stay
available in keyboard-accessible, initially collapsed disclosures.

### Service-action-v2 review

The browser accepts both the unchanged strict v1 contract and the independent
v2 full-admin service contract. V2 requires the exact local scope/review notice,
up to 256 sorted eligible/excluded units, and each eligible unit's complete
sorted affected-service list (1–64 units including the target). Before displaying
a preview, it compares that list with the selected capability and independently
checks SHA-256 of the canonical impact JSON against the signed plan projection.
This browser check is not signature verification or host authorization: the
manager and root helper independently enforce those boundaries.

The review shows every affected service in a scrollable list, the exact authority
warning, expiry and any HTTP risk before explicit interruption consent. Technical
digests and inert exclusion reasons remain collapsed. Closing, navigation,
access/session changes, stale replies and new preview bytes never retain consent.
Approval still submits only the original preview ID and digest, revalidates the
named session and never retries a service action automatically. Only service-view
response reads use the 256 KiB v2 allowance; session reads retain the 32 KiB bound.
Known v1 preview/approval responses retain the original 32 KiB cap; v2 preview
responses explicitly select 256 KiB from the validated view, and approvals select
the version of the reviewed preview. Initial status GET negotiates within 256 KiB.
Subsequent status reads retain the discovered version/bound; responses cannot
silently switch versions until fresh discovery.
No setup grant, native dispatch, provider call or production acceptance follows
from browser fixtures. Unit/API/component coverage is executable with `npm test`.
