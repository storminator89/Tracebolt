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

The full-width overview leads with CPU, memory and disk observations. Software and
certificate summaries share the desktop width and stack on small screens. Complete
software counts, original collection time, age and status stay visible; generation
identifiers and retention details expand on request.

For journal-compatible service units, **Open logs** in Services or Health opens the
existing Logs tab with only the exact-unit draft filled in. It does not create or
cancel a capture, grant local access, or acknowledge content/plaintext consent.
Existing captures keep their own service and query labels. Repeatedly selecting
Logs and refreshing device metadata preserve the current form instance and draft;
leaving the tab or device discards the handoff.

The hosted journal and v3 browser cases include service handoff/back navigation and
responsive overview checks. They also capture the invented desktop/mobile device
overview as `synthetic-v3-device-overview-{desktop,mobile}-en.png`. These are required
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
