# Application-check setup: persisted configuration contract

This is an **unpublished source candidate**. It implements administrator setup for
the existing bounded HTTP/HTTPS, verified leaf-certificate expiry, DNS and TCP
checks. It adds no probe kind, credential support, endpoint permission grant,
incident history or alarm integration. Source/fixture tests do not authorize
configuration or outbound checks on a deployed manager.

## Operator workflow

Open **Settings → Application check setup** using a shared pilot administrator or
a named account explicitly provisioned with `manage_application_checks`.
Ordinary named `read`, `manage_alarms`, update and service-action grants do not
allow reading destinations or changing check settings. This UI cannot create an
account or grant the new capability.

1. Choose **Add targets** or **Edit targets**. Add one to eight targets total:
   HTTP/HTTPS uses a fixed URL; DNS uses a hostname; TCP uses a hostname or numeric
   address and one port. HTTPS automatically includes verified leaf expiry.
2. Supply distinct nonsecret IDs, 1–16 exact numeric allowed IPs per target, and a
   completion-based interval from 60 to 3600 seconds. Review and explicitly check
   private-LAN and plaintext-HTTP approvals where needed. Editing target fields
   clears their prior approvals. No IP/port range or credential field exists.
3. **Save draft** applies the existing strict destination validators and persists
   the complete draft **disabled**. It does not start a check. Saving a replacement
   cancels and joins the previous generation. A previously started request may
   already have reached its target; cancellation cannot recall it.
4. **Enable checks** shows the exact saved targets, IPs and interval. New unchecked
   confirmations acknowledge manager-origin checks and recurring requests to those
   destinations. An HTTP-test operator connection additionally requires its own
   plaintext configuration/approval warning. **Confirm enable** is bound to the
   displayed saved revision, not unsaved editor fields.
5. **Disable checks → Confirm disable** cancels and joins the worker and retains
   the disabled saved targets. Re-enabling requires a new explicit review.

The form does not store destinations or acknowledgements in browser storage.
Cancel, Close/Escape, navigation, hiding the page, access changes and uncertain
requests clear the relevant form/review authority. A lost or unsupported mutation
response is not retried automatically; refresh reads current saved state before
another decision. The form has no “test connection” or one-shot probe action.

## Existing destination policy is unchanged

All checks run from the management server. The existing strict v2 per-kind parser
is reused, including exact field sets, ID/URL/hostname/port syntax and IP policy.
Every DNS answer must match the exact target allowlist. Private-LAN approval never
admits loopback, link-local, metadata or permanently excluded special ranges.
Numeric pinning, one connection, no redirects/proxies/retries, normal TLS chain
and hostname verification, five-second attempts, bounded HTTP reads and at most
eight sequential targets remain unchanged.

Only side-effect-free, credential-free resources are supported. HTTP uses GET;
DNS observes system resolution; TCP connects to a single selected numeric address
and closes without application data. No auth headers, queries, request bodies,
content assertions, private-CA installation or insecure-TLS switches are added.
See [application checks](application-checks.md) and [DNS/TCP semantics](application-network-checks.md).

## API and authority

- `GET /api/application-checks/status` remains the original destination-free,
  authenticated read-only summary. Polling it performs no outbound check.
- `GET /api/application-checks/settings` returns the privileged setup view only
  after administrator capability admission. It is absent from development/agent
  surfaces. Named read-only accounts neither receive destinations nor issue this
  settings read from the UI.
- `POST /api/application-checks/settings` accepts operation-specific strict JSON
  within 32 KiB. Existing Origin/Host, authenticated session, CSRF, named capability
  and active-session mutation boundaries apply. Unknown, duplicate, null, aliased
  and operation-inappropriate fields fail closed. No other probe route is added.

The settings schema is `tracebolt.application-check-settings.v1`, with mode,
revision, configured/enabled/blocked flags, interval and exact v2 typed targets.
`save` sends revision, interval and targets. `enable` sends revision plus separate
manager-origin/destination acknowledgements and, for HTTP-test, operator-transport
acknowledgement. `disable` sends only revision and operation. Accepted changes
rotate both revision and internal generation; stale revisions and concurrent
changes fail rather than silently overwrite or replay.

## Persistence and lifecycle

Without `--application-checks-config`, the manager uses the initially off
`application-check-settings.json` inside its existing protected state directory.
The file binds manager identity (empty in manual mode), operator origin and
transport profile. The existing profile/account identity is never expanded or
recreated. Saved enabled configurations resume only when the manager's normal
supervisor lifecycle starts; constructing or reading settings is inert.

Strict bounded state and the latest 32 secret-free audit events share one atomic
protected envelope. Each event contains actor, operation, revision, generation and
timestamp only. Array/revision order records commit order; timestamps retain the
actual wall clock even after a clock correction, and Disable still stops checks.
Target URLs, hostnames, addresses, raw errors and certificate
subjects are not audit fields. File writes use owner-only temporary files,
create-only initial publication or atomic replacement, file/directory syncing and
protected readback. Unexpected file changes are detected before writes or new
worker activation. Corrupt, unsafe or mismatched saved state fails startup closed.

One supervisor owns one monitor. Save/enable/disable cancel and join the old
monitor before publishing a new generation; old retained rows never become rows
for a different draft. A completion-based cooldown uses monotonic scheduling and survives browser-driven
reconfiguration, so repeated toggles cannot turn the controls into a rapid probe
API. A newly enabled generation may therefore wait for the previous generation’s
cooldown before its first attempt. The existing sequential round interval still
applies. Stop/shutdown joins
checks before manager stores close.

A failed or uncertain durable change stops local checks and blocks this controller.
Refreshing does not clear that block. Restart revalidates the protected persisted
file; the last durably committed configuration may be the old or new revision.
Inspect it before restarting after an uncertain administrative change. The UI
never reports an unconfirmed mutation as accepted.

An explicit `--application-checks-config` file takes precedence, including an
explicitly disabled file. Its startup snapshot remains browser read-only and does
not adopt or overwrite managed settings. Changes to that file still require a
separately authorized manager restart. No file paths or targets are supplied by
this source candidate.

## Verification and remaining acceptance

Core tests inject transports and clocks to cover no-network construction/saves,
persisted restart bindings, explicit-file precedence, strict parser reuse,
capability/CSRF/session boundaries, durable failures, cancel/join, old results and
cooldown. UI tests cover save-off/review/enable/disable, target limits, invalid
responses, acknowledgement reset and interrupted writes. Hosted browser fixtures
intercept invented configuration; they never contact a target or write real
settings. Their geometry and screenshot assertions require an exact-revision
browser run. Local Chromium was blocked before page creation by the editing
sandbox's socket permission; no visual/native acceptance is claimed here.

Publication, deployment, real destination selection, managed-file provisioning
through the UI and actual outbound acceptance remain separate authorized work.
