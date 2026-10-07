# Disposable Windows acceptance protocol fixture

This package is a **source candidate for an explicitly approved future native
Windows gate**. Importing it has no side effects. The controller alone may call
`Start(ctx)` or `StartSelected(ctx, selection)` after its exact runtime approval checks. It must not be called from `init`,
an ordinary `Test...`, an automatic native test, or a production manager.

This is not the Linux manager: it does not use or relax `enrollmentstore`'s Linux
protection gate, write SQLite, persist enrollment, serve a dashboard, establish a
browser result, or establish manager crash/reboot persistence. It uses the real
`enrollmentstate.Engine`, `enrollmentcrypto`, `enrollmentissuer`, and
`lanstore.ValidateFrame` / `FrameMatchesCollectionProfile` contracts in a one-identity,
non-durable fixture. Explicit HTTP inventory uses the production `signedhttp.New`
and `Verify` path, while receipt/replay state here still lives only in memory.

## Deliberate controller API

- `Start(ctx) (*Fixture, error)` creates only disposable memory authority and two
  ephemeral `127.0.0.1` TLS 1.3 listeners. The context or a 45-minute hard lifetime
  closes them. There are no configurable bind addresses or arbitrary routes.
- `StartSelected(ctx, profile.Selection) (*Fixture, error)` admits exactly
  `basic-readonly-v1` + `tls`, `windows-inventory-v1` + `tls`, or
  `windows-inventory-v1` + `http-test`. Zero, missing, broadened, or mixed
  selections fail before authority or listeners are created. `Start` remains
  the explicit basic/TLS compatibility entry point. The selected HTTP test uses
  the same fixed IPv4 loopback bounds and never falls back from TLS.
- `Bootstrap() enrollmentclient.Bootstrap` returns the exact selected profile,
  transport and origins, public issuer/root, and invitation ID. TLS returns the
  public server CA; explicit HTTP returns an empty `serverCaPem`. HTTP signatures
  do not encrypt inventory, hostnames, addresses, or enrollment traffic and do
  not authenticate the server. That plaintext risk needs its separate approval.
- `Secret(context.Context) ([]byte, error)` is callback-compatible. It returns a
  fresh memory copy for the approved enrollment client; that client must clear
  it. Never put these bytes in arguments, environment, files, URLs, logs, or chat.
- `Approve(expectedFingerprint, expectedComparison string) error` requires both
  exact values independently obtained from the endpoint's public display. There
  is no auto-approval or HTTP approval route. The real Engine records approval
  and intent before the disposable in-memory issuer signs and commits the leaf.
- `Snapshot()` returns only the real public lifecycle snapshot. `Evidence()`
  returns finite state/platform/profile/transport/count/sequence/outage metadata
  and `Inventory profile.Observation`. Its frame count and eight quality labels
  cover CPU, memory, disk, hostname, processes, services, software and interfaces.
  Every quality is `not_run` until an inventory frame is accepted. Accepted
  labels are only `healthy`, `partial`, `denied`, or `unavailable`; metric
  `unknown` maps to `unavailable`. `Usable()` requires a positive frame count and
  all eight qualities healthy/partial. No rows, names, addresses, metric values,
  raw frame, secret, verifier or private key are exported. Basic frames never
  create inventory evidence; retries do not refresh it.
- `ToggleUnavailable(bool)` returns a bounded 503 outage on the existing routes.
  It does not reset state/counters, change collection scope, adjust the clock, or
  shorten service deadlines. `Evidence.UnavailableRequests` counts admitted
  requests actually rejected during that outage without retaining their bodies.
  `Close()` is idempotent and closes both listeners.

The fixture never creates endpoint private state, invokes collectors, installs
services/accounts, changes ACLs/firewall/global trust, or exports a private key.
Native endpoint work remains the separately gated controller's responsibility.
Its public handle redacts formatting, JSON/text serialization, and structured
logging. Error responses contain fixed generic text.

## Fixed protocol and resource boundaries

The basic bootstrap/enrollment listener supports POST only on:

- `/v2/enrollment/challenge`
- `/v2/enrollment/claim`
- `/v2/enrollment/status`
- `/v2/enrollment/credential`
- `/v2/enrollment/activate`

Inventory substitutes the fixed `/v2/windows/enrollment/` prefix for the same
five enrollment operations and admits only `/v1/windows/agent/telemetry` on the
separate agent listener. Basic telemetry stays `/v1/agent/telemetry`. Profiles
cannot cross these routes or relabel a telemetry body.

TLS 1.3 requires a client certificate anchored to the exact disposable
client-only intermediate and matching the current activated identity. TLS 1.2,
HTTP fallback, and signed-HTTP headers on either TLS surface are rejected. The
explicit inventory HTTP peer requires all production Ed25519 signed-request
headers, exact Windows path/body/sequence/time binding, and the exact current
activated fixture certificate. Public-certificate authorization is checked under
the fixture lock before and after body verification, then checked again with
receipt/replay commit under that lock. A verified signature cannot retain
expired, inactive or changed authority. No signed fallback exists on TLS.
Cookies, ambient trust, forwarding/proxy headers, query aliases, extra
Tracebolt headers, redirects and arbitrary route dispatch are absent or rejected.

Every proof uses a purpose-bound, consume-once 60-second challenge and the actual
cryptographic proof decoder. There are at most 16 live challenges, two in-flight
handlers, eight live connections per listener, 4,096 admitted requests and 64
accepted distinct frames. Read/write/header/idle deadlines and byte caps apply.
The real Engine's ten-minute invitation and thirty-minute pending lifetimes are
unchanged. An explicitly approved native delayed-approval check may wait seconds;
it is not evidence for a thirty-minute wait. Deterministic service coordinator
deadline tests are a different proof.

The production frame/profile validators accept only the selected Windows
basic `tracebolt.agent-telemetry.v1` or inventory
`tracebolt.agent-telemetry.windows.v1` contract. Accepted sequence and
collection/envelope time floors strictly advance. Inventory also requires a
changed generation ID and strictly later inventory collection time. Exact
duplicate bytes at the current sequence precede those advancement checks and
produce the original `tracebolt.agent-receipt.v1` timestamps with
`duplicate: true`; conflicting or old sequence bodies fail.

The fixture retains the last body hash, receipt, generation/capture fences,
counters and finite quality labels. Raw telemetry is private and transient,
never retained in state or exported. Receiver receipts verify this protocol
peer's acceptance; native OS provenance still requires the controller's actual
Windows execution. Nothing here establishes Linux durable-manager or browser
acceptance.

## Disposable root custody

`Start` / `StartSelected` create a short-lived root, a distinct client-only pathLen0 intermediate,
and a separate loopback server leaf **in memory only**. Root generation here is
an explicit disposable acceptance-fixture exception, never production CA
provisioning. The root key is scoped to authority creation and cleared before
return; it is never stored in the fixture. Closing drops retained signing
handles and clears the invitation. Go/crypto may retain temporary copies, so
this is not a claim of secure memory erasure. No OS certificate store is used.

## Source verification and limits

Ordinary package tests use a private synthetic constructor with a fake clock,
invented Windows-shaped samples, and disposable memory-only cryptographic keys.
They never call either public start function, open sockets, perform a TLS handshake, read real OS
telemetry, touch endpoint private paths, create services, or modify ACLs. Handler
tests explicitly simulate TLS metadata and separately verify certificate chains.
HTTP tests use production signature construction/verification and a recent
injected timestamp because the production signed transport checks the real clock.
Those tests, the race detector and Windows cross-compilation are source evidence
only. The actual selected loopback exchange, native persistent identity/service/ACL
lifecycle, and future controller cleanup still require their approved native run.
