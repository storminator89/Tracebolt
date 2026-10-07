# Disposable Windows acceptance protocol fixture

This package is a **source candidate for an explicitly approved future native
Windows gate**. Importing it has no side effects. The controller alone may call
`Start(ctx)` after its runtime approval checks. It must not be called from `init`,
an ordinary `Test...`, an automatic native test, or a production manager.

This is not the Linux manager: it does not use or relax `enrollmentstore`'s Linux
protection gate, write SQLite, persist enrollment, serve a dashboard, establish a
browser result, or establish manager crash/reboot persistence. It uses the real
`enrollmentstate.Engine`, `enrollmentcrypto`, `enrollmentissuer`, and
`lanstore.ValidateFrame` contracts in a one-identity, non-durable fixture.

## Deliberate controller API

- `Start(ctx) (*Fixture, error)` creates only disposable memory authority and two
  ephemeral `127.0.0.1` TLS 1.3 listeners. The context or a 45-minute hard lifetime
  closes them. There are no configurable bind addresses or arbitrary routes.
- `Bootstrap() enrollmentclient.Bootstrap` returns the explicit public CA,
  dedicated issuer, invitation ID, TLS origins, and `basic-readonly-v1` profile.
- `Secret(context.Context) ([]byte, error)` is callback-compatible. It returns a
  fresh memory copy for the approved enrollment client; that client must clear
  it. Never put these bytes in arguments, environment, files, URLs, logs, or chat.
- `Approve(expectedFingerprint, expectedComparison string) error` requires both
  exact values independently obtained from the endpoint's public display. There
  is no auto-approval or HTTP approval route. The real Engine records approval
  and intent before the disposable in-memory issuer signs and commits the leaf.
- `Snapshot()` returns only the real public lifecycle snapshot. `Evidence()`
  returns finite state/platform/profile/count/sequence/outage metadata, never a
  raw frame, metric, observation, secret, verifier, or private key.
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

The bootstrap/enrollment listener supports POST only on:

- `/v2/enrollment/challenge`
- `/v2/enrollment/claim`
- `/v2/enrollment/status`
- `/v2/enrollment/credential`
- `/v2/enrollment/activate`

The separate agent listener requires a client certificate anchored to the exact
disposable client-only intermediate and supports only POST
`/v1/agent/telemetry`. The exact issued leaf must also belong to the activated
Windows/basic identity. TLS 1.2, HTTP fallback, ambient trust, cookies, forwarding
headers, signed-HTTP headers, redirects, proxy headers, query aliases and
arbitrary route dispatch are absent or rejected.

Every proof uses a purpose-bound, consume-once 60-second challenge and the actual
cryptographic proof decoder. There are at most 16 live challenges, two in-flight
handlers, eight live connections per listener, 4,096 admitted requests and 64
accepted distinct frames. Read/write/header/idle deadlines and byte caps apply.
The real Engine's ten-minute invitation and thirty-minute pending lifetimes are
unchanged. An explicitly approved native delayed-approval check may wait seconds;
it is not evidence for a thirty-minute wait. Deterministic service coordinator
deadline tests are a different proof.

Only schema-valid `tracebolt.agent-telemetry.v1` frames with Windows platform and
the basic profile are accepted. Accepted sequence and collection/envelope time
floors are monotonic. Exact duplicate bytes at the current sequence produce the
original `tracebolt.agent-receipt.v1` timestamps with `duplicate: true`; conflicting
or old sequence bodies fail. The fixture retains only the last body hash, receipt
and counters, not raw telemetry. Receiver receipts verify the protocol peer's
acceptance; native OS provenance still requires the controller's actual Windows
execution. Nothing here establishes Linux durable-manager or browser acceptance.

## Disposable root custody

`Start` creates a short-lived root, a distinct client-only pathLen0 intermediate,
and a separate loopback server leaf **in memory only**. Root generation here is
an explicit disposable acceptance-fixture exception, never production CA
provisioning. The root key is scoped to authority creation and cleared before
return; it is never stored in the fixture. Closing drops retained signing
handles and clears the invitation. Go/crypto may retain temporary copies, so
this is not a claim of secure memory erasure. No OS certificate store is used.

## Source verification and limits

Ordinary package tests use a private synthetic constructor with a fake clock,
invented Windows-shaped samples, and disposable memory-only cryptographic keys.
They never call `Start`, open sockets, perform a TLS handshake, read real OS
telemetry, touch endpoint private paths, create services, or modify ACLs. Handler
tests explicitly simulate TLS metadata and separately verify certificate chains.
Those tests, the race detector and Windows cross-compilation are source evidence
only. The actual loopback TLS exchange, native persistent identity/service/ACL
lifecycle, and future controller cleanup still require their approved native run.
