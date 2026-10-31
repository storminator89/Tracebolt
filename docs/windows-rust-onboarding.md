# Rust Windows onboarding without manual tokens

The Rust basic Windows installer defaults to automatic registration after
installation. A manager address and authenticated server TLS trust remain
required. The service generates its own fresh endpoint key, requests enrollment,
waits in the background for operator approval, obtains and activates its client
certificate, then reports automatically. No invitation needs to be copied into
a terminal. The existing invitation/token workflow remains available as an
explicit alternative and is unchanged.

## Manager prerequisite and approval

Use a configured Windows guided-enrollment **TLS, non-renewal** domain with its
protected client-auth issuer. This does not turn the synthetic demo or manual-v1
manager into a provisioned enrollment server, generate a server CA, or remove
certificate checks. The new routes are exposed by default in that existing
Windows TLS domain. Linux and macOS non-renewal TLS domains also support
automatic registration through their platform-specific public bootstrap artifacts;
HTTP-test and renewable domains retain the explicit invitation path.

In **Devices → Setup → Windows**, automatic requests are labeled
**automatic registration** (with the configured platform/profile). Compare the endpoint's local
public fingerprint and comparison value before approving. A name or request
alone is not device identity. Pending devices cannot fetch a usable certificate
or submit telemetry. Approval continues to use the existing Windows inventory
enrollment scope; the Rust implementation collects only CPU, physical RAM,
system-drive capacity and uptime. The display label does not establish a new
server-side basic-only authorization domain or attest to the installed program.

The agent listener still requires mutual TLS. Enrollment uses the separate
operator listener, with server-authenticated TLS 1.3 and no browser session.
Trust must already authenticate that listener; bootstrap data is never accepted
over unauthenticated HTTP. A configured agent origin can be separately pinned
by the installer/client.

## Protocol

0. Before installer staging or fresh enrollment initialization, read the public,
   bounded `/v1/windows/rust-basic-capabilities` contract over the independently
   selected TLS trust. Require the exact Rust-basic/enrollment/frame/receipt
   versions, origins and automatic-registration capability. This read creates no
   invitation, key, challenge or ledger and never grants consent. See
   [compatibility and failure boundaries](rust-manager-compatibility.md).
1. Generate/persist one fresh Ed25519 key and stable random `invite_`, `claim_`
   and `request_` identifiers before sending enrollment requests. Derive automated
   claim secret material from that key under a dedicated domain; do not expose
   it to the operator, log it, or write a separate invitation-token file.
2. POST `{ "invitationId": "invite_<32 lowercase hex>" }` to
   `/v2/windows/enrollment/self-bootstrap` over trusted server TLS. The response
   is the existing public `tracebolt.enrollment-bootstrap.v2` shape, with the
   requested invitation ID, exact manager/agent origins, issuer and public CAs.
3. Obtain a standard one-use `claim` challenge from
   `/v2/windows/enrollment/challenge`. Sign the standard v2 claim, including
   CSR and context-bound key-possession proof, then POST it to
   `/v2/windows/enrollment/self-claim` instead of `/claim`.
4. The manager verifies the proof and atomically creates the invitation and
   `claimed_pending` state. No half-created invitation remains on failed proof
   or transaction. Exact retries keep the original identity and deadline;
   conventional invitations cannot be adopted, and later lifecycle states are
   never reset. Clients reconcile uncertain submission using signed status.
5. Existing signed `/status`, `/credential` and `/activate` messages handle
   approval, issuance, delivery and activation. Private keys never leave the
   endpoint. Only activated certificates may use the existing telemetry ingress.

All normal freshness, original expiry, fingerprint comparison, operator mutation
authentication, revocation, retained-record limits and bounded proof concurrency
remain. Public bootstrap has its own per-peer/global admission budget. Challenges
retain their rate limits and one-use behavior. The pilot still has a 25-record
retention limit including tombstones; it is not an unlimited public registration
service and does not silently delete old identities to make room.

The optional token flow uses an operator-created invitation and the unchanged
`/claim` route. Its secret still belongs only in a hidden local prompt, never an
argument, environment variable, URL, log or installer package.

## Evidence

`self_claim` store/service tests cover atomic creation, replay/restart, failed
proof rollback, other-domain rejection, conventional-invitation isolation and
the approval-before-issuance boundary. API fixtures exercise actual loopback TLS
bootstrap without a browser session and reject old TLS/browser credentials.
The Windows enrollment UI test keeps fingerprint approval unchecked. These
tests do not establish a real Windows installation, endpoint trust provisioning,
native service-account acceptance or a live dashboard report.
