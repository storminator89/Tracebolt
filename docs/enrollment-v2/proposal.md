# Guided enrollment and native lifecycle proposal

This document preserves the original design proposal. For the implemented opt-in Linux checkpoint, use [runtime configuration](runtime-config.md), [HTTP contract](http-contract.md) and [native client](native-client.md). Proposed limits/routes and installer/service plans below are not a substitute for those contracts.

> Historical design/model baseline. Subsequent isolated implementation now includes the durable store, fixed issuer, application service and optional HTTP handler. See [durable store](durable-store.md), [issuer](issuer.md) and [HTTP integration contract](http-contract.md) for current boundaries. The original statements below describe their earlier stage; they are not native installation or deployment acceptance. Inspection JSON still cannot restore authority; RestoreTrustedLedger is an explicitly trusted local-storage boundary.


## Decision and status

The next milestone should replace manual certificate-file handling with **Add device → run the platform-specific installer → review the matching device code → approve → see connection and collection status**. Keep one administrator and one environment. This document proposes contracts and acceptance tests; no issuer, invitation, installer or service behavior described here is implemented or deployed yet.

The checked baseline is the separate LAN manager plus Linux one-shot sender. Their source overlays are identified by manifest SHA256 `5bdcf28bf81d386b7ee5115b6975717161df0289c7cd8c2ed1b5292de62091a5` and `f4494deb227775d561274333718f8d3c92670b5a2bbb1068a8a7524c70e055af`. Existing v1 protocols and manually approved identities must remain usable during an explicit version transition. Broad inventory collection is a following, independently reviewed protocol/profile change.

## What exists today

- `internal/operatorauth` and `internal/api/operator.go`: bounded single-admin authentication, exact Origin/CSRF checks, session expiry, logout mutation ordering and analysis cancellation.
- `internal/lantrust`: manually approved public certificates; explicit roots; TLS 1.3; request-time approval/revocation.
- `internal/lanstore`: opaque identities, durable latest observations and replay floor; atomic revocation check at telemetry commit.
- `internal/signedhttp`: a deliberately separate HTTP-test signature protocol, without confidentiality or server/UI authenticity.
- `internal/lanclient` and `internal/lanclientstate`: protected preprovided material, one Linux foreground attempt, one bounded exact pending frame, private atomic state and fail-closed destination binding.
- `tests/lanclient`: actual separate native manager/sender processes, restart/replay/revocation proof on loopback using disposable trust material.

There is no built-in certificate issuer, enrollment invitation, automatic renewal, installer, scheduled service, full inventory profile or production deployment acceptance. The current support bundle remains a limited, identifier-minimizing observation.

## Administrator experience

1. **Prepare the server once.** A guided, local setup explains the operator origin, agent origin, storage location and TLS trust. It validates the supplied browser/server certificate and guides an explicit user-led import/provisioning step for a per-instance agent-issuing intermediate. The root private key remains offline and outside the runtime; there is no automatic CA creation. No real key or credential is created as part of this design work. An already configured Docker or native server presents the same UI.
2. **Add device.** Select Linux, Windows or macOS and a display label. The UI shows the collection profile, transport and permissions that will be requested. Unsupported installer platforms remain visibly unavailable rather than presenting a fake download.
3. **Start the verified installer.** Prefer a signed/version-pinned artifact and a public bootstrap file, followed by a hidden invitation prompt. A browser download cannot guarantee private file permissions. A secret-bearing enrollment file is an optional later route only if it is created with private ownership/ACL protections before its first secret byte is written. Checking or chmodding an ordinary download afterward cannot undo exposure, so this optional route stays disabled until that property is guaranteed. Do not put the invitation in a URL, shell history, process arguments, environment variables, logs or browser storage. The default bootstrap file contains public origin/trust information only; users do not hunt for certificate files. Never suggest echoing a token into a command or environment variable.
4. **Match and approve.** The installer generates its private key locally, claims a pending registration and displays the complete SHA256 public-key fingerprint and a context-bound 128-bit comparison value, grouped for readability. Derive the comparison value from a versioned domain plus manager instance, invitation ID, claim ID and public-key fingerprint. A short numeric code must not become the sole approval evidence. The operator sees the same code, the requested platform/version and transport. Approval is a deliberate authenticated action. Labels, OS information and check codes are claims, not proof of a healthy or uncompromised endpoint.
5. **Show useful progress.** Distinguish invitation created, waiting for client, waiting for approval, identity issued, first connection, collection partial, last observation stale, credential expiring and revoked. A received sample is not evidence of an installed or continuously running service.
6. **Install the native lifecycle only when supported.** An installer explains its service account, read permissions, startup behavior, data directory, update policy and removal behavior before requesting elevation. The one-shot/foreground mode remains available. Actual service installation/reboot/uninstall tests require a separately authorized target environment.

Errors should name the next action without leaking tokens or raw server messages: wrong server/trust pin, expired invitation, already claimed by another key, awaiting approval, approval rejected, unsupported platform, denied collection permission, clock skew, state binding mismatch, storage full, revoked identity or unreachable manager. Repeated clicks and interrupted responses must not create duplicate active devices.

## Trust setup and issuer custody

Keep the root private key offline and use a distinct per-instance **agent-only issuing intermediate** with path-length zero, separate from the operator/server TLS identity and from the HTTP-test issuer. The narrow first implementation accepts preprovided protected intermediate material or an explicitly configured external signer; it does not create a CA automatically. The eventual user-led setup wizard must guide provisioning/import and protected recovery without requiring routine manual certificate-file hunting. Keeping the root private key outside the runtime limits online issuer custody; public root certificates may be distributed for normal verification. Basic-constraints/path-length enforcement follows the X.509 certificate profile, while the exact custody policy is this project's choice. [RFC 5280 basic constraints](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9)

The manager identity includes a random immutable instance ID and versioned public trust metadata. Agents bootstrap from an exact origin plus an explicitly supplied public CA bundle obtained through the authenticated operator workflow, optionally with an additional server public-key pin. Normal certificate-chain and SAN checks remain enabled; a pin is not permission to disable TLS verification. The public bootstrap file carries this trust material so the user does not locate it manually. There is no silent trust-on-first-use, redirected enrollment, proxy-derived authority or global OS trust-store change. A browser still needs a normally trusted operator TLS certificate; an installer cannot make an untrusted browser session trustworthy by hiding its warning.

Keep the intermediate issuing key in a dedicated private file or an explicitly configured secret provider, never ordinary SQLite records, logs, backups of exported reports, container layers or browser responses. Validate ownership, symlinks, role and key agreement before use. A file-only pilot protects the key through a dedicated runtime account and private volume; it does not claim hardware isolation or encryption against a compromised runtime UID. Document protected backup/restore and compromise recovery before allowing unattended use. The policy should account for key generation, custody, rotation and destruction throughout the lifecycle. [OWASP key management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)

Issuance uses standard X.509 primitives and a fixed client-only template: server-assigned identity, approved public key, non-CA, digital signature, exclusive client-auth EKU, bounded validity and unique serial. Verify the PKCS#10 signature before considering a CSR, then treat subjects, names, extensions, usages and validity as untrusted requests rather than authorization. Signature verification and the authority's issuance decision are separate steps. [PKCS#10 request processing](https://www.rfc-editor.org/rfc/rfc2986.html#section-3) Issuer possession alone must not authorize telemetry: the independent device/key approval registry and active certificate records are checked on every request and durable commit.

## Proposed enrollment state machine

Suggested initial limits are proposals to verify under load, not measured product guarantees: invitation TTL 10 minutes, at most one successful claim, pending approval TTL 30 minutes, at most 100 outstanding invitations and100 pending claims per instance, and bounded per-source plus global claim rates. Use 256-bit random invitation secrets and store only a keyed or SHA256 verifier with constant-time comparison; raw secrets are returned once through an authenticated response or protected download.

`created → claimed_pending → approved_issued → activated`

Terminal alternatives are `expired`, `canceled`, `rejected` and `revoked`. Terminal states do not silently return to active. Device and invitation identifiers are generated by the server. A public pending ID does not authorize polling, issuance or telemetry.

- Invitation creation is an authenticated, CSRF-protected operator mutation with a recent-authentication policy for access-granting actions. Bind it to the manager instance, transport profile, intended installer/platform and selected collection profile. Platform information from a client remains untrusted.
- A claim includes the invitation, a bounded CSR/public key, agent protocol/version, and proof of possession bound to the exact manager instance/origin, invitation ID, request ID, challenge and canonical request digest.
- Atomically consume the invitation and bind it to that key and claim digest. An exact same-claim retry returns the same pending outcome; a different key or changed claim cannot reuse it. Loss of the original invitation-create response is handled by revoking/replacing the inaccessible invitation, not by storing retrievable plaintext secrets.
- Pending status requests require proof from the bound device key and a short-lived challenge. They can read only that pending outcome and cannot submit telemetry, enumerate other candidates or act as an operator.
- Approval records the selected public key and assigned device identity before any certificate is available to the client. Persist an issuance intent with its serial, key fingerprint, immutable template and validity before signing. Store the resulting certificate before delivery and return that same certificate on retries. A crash between signing and committing must not create a second identity or deliver an unrecorded usable credential; an external signer must have an explicit idempotency/reconciliation contract.
- First authenticated telemetry activates the already approved identity; it does not approve a new key. Rejection, expiration, cancellation and revocation are checked again before issuance and before the first commit.

## Draft API boundaries

These route names are illustrative v2 contracts, not existing endpoints:

| Surface | Proposed operation | Authority and scope |
| --- | --- | --- |
| Operator | `POST /api/enrollment/invitations` | Session, exact Origin, CSRF, recent authentication; creates one bounded invitation |
| Operator | `GET /api/enrollment/invitations` | Redacted IDs/status/expiry only; never secret recovery |
| Operator | `POST /api/enrollment/invitations/{id}/cancel` | Revokes unused/claimed invitation as a durable mutation |
| Operator | `GET /api/enrollment/pending` | Minimal bounded pending metadata and public-key comparison code |
| Operator | `POST /api/enrollment/pending/{id}/approve` | Explicit fingerprint/key confirmation and selected collection profile |
| Operator | `POST /api/enrollment/pending/{id}/reject` | Durable denial; does not erase audit/replay records |
| Enrollment | `POST /v2/enrollment/claim` | Verified server TLS plus single-use invitation and key proof; no browser/operator cookies |
| Enrollment | `POST /v2/enrollment/status` | Bound pending-key proof/challenge; exact pending object only |
| Agent | `POST /v2/agent/renew` | Current active credential plus new-key proof; generation and revocation checked atomically |
| Agent | `POST /v2/agent/telemetry` | Active identity and negotiated typed collection contract |

Enrollment must have a distinct router and a **server-authenticated TLS handshake that does not require a client certificate**. A path behind the existing RequireAndVerifyClientCert telemetry listener cannot bootstrap a new client. The minimal proposal partitions the already server-authenticated operator HTTPS listener with an exact enrollment route dispatcher; enrollment rejects browser cookies, Origin headers and operator credentials and retains its own bounds/rates. A separate enrollment listener is an alternative if strict router separation is not straightforward. The existing agent listener continues to require mTLS with no fallback. Operator routes still use their original session/Origin/CSRF handler unchanged. An invitation is never accepted as an operator session or as a telemetry credential. All inputs need strict duplicate/type/field validation, finite size limits, canonical authority/path checks and no redirects/CORS. Rate-limit identity comes from the actual peer, never an untrusted forwarding header. Challenge/attempt maps and durable terminal records have explicit retention/capacity policies.

## Renewal and identity version transition

A candidate initial certificate lifetime is 30 days, with bounded renewal attempts starting 7 days before expiry. These values require operational acceptance and clock-skew testing. The preferred renewal flow authenticates with the current valid credential and proves possession of a new locally generated key; it may remain automatic under the administrator's continuing device approval, with a policy option to require approval for rotation. A revoked or expired device cannot resurrect itself through enrollment/renewal fallbacks. Renewal failures produce visible expiring/expired states. EST is useful renewal/rekey precedent; this application-specific invitation/approval protocol does not claim EST compliance. [EST client certificate enrollment and reenrollment](https://www.rfc-editor.org/rfc/rfc7030.html#section-4.2)

The current sender binds state to the full leaf certificate fingerprint. Renewal changes that fingerprint. Therefore v2 must explicitly define stable identity as manager instance ID + server-assigned device ID + approved public-key fingerprint + transport/profile, while maintaining separately authorized certificate serials/epochs. Never simply ignore a v1 binding mismatch or reset its replay counter.

Plan an explicit migration handshake: verify the existing active v1 identity, create a recorded v2 identity epoch, persist the new binding before use, and keep a bounded documented overlap for exact in-flight retries. Sequence/replay domains and pending payloads must have an unambiguous version/epoch. An old unacknowledged observation cannot be retimestamped or silently re-signed under another identity.

Treat each new key as an explicit recorded generation. Require current-key authentication and new-key proof; allow an operator to demand approval. Before activation, drain, acknowledge or explicitly discard the prior generation's exact pending frame while preserving the replay floor. Record bounded overlap and revoke the old key after confirmed activation. Lost activation responses must be recoverable through proof from the already bound new key, never through an unauthenticated reset. If the key is lost, state is corrupt, the certificate is expired beyond the recovery policy, the manager instance changed or the issuing trust is lost, require a fresh explicit operator recovery/enrollment action. Do not use the old invitation or an unauthenticated reset to regain access.

Manager backup/restore must retain device/key approvals, revocation tombstones, certificate epochs and replay floors together. Restoring an older replay database is a security-relevant recovery event, not transparent rollback. Define quarantine/reconciliation or a new instance epoch before accepting existing agents. Test issuer rollover and fail-closed behavior when only part of a backup is available.

## HTTP test limits

HTTP enrollment must be a separately acknowledged disposable test profile, with separate issuer, invitations, state, cookie and identity domains. Reuse or fallback from TLS is rejected. Payload signatures can authenticate a previously approved key, but HTTP cannot protect the invitation/password, authenticate the manager or prevent UI substitution and operator-session hijacking. A short-lived invitation and manual comparison reduce accidental registration; they do not make an active network attacker safe. No browser padlock or secure-enrollment claim is shown in this profile.

A test installer should require an explicit plaintext acknowledgement and label its output and status continuously. It must never install an unattended production service using HTTP test settings without a separate, deliberate user action and warning. Default installer/profile selection remains HTTPS.

For chain compatibility, keep HTTP test enrollment leaf-only and within the existing 4 KiB encoded certificate-header cap. Explicitly provision the public test-issuing intermediate itself in that profile's trusted issuer set, so the leaf is directly issued by a configured trust anchor; do not rely on an unsent intermediate chain or silently widen the v1 header/parser contract. This is a deliberate test-profile trust configuration, separate from the offline root and from HTTPS trust. HTTPS v2 may deliver its complete client chain for normal TLS verification. Any future multi-certificate signed-HTTP envelope needs a separate version and reviewed bounds. Enrollment v2 does not silently migrate an existing v1 identity or endpoint.

## Threat analysis for the proposed change

This is a forward-looking engineering threat analysis, not a claim that the new controls exist or that a security scan has verified them.

| Threat and attacker | Trust boundary | Required control | Acceptance evidence |
| --- | --- | --- | --- |
| Stolen or guessed invitation | Unauthenticated enrollment to pending registry | High entropy, short TTL, one atomic claim, bounded attempts, pending approval | Concurrent different-key claims yield at most one pending binding; expired/canceled invites never issue |
| CSR identity or privilege injection | Untrusted client CSR to issuer | Fixed template and server-assigned ID; ignore requested role/SAN/CA extensions | Adversarial CSR suite cannot create CA/server-auth/cross-device credentials |
| Manager impersonation or rebinding | Installer to configured manager | Explicit trusted TLS origin/CA and optional pin, vetted literal dial, no redirects/proxies/TOFU | Wrong CA/SAN/origin/pin and mixed hostile DNS answers fail before secret transmission |
| Cross-surface credential confusion | Operator, enrollment and telemetry routers | Separate credential types/domains and canonical routes | Cookie, invite, pending proof and client certificate cannot substitute across surfaces |
| Approval/revocation race | Browser action or claim to durable issuance/telemetry | Existing session mutation lease plus transactional lifecycle checks | Logout, cancel, reject and revoke at controlled interleavings prevent later unauthorized work |
| Renewal resurrection or key substitution | Existing identity to new certificate epoch | Current-key authentication, new-key proof and explicit generation activation; active registry check | Revoked/expired/wrong-key renewal denied; exact retry remains idempotent |
| Issuer or state file substitution | Local filesystem to trust state | Private dedicated owner/path controls, atomic state, protected backup | Symlink/hardlink/permission/corruption/partial-restore tests fail closed |
| Enrollment flooding | Network to crypto/parser/DB resources | Size, concurrency, rate and capacity caps; bounded cleanup | Load tests show bounded CPU/memory/state growth and no unbounded pending map |
| Installer supply-chain substitution | Download to privileged local execution | Signed/version-pinned artifacts, verified provenance, explicit elevation | Tampered artifact/config and wrong OS/arch rejected; no arbitrary remote script execution |
| Overcollection or secret export | Native providers to manager and optional AI | Typed allowlists, bounded profiles, exclusions, separate AI export consent | Fixture secrets/command lines/env/private files never enter default telemetry or model packets |
| False online or complete-health claims | Receipt/capability data to UI | Separate connection, service-reported state, coverage, freshness and health | Missing/partial/denied/stale sections never become green completeness or healthy-host status |

## Implementation gates

1. Review this lifecycle, custody and version-transition design, including failure recovery. Agree the minimal installer/bootstrap route and exact invitation semantics.
2. Implement a pure state machine, strict contracts and ephemeral issuer fixtures. Test concurrency, cancellation, replay, expiry, issuer roles and recovery before wiring production endpoints.
3. Add the bounded operator enrollment API/UI and native foreground enrollment. Test real loopback TLS with fresh temporary keys; no real credential provisioning or deployment.
4. Add one supported native installer/service lifecycle at a time. Validate least privilege, restart/reboot, upgrade, disable/revoke and uninstall on an explicitly authorized target. Windows/macOS require their own signing, ACL and user-consent acceptance.
5. Introduce typed collection profiles only after the identity/transport version is settled. Preserve the existing manual support-bundle privacy contract and explicitly show every unsupported or uncollected category.

Repository scope: the Tracebolt repository, proposed enrollment v2 over the source-only baseline manifests above. This design does not authorize real credential creation, trust-store changes, service installation, network exposure or deployment.
