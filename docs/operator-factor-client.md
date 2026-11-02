# Non-browser factor custody and management

`operator-factor` supplies the explicit Linux terminal workflow for the
[live-account factor protocol](live-operator-factors.md). It is compiled by
`make build` and packaged at `/tracebolt/operator-factor` in the existing manager
image. Merely building or packaging it performs no provisioning, activation,
service/permission change or network operation. It does not need a browser.

This is source/protocol-fixture evidence, not an approved installation or proof
of a real authenticator/device handoff. The cockpit OTP input still has its
separate pending frontend build gate; this command does not bypass that gate or
complete #140's broader recovery/WebAuthn/OIDC/UI work.

## Preconditions and secret boundaries

- Use the matching reviewed manager/client source and live TLS v3 authority.
  The client refuses older/static/HTTP profiles before requesting credentials.
- The public server leaf certificate must be independently approved. It is
  pinned exactly, with hostname, expiry and TLS 1.3 verification; no ambient root
  trust, proxy, redirect, HTTP fallback or certificate auto-acceptance is used.
  A changed/expired leaf requires a separately reviewed certificate update.
- Commands require a foreground controlling `/dev/tty`. Username, password and
  OTP prompts are hidden; redirected stdin, environment and credential arguments
  are not supported. Echo/input state is restored on completion or cancellation.
  No credential, session cookie or CSRF token is written to command output.
- `prepare` additionally requires the existing nonroot manager runtime UID and
  its approved private custody access. It reads the protected LAN configuration,
  v3 reference/marker and **public** certificate, not the server private key,
  issuer key, agent CA or account journal. It does not stop/restart the manager.
- State and handoff parents must already satisfy the protected-owner/ancestor
  checks. The handoff parent must be mode 0700 and owned by the executing runtime
  UID, outside state and served frontend paths. The command does not create
  directories, repair modes/ownership or invent writable container mounts.

The command's API connection keeps its cookie and CSRF only in memory. All URLs
are fixed paths under the approved canonical HTTPS origin. Passwords and short
OTP proofs travel only in the protected JSON request body. The long-term factor
secret never travels through the management API, a URL, argument or environment.

## Workflow

The following are schematic commands: replace every uppercase placeholder with
independently reviewed public identity/path values. They are not authorization
to provision an installation or supply real material in chat/logs.

### 1. Review existing accounts

```sh
operator-factor status \
  --operator-origin HTTPS_ORIGIN \
  --server-certificate-file ABS_PUBLIC_SERVER_CERT
```

Enter the current administrator's username/password and, if enrolled, OTP at the
hidden prompts. `status` requires actual `manage_accounts`; it does not invent
read-user visibility. Its bounded output contains only existing account IDs,
revisions, grants, disabled/uncertain state and factor state/generation. Treat
that account metadata as private. No username, token or secret is returned.

### 2. Stage approved local custody

Run as the existing approved nonroot manager UID:

```sh
operator-factor prepare \
  --lan-config ABS_EXISTING_LAN_CONFIG \
  --runtime-uid APPROVED_RUNTIME_UID \
  --actor-id APPROVED_EXISTING_OPERATOR_ID \
  --expected-revision REVIEWED_REVISION \
  --handoff-file ABS_NEW_PRIVATE_HANDOFF \
  --acknowledge-factor-custody
```

The command preflights the pinned server, requests hidden administrator login,
then reviews the actual target/revision through the authenticated API. Disabled,
uncertain, stale or already-active factor targets are rejected before staging.
Only an unbound or explicitly reset/pending factor can be staged.

A fresh 32-byte random factor is written to two exclusive mode-0600 files:

1. A private handoff JSON at the approved new destination, containing the exact
   authority/actor/revision and SHA256/eight-digit/30-second authenticator profile.
2. The fixed adjacent proposal expected by the manager's factor reader.

The command never prints the secret or computes an OTP from this custody copy.
Only after confirmed staging should the authorized custodian transfer the private
handoff to its intended operator through the approved local/private channel. The
operator imports it into an authenticator supporting that exact profile. Do not
paste it into chat, shell history, a web QR service, a cloud editor or logs. Human
import into the intended authenticator is the deliberate possession step; no
remote app/service is invoked or claimed by the tool.

For a previously consumed proposal, `prepare` refuses ordinary replacement.
After reviewing the current pending target/revision, add the separate
`--replace-stale-proposal` flag. Only a valid same-authority/actor proposal with
an **older** revision is moved with no-replace semantics to
`<proposal>.retired-<oldRevision>`. Existing archives are never overwritten and
their bytes are retained. No authority ledger, floor, session or consumed receipt
is erased. Partial file/archive results are preserved for inspection, not rolled
back or automatically retried. Never use an unconfirmed handoff after an error.

### 3. Prove possession and enroll

```sh
operator-factor enroll \
  --operator-origin HTTPS_ORIGIN \
  --server-certificate-file ABS_PUBLIC_SERVER_CERT \
  --expected-revision REVIEWED_REVISION \
  --acknowledge-factor-enrollment
```

Enter the intended account's username/password and a code from its authenticator.
The command does not read the secret/proposal to generate that code. Enrollment
binds the already provisioned material and consumes the code; it does not issue
a session. Wait for a fresh code before a subsequent login/status operation.

### 4. Reset an existing active factor

```sh
operator-factor reset \
  --operator-origin HTTPS_ORIGIN \
  --server-certificate-file ABS_PUBLIC_SERVER_CERT \
  --actor-id APPROVED_EXISTING_OPERATOR_ID \
  --expected-revision REVIEWED_REVISION \
  --acknowledge-factor-reset
```

The administrator logs in at hidden prompts and reviews the exact target/revision.
Then the command requests the **requester's password again** and a **fresh,
different unused OTP**; wait for the next authenticator code if needed. The target's
password/OTP cannot impersonate the requester. A confirmed reset withdraws the
target's sessions and old job epochs and requires new custody/enrollment; it does
not disable MFA or affect independent operators. The last usable administrator
remains protected. Use steps 1–3 with a new handoff and current revision afterward.

## Confirmation and uncertainty

The fixed JSON result distinguishes `confirmed`, `operationApplied`,
`operationUncertain` and, after temporary login, `cleanupConfirmed`. A bounded,
explicit logout is attempted; it is not hidden in transport destruction. A
confirmed self-reset's already revoked session is treated as cleaned up only
after the validated reset response. Other failures are not guessed successful.

Transport loss, malformed successful mutation replies, durable-authority errors
or failed fsync can mean an operation already happened. The tool never retries a
mutation. If cleanup is unconfirmed, do not repeat a reset just because the exit
code is nonzero: its operation may already be confirmed. Review current authority
with an independent authorized administrator and inspect retained private files.
Never delete used state or lower replay floors to recover. Capacity/history and
all-factor-loss boundaries in the factor contract remain in force.

Targeted tests use synthetic PTYs, private temporary files, a real TLS manager,
real account journal, separate software-authenticator proofs, reset/re-enrollment
and journal reopen. They do not execute real host provisioning, an actual mobile
authenticator import, container deployment or browser interaction.
