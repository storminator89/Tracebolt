# Installation runbook: humans and automation agents

Start here when given this repository to install. **This is a self-hosted LAN
pilot, not an unattended fleet installer.** The supported path today is a
Docker or native Linux central manager plus native Linux senders. The default
manual-v1 mode uses preprovided approved material; optional guided-v2 adds a
hidden-terminal bootstrap and deliberate operator approval. Reporting can run
once or repeatedly in the foreground. The Linux/systemd installer
adds explicit service operations and the fresh combined read-admin path below.
A repository link alone does not authorize a deployment or
provide credentials. Read the checklist before executing the quickstart.

For a fresh supported Linux endpoint, the normal published-release path is the
**[verified dashboard download](dashboard-verified-download.md)**: copy one public
installation command, run it deliberately as root in a local terminal after
approving account/service and persistent identity creation, enter the invitation
only at the hidden prompt, then compare and approve the device in the dashboard.
Downloads, release verification and artifact checks are internal to that command;
no endpoint Go build, file transfer or manual checksum step is needed. Review the
supported platform and existing prerequisites first; dependencies are not installed.

**Current release:** the dashboard pins `v0.1.0-rc.3`, built from
`405f57f184e75736477cbd3af7a2536ddfe0e6f6`. Its [build/publication](https://github.com/storminator89/Tracebolt/actions/runs/37573387512) and
[all-asset public-byte/provenance check](https://github.com/storminator89/Tracebolt/actions/runs/37574492167) passed. The complete
`managed-operations-v3` profile selects `--read-admin` and the validated agent
ingress, with one combined terminal approval for inventory, network identity,
current/future exact-service journals and isolated socket-owner metadata. The main
agent remains nonroot; the separate socket helper's broad process-memory authority
is explicitly disclosed.

The [one-command read-admin guide](read-admin-onboarding.md) describes that scope
and the required hidden invitation entry and dashboard fingerprint approval. Keep
the local terminal open until all phases finish. Basic/non-complete profiles retain
ordinary pending-service behavior. A missing or incompatible pin cannot downgrade
a complete installation. Manager deployment is separate; see the
[fresh Docker-manager guide](http-complete-first-start.md).

For a completed read-admin v2 installation, rc.3 supports the
[same-identity, same-scope update](read-admin-upgrade.md) with a local terminal
approval and no new enrollment. The [native Ubuntu TLS gate](https://github.com/storminator89/Tracebolt/actions/runs/37572468648) passed
the verified rc.2-to-405f source-built replacement, all four upgrade checks, all six
functional checks and cleanup. Released rc.3 artifacts are independently verified
above; the user's download-based Debian/HTTP upgrade and actual OS reboot remain
separate local acceptance steps.

For an existing activated v3 agent, the [one-time inventory collection guide](guided-inventory-setup.md)
can group the existing full process/mount and full cached APT grants into one
explicit local confirmation. It checks actual installed CLI support, preserves
the identity and counters, and does not upgrade the agent or configure journals.
Hostname/interfaces remain a separate optional selection.

For the separate default-off service-action workflow, read the
[guided create-only action setup candidate](guided-service-action-setup.md). Its
manager and endpoint source commands never upgrade the installed pinned release;
compatible source/fixture tests leave native privileged acceptance outstanding.

## 1. Choose the correct milestone

| Component | Available now | Not provided by this milestone |
| --- | --- | --- |
| Central manager | Separate `cmd/lan-manager`, Admin UI, authenticated operator API, approved agent ingress; Docker or native Linux execution | Production assurance, automatic provisioning, HA/shared SQLite writers |
| Linux endpoint | Native `cmd/lan-agent --config …`, one-shot or bounded foreground reporting; optional `cmd/enroll-agent` with explicit guided-v2 configuration; `cmd/agent-service` with explicit fixed-path operations and fresh combined read-admin setup | Verified OS reboot persistence, automatic renewal or remote updater; native Ubuntu TLS acceptance is recorded above; other host/profile combinations remain separate |
| Windows/macOS endpoint | Native `cmd/agent` bounded stdout-only collector; limited platform reads | Supported LAN sender, native ACL/state lifecycle, installed service or fleet deployment |
| Docker architectures | Linux amd64 TLS and explicit HTTP-test lifecycle gates; Linux arm64 cross-build support | arm64 runtime acceptance from cross-building alone |

Use the selected revision's actual CI results, not this table, to establish what
passed. Windows/macOS collector runtime results do **not** validate a LAN sender.
The product direction is native agents on Windows, Linux and macOS with a Docker
or native manager; all three endpoint installation paths are not shipped yet.
The original enrollment proposal remains design history. Use the implemented
[runtime configuration](enrollment-v2/runtime-config.md) and [native client](enrollment-v2/native-client.md) contracts for guided-v2; do not invent commands from proposed routes. Do not substitute the synthetic development manager
(`make run`, `cmd/manager`) or loopback `cmd/dev-agent` for the LAN manager/sender.

## 2. Preflight and approval checklist

An installation agent must first inspect, then propose the smallest supported
plan. Record these answers without secrets:

- Exact repository URL, chosen full commit SHA, clean/dirty checkout, relevant CI
  run and evidence. Preserve existing work. Confirm which computer is the target;
  an editing sandbox is not implicitly the user's server.
- Manager OS/architecture, Docker Engine/Compose availability or native Go/Node
  toolchain, available disk and existing workloads/ports. Prefer Linux for the
  current protected-file contract; Docker Desktop mount semantics need separate
  verification. Do not assume administrator/root access.
- Chosen runtime UID/GID, private configuration/state locations, backup location,
  whether state already exists, and the owners of all parent directories.
- Exact operator origin, agent ingress origin, intended LAN IP, DNS/SAN names,
  reachable endpoint networks and approved firewall scope. No Internet exposure.
- TLS (default) or explicitly approved isolated HTTP test, operator who will sign
  in, credential/certificate custodian, and endpoint/public fingerprint to approve.
- Endpoint OS/architecture, ordinary-user collection constraints, and whether a
  foreground Linux sender meets the request. If a Windows/macOS LAN client or an
  installed service is required, read the candidate [service contract](linux-agent-service.md)
  and exact manual-gate evidence. True reboot persistence remains unverified.

Before changing the target, get approval for the concrete plan, destinations and
paths. Persistent credential creation/import, device trust approval/revocation,
firewall/network/security settings, global certificate trust, account/service
creation, startup persistence and destructive deletion need their appropriate
explicit approval; obey any stronger policy of the agent's execution environment.
A generic “install this” is not permission to disable security or provision
unbounded access. A permission-denied result is a blocker to explain, not a reason
to retry as root or through another channel.

Do not silently install tools, open ports, change DNS/hosts, trust a CA, disable a
firewall, bypass a browser certificate warning, use `curl -k`, or fall back to
HTTP. Never request passwords/private keys in chat, commit them, put them in
command arguments, print them to a transcript, or pass them as Docker build args
or environment variables. Use the user's approved secure provisioning/handoff
mechanism. Read only the minimum private files needed; do not dump their contents.

## 3. Pin and inspect source

On a fresh work directory, with the intended repository and revision confirmed:

```sh
git clone https://github.com/storminator89/Tracebolt.git
cd Tracebolt
git fetch origin
# Set this to the full, independently selected commit SHA, not a moving branch.
REVISION=REPLACE_WITH_FULL_COMMIT_SHA
git checkout --detach "$REVISION"
git rev-parse HEAD
git status --short
```

Do not run the checkout command over existing uncommitted work. For an existing
checkout, inspect its remote, status and revision first. A Git SHA identifies
content; it does not prove publisher identity. Compare the revision with the
trusted repository/release/CI record, and verify any published signature or
checksum if one is provided. Do not invent a signed-release guarantee. Review
`Dockerfile`, `deploy/`, dependency locks and CI for this exact revision.

Prerequisites for source builds: Go **1.27.1** as declared in `go.mod`, Node.js
**24** with npm as used in the Dockerfile/CI, Git, and a POSIX shell for the commands
below. The race detector also needs a C toolchain. Native manager runtime uses
SQLite without a separate database server. Docker packaging needs a running
Docker Engine, Compose **v2** and BuildKit; inspect `docker version` and
`docker compose version` before using them. Docker access is powerful host access;
do not “fix” it by changing socket permissions or group membership silently.
Check runtime licensing before installation; no project license has been selected.

Go modules are locked by `go.mod`/`go.sum`; npm uses `web/package-lock.json`.
Builds need dependency/image registry access. Docker base tags are version-selected,
not digest-pinned: record the resulting image ID as well as the source SHA. Do not
claim bit-for-bit reproducibility or pull an unverified prebuilt project image.

## 4. Quickstart: TLS Docker manager, preprovided material

**Gate:** this sequence assumes an approved target and correctly provisioned,
protected material already exist. There is no bundled credential issuer or
operator-password setup command. If these prerequisites are absent, stop at the
material checklist below; do not turn test fixtures into deployment identities.
All commands in this section run from the repository root.

1. Prepare an external private config directory with `lan.json`, `server.pem`,
   `server.key`, `agent-ca.pem`, and `operator-auth.json`. Use
   [`deploy/lan.tls.example.json`](../deploy/lan.tls.example.json) as the shape of
   `lan.json`, replacing both documentation origins with the exact real origins.
   Keep its container paths: `/run/tracebolt/…`, `/data/state`, `/tracebolt/web`.
2. Have the authorized administrator arrange ownership for UID/GID `65532:65532`
   and private-file access as described below. Verify host and container mount
   semantics. This runbook deliberately does not recursively `chown` a user path.
3. Set only nonsecret configuration paths/bind addresses and build:

```sh
export TRACEBOLT_CONFIG_DIR=/absolute/path/to/private/tracebolt-config
# Initial publication is loopback only. This is not yet endpoint LAN access.
export TRACEBOLT_BIND_IP=127.0.0.1
docker compose -f deploy/compose.yaml config
docker compose -f deploy/compose.yaml build manager
docker image inspect tracebolt-manager:local --format '{{.Id}}'
docker compose -f deploy/compose.yaml up --no-build -d manager
docker compose -f deploy/compose.yaml ps
docker compose -f deploy/compose.yaml logs --tail=50 manager
```

Review logs locally; do not upload unreviewed logs or private paths. A process
running is only startup evidence. Do not test against `localhost` if the
configured public origin/SAN is a different host: exact Host/Origin checks still
apply. Use the configured origin with approved DNS/routing to this listener.
For an authorized LAN deployment, set `TRACEBOLT_BIND_IP` to the selected server
LAN address (not a blanket `0.0.0.0` exposure) and recreate with the same `up`
command. Review exposure before executing; the origins and certificate SANs must
match client-visible names/IPs and ports. This is an explicit deployment change.

Default host ports are TCP **8443** for operator HTTPS and TCP **8444** for agent
mTLS. Permit only the chosen operator/endpoint networks in the host/network
firewall. Compose does not configure that firewall. The container listens on
`0.0.0.0` internally; host port bindings determine publication. There is no
required inbound endpoint port. Do not use host networking, privileged mode,
Docker socket mounts, or a proxy that removes agent mTLS. Proxy/header-based TLS
termination is not this runtime's trust contract.

### Material and filesystem checklist

- `server.pem` + `server.key`: matching manager certificate and private key,
  currently valid, SANs covering both origin hosts, **ServerAuth only** leaf EKU.
- `agent-ca.pem`: public CA roots that may issue client certificates. No root CA
  private key belongs on the manager or endpoint. Default manual-v1 uses
  externally provisioned client leaves. Optional guided-v2 instead requires the
  dedicated online intermediate and custody boundary described below.
- `operator-auth.json`: schema `tracebolt.operator-auth.v1`, profile `tls`, and a
  previously provisioned `passwordHash` Argon2id PHC verifier. Accepted parameters:
  version 19, memory 65536–131072 KiB, iterations 2–4, parallelism 1–4,
  salt 16–32 bytes, output 32 bytes. The login password must be 12–1024 UTF-8 bytes.
  A placeholder is not usable authentication. Treat the verifier as secret data.
- Private key and auth files: runtime-UID-owned regular single-link files, normally
  `0400` or `0600`, with no group/world access. Public config/cert/CA files may be
  `0644`, never group/world writable, and owned by the runtime UID or root.
  All referenced paths must be absolute. Parents must be owned by that UID or
  root, traversable by the runtime, and not symlinks or replaceable by another
  account (the implementation permits root-owned sticky temporary ancestors
  for isolated fixtures).
- State: dedicated runtime-owned `0700` directory. Do not use a shared writable
  directory, insecure existing data, another profile's directory, or silently
  reset a rejected store. Docker supplies a named `/data` volume; a fresh volume
  receives the image's private ownership. One manager owns it, no replicas.
- Check mount ownership on Docker Desktop before claiming compatibility. File
  permissions that look correct on the host may not satisfy Linux checks inside
  the container. Do not weaken checks; report this as a platform blocker.

Detailed certificate roles/key strengths and protected paths are specified in
[LAN trust](lan-trust.md) and [LAN runtime](lan-runtime.md).

## 5. Native Linux manager alternative

Use the same material and trust contract, but paths in `lan.json` refer to the
**host**, not container paths. Set distinct literal `operatorListen`/`agentListen`
addresses on the approved interface, private host state, and `webDirectory` to the
absolute path of this build's `web/dist`. Do not copy Docker's internal
`0.0.0.0` binds to a host without reviewing the exposure.

```sh
(cd web && npm ci --ignore-scripts && npm run build)
go build -buildvcs=false -trimpath -o bin/lan-manager ./cmd/lan-manager
./bin/lan-manager --lan-config /absolute/path/to/private/lan.json
```

Run foreground as the chosen unprivileged owner. Stop with Ctrl+C/SIGTERM. There
is a separate Linux endpoint service candidate, but no manager service installer;
do not describe a foreground manager run as boot persistence.
The build toolchain is not needed on a host receiving an independently verified
matching binary plus matching frontend assets, but this repository does not
provide a complete signed binary distribution/install workflow.

## 6. Default manual-v1: sign in, approve a public certificate, run Linux

1. Open the exact HTTPS **operator** origin in a normally trusting browser. If
   trust is absent, have the administrator provide an approved trust solution;
   do not click through a warning. Sign in with the preprovided operator password.
2. Provision the endpoint's own ClientAuth-only certificate and matching private
   key through the separately authorized credential workflow. Keep its private
   key on the endpoint. The manager only needs the **public** leaf/chain.
3. Independently verify the full lowercase SHA-256 of the leaf DER and the intended
   endpoint. A certificate label/hostname is not identity. An approved operator
   must approve that exact fingerprint through the authenticated operator API.
   This default manual-v1 path uses the public-certificate API below. The separate
   opt-in guided-v2 interface/native bootstrap is described in section 6B; neither
   path installs an OS service.

The actual API sequence is documented in
[`lan-operator-api-contract.json`](lan-operator-api-contract.json):

- `POST /api/auth/login` uses exact operator Origin, JSON `{ "password": … }` and
  returns a cookie/session with `csrfToken`. Handle password, cookie and token
  only in a secure local client; do not paste them into commands/chat/logs.
- `POST /api/lan/agents/approve` uses that cookie, `X-CSRF-Token`, exact Origin,
  JSON content type and `{ "certificatePEM": …, "label": …,
  "expectedFingerprintSHA256": … }`. Submit public certificate blocks only.
- A successful HTTP **201** returns a public descriptor whose **`id`** is the
  server-assigned `agent_` followed by 32 lowercase hex digits. Use that value as
  **`agentId`** in the endpoint configuration. Do not generate your own ID.
- `GET /api/lan/agents` checks the authenticated public registry. A CA-valid client
  is not authorized until its exact leaf has been manually approved.

The API contract is provided for an approved secure client/integration, not as
permission to create trust. There is no bundled secret-safe provisioning helper;
if your agent cannot complete this step safely, hand it to the administrator and
report exactly which public ID/config input is still missing.

On the **Linux endpoint**, build from the same reviewed source:

```sh
go build -buildvcs=false -trimpath -o bin/lan-agent ./cmd/lan-agent
./bin/lan-agent --config /absolute/path/to/private/agent.json
```

Start from [`examples/lan-agent.tls.json`](examples/lan-agent.tls.json). Replace
all placeholders: `managerOrigin` is the **agent ingress**, normally HTTPS port
8444, not the operator URL; `agentId` is the approval response's `id`;
`certificateFile`/`privateKeyFile` belong to this endpoint; `serverCAFile` is the
explicit public server CA; `stateDirectory` is private persistent endpoint state.
Its private files/path ownership follow the same policy as the manager, owned by
the endpoint runtime UID. Server/client CAs may be different; configure their
roles correctly. No ambient CA, environment proxy, redirect or downgrade is used.

Expected success: exit 0 and bounded `tracebolt.agent-run.v1` JSON with
`status: "acknowledged"`, profile and sequence. Exit 1 means delivery was not
confirmed; exit 2 covers unsupported platform/configuration or output failure.
An explicit later invocation sends a new sample or retries the exact pending
frame. Preserve state across invocations; never delete it to “fix” replay errors.
Only one process may use a sender state directory. A lost response retains a
pending frame, not proof of loss at the manager. A stale pending frame is discarded
without reusing its sequence, and a genuinely new observation can be collected.
The default command performs one attempt. Add `--foreground --interval 30s` for
serial repeated reporting; the interval must be 15 seconds to 1 hour. It retains
the exclusive sender-state lock during attempts and backoff, preserves pending
bytes/timestamps and stops on invalid state/configuration. Ctrl+C/SIGTERM stops
it; no service or boot persistence is installed. See the [sender contract](lan-agent.md)
and [foreground loop](agent-loop.md).

Windows/macOS: stop here for LAN installation. You may separately build/run the
stdout collector with `go build -buildvcs=false -trimpath -o bin/agent ./cmd/agent`
on macOS (use `bin/agent.exe` on Windows) and its `--support-bundle` flag, but that
prints local observation data and does not send it to this manager. Review/export
handling is separate; do not upload the sample automatically. Do not improvise a
scheduled task, launchd job, cron or systemd service as if it were shipped support.

## 6B. Optional guided-v2: bootstrap, compare, approve and report

This mode is deliberately opt-in and mutually exclusive with manual-v1 identity
state. Before using it on a real target, obtain approval for the dedicated issuer
private-key custody, endpoint credential creation, invitation transfer and device
trust grant. Automation must hand secret invitation entry to the human or the
approved secure handoff. A source checkout or successful fixture test is not that
permission. No CA is automatically provisioned.

### Manager prerequisites and start

Use an empty legacy registry, including tombstones, and a dedicated protected
state location. There is no automatic migration, adoption or downgrade. Supply
a preprovided **Ed25519 client-auth-only issuing intermediate**, path length zero,
directly chained to its explicit public root. Keep the root private key offline.
The intermediate signing key alone is available to the manager, as protected
PKCS#8 material owned by the runtime UID (normally 0400/0600). This online custody
is a security boundary; it is not hardware isolation or encrypted storage.

The LAN configuration's `agentClientCAFile` must contain exactly this dedicated
intermediate, not the root or a sibling/combined pool. Add a separate protected
`tracebolt.enrollment-config.v2` JSON file with the matching profile, stable
manager instance ID, issuer certificate/key/root paths, full expected issuer
fingerprint and TLS bootstrap server-CA path. For HTTP test the bootstrap
server-CA field must be empty. Validate the exact fields and roles against
[the runtime contract](enrollment-v2/runtime-config.md); placeholders do not work.

```sh
go build -buildvcs=false -trimpath -o bin/lan-manager ./cmd/lan-manager
./bin/lan-manager --lan-config /absolute/path/private/lan.json \
  --enrollment-config /absolute/path/private/enrollment.json
```

For Docker, retain the protected read-only material mount and image hardening,
then explicitly add `--enrollment-config /run/tracebolt/enrollment.json` alongside
`--lan-config /run/tracebolt/lan.json` in an approved Compose override. The shipped
Compose examples keep manual-v1 as their default; no guided-mode container
acceptance is inferred from a manual-profile Docker pass.

A durable private mode marker binds profile, origins, instance, collection
profile, issuer/root and server trust. Existing unmarked or mismatched database/
sidecar files are rejected unchanged. Never remove that marker or reset a
registry to switch modes. The current enrollment ledger retains at most 25
records, including terminal records; it is a bounded pilot, not a fleet-scale
capacity claim or invitation-cleanup permission.

### Endpoint and deliberate approval

1. Sign in at the exact configured operator origin. In the enabled enrollment
   interface, create a Linux invitation only after the explicit creation step.
   Export its **public bootstrap JSON** to the intended Linux endpoint through a
   trusted channel. The export excludes the invitation secret and private keys.
   The interface appears only when the runtime capability is enabled.
2. Build the native commands from the same reviewed revision:

```sh
go build -buildvcs=false -trimpath -o bin/enroll-agent ./cmd/enroll-agent
go build -buildvcs=false -trimpath -o bin/lan-agent ./cmd/lan-agent
./bin/enroll-agent --bootstrap /absolute/path/bootstrap.json \
  --state-directory /absolute/path/new-private-device-directory
```

3. Use a controlling local terminal. Before secret entry, independently inspect
   the exact origins, profile, instance/invitation IDs, public CA/issuer
   fingerprints, locally generated full SPKI SHA-256 and context-bound 128-bit
   comparison value. The bootstrap is locally supplied trust, not authority
   learned from an unauthenticated response. Endpoint credential creation needs
   its required authorization before this command runs.
4. Enter the invitation only in the hidden terminal prompt. There is no supported
   invitation argument, environment variable, URL, bootstrap-secret field, stdin
   mode or downloadable secret file. Do not paste it into an agent conversation
   or transcript. The human/operator checks the entire fingerprint and comparison
   value against the manager's pending claim and explicitly approves that device.
   A label or short code alone does not establish identity.
5. The client verifies the committed credential/intent, activates the bound
   identity and prepares protected sender state. Default cooperative approval
   timeout is 15 minutes, with `--timeout` capped at 30 minutes. On success, run
   the exact safely quoted handoff command it prints, equivalent to:

```sh
./bin/lan-agent --config /absolute/path/new-private-device-directory/agent.json \
  --foreground --interval 30s
```

This starts foreground reporting only. Closing/stopping it stops reporting.
This command installs no service. A separate Linux/systemd installer candidate is
described below; automatic renewal and true reboot acceptance remain open.
Keep Windows/macOS limited to their separately tested stdout collectors.

For deliberately insecure HTTP testing, the native enrollment command also
requires `--insecure-http-test` on every invocation. Invitations, reports and
operator sessions are readable; the manager can be impersonated. An HTTP
activation response is not verified server activation. Use separate disposable
material/state and retain every visible warning; never downgrade a TLS setup.

### Resume, uncertainty and protected state

Resume only with the identical trusted bootstrap and private directory. The local
key, CSR, operation IDs and semantic claim hash are persisted before network
actions; the invitation itself is not saved. Preserve the complete private
ledger, handoff files, ready marker and telemetry directory. Missing or mismatched
state fails closed. Do not delete temporaries, replace keys, reset a sequence or
re-enroll automatically to work around an uncertain result.

A definite authenticated TLS rejection can permit corrected invitation entry
only after the client's bound-key status reconciliation, using the same local
identity. An uncertain response keeps the earlier candidate pinned. HTTP-test
rejections cannot authorize correction: a wrong token may require operator
cancellation and a new separately authorized invitation/directory. Follow the
[native recovery contract](enrollment-v2/native-client.md), rather than improvising
a reset. Stop an active foreground sender before enrollment validates a completed
handoff, because both protect the same sender-state lock boundary.

Before revoking a real endpoint, get the appropriate explicit approval. Revocation
is durable; a transport error is not evidence of revocation and does not authorize
new credentials. Lost-key recovery, issuer rotation, renewal, old-backup rollback
detection remain separate work. Service installation uses the separately authorized
Linux/systemd candidate below.

## 6c. Optional Linux/systemd service candidate

Read [the complete service contract](linux-agent-service.md) and its
[targeted review](agent-install-security-review.md) before acting. Build
`cmd/agent-service` from the exact selected revision alongside `enroll-agent` and
`lan-agent`. Its default is read-only preflight; `--apply` requires concrete
administrator approval for the specified host, account/service changes and
persistent endpoint identity.

The installation uses fixed owned paths, a dedicated non-login account and a
numeric-UID/GID systemd unit. It requires independently selected hashes for the
local binary pair, source archive and public bootstrap. The installer never
fetches an executable or accepts an invitation argument. A human/approved secure
handoff enters the invitation through the hidden native prompt, followed by
public fingerprint/comparison approval.

`--action install`, `restart`, `upgrade` and `uninstall` are explicit operations;
consult the component contract for their exact required inputs. Upgrades preserve
identity and the sequence domain. Uninstall stops/disables and removes owned
unit/binaries while retaining the account, bootstrap and private identity/state.
There is no reset or purge flag. An uncertain transaction needs inspection rather
than deletion or automatic re-enrollment.

The manual [disposable-systemd acceptance gate](../tests/systemd/README.md) tests
actual install/start/reporting/restart/artifact replacement/uninstall only when
explicitly enabled on a fresh hosted Ubuntu VM. Default tests skip it before
effects. Source and inert-fixture passes do not establish this runtime result;
check the selected source's manual workflow evidence. True OS reboot, native
Windows/macOS installation and automatic credential renewal remain separate gaps.

### Optional on-demand service log content

The separate [local journal helper setup](linux-journal-helper.md) supplies a
read-only plan and an explicitly approved create-only apply command for an
already installed, activated v3 Linux agent. It adds a distinct non-login helper
and unit-only journal access; the main agent identity/groups stay unchanged.
Logs require their own selected-service content grant and HTTP-only plaintext
acknowledgement. Inert setup tests are not real source/systemd acceptance.

## 7. Acceptance: establish evidence, not just uptime

On the actual approved target, confirm all of the following:

- Exact configured operator origin verifies TLS normally; login works, protected
  inventory is denied before authentication, and no synthetic devices appear.
- Endpoint approval was deliberate; no measurements appear before its first send.
  For guided-v2, record matching local/manager public fingerprints, explicit approval,
  verified TLS activation and the private handoff; HTTP-test activation is untrusted.
- A real one-shot sender exits successfully; authenticated inventory shows the
  server-assigned ID, `source=lan`, `synthetic=false`, and an observation time.
  Unknown health/unavailable metrics are valid results, not proof of a healthy host.
- A second explicit invocation preserves state and advances/retries appropriately.
- An approved maintenance restart preserves approvals and accepted observations;
  it invalidates operator sessions. Sign in again. Verify ports/exposure remain
  within the agreed scope.
- Prove rejection/revocation/replay scenarios with isolated disposable fixtures.
  Do not revoke a real endpoint or discard its state merely for a smoke test.

These repository commands test the corresponding isolated contracts; they are
not real installation, browser acceptance or production-hardening proof:

```sh
# Linux: separate actual manager/sender subprocesses and temporary loopback trust.
go test -count=1 -timeout=4m ./tests/lanclient
# Guided-v2: actual manager, hidden-terminal client and foreground sender.
go test -race ./cmd/lan-manager -run '^TestGuidedThreeBinaryEnrollmentAndForeground$' -count=1 -timeout=8m
# Broader Go coverage; race mode requires a working C toolchain.
go test -race ./...
# Frontend tests and build, from the repository root.
(cd web && npm ci --ignore-scripts && npm test && npm run build)
```

The Linux two-binary test collects bounded real observations from the test host.
Get the host/collection scope right; avoid logging those samples. Disposable
certificate fixtures are not persistent enrollment. Container acceptance is
separate, on an approved disposable native Linux Docker runner:

```sh
docker build -t tracebolt-manager:ci .
TRACEBOLT_CONTAINER_IMAGE=tracebolt-manager:ci go test -count=1 -v ./tests/container
```

Read [`tests/container/README.md`](../tests/container/README.md) first: fixtures
require narrowly scoped passwordless `sudo chown` for their fresh temporary
material. Do not change sudo policy just to make them run; use a suitable approved
runner. Without the environment variable these lifecycle tests **skip**. Tests
create/remove only disposable containers/volumes, not the deployment volume.
Run natively on each architecture you intend to claim. Never call an arm64
cross-build an arm64 runtime pass. Record revision, architecture, exact command,
pass/fail/skip, and safe outcome summaries, not secret material or raw telemetry.

## 8. Optional, explicit plaintext LAN test

Use [Docker's HTTP-test instructions](docker.md#explicit-http-lan-test-profile)
only after the user accepts that passwords, sessions and telemetry are readable
and the server/UI can be impersonated. Signature verification is not encryption
or server authentication. Use an isolated network and **separate disposable**
authentication, certificate/key and state. Never downgrade the TLS installation.

The standalone `deploy/compose.http-test.yaml` requires
`TRACEBOLT_HTTP_TEST_BIND_IP` and `TRACEBOLT_HTTP_TEST_CONFIG_DIR`, profile
`--profile http-test`, and `http-test.json` based on
`deploy/lan.http-test.example.json`. Its ports are **8787 operator / 8788 agent**,
its project/volume differ from TLS, and it does not auto-restart. Do not merge the
two Compose files. Both manager and sender explicitly require `profile: "http-test"`
and `insecureHTTPAcknowledged: true`. Auth profile must also be `http-test`.
The test client's Ed25519 leaf must be directly issued by a configured root;
submit only that leaf. The manager still needs `agent-ca.pem`, but no server TLS
key/certificate. The sender must omit `serverCAFile`.

The generic HTTP sender template's example port is **8444**; when paired with
this Compose profile, replace its `managerOrigin` with the actual **8788** ingress
origin. Never assume template addresses or ports are deployable defaults. HTTP
sender destinations are limited to loopback, RFC1918 or IPv6 ULA; special/metadata,
public or overlay/CGNAT exceptions are not silently supported.

## 9. Diagnose without weakening security

- **Configuration rejected:** verify strict JSON keys/schema/profile, absolute
  canonical paths, owner/modes/ancestors, matching key/certificate, current
  validity, exclusive EKU roles, both SANs, and Argon2id bounds. Do not print the
  key/hash or recursively relax permissions. There is no separate config-check CLI.
- **Cannot start listener:** inspect exact configured IPs/ports and existing
  listeners. Select approved free ports and update origins consistently; do not
  kill another application's process. Compose host/container ports are distinct.
- **TLS failure:** verify endpoint clock, explicit CA and correct hostname/SAN.
  Stop on trust errors; do not add `-k`, accept all certificates, or change trust
  globally. HTTP profiles cannot use a TLS state/auth directory.
- **Login/403:** use exact operator origin, correct profile, browser cookie and
  fresh session/CSRF. No trailing slash/path in configured origins. Rate limiting
  is deliberate; do not hammer retries. Restart means a new login.
- **Sender pending/rejected:** check approved ID/fingerprint, revocation, time,
  network reachability, matching profile/origin, state ownership/lock and receipt.
  Age window is 2 minutes with up to 30 seconds future skew. Do not reset sequence
  or rewrite timestamps. Approval does not make a wrong origin valid.
- **State/registry unavailable:** preserve the complete state and stop writes.
  Investigate disk, ownership and backup recovery; never delete revocation rows
  or initialize an empty DB to bypass a failed load. No in-place repair command
  is provided.
- **Browser empty/unknown inventory:** check first successful native delivery;
  manager self-sampling and synthetic fallback are intentionally absent.

## 10. Stop, back up, restore, update, uninstall

**Stop:** Docker `docker compose -f deploy/compose.yaml stop manager` stops while
retaining the named state volume. `down` also retains it. **Do not use `down -v`**
for ordinary shutdown. Native foreground manager stops with Ctrl+C/SIGTERM;
the default one-shot sender leaves no background process. An explicitly started
foreground sender must also receive Ctrl+C/SIGTERM; it is not an installed service.

**Backup:** stop all writers first. Use the site's approved volume/filesystem
backup procedure to capture the **complete** private manager state (including
SQLite sidecars/profile marker), separate protected configuration and required
credential material under the credential custodian's controls. Preserve modes,
UID/GID and integrity; protect backups as telemetry/security data, encrypt under
site policy, and do not upload them to Git/CI/chat. This project has no backup CLI.
Keep endpoint sender state too; do not clone one sender's state/identity to another.

**Restore:** with services stopped, restore into a private location/volume owned
by the same intended runtime UID, using the matching profile/config/build. Test
first in an isolated target, with deliberate network exposure and no duplicate
writer. Old backups can predate revocations and replay floors: reconcile those
security changes before reconnecting endpoints. Never treat a stale backup as a
safe trust reset. Endpoints with pending/advanced sequences need review; do not
“synchronize” them by deleting state. Confirm sign-in, expected public approvals,
revocations and accepted observations after restoring.

**Update:** choose a reviewed revision and its CI results; keep the old source,
manager binary/UI or exact Docker image ID, configuration and consistent stopped
backup. Build separately, review schema/migration changes, get the maintenance
window approved, stop the old writer and start the replacement with the approved
existing state. Re-run acceptance. No automatic updater is shipped.

**Rollback:** do not simply run an old binary against a possibly migrated newer
DB. Restore the matching pre-update backup and tested build after reviewing lost
telemetry and intervening approval/revocation changes. Never restore a revoked
identity silently. There is no guaranteed database downgrade path or automatic
rollback tool.

**Uninstall:** stop/remove only the known deployment containers or foreground
binaries. For an explicitly installed Linux agent, use the reviewed owned
`agent-service --action uninstall` preflight and separately approved `--apply`;
retain identity/state by default. Inventory any other separately approved service,
firewall or trust changes and remove only those exact changes with approval. Credential revocation
is separate from deleting a key file. Confirm whether data/volumes/configuration,
credentials and backups should be retained or destroyed before deleting anything;
permanent deletion requires explicit action-time confirmation in an agent workflow.
Avoid broad cleanup commands, recursive deletion of guessed paths and volume prune.

## Completion report for an installation agent

Report source SHA/image ID, actual host/architecture and route, configured
nonsecret origins, what ran, exact passed/failed/skipped checks, retained data,
remaining manual/provisioning steps and the next safe action. Say “Linux one-shot
sender verified” only when it actually sent and inventory was checked. Say
“blocked awaiting protected credentials/public approval ID” when that is true.
Do not say “installed fleet”, “boot-persistent monitoring” or “production ready”.
Describe foreground reporting separately, including that it stops with the process.

Suggested German handoff: „Lies zuerst `AGENTS.md` und `docs/installation.md`.
Prüfe Zielrechner, Commit und vorhandene Konfiguration. Schlage den passenden
Installationsweg vor und frage vor Zugangsdaten-, Vertrauens-, Firewall- oder
Dienständerungen. Erfinde keine Installer-/Enrollment-Befehle. Berichte klar,
was wirklich getestet wurde und welche manuellen Schritte noch fehlen.“
