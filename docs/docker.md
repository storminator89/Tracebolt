# Containerized central manager

Docker is an **optional server packaging route**, alongside native installation.
The image contains the Go manager, Admin UI and client ingestion API. Windows,
macOS and Linux endpoint agents remain native processes: putting an agent in a
container does not give it a reliable view of the endpoint.

This is a self-hosted pilot implementation, not a production security assurance.
Building an image does not deploy anything. No image registry account, registry
upload, paid service or project license is selected by this setup.

## Image and runtime boundary

- Multi-stage build: Node builds the UI; Go builds a static Linux manager.
- Shell-free final image; fixed UID/GID `65532:65532`; no package manager.
  A public CA bundle supports optional outbound HTTPS integrations. Agent
  authentication still uses only the explicitly supplied agent CA.
- Read-only root filesystem, all Linux capabilities dropped,
  `no-new-privileges`, process/memory/CPU limits and rotated Docker logs.
- `/data` is a named volume initialized with private directory permissions. One
  manager owns this SQLite state; do not run multiple replicas against it.
- Configuration, operator password verifier and TLS materials are supplied
  externally through a read-only directory. They never belong in image layers,
  build arguments, repository files or environment variables.
- No privileged mode, Docker socket, host network/PID namespace, endpoint
  filesystem mounts or automatic host service installation.
- The default Compose file publishes only `127.0.0.1:8443` (operator HTTPS) and
  `127.0.0.1:8444` (agent mTLS). Explicitly changing the host binding is required
  for a LAN deployment. Container-internal listeners necessarily bind to their
  container network interfaces; that alone is not a LAN deployment.

The two listeners serve different trust roles. Browsers use the operator URL.
Agents use the ingestion URL, verify the manager certificate, and present their
own client certificate; an authenticated operator must approve the exact public
certificate fingerprint before its samples are accepted. Do not route browser
sessions to agent ingress or replace mTLS with a reverse proxy that strips it.

## Build

From the repository root, with Docker Engine and the Compose v2 plugin:

```sh
docker build --tag tracebolt-manager:local .
```

The build uses the repository's Go version and npm lockfile. Base image tags are
version-selected, not immutable digest pins: record the actual resulting image
ID/digest when validating a deployment. Dependency registries and image pulls
require network access during build. No runtime shell or download step exists.

The Dockerfile can cross-build Linux `amd64` and `arm64` via BuildKit:

```sh
docker buildx build --platform linux/amd64 --load -t tracebolt-manager:amd64 .
docker buildx build --platform linux/arm64 --load -t tracebolt-manager:arm64 .
```

A cross-build does not validate runtime behavior on that architecture. Use a
native host/runner for each architecture before treating it as tested. The
multi-architecture command with both platforms needs a configured exporter;
this guide intentionally does not push a registry manifest.

## Configuration and start

Supply previously provisioned operator/TLS configuration according to the native
LAN server contract. Configuration paths refer to paths *inside* the container;
state belongs under `/data/state` and read-only materials under `/run/tracebolt`.
The public origins must match the exact host and published port the browser and
agents use, including certificate DNS/IP subject alternative names.

The directory must contain `server.pem`, `server.key`, `agent-ca.pem` and
`operator-auth.json` and `lan.json`. Copy `deploy/lan.tls.example.json` as the
starting shape for `lan.json` and set the two exact public origins. The auth file has this structure (supply your previously
provisioned verifier; the placeholder cannot authenticate):

```json
{"schemaVersion":"tracebolt.operator-auth.v1","profile":"tls","passwordHash":"REPLACE_WITH_PREPROVISIONED_ARGON2ID_VERIFIER"}
```

Prepare the external directory so UID/GID 65532 can traverse it and read its
private files, while other users cannot. Private files must meet the manager's
strict permission checks. Docker Compose file-backed secrets do not reliably
change underlying file ownership; this configuration uses an explicit read-only
bind and never silently fixes host ownership as root. On Docker Desktop, verify
its bind-mount ownership semantics; use a native Linux server if those semantics
cannot meet the manager's private-file checks.

```sh
export TRACEBOLT_CONFIG_DIR=/absolute/path/to/your/private/tracebolt-config
docker compose -f deploy/compose.yaml config
docker compose -f deploy/compose.yaml up --build -d
```

For an explicitly authorized LAN deployment, set `TRACEBOLT_BIND_IP` to the
server's chosen LAN address before starting. Keep public origins/certificate
names consistent. Restrict host firewall access to the intended operator and
endpoint networks; this repository does not change firewall rules. Never expose
this pilot directly to the public Internet.

A running process is not proof of successful authentication. Open the exact HTTPS
operator origin using the configured CA, sign in, approve the intended public
client certificate only after verifying its fingerprint, then use the native
agent sender against the separate ingestion origin. Do not use TLS verification
bypass flags or trust all certificates.

## State, restart and rollback

`docker compose ... restart` and `down` retain the named state volume. `down -v`
deletes it and must not be used as routine shutdown. Stop the manager before
backing up the complete private data directory; SQLite sidecars and file modes
matter. Protect backups like endpoint telemetry and approval metadata. Restore
only into a private volume with the same ownership. Retain a pre-upgrade backup
and the prior tested image: compatibility of downgrading database schemas is
not guaranteed. Operator sessions are in memory and sign-in is required again
after a restart; approvals, revocations and accepted telemetry are durable.

## Verification and limitations

`tests/container` contains isolated smoke tests intended for a standard Linux
Docker runner. They use fresh short-lived fixture certificates and a random test
password, fabricate unknown endpoint metrics, publish ports to loopback only,
and clean up their containers/volume/files. They do not provision real endpoint
credentials, alter system trust, install agents or deploy to a user LAN.

The cloud editing shell has no Docker daemon. Passing Go fixture/static checks
there is **not** evidence that an image builds or a container starts. Consult the
exact commit's CI result for image-build and runtime evidence; architectures not
run there remain untested. Native endpoint installation, certificate operations,
retention/audit policies, host isolation and deployment review remain separate
acceptance gates.

Docker Engine on Linux and alternative compatible runtimes can avoid a paid
hosted service; check the runtime provider's current licensing terms. Docker
Desktop licensing depends on use. Tracebolt has not selected a project license;
public source availability does not grant one.

## Explicit HTTP LAN test profile

HTTPS is optional **only in the separately selected `http-test` mode**. This can
serve both the operator UI and agent API on a chosen LAN address. It is not a TLS
verification bypass and the normal TLS profile does not fall back to it.

**HTTP is unencrypted.** Other systems on the path may read or alter passwords,
sessions and telemetry. Use a segregated test network and disposable test-only
credentials/data. Do not reuse your TLS deployment's password verifier, client
keys, auth file or state volume. Operator authentication and device approval do
not supply confidentiality. Keep the application's unencrypted warning visible.

Copy `deploy/lan.http-test.example.json` to `http-test.json` in a **separate**
private configuration directory. Replace the documentation address `192.0.2.10`
with the actual chosen server LAN address in both origins. The explicit
`profile: "http-test"` and `insecureHTTPAcknowledged: true` are required. Its
`operator-auth.json` must likewise use `profile: "http-test"` and a separate
preprovisioned Argon2id verifier. Supply the test client public CA as
`agent-ca.pem`; do not copy a CA private key into the manager. TLS certificate/key
fields are omitted in this profile. Client configuration must explicitly select
the matching test transport with its separate Ed25519 client certificate/key.
HTTP agent requests bind the exact body, sequence, timestamp and origin with a
signature; this provides neither encryption nor server authentication. Never simply replace `https` with `http` in a normal
TLS deployment's configuration.

```sh
export TRACEBOLT_HTTP_TEST_BIND_IP=192.0.2.10  # replace with chosen server LAN IP
export TRACEBOLT_HTTP_TEST_CONFIG_DIR=/absolute/path/to/private/test-only-config
docker compose -f deploy/compose.http-test.yaml --profile http-test config
docker compose -f deploy/compose.http-test.yaml --profile http-test up --build -d
```

Use this as a standalone Compose file, not an override merged with the TLS file.
It has a different project/volume, ports 8787 (operator) and 8788 (agent), requires
an explicit bind address and does not auto-restart. No real LAN exposure occurs
until you deliberately run it on your server. State/auth profile checks reject
reuse across modes. Upgrading a test into a secure deployment requires new TLS
configuration and appropriate credentials/approval, not removing the warning or
silently changing its scheme.

This profile's template availability is not proof of runtime acceptance. Check
the exact commit's separately named HTTP container test result before use.
