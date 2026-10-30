# Guided manager configuration and read-only doctor (TB-03 source candidate)

`cmd/manager-setup` adds **native Linux guided-TLS configuration-only** setup.
It is not an installer, credential issuer, live health probe, database checker or
Windows acceptance result. It does not change the existing `lan-manager` startup
contract. Follow [installation](installation.md) for approvals, exposure, support
and acceptance, and [guided enrollment](enrollment-v2/runtime-config.md) for the
separate dedicated client-auth issuer.

## 1. Select the target and provision approved material

Inspect the actual Linux host, architecture, exact source revision, existing
state, intended nonroot runtime UID and network namespace first. An editing PC is
not implicitly the deployment server. Preserve every existing identity, receipt,
revocation, replay/consumption floor and partial file. This create-only command
cannot adopt, migrate, reset or overwrite an existing installation.

Have an authorized administrator/custodian provision, through their approved
secure handoff:

- An existing runtime-owned private configuration directory, normally `0700`, and
  a separate existing **empty** runtime-owned private state directory.
- A currently valid ServerAuth-only server certificate/key pair with SANs for
  **both** exact client-visible HTTPS origin hosts.
- A dedicated Ed25519 client-auth-only pathLen0 issuing intermediate, its matching
  PKCS#8 key and the **public** offline root certificate. The root private key stays
  offline; this command never requests, generates or writes it. The ingress CA
  file contains exactly the dedicated intermediate, not the root or a mixed pool.
- A protected `tracebolt.enrollment-config.v2` file with the explicit manager ID,
  issuer fingerprint, issuer paths and separately selected public server CA.
- Profile-bound operator-auth v1/v2 data with an accepted Argon2id verifier and,
  where selected, the exact reviewed operator capabilities. No passwords,
  verifier strings, invitations or private keys belong in arguments, environment,
  chat, logs or source control.
- A built frontend from the **same reviewed revision**, in a protected directory
  with `index.html`. This tool checks the entry point, not a full release manifest.

Private keys and auth must be regular, single-link, runtime-UID-owned files with
no group/world access (normally `0400`/`0600`). Public material can be root- or
runtime-owned, never group/world writable. Absolute canonical paths and protected
non-symlink ancestor chains are required. No ownership, mode, account, firewall,
DNS, trust-store or service changes are performed by setup or doctor.

The command deliberately does **not** solve missing trust or credentials by using
fixtures, inventing production values, weakening protection or falling back to
HTTP. Stop at missing material/authorization. See the installation material
checklist and the separately authorized custodian workflow.

## 2. Build the tools from one revision

Use the selected source's locked dependencies, Go **1.27.1**, Node **24** and
existing npm lockfile. With the approved build prerequisites already available:

```sh
(cd web && npm ci --ignore-scripts && npm run build)
go build -buildvcs=false -trimpath -o bin/lan-manager ./cmd/lan-manager
go build -buildvcs=false -trimpath -o bin/manager-setup ./cmd/manager-setup
./bin/manager-setup --help
```

Record the full source SHA and resulting binary/frontend hashes. A source hash
or local build is not a signed publisher guarantee. A versioned published manager
image/digest and image packaging of this command remain separate TB-01 gates;
this native command does not manufacture either. The existing Docker image uses
container paths and mount/UID semantics: do not pass those paths to a host-native
check and mistake that for container acceptance. The following example is a
**native host-path** workflow only.

## 3. Create one new LAN configuration

Run as the already authorized nonroot runtime UID, **not root**. Replace the
example UID, paths, origins and binds with the locally reviewed target values.
The `.invalid` hostname is documentation, not usable production configuration.

```sh
./bin/manager-setup init \
  --runtime-uid 65532 \
  --output /srv/tracebolt/private/lan.json \
  --enrollment-config /srv/tracebolt/private/enrollment.json \
  --ack-provisioned-material \
  --operator-origin https://manager.example.invalid:8443 \
  --agent-origin https://manager.example.invalid:8444 \
  --operator-listen 127.0.0.1:8443 \
  --agent-listen 127.0.0.1:8444 \
  --tls-certificate /srv/tracebolt/private/server.pem \
  --tls-private-key /srv/tracebolt/private/server.key \
  --agent-client-ca /srv/tracebolt/private/client-issuer.pem \
  --operator-auth /srv/tracebolt/private/operator-auth.json \
  --state-directory /srv/tracebolt/state \
  --web-directory /srv/tracebolt/web \
  --windows-inventory
```

Loopback binds are the safe defaults, **not** an endpoint-reachable deployment.
A real Windows endpoint needs the approved reachable literal LAN bind addresses,
DNS/SAN mapping and exposure plan from the installation runbook. Choosing and
publishing those addresses/firewall rules is a separate authorized host action.

`--ack-provisioned-material` acknowledges the reviewed preprovisioned material
and the new config write; it never grants endpoint scopes or authorizes broader
host changes. `--windows-inventory` is a deliberate fresh manager configuration
opt-in, not an upgrade or reconsent of existing device identities.

Before writing, init performs doctor checks and requires empty protected state.
It creates **only** `lan.json`, with exclusive creation and private mode, then
syncs file and directory. Existing or dangling-link targets and concurrent losers
are refused unchanged. State and frontend trees must be disjoint; configuration targets cannot be
inside either, and selected configuration/credential/issuer material cannot be
inside the served frontend. No keys, auth, enrollment configuration, mode markers,
database, services or directories are created. A failed write/sync may leave a
partial or durability-uncertain file: it is retained for local inspection, never
automatically deleted or overwritten. Stop dependent startup and do not blindly
retry initialization.

## 4. Run the non-mutating doctor

Use the same runtime UID and filesystem/network namespace as the intended manager:

```sh
./bin/manager-setup doctor \
  --runtime-uid 65532 \
  --lan-config /srv/tracebolt/private/lan.json \
  --enrollment-config /srv/tracebolt/private/enrollment.json \
  --require-windows
```

Every diagnostic is fixed-text JSON under schema `tracebolt.manager-setup.v1`:
`operation`, `scope`, `ok`, `created`, `checks[]` (`code`, `status`, `message`,
`nextStep`) and explicit `limitations`. No input paths, hosts, values, raw errors,
certificates, key bytes, verifier strings, usernames or database content are echoed.
Exit `0` means configuration checks passed; failure or an unknown check exits
nonzero. `created` is true only after confirmed init durability; `doctor` never
sets it. Invalid arguments are also redacted structured diagnostics. Help contains
only static usage text.

Checks include strict canonical origins/listener shapes, the runtime UID, bounded
protected file reads, server key pairing, each origin's SAN, server and issuer
validity, operator schema/verifier policy, the complete runtime issuer/trust/key
contract, explicit Windows profile, state-directory protection and frontend entry
point. TLS 1.3 is the selected runtime's fixed source policy, **not a live handshake**.

| Diagnostic code | Next action |
| --- | --- |
| `runtime_uid` | Run as the selected nonroot UID; do not substitute root. |
| `lan_config`, `tls_origins` | Review canonical distinct HTTPS origins, schema and literal-IP listener addresses. |
| `operator_san`, `agent_san` | Review the exact client-visible host and approved server SANs; never bypass verification. |
| `server_key_file`, `operator_auth_file` | Custodian reviews runtime ownership, private mode, single-link file and ancestor protection locally. |
| `operator_auth` | Custodian supplies valid profile-bound verifier/capabilities, not placeholders. |
| `issuer_missing`, `issuer_config_file` | Supply the separately approved protected issuer configuration; keep root private keys offline. |
| `issuer_validity`, `issuer_trust_validity` | Review issuer/root lifetime, exact fingerprint/key/role and selected server trust; no automatic issuer replacement. |
| `windows_profile` | Review the explicit fresh Windows manager opt-in; no identity or receipt promotion. |
| `listener_overlap`, `operator_port`, `agent_port` | Inspect the existing workload and chosen port/exposure locally; doctor never stops a service. |
| `port_snapshot` (`unknown`) | A complete bounded procfs snapshot was unavailable; inspect locally in the correct namespace. |
| `additional_capabilities` (`unknown`) | Review separately configured macOS/action/update/MSI/package domains through their own contracts; do not rewrite scopes to make doctor pass. |
| `output_separation`, `directory_separation`, `material_exposure`, `issuer_material_exposure`, `configuration_exposure` | Preserve existing material and review state/frontend/configuration/credential tree separation with the custodian. |

Ports are inspected by bounded **reads** of `/proc/net/tcp` and `tcp6`, never by
binding, listening, connecting, killing a process or modifying host settings.
IPv6 wildcard collisions are conservative because procfs does not prove v6-only
socket policy. Results cover the current Linux network namespace and instant;
Docker host publication must be inspected separately. An already running manager
can be the expected conflict. No successful result reserves a port.

Doctor never calls runtime preparation, opens SQLite, creates or validates a mode
marker, reads database contents, repairs journals, initializes counters or changes
identities. Ordinary read access may update filesystem access-time metadata; no
configuration/key content, mode, modification time or database write is performed.
`ok:true` therefore means **configuration-only**, not safe migration, database
integrity, successful login, startup, endpoint reachability or native acceptance.

## 5. Start only under the separately approved deployment plan

After all configuration checks and independent state/identity compatibility
review, follow the installation runbook's native manager startup:

```sh
./bin/lan-manager \
  --lan-config /srv/tracebolt/private/lan.json \
  --enrollment-config /srv/tracebolt/private/enrollment.json
```

Startup, unlike doctor, initializes runtime state and opens approved listeners.
Then establish normal authenticated TLS login and protected API behavior at the
exact configured origin. Use the matching reviewed Windows Setup and
[Windows enrollment/status evidence](windows-status.md), explicitly acknowledge
its actual scopes, enter invitation secrets only through the supported hidden
local handoff and compare/approve the real public device fingerprint. Confirm
fresh non-synthetic observations. Do not run a Linux endpoint command on Windows
or use an older release's successful run as this acceptance evidence.

## Evidence and open gates

The targeted Go source tests use **generated disposable certificate fixtures**.
They cover unchanged contents/modes/mtimes/directory entries across success and
failure diagnostics, retained fake databases/markers not opened, SAN/origin/auth/
file-mode/issuer lifetime/Windows errors, port snapshots/conflicts/unknowns,
redaction, existing/dangling-link/hardlink refusal, nonempty-state refusal and
concurrent exclusive creation. These are source tests, not host provisioning,
Docker runtime, a live TLS handshake, Windows execution or Windows↔Linux↔browser
E2E. Race/build/cross-build evidence must be recorded separately for the exact
revision.

TB-03 is **not closed** by this bounded implementation. Still required: published
versioned manager image with digest and jointly pinned frontend (TB-01), reviewed
real DNS/TLS/auth/issuer material, image/container-path/UID acceptance, and a real
supported fresh Linux host reaching Windows enrollment readiness and completing
native/browser acceptance without mixed source pins. No host/security/credential
changes or external deployment were authorized or performed by these source tests.
