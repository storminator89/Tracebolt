# First Linux test: central manager → Add device → reports

Use this page only with the exact reviewed source revision that contains it.
The corrected systemd installer needs its own green native acceptance result;
a successful build or foreground report is not that result. The repository's
published revision and a newer local source archive may contain different features.

For the current fresh disposable HTTP test with a native background service,
use the [inventory first-start guide](http-inventory-first-start.md). The process-level
examples below remain a manual setup and diagnostic reference.

## Manual setup and diagnostic route

Choose one fresh test environment, one Linux manager and one Linux endpoint.
Use the **guided `managed-operations-v2` collection profile** for the package and
operational views in this revision. Older basic/manual identities are retained
for compatibility; do not reuse their state directory for this test or switch
an existing installation's profile in place.

Start with foreground reporting below. Add the systemd service only after the
exact installer's native gate passes and you authorize changes on your endpoint.
No discovery scan, push installation or cloud account is needed.

## 1. Prepare the manager once

The remaining manual prerequisite is server/issuer material. There is currently
no one-click server setup wizard that provisions it for you.

Have the authorized administrator prepare a dedicated protected configuration
directory, a fresh private state volume and these files:

- LAN configuration from `deploy/lan.tls.example.json`, with your exact operator
  and agent origins and listener ports. The agent CA file must contain the
  dedicated client issuer certificate described below.
- A profile-matching `operator-auth.json` with the existing supported Argon2id
  password verifier. The password is entered at sign-in, never in a command.
- For TLS: a server certificate/key valid for **both** configured listener names,
  plus the public server CA used by the native bootstrap. The browser must already
  trust the server certificate normally; do not bypass a certificate warning.
- For guided enrollment: the protected Ed25519 client-auth-only, path-length-zero
  intermediate signing key and its certificate, its public root certificate,
  and the issuer certificate's expected SHA-256 DER fingerprint. The **root
  private key stays offline** and is never mounted into the manager.
- `enrollment.json` using the exact schema in
  [runtime configuration](enrollment-v2/runtime-config.md), with the additional
  field `"collectionProfile": "managed-operations-v2"`. Its profile must match
  the LAN configuration. Choose the manager instance ID once and retain it.

Private keys/verifiers must satisfy the documented private ownership and file
modes before first use. The container runs as UID/GID 65532; its private material
must be readable by that identity and pass the loader's protection checks.
Do not recursively change permissions on an existing directory to make startup
pass. Material loading, origin matching, issuer and state errors fail closed.

[Installation material checklist](installation.md) and
[guided configuration](enrollment-v2/runtime-config.md) contain the exact roles,
permissions and schema. Generated fixture keys are not deployment credentials.

### Docker, guided TLS

Run from the source root after substituting the approved real directory and LAN
address. The address/origins and certificate names must agree. This command keeps
the test manager in the foreground. Choose a new, unused Compose project name
for the first test. Its named state volume is then retained for subsequent runs
of that same project; a container exit does not erase the state. If the chosen
project/volume already exists, stop and inspect it or choose a different unused
name. Do not delete, reset or adopt it merely to complete this quickstart.

```sh
export TRACEBOLT_CONFIG_DIR=/absolute/path/to/private/manager-config
export TRACEBOLT_BIND_IP=YOUR_APPROVED_LAN_IP
export TRACEBOLT_TEST_PROJECT=YOUR_NEW_UNUSED_TLS_PROJECT_NAME

docker compose -p "$TRACEBOLT_TEST_PROJECT" -f deploy/compose.yaml build manager
docker compose -p "$TRACEBOLT_TEST_PROJECT" -f deploy/compose.yaml run --service-ports --rm manager \
  --lan-config /run/tracebolt/lan.json \
  --enrollment-config /run/tracebolt/enrollment.json
```

The explicit second argument matters: the existing base Compose command without
`--enrollment-config` starts the separate manual-approval mode. Do not run both
commands against the same state or ports. Keep the selected revision's Docker
acceptance evidence distinct from native process tests.

### Deliberately unencrypted LAN test

If you deliberately choose HTTP, use the separate configuration/state volume and
HTTP profile. Invitations, sign-in sessions and telemetry can be observed or
altered by network attackers; signed device payloads do not authenticate the
HTTP manager/UI or provide confidentiality. Use disposable test identities.
Issuer material and explicit device approval are still required.

```sh
export TRACEBOLT_HTTP_TEST_CONFIG_DIR=/absolute/path/to/separate/http-test-config
export TRACEBOLT_HTTP_TEST_BIND_IP=YOUR_APPROVED_LAN_IP
export TRACEBOLT_HTTP_TEST_PROJECT=YOUR_NEW_UNUSED_HTTP_PROJECT_NAME

docker compose -p "$TRACEBOLT_HTTP_TEST_PROJECT" -f deploy/compose.http-test.yaml --profile http-test build manager-http-test
docker compose -p "$TRACEBOLT_HTTP_TEST_PROJECT" -f deploy/compose.http-test.yaml --profile http-test run --service-ports --rm manager-http-test \
  --lan-config /run/tracebolt/http-test.json \
  --enrollment-config /run/tracebolt/enrollment.json
```

Both JSON files use `profile: "http-test"`; the LAN JSON explicitly acknowledges
HTTP and enrollment's `bootstrapServerCAFile` is empty. Never reuse the TLS state
volume or keys. The UI and native command keep the unencrypted warning visible.

### Native manager alternative

Build `cmd/lan-manager`, point the LAN JSON at host paths and the built `web/dist`,
then use the same two arguments:

```sh
/absolute/path/lan-manager --lan-config /absolute/path/lan.json \
  --enrollment-config /absolute/path/enrollment.json
```

No command here changes firewall, global trust or your network automatically.
The administrator selects approved LAN exposure separately.

## 2. Build the Linux endpoint commands

Build on the endpoint's Linux architecture from the same selected source revision,
using Go 1.27.1. No binary download, signed publisher distribution or source-to-binary
reproducibility guarantee is supplied by these commands.

```sh
go build -buildvcs=false -o bin/enroll-agent ./cmd/enroll-agent
go build -buildvcs=false -o bin/lan-agent ./cmd/lan-agent
go build -buildvcs=false -o bin/agent-service ./cmd/agent-service
```

## 3. Add, approve and watch one device

1. Open the configured manager address and sign in. Choose **Add device → Linux**.
   Read and affirm the displayed collection notice. Download only the public
   bootstrap to the endpoint through a trusted channel.
2. From a real endpoint terminal, start enrollment with an absolute protected
   bootstrap path and a **new** private endpoint state directory:

   ```sh
   /absolute/path/enroll-agent --bootstrap /absolute/path/bootstrap.json \
     --state-directory /absolute/path/new-private-device-state
   ```

   HTTP test also requires `--insecure-http-test`. Check the destinations and
   certificate fingerprints shown locally. Enter the one-time invitation only
   at the hidden prompt. Never put it in a command, URL, environment or file.
3. Compare the complete local fingerprint and comparison value with the pending
   device in the manager, then approve that device. Preserve the same local state
   when resuming an interrupted enrollment.
4. After successful enrollment, use the printed sender command:

   ```sh
   /absolute/path/lan-agent --config /absolute/path/new-private-device-state/agent.json --foreground
   ```

5. In the Admin UI, check the device's advancing collection/receipt times. Open
   **Inventory** for the bounded agent-visible operational sections and **Security**
   for exact release/package observations, coverage and optional catalog review.
   Missing/denied/partial data stays visible. A catalog is unverified; review
   candidates do not establish confirmed CVEs or offered updates.

Foreground reporting stops with the terminal/process. Keep this distinction
visible until the installed service is tested on your authorized target.

## 4. Optional installed Linux service

Use [the fixed-path service guide](linux-agent-service.md) only after checking its
exact native acceptance result. `agent-service` defaults to read-only preflight;
`--apply` creates a dedicated non-login account and service and needs administrator
authorization. It verifies selected source/binary/bootstrap hashes, enrolls as the
dedicated account, and starts only after the existing guided state validates.

The installer owns a **different fixed state domain** from the foreground example.
Do not move/copy the foreground private ledger into it. Either use foreground
for this test, or create the service's own invitation and follow the service guide
from the start. An installer failure may retain state for same-identity recovery.

## If the first test stops

- **Manager will not start:** check exact config/profile/origins, current certificate
  roles/SANs, ownership and fresh or correctly bound state. Keep the fixed error
  code; never upload private configuration or keys.
- **Add device unavailable:** confirm the manager was started with both config
  arguments and the guided profile. Do not populate a manual registry and then
  try to adopt it into guided mode.
- **Enrollment interrupted:** retry the same bootstrap and state directory. Do
  not reset missing/rejected sequence state. HTTP ambiguity has stricter recovery
  limits in [the native client guide](enrollment-v2/native-client.md).
- **Inventory unknown/denied:** collection has not proved those facts. Check the
  supported distro and reported fixed reason; do not grant root or weaken the
  service sandbox merely to obtain a green result.
- **Service preflight/apply fails:** retain the fixed stage and local state; stop
  before manual cleanup. A service restart is not evidence of an OS reboot test.

Windows/macOS installation and a cached-APT executor are outside this Linux test.
There is no automatic patch installation in this flow.
