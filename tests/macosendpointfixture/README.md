# Source-only macOS endpoint fixture

This is a **native endpoint fixture with a simulated loopback manager**, not
production-manager interoperability or macOS release acceptance. No native run,
credential generation, listener, PTY or collector execution was performed to
prepare this source packet. The initial slice is basic TLS only. Renewal,
inventory, real Linux-manager persistence, launchd, installers and accounts are
out of scope.

The original default entry points remain unconditionally inert:

- `run.py` writes one exact boolean-only blocked result and exits 2. It does not
  parse arguments, inspect environment/state, start processes or inspect the host.
- The Go executable writes a fixed blocked result. Its `main` does not call the
  runtime peer. No flag, environment variable or stdin command enables execution.
- `run_after_exact_review` raises a fixed safe exception. This is deliberately an
  unavailable execution edge, not a permission token or an undocumented unlock.

The separate [manual hosted gate](NATIVE_GATE.md) now prepares an explicit
Darwin-only tagged peer and a dedicated wrapper. Neither original default edge
is replaced. The new workflow is manual-only and defaults off; publication,
compilation or approval of Mac inventory/log/interface probes cannot authorize
its dispatch. Exact runtime approval is still absent and no native endpoint run
is claimed. The gate records observed build hashes and checks custody before
every invocation; it does not claim those binary bytes were reviewed in advance.

## Prepared endpoint subset

The future-only Python adapters and `_exercise` compose:

1. Two peer-owned literal `127.0.0.1` ephemeral TLS origins, separate enrollment
   and telemetry. Dedicated synthetic client-auth issuer; explicit server CA and
   literal IP SAN; TLS 1.3 only; no default trust, DNS, proxy or redirects.
2. Actual unchanged Darwin `enroll-agent` under a bounded controlling PTY. Cancel
   once at the hidden prompt, reap the child, and compare complete saved seed,
   CSR, claim and operation IDs on resume. Check native terminal attributes are
   restored after cancellation and success. Check no invitation bytes were echoed.
3. Match the complete local public SPKI fingerprint and 128-bit comparison code
   with the peer's cryptographically verified pending claim before scripted
   approval. This is comparison plumbing, not an independent human trust decision.
4. Activate and validate the actual handoff with `macos-agent --validate-guided`,
   then send the first one-shot basic report. The peer verifies the current exact
   issued leaf and binding; a separate no-client-certificate request must receive
   the specific remote TLS certificate-required alert. Connection, timeout, SAN
   and trust errors cannot satisfy that negative check.
5. Accept report 2 only in peer memory, close its owned connection before sending
   any receipt, and require the endpoint to retain pending state. Reap that sender
   and start another with exactly the same state. Require byte-identical pending
   body/sequence/collection times and the original first-receipt timestamp. The
   ordinary two-minute basic freshness policy remains active. Report 3 must then
   advance the floor. No key regeneration, counter reset or retimestamping.
6. Stop/join the owned peer and children, verify custody, then remove only the new
   fixture tree. Failure/custody uncertainty must stay a failed or blocked result.

The Go peer reuses `enrollmentcrypto`, `enrollmentissuer`, `enrollmentstate`,
`lanconfig.StrictObject` and `lanstore.ValidateFrame`. Importing the frame
validator does **not** open a store. No `enrollmentstore.Open`, `lanstore.Open`,
production handler substitution or protected-store bypass is present. The
process-local `Engine` and `receiptMemory` are explicitly simulated, volatile
state. They cannot prove transactions, SQLite durability, manager restart,
operator authentication, production replay retention or certificate retirement.

The fixture requires the basic wire schema, public `macos` platform, native
architecture and fixed `local-macos` collector role. It checks expected source
identities, unavailable CPU/used-memory percentages, metric/evidence quality
consistency and the absence of expanded fields. Unknown or denied observations
remain valid unavailable evidence, rather than invented successful measurements.

## Deliberate unresolved gate

Exclusive-custody acceptance remains unimplemented. The unchanged one-shot CLI
prints the same safe failure message for a lock conflict and other failures;
a second sender's generic failure is not enough proof. This packet does not add
a production diagnostic seam or call a generic failure a lock pass.

The result therefore keeps `custody_case_implemented` and `stage1_passed` false,
and `blocked` true even if a future reviewed run proves the implemented endpoint
subset. Individual booleans plus `endpoint_cases_passed` express that narrower
outcome. No skipped or incomplete case becomes full Stage 1 acceptance.

## Exact effects to review before future execution

### Inputs and origin

Select one identified nonroot existing Mac identity and one architecture per run:
Apple Silicon `arm64` or Intel `amd64`. Confirm the actual native platform,
canonical protected temporary parent, supported local filesystem and exact
source/tool/binary provenance. Existing hosted-runner privileges limit the claim.
The manual hosted gate uses the established pinned checkout/setup-go actions
and Go 1.27.1, builds exact reviewed project source in its new private task tree,
records the resulting binary/tool hashes and checks binary inode/hash custody
immediately before dispatch. Tool/module preparation precedes endpoint effects;
there is no module acquisition or tool download within the native endpoint phase.

The manual wrapper requires the exact reviewed source digest covering itself,
this fixture, the reused supervisor and all `cmd`/`internal` sources. It emits only
allowlisted public provenance/OS/architecture fields outside the closed result.
`FutureInputs` contains observed binary hashes but is **not** an authorization
object. The gate establishes a protected new binary directory and rechecks inode,
mode and exact hash immediately before every child. The trusted disposable runner
context must exclude concurrent same-UID modification; these checks cannot make
a later pathname exec atomic or promise immutable storage against the owner. No
host-global security change is implied.

The peer opens exactly two `tcp4` sockets on `127.0.0.1:0`; selected origins are
then fixed for that invocation. Enrollment routes are only
`/v2/macos/enrollment/{challenge,claim,status,credential,activate}`. Telemetry is
only `/v1/macos/telemetry`. The peer also makes one certificate-less TLS request
to that exact telemetry origin. No LAN, external endpoint, tunnel, discovery,
ambient proxy, redirect or DNS is intended. This is not a firewall sandbox.

### Keys and material

Execution generates new Ed25519 root, client-issuer and server test keys in peer
memory, plus one 32-byte invitation in memory. The root/server/issuer keys are
never serialized to files or protocol output. The actual endpoint creates a new
Ed25519 identity and persists its private seed/key in the new private state.
The short-lived fixture leaf uses the same endpoint key and the existing fixed
client template. No production credential, account, user invitation or system
trust store is used.

The peer `start` response contains only public bootstrap and invitation on its
private parent pipe. The invitation goes from that pipe to supervisor memory
and the owned controlling PTY only after native echo is verified disabled. It
never goes into arguments, environment, files, URLs, ordinary agent stdin or
public output. Strings/copies in Python and Go cannot promise perfect memory
erasure; mutable buffers are cleared best-effort. Process exit is not proof of
physical erasure.

### Reads, writes and subprocesses

Approve these unchanged native commands, with exact absolute reviewed paths:

```text
enroll-agent --bootstrap ABS_NEW_BOOTSTRAP --state-directory ABS_NEW_STATE --timeout 2m
macos-agent --config ABS_ACTUAL_AGENT_JSON --validate-guided
macos-agent --config ABS_ACTUAL_AGENT_JSON
```

The first command is started twice (prompt cancellation, then resume). Validation
is once; reporting is four one-shot children (fresh, lost receipt, exact retry,
fresh next sequence). There is no shell or collector subprocess. The supervisor
owns and bounds all children and their outputs. The peer has a four-minute
context bound; enrollment uses its real two-minute CLI deadline. Cleanup is also
bounded. Ordinary native read scope is exactly:

- `sysctl(kern.osproductversion)` and `sysctl(kern.osrelease)`
- `sysctl(kern.boottime)` and `sysctl(hw.memsize)`
- `statfs("/")`, clock and runtime architecture
- `/dev/tty`, owned PTY termios reads/writes and process lifecycle operations
- Protected directory ancestor metadata/ACL inspection and no-follow private
  file reads/writes, exclusive locks, rename, flush and directory synchronization

No log content, account enumeration, inventory, package queries, TCC/Full Disk
Access, Keychain/system trust, sudo, service, launchd, firewall, entitlement or
security setting changes are allowed.

Create one canonical mode-0700 invocation tree under the explicitly approved
canonical temporary parent. Do not normalize `/tmp` or `/var` symlink aliases
inside product paths. Public bootstrap is mode 0600. Runtime endpoint state
includes enrollment lock/ledger, key/certificate, explicit CA, actual generated
`agent.json`, `ready.json`, and `telemetry/` sender state. The driver reads bounded
private bytes only to compare seed/CSR/IDs, original key and exact pending state.
Do not expose those bytes or their hashes. There is no prior state to adopt.

### Cleanup and evidence

After all owned children are reaped and peer listeners/handlers are joined, the
supervisor inventories only its new tree via no-follow directory descriptors,
checks ownership, regular-file type, mode, single-link files and recorded inode
identity, then removes those recorded entries. A custody mismatch preserves the
remaining tree and prevents a pass. No broad glob, external path cleanup,
symlink following, permission repair or failed-user-enrollment rollback exists.
Python cannot claim atomic inode compare-and-unlink against a hostile same-UID
race; the approved runtime context must exclude concurrent modification.

One final result is bounded and closed to boolean fields. The peer status
contains only its fixed booleans and bounded counts; command responses are
private protocol material, not result evidence. Output must never include raw
stdout/stderr, PTY data, reports, measurements, identifiers, paths, PIDs,
invitation, verifiers, keys/certificates, private state or telemetry hashes.
The separate exact gate adds observed public source/tool/OS provenance and a
closed failure code after admission; this source packet does not invent runtime
facts. Local-only results are valid. Public artifact upload is separate approval.

## Safe source checks

These tests exercise only deterministic in-memory contracts and fake adapters.
They must never call `newScriptedPeer`, `runPeer`, `NativeRuntime`, `_spawn`, a
native collector or an actual PTY. There is no dynamic integration test switch.

```sh
GOTOOLCHAIN=local GOENV=off GOPROXY=off GOSUMDB=off GOMAXPROCS=2 \
  go test -p 1 -buildvcs=false ./tests/macosendpointfixture
python3 -B -m unittest discover -s tests/macosendpointfixture -p test_run.py
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go test -c -p 1 -buildvcs=false \
  -o /APPROVED_BUILD_OUTPUT/endpoint-arm64.test ./tests/macosendpointfixture
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go test -c -p 1 -buildvcs=false \
  -o /APPROVED_BUILD_OUTPUT/endpoint-amd64.test ./tests/macosendpointfixture
```

Use the pinned Go version and already available offline module cache. The Darwin
commands compile only; do not execute those binaries. Test success and
cross-compilation establish source consistency only. The bounded PTY, TLS
protocol composition, hidden-prompt restoration, protected native filesystem
behavior and endpoint retry still need a separately approved native run.
