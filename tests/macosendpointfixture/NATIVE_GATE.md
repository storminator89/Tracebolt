# Manual hosted endpoint-subset gate: source prepared, execution unapproved

This gate is separate from the inventory, log and interface gates. Its only target
is one standard disposable GitHub-hosted `macos-15` (arm64) or
`macos-15-intel` (amd64) VM in `storminator89/Tracebolt`. There is no local-Mac,
self-hosted, automatic CI, release or installation path. Publishing this source,
passing its fake tests or building it does not approve a native run.

The endpoint still talks to a **simulated loopback manager**. It cannot establish
production-manager interoperability, independent human trust approval, durable
manager transactions, renewal, launchd or a macOS release. Exclusive sender-lock
conflict proof remains missing. `blocked=true`, `custody_case_implemented=false`
and `stage1_passed=false` remain unconditional even if every prepared endpoint
case passes. Job success means only that the narrower endpoint subset and cleanup
succeeded; it must not be promoted into full Stage 1 acceptance.

## Source boundary and fixed workflow

The original `run.py` main and `run_after_exact_review` stay inert. An ordinary
Go build stays inert. The explicit Darwin-only `tracebolt_endpoint_native` build
tag selects `native_main.go`, which admits only nonroot same-UID execution with
private parent stdin/stdout pipes. It calls the unchanged peer implementation.
That tagged binary is a native test artifact, not a product or a generic unlock.
Do not execute it separately, run tagged tests natively or publish its bytes.

`gate.py` is a separate wrapper. No arguments emits a closed blocked result and
returns 2 without source/host inspection. `--check` hashes public source only; it
cannot construct a runtime, inspect native endpoint state, compile, start a child,
open a PTY/socket or generate credentials. `--verify-dispatch` only checks the
same source plus fixed hosted metadata. `--execute` requires all of:

- Native Darwin, exactly the chosen standard runner/architecture, public named
  repository, `workflow_dispatch`, and run attempt 1
- Explicit `endpoint_subset=true`, default false in the manual-only workflow
- Exact 40-character reviewed commit matching both `GITHUB_SHA` and
  `GITHUB_WORKFLOW_SHA`, and the independent exact source digest
- Nonroot equal real/effective UID and GID, isolated/no-site/no-bytecode Python
- Verified source-loaded helper and fixture bytes, never `.pyc` dependency loading
- Successful bounded tool preparation, captured matching Git source identity,
  strict public OS/image metadata and immediate binary custody rechecks

Ambient environment is not an authorization credential. GitHub dispatch must
still be explicitly authorized for the reviewed effect plan below. A rerun is
rejected; an uncertain run needs investigation and fresh approval, not automatic
retry. Checks fail closed on a changed source, different runner or toolchain,
missing metadata, output bound, unknown schema, failed reap or uncertain custody.

The source digest covers `go.mod`, `go.sum`, `AGENTS.md`, the exact workflow,
the separate source-only CI workflow, macOS status, all `cmd` and `internal` files, and both test-source trees. The
unchanged supervisor is included because this wrapper reuses only its bounded
`Processes`/`TaskTree` and fixed source/tool/OS metadata helpers. None of its
log, inventory or interface preparation/execution functions is called.

For review, compute the public source digest without runtime activity:

```sh
python3 -I -S -B tests/macosendpointfixture/gate.py --check
```

Future approval must identify the exact published commit, this digest, selected
runner/architecture, one first-attempt invocation and the complete effects below.
Do not use a moving branch, a shortened hash, a different workflow SHA or an old
gate approval. The workflow has no push/PR/scheduled/reusable trigger, no native
matrix fan-out, no artifact upload and no automatic retry.

## Tool and executable provenance

The workflow uses the same pinned checkout and setup-go action commits as the
existing native supervisor, with persisted checkout credentials disabled, Go
1.27.1 fixed, no setup-go cache and no version fallback. Tool setup and bounded
Go module download/verification are preparation effects. Builds use private
HOME/TMP/cache/modules, fixed module proxy/checksum endpoints, no ambient Go
configuration, `GOTOOLCHAIN=local`, `GOENV=off`, `GOWORK=off`,
`GOFLAGS=-mod=readonly`, `CGO_ENABLED=0`, `GOVCS=*:off`, `-trimpath`,
`-buildvcs=false`, and one compiler worker. Module access is disabled before the
three exact project builds finish and remains absent from the endpoint phase.
No custom installer, `sudo`, account grant, permission repair or tool fallback
is introduced.

The three compiled artifacts are only:

1. `./tests/macosendpointfixture` with the explicit native tag
2. `./cmd/enroll-agent`, unchanged product source
3. `./cmd/macos-agent`, unchanged product source

Observed Python, Go, compile, link and resulting binary SHA-256 values are recorded.
This is reviewed-source/trusted-toolchain build provenance, not a claim that the
resulting binary hashes were independently reviewed before compilation. A new
mode-0700 task/bin tree contains single-link regular binaries. Inode, ownership,
mode, size, timestamps and hash are checked after building and immediately before
every child invocation. The source manifest is rechecked after building and
before the native phase. The pinned helper obtains matching actual HEAD/tree
metadata; only allowlisted public hashes, versions and architecture leave the gate.

The standard hosted runner and installed Python/stdlib are trusted execution
prerequisites. Hashing the already-running interpreter is provenance, not verified
boot. A hostile same-UID process can defeat pathname checks; the disposable run
must exclude concurrent untrusted jobs/modification. This source does not add an
OS sandbox, immutable filesystem flag or security-setting change.

## Exact future execution effects requiring separate approval

Read the full [fixture plan](README.md#exact-effects-to-review-before-future-execution).
The wrapper adds only fixed build/source/version metadata work; the endpoint
subset retains that plan unchanged:

- Generate disposable peer CA/issuer/server keys and invitation in memory, plus
  one persisted fresh endpoint identity in a new private invocation subtree
- Bind exactly two peer-owned IPv4 TLS 1.3 listeners on literal `127.0.0.1:0`;
  make one certificate-less negative request to the exact telemetry origin
- Start unchanged enrollment twice under a bounded controlling PTY, cancel the
  first hidden prompt, restore echo, resume exact seed/CSR/IDs, and transfer the
  synthetic invitation privately from peer pipe to supervisor memory to hidden
  PTY; no invitation in args, environment, files, URL or public output
- Compare complete public fingerprint and comparison code with the simulated
  peer before scripted approval; this is plumbing, not independent human trust
- Run one unchanged `--validate-guided` and four one-shot unchanged reporters;
  verify lost-receipt pending retry, original timestamps and advancing sequence
- Read only the documented basic sysctl/root-statfs sources plus owned terminal,
  process and protected new-file metadata/state required by these native commands
- Stop/reap owned children, join peer listeners, validate and remove only the new
  fixture subtree; never adopt/reset prior state or delete uncertain custody

There are seven endpoint children plus the peer. The peer has its own four-minute
bound; the wrapper native phase has a five-minute alarm. Build processes have
individual limits and the workflow has a 30-minute bound. The wrapper defers
cancellation while registering a returned endpoint child, then delivers it to the
fixture so cleanup retains its handle. Fixture cleanup masks all three supported signals in the supervisor only;
no child is started while masked. Final parent-only cleanup independently reaps
known runtime handles as well as build children and removes build scratch only
after the fixture has proved
its children/listeners stopped and its owned tree removed. Invalid execution
evidence yields unknown/false cleanup booleans rather than invented success. A failed construction
or uncertain cleanup preserves the parent task tree and prevents a pass.

The wrapper also invokes only these fixed metadata commands: Git HEAD/tree
verification, `sw_vers -productVersion`, `sw_vers -buildVersion`, `uname -r`, and
`uname -m`. It does not run `sysctl`, `pkgutil`, `ps`, `ifconfig` or `log` probes.
Product basic collection itself makes its previously documented native reads.
There is no inventory, OSLog, package/provider call, user account enumeration,
TCC/Full Disk Access, Keychain/trust, service, launchd, firewall, persistence,
production credential or real user invitation.

## Output and validation

Final execution evidence is one bounded closed metadata-only JSON line in
ordinary job output; the earlier dispatch check emits its separate closed line.
These wrapper emissions contain no raw exception, child stdout/stderr, PTY text,
report payload, private state/telemetry hash, endpoint identity, PID, path,
invitation, key or certificate. Trusted checkout/setup-go steps have their own
ordinary public source/tool logs, which can include runner/tool paths; they run
before endpoint effects and do not receive endpoint private bytes.
No files are uploaded. Public job logs and their ordinary retention are part of
the future workflow approval; wider artifact publication remains separate.

`endpoint_cases_passed` reports only the implemented subset. Cleanup failure
cannot leave `reason=endpoint_subset_passed`. The wrapper never changes the
fixture's permanent full-stage block or claims a lock-conflict pass from a generic
CLI failure. `FutureInputs` and dispatch inputs cannot authorize anything alone.

Safe checks are the unchanged five pure Go contracts, unchanged 37 fake Python
fixture checks, the new fake `test_gate.py` checks, and cross-compilation only.
The gate tests globally deny real subprocess, socket, PTY and termios acquisition;
fake runtime objects supply every orchestration result. Do not run the tagged
peer, native fixture adapter, native enrollment or collector during source checks.

The separate `macos-endpoint-source.yml` job runs only on standard Ubuntu, with
path-filtered pull requests/main pushes for this fixture, its two workflows and
locked Go files. It uses the same pinned actions/tool version, runs only pure Go
and fake Python tests, and cross-compiles both Darwin architectures using the
manual gate's exact `-trimpath -buildvcs=false` commands including the native peer
tag. It never executes those Darwin outputs, dispatches the manual workflow,
opens endpoint/network/PTY providers or uploads binaries. A source-CI pass is
compilation evidence only; native approval and full-stage blocks are unchanged.
