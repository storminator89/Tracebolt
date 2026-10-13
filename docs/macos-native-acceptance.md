# macOS manual native evidence candidate

**Source candidate, default-off, not production acceptance.** The first separately
approved native run is recorded in [2026-10-13 evidence](macos-native-evidence-20261013.md).
It does not authorize another run. The log version-2 diagnostics and the
separate [Gate I interface diagnostics](macos-interface-diagnostics.md) are
source-only and have not been executed natively. This harness is not a Tracebolt
agent, production log adapter, host grant, installation, release or proof of
normal non-admin access. Existing fixture workflows remain unchanged.
Publishing or merging these files does not authorize a dispatch. Independently
review the exact assembled commit/tree and source digest, then obtain separate
approval of the selected gates, two hosts and public evidence upload before a run.

## Fixed dispatch boundary

`.github/workflows/macos-native-acceptance.yml` has only `workflow_dispatch`.
All three gate selectors (A, B and I) default to false. Gate A and Gate I are
mutually exclusive; Gate B remains an independent selection. It accepts only public
`storminator89/Tracebolt`, first run attempt, standard GitHub-hosted `macos-15`
(ARM64) and `macos-15-intel` (X64). There is no caller-supplied runner, command,
path, predicate or time window. A private fork, different label, rerun, non-Darwin
host, missing explicit selection or mismatched reviewed source is refused. This
is an accident guard, not authentication or permission by itself.

Each job has a 20-minute limit. Permissions are only `contents: read`: no OIDC,
secrets input, service container, sudo, larger/self-hosted runner, automatic
rerun or cache upload. Checkout uses the existing reviewed action pin and does
not persist its credential. The exact approved commit must match both
`GITHUB_SHA` and `GITHUB_WORKFLOW_SHA`; checkout uses that current commit.

After all source files have been assembled, an inert check is:

```sh
python3 -B tests/macosnativeacceptance/run.py --check
python3 -B -m unittest discover -s tests/macosnativeacceptance -p 'test_*.py'
```

The first command only hashes public source files. It does not inspect the host
identity, invoke a subprocess/compiler, build or execute a native probe, or
contact a service. No argument also performs this inert check. The dedicated
`--execute` edge requires the verified manual context. A later, separately
approved dispatch must supply `reviewed_commit` and this exact `sourceSHA256`.
Source hashing includes `go.mod`, `go.sum`, this document, the focused
[Gate I disclosure](macos-interface-diagnostics.md), the workflow, every file
beneath `internal/`, and every harness source file, excluding Python bytecode
only. Symlink sources/parents, missing files or size bounds fail closed. The
aggregate includes path, executable-mode bit, length and SHA-256; public hashes
for the fixed harness files are retained. The source tree is independently read
with fixed bounded Git revision commands before preparation. A source change
requires a new review and new digest. Source invariance is checked again after
build and before each native gate; protected compiled-binary custody and hashes
are rechecked immediately before execution. The log module is compiled from
the exact hashed source bytes; Python bytecode caches are never loaded for it. Review input is not user authorization.

## Preparation and metadata

Gate A or Gate I needs pinned `actions/setup-go` and Go `1.27.1`. The existing pinned
action uses its default documented vendor download flow, `token: ''`,
`GO_DOWNLOAD_BASE_URL: ''`, `cache: false`, and `check-latest: false`. No custom
installer or credential-bearing download wrapper is added. The PATH-selected exact `RUNNER_TOOL_CACHE/go/1.27.1/{arm64,x64}/bin/go`
is required; stale ambient GOROOT is ignored. The installed Go
version and executable hash are verified/recorded before our native probe.
This is post-setup provenance: setup-go may already have executed the downloaded
Go tool. It is not a separately enforced pre-execution archive-checksum gate.
Normal public setup-go version/environment/download metadata can appear in the
Actions console; the native provider no-content rule below does not claim to
suppress the action's ordinary output.

Within a new task tree, selected Gate A or I prepares locked modules with `go mod download` and
`go mod verify`, `GOPROXY=https://proxy.golang.org`, `GOSUMDB=sum.golang.org` and
`GOVCS=*:off`. There is no direct/VCS fallback. Then `GOPROXY=off`, `GOSUMDB=off`,
`GOTOOLCHAIN=local`, `GOWORK=off`, `GOFLAGS=-mod=readonly`, `CGO_ENABLED=0` and
`go build -trimpath -buildvcs=false` builds only the selected reviewed probe:
Gate A inventory, or Gate I interfaces with the explicit
`-tags=tracebolt_interface_diagnostics` tag. Each preparation
child is bounded to 240 seconds and at most 1 MiB per output stream for module
steps, 64 KiB per stream for compilation. Text is discarded, including normal
module-progress stderr. This does not execute the compiled probe.

Only Gate B resolves the already installed Apple clang and SDK with fixed
`xcrun --find clang`, `--show-sdk-path` and `--show-sdk-version` calls. It records
the clang executable hash and numeric version, numeric SDK version and
`SDKSettings.json` hash; paths and full version text are discarded. It compiles
the reviewed emitter with `-O0 -Wall -Wextra -Werror`, explicit selected
`-isysroot`, and a fixed task-owned output path. No install, signing identity or
entitlement is involved. Missing compiler/SDK blocks preparation. The new
diagnostic revision has not run that compiler; first-run preparation is recorded
separately. Toolchain/compiler binary hashing allows
256 MiB in five seconds; fixed OS executable hashes allow 32 MiB in five seconds.
SDK settings hashing allows 1 MiB in five seconds.

A separate 120-second native supervisor budget starts after builds. Published
elapsed time includes subsequent cleanup and is the actual nonnegative count,
up to the 20-minute job ceiling; outside that schema range it is `null` and
failed, never a silently clipped measurement. Cleanup does not extend a native
provider/query deadline. Fixed
`sw_vers -productVersion`, `sw_vers -buildVersion`, `uname -r` and `uname -m`
commands get five seconds and 128 bytes per stream; unrecognized values are
rejected. Only bounded OS/build/version forms, fixed label, image version,
architecture, commit/tree/source/tool hashes and counts are public. The harness
never asks for a hostname, machine UUID or serial. It hashes the fixed `sysctl`,
`pkgutil`, `ps`, `ifconfig` and `log` executables without emitting their contents.

The existing runner's numeric real/effective UID/GID and at most 64 supplementary
groups are recorded. Root or mismatched real/effective IDs are refused. Admin
membership is explicitly unknown (`null`, `not_queried`); no membership,
account/group enumeration or `sudo` query is used. The current UID's passwd home
is obtained only for configuration checks, never output. These observations do
not prove the runner is an ordinary non-admin user.

## Gate A: existing fixed inventory reads once

The new Go `inventoryprobe` package invokes unchanged
`macosinventory.CollectNative` once with synthetic in-memory request/consent
inputs. This creates no production grant, endpoint identity, file or sender.
The five existing commands remain:

- `/usr/sbin/sysctl -n hw.model hw.physicalcpu hw.logicalcpu hw.memsize`
- `/usr/sbin/pkgutil --pkgs-plist`
- `/bin/ps -A -o ucomm=,pid=,ppid=`
- `/sbin/ifconfig -a inet`
- `/sbin/ifconfig -a inet6`

The existing one-second command, 200-ms pipe-wait, two-second provider,
eight-second collection and 512-KiB snapshot limits remain unchanged. Output is
restricted to fixed schema/source IDs, independent source outcomes, closed
reasons, row/address counts, validation booleans and observed outer timing/size.
Native values are validated/round-tripped only in memory. No model/RAM value,
receipt ID, PID, accounting label, interface name, address, snapshot bytes or
snapshot-content hash leaves the probe. A failed provider remains failed;
successful siblings are preserved. Receipts may be validly empty. The current
interface parser rejects an empty interface list: it is not relabeled a pass.

The unchanged collector does not expose per-command bytes, elapsed time, exit,
start or reap observations. Those fields remain `null` and
`commandMetricsAvailable=false`. Fixed declared limits are not measurements.
The outer supervisor separately measures and reaps the inventory-probe process,
with a 12-second deadline and a 64-KiB stdout/1-KiB stderr cap. A normally reaped
probe does not independently prove every product-internal child was reaped.
Nonzero exit 1 can preserve a strictly validated failure projection; arbitrary
output, stderr, truncation, unknown fields and exception text are discarded.

## Gate I: narrow interface diagnostics once

The separate [Gate I disclosure](macos-interface-diagnostics.md) defines the
exact two once-only interface commands, explicit diagnostic build tag, unchanged
runner/parser limits, null unavailable inner-command measurements and closed
16-KiB `tracebolt.macos-native-interface-diagnostics.v1` result. Gate I does not
call the complete inventory collector. A plus I is rejected; choosing I grants
no Gate B writes or reads. Any future I-only proposal uses `gate_a: false`,
`gate_b: false`, `gate_i: true` and requires fresh exact-source approval.

The assembled supervisor report uses numeric `schemaVersion: 2` and
`scope: macos-native-evidence-v2`. It carries independently selected gate results
and the new interface-probe metadata. Historical outer-v1 reports retain their
original validator and are not rewritten or interpreted as outer-v2 evidence.
This report-version change is separate from Gate B's nested log schema below.

## Gate B: synthetic write/read, not a production provider

This gate needs explicit approval of both writes and reads. Before emission and
before every query, definite `.logrc` absence is required in isolated HOME,
original runner HOME and current passwd home. Only path metadata is checked;
any file, symlink, permission error or ambiguity blocks B. No configuration is
read, renamed, removed or repaired. The installed `/usr/share/man/man1/log.1`
must match the reviewed installed-manual SHA-256
`d89cb620dbcab9e849161d2f3c63c4be62c5bd8240bba851d395a09fc7504c08` under the prior 128-KiB source/256-KiB decoded, five-second read limits and
root-owned non-writable, no-follow descriptor checks on every fixed component.
Only this uncompressed installed path is read; no alternative is searched. Changed/unavailable documentation blocks B and needs fresh review.

The reviewed emitter makes exactly three nonsecret default-level messages,
including fixed public, multiline/Unicode and private-canary samples. Its unique
subsystem uses an ephemeral random nonce; category is `schema`. No native
identity/value enters a message. It stays alive under a 90-second ceiling while
three `log show` queries run: JSON positive, NDJSON positive, JSON negative with
category `never-emitted`. Source freezes the exact predicates, owned emitter PID,
UTC window and documented flags. There is no broad/text fallback, time widening,
re-emission, retry as root, added info/debug, `stream`, `collect`, `config`,
`repack` or `erase`. The system utility may inspect its datastore internally;
filtered-query permission is not a physical-record access sandbox.

Each query has a 15-second external deadline, 1-MiB combined output cap, 64 events,
64-KiB objects/NDJSON lines, depth eight and 64 keys per object. Strict framing,
duplicate-key rejection, exact synthetic provenance and reviewed field/type
hypotheses fail closed. The hypotheses are not native Apple schema evidence.
Unknown event shapes are unsupported; positive empty results are inconclusive.
All expected messages in both positive formats and a complete empty negative
query are required. Private-canary visibility is a sample observation, never a
general privacy/redaction guarantee. Boundary inclusivity, retention, broad query
performance, non-admin visibility and a production adapter remain unproved.

### Source-only rejection diagnostics (synthetic result version 2)

The nested `syntheticLog.schemaVersion` is explicitly **2**. Its query rows add
one closed `diagnostic` object. The log-only change did not change the outer
report; this assembled Gate I composition separately uses outer numeric version
2 and `scope: macos-native-evidence-v2`, as described above.
Version-1 reports remain immutable first-run evidence and must be interpreted
with their original reviewed validator. They are not rewritten or silently
accepted as version 2. The first run established only `unsupported_schema` on
one decoded object per architecture; it did not identify the missing, extra or
mismatched field, its name, type or value.

`diagnostic.code` is one fixed source constant: `none`, `duplicate_keys`,
`structural_json`, `decode_json`, `numeric_encoding`, `object_shape`, `framing`,
`terminal_shape`, `missing_required`, `extra_event_keys`, `event_type`,
`message_type`, `known_field_type`, `backtrace_shape`, `attribution`,
`negative_event`, `duplicate_marker`, `timestamp_shape` or `outside_window`.
Codes distinguish parser branches without copying native text. Existing failure
reasons, including literal `unsupported_schema`, remain authoritative. Fixed
limit reasons continue unchanged, with `code: none`. A code is not evidence that
a rejected event or its schema was accepted.

Event-derived diagnostic metadata is available only on a positive query's
rejected event after the exact fresh subsystem, `schema` category, owned emitter
PID, one of the exact fixed synthetic messages, and valid timestamp inside the
original fixed window have all been verified. Only then can
`syntheticAttributionVerified` be true, `knownFieldTypes` contain present names
from the existing `FIELD_TYPES` allowlist with closed JSON type labels, and
`unknownKeyCount` contain a 0–64 top-level count. Known plus unknown keys cannot
exceed 64. Unknown names, nested names, values, paths, identifiers, message text
and raw bytes are never copied. No candidate field names are added to either
the accepted schema or the diagnostic allowlist. Nested backtrace rejection gets
only its fixed code plus eligible top-level metadata, never a nested projection.

Missing any required field, inexact attribution, invalid/out-of-window timestamp,
decode/framing/terminal failure, negative-query events and duplicate markers
produce no event-derived diagnostic metadata: false attribution flag, empty
known-field map, null unknown-key count. Schema failures retain their original
precedence even if a timestamp also fails; timestamp checking is an additional
disclosure guard, not a reason to accept an unknown schema. Failed-query success
fields and observations remain empty. Cleanup cancellation or unproven query
reap clears its diagnostic. Strict output validation binds codes to failure
reason/status and allows no diagnostic to establish success.

This change does not alter the three fixed query forms, matching rules, native
bounds, cancellation, emitter, installed-manual pin, configuration guard, stdout
handling or pass criteria. Inert parser and fake-process tests are source checks,
not evidence about Apple schema or native access.

### Proposed separately approved diagnostic repeat

No new native workflow is created and no dispatch or rerun is authorized by this text.
After review of the assembled new commit/tree/source digest, the narrow proposed
scope is one **new** manual first-attempt dispatch of the existing workflow with
`gate_a: false`, `gate_b: true` and `gate_i: false`, on the same standard GitHub-hosted `macos-15`
ARM64 and `macos-15-intel` X64 labels. Gate A's inventory reads are not repeated.
Each host compiles the unchanged emitter under the same preparation rules,
writes its same three synthetic messages once, and runs up to the original three
fixed queries, stopping on the first failure. There is no re-emission, query
retry, time widening, schema relaxation or host privilege change.

The requested additional public evidence is only the version-2 rejection codes
and attribution/window-gated metadata described above, within the same one
strict JSON report per architecture, 64-KiB limit and 14-day public Actions
artifact retention. The original report/provenance, identity metadata, fixed
manual/configuration checks, bounds and cleanup scope remain as documented.
Fresh execution and the additional metadata disclosure require explicit approval
after source review; the failed first run and its version-1 artifacts are retained
unchanged. The review must provide the final exact commit and source digest,
which cannot be specified before the complete candidate is assembled.

## Environment, public output and cleanup

A canonical mode-0700 task tree under canonical `RUNNER_TEMP` owns empty HOME,
temp, binary and build-cache directories. OSLog children get only fixed PATH,
LANG/LC_ALL=C, TZ=UTC, task HOME/TMPDIR, closed stdin and task HOME cwd. The
inventory collector and tagged interface diagnostic bridge retain the unchanged
runner environment and `/` cwd.
Ambient proxy, developer, credential and logging variables are not inherited.
Owned children have incremental bounded pipe reads, monotonic deadlines,
cancellation/overflow group termination and direct wait/reap. No global kill or
signals to discovered host PIDs are used. Stderr is counted without retaining
text. Native time/output bounds constrain the harness, not work macOS services
may do internally.

Only one strict-schema result JSON, at most 64 KiB, is uploaded per architecture
to the approved public Actions run for 14 days. No raw native stdout/stderr,
usernames, home paths, arbitrary error strings, host labels, PIDs, IPs, telemetry
values/content hashes, raw log JSON, binaries, cache, HOME or credentials are
published. Upload requires this invocation
to have exclusively created and validated the report; a prior/stale artifact
cannot enable upload after failed admission or preparation. Artifact parent
directories are opened/created descriptor-relative without following symlinks.
Numeric identity and reviewed source/tool provenance are the explicit
metadata exceptions. No generic debug dump is emitted on failure.

Runtime probe code opens no network socket. Preparation and Actions delivery
are not an OS firewall sandbox. Vendor infrastructure includes github.com,
api.github.com, codeload.github.com, raw.githubusercontent.com,
objects.githubusercontent.com, release-assets.githubusercontent.com,
*.actions.githubusercontent.com, go.dev/dl, dl.google.com, proxy.golang.org,
sum.golang.org and storage.googleapis.com. Artifact delivery also uses
results-receiver.actions.githubusercontent.com and GitHub's *.blob.core.windows.net
artifact service. No firewall/security changes are made to enforce this declared
scope. A changed preparation destination needs review.

Cleanup stops/reaps owned children before descriptor-relative, no-follow deletion
of only the recorded new task tree. Build scratch/cache is inside that tree.
Unproven reap or ownership/inode changes retain the tree and report failure;
there is no broad recursive deletion. Missing cleanup is not claimed successful.
The three synthetic OSLog messages may remain until normal retention or hosted
VM disposal. They are never erased. No account, service, credential, enrollment,
TCC, Full Disk Access, entitlement or security setting is created or changed.
Fresh enrollment/renewal, dedicated non-admin operation, launchd lifecycle and
reboot persistence require their own reviewed artifacts and approvals.
