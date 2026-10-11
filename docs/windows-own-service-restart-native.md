# Separate existing-agent own-restart native acceptance case

## Status and exact claim

This is an opt-in **source candidate**. Portable tests and tagged cross-builds
are source/compilation evidence only. No actual Windows restart, retained manager,
browser login, grant or acceptance run is established by this change.

The case observes one already installed `TraceboltWindowsAgent`, its existing
completed ownership receipt, public identity and already approved read scopes.
It is separate from the seven-phase Windows/Linux parity gate. None of the older
gate's artifacts, approvals or reports is relabeled as evidence for these bytes.

A successful result is the conjunction of:

1. One ordinary installed `--restart --apply` invocation refuses without a native
   effect while the controller holds the **real existing installer Store lease**.
2. After fully verified refusal and clean release, one later ordinary installed
   `--restart --apply` invocation completes successfully, the held exact old
   process object exits with status zero, and a separately checked process
   generation owns SCM Running.
3. The ownership receipt/intent and bounded public bootstrap/config/ready/
   certificate bindings remain unchanged. The observer never acquires the live
   sender, private key or grant-ledger locks.
4. The same retained, pinned real Linux manager accepts **two** advancing fresh
   inventory samples under the selected already activated device, certificate,
   invitation and exact grants after the one-shot Windows completion boundary.

Every result has `fullAcceptance:false`. `dashboardRendered:false` is explicit:
this case establishes accepted API observation, not matching dashboard rendering.
The browser opens the real compiled dashboard for a human login but does not
infer a rendered generation merely from an API GET.

## Permission and prerequisites

Source approval does **not** authorize executing this procedure. Before native
execution, obtain separate external action-time approval for all of:

- The exact disposable Windows Server 2025 x64 target, installed PR36 bytes and
  two CLI invocations. The first is expected to refuse under the held lease. The
  second is allowed only after verified no-effect refusal and clean release.
  Approval must cover interruption of the existing agent and possible loss of
  memory-only event results. No additional service action, retry or compensation
  is included.
- The exact retained real Linux manager process and compatible pinned dashboard,
  read-only local process/config/listener inspection, an isolated real Chromium
  window, and human login to that already selected manager. No fresh manager,
  synthetic manager, empty state directory, invitation, enrollment, approval,
  credential or grant is created.
- The named fixed GET observations `/api/windows/enrollment` and
  `/api/devices/<selected-device>/windows-inventory`, plus normal dashboard assets
  and human login. No programmatic authentication or arbitrary API operation is
  available. The existing browser session and normal HTTPS system trust must work.
- One baseline transfer Linux to Windows and one completion transfer Windows to
  Linux, to the exact private paths in the plan, including public identity hashes,
  source/artifact pins, projected sequence/generation/original timestamps and
  bounded process-generation fingerprints. No raw telemetry, key, password,
  cookie, process command line, PID, error text or private state is transferred.

Approval-reference strings, a plan hash, `--execute` and the local typed phrase
are accidental-invocation guards, not proof of authority. An actual terminal is
required. On Windows the operator sees the exact selected machine hash, target,
two-invocation scope and warning, then must type the fixed displayed phrase.
There is no `--yes`, environment or plan-value bypass. Missing, wrong, canceled or
EOF input launches no controller. This does not replace external approval.

The service must already be installed, Running, activated and receipt-owned with
all selected grants. The installed binary must be the application pin below.
The manager must already be running under the selected nonroot UID with exactly:

```text
<absolute-pinned-manager> --lan-config <absolute-plan-lan-config> --enrollment-config <absolute-plan-enrollment-config>
```

Both exact configured private IPv4 listeners must belong to that retained process
in the observer's network, mount and user namespaces. The process is identified by PID plus Linux
start ticks, UID, actual `/proc/<pid>/exe` bytes, config hashes and exact arguments.
These are rechecked throughout, not inferred from a matching-looking HTTPS page.
A retained nonempty state directory is required, but its private contents are not
copied or opened as an acceptance shortcut. The harness never starts or stops the
manager. Unavailable inspection access blocks; never add permissions to pass.

## Source and artifact pins: keep their identities separate

The strict plan has four source bindings, each with its own actual reviewed Git
commit, tree and complete source inventory SHA256:

- `harness`: this acceptance controller and Python/Node source revision
- `application`: the installed ordinary PR36 Windows executable, fixed to commit
  `858d7846b4fa2f7b3cdaf672c067400d894369a4`, tree
  `91999db7fcf6687795ba052b0029e670c01b01c7`
- `manager`: the actual compatible retained manager source revision
- `dashboard`: the actual compiled dashboard source revision

The earlier assessment's parent-supplied `16ebffed...` label is not substituted
for the verified application commit. A new harness commit does not require
rebuilding/replacing the approved installed application or retained manager.
Mixed manager/dashboard revisions require explicit compatibility review of the
existing GET response contracts. Do not pretend a prior artifact was built from
the latest harness source. Node, Chromium, the full dependency tree and compiled
web files have separate exact artifact/content inventories; those upstream binary
hashes are not mislabeled as this repository's source commit.

### Reproducible source-only inventory and controller build

Use a clean, reviewed Git checkout for each source role, with artifacts, inventories
and dependency installations **outside** its exported source root. Preserve every
tracked byte and executable bit. No cache, untracked file, symlink, reparse point,
submodule, alternate stage or source shadow module is accepted. The new source-only
helper exports the raw Git commit object and a complete inventory, create-only:

```sh
python -I -B /reviewed/harness/tests/windows_own_restart_native/inventory.py \
  --root /reviewed/harness \
  --inventory /private/pins/harness.inventory.json \
  --commit-object /private/pins/harness.commit
```

Run separately for the actual application, manager and dashboard checkout; copy
those exact exported trees and pin files to the selected hosts as separately
approved. The helper prints the commit/tree/inventory hash. It reads Git metadata
and source only; it never runs an application or contacts a target. The gate
rebuilds the Git tree hash from every inventory row, verifies the raw commit
object's hash/tree, hashes all source bytes and rejects extra/missing files.
Inventory rows have exactly `path`, `sha` (Git blob SHA1), `sha256`, `mode`
(`100644`/`100755`) and `size`. Artifact/dependency inventories use the same
complete-directory row format without claiming a Git commit. Generate them from
the exact approved installed content, not a hand-edited list omitting files. The
unchanged, inert inventory helper from the separate parity directory can produce
these two content inventories without invoking any of its native operations:

```sh
python -I -B /reviewed/harness/tests/windows_linux_native_parity/inventory.py \
  --root /private/compiled-web --output /private/pins/web.inventory.json
python -I -B /reviewed/harness/tests/windows_linux_native_parity/inventory.py \
  --root /private/browser-dependencies --output /private/pins/browser.inventory.json
```

Do not put either inventory inside its content root. For a source-only preparation
of the dependency root, copy the exact application `web/package.json` and
`web/package-lock.json` there, then use the existing approved local npm cache:

```sh
cd /private/browser-dependencies
npm ci --offline --bin-links=false --ignore-scripts --no-audit --no-fund
```

This is a separately performed source preparation, never a native runner install.
`--bin-links=false` avoids dependency `.bin` symlinks that the strict inventory
correctly rejects. The esbuild native platform package is lock-pinned and resolved
directly; no postinstall or ambient fallback is needed. If the trusted cache lacks
a locked package, stop and separately prepare the dependencies. Do not weaken the
inventory or enable scripts/network silently. Compile the dashboard from its
actual pinned source using its normal reviewed build route, outside source roots;
pin the resulting complete directory and its real source role.

From the actual reviewed harness checkout, use the repository's pinned Go
version to compile (not execute) a Windows x64 controller outside the source root:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c \
  -tags=tracebolt_restart_acceptance \
  -ldflags="-X localrmm/cmd/windows-service.restartCompiledSourceCommit=$HARNESS_COMMIT -X localrmm/cmd/windows-service.restartCompiledSourceTree=$HARNESS_TREE -X localrmm/cmd/windows-service.restartCompiledSourceInventory=$HARNESS_INVENTORY_SHA256" \
  -o /private/artifacts/restart-acceptance-amd64.exe ./cmd/windows-service
sha256sum /private/artifacts/restart-acceptance-amd64.exe
```

The linker symbols are the package-qualified
`localrmm/cmd/windows-service.restartCompiledSource*`, **not** `main.*`; Go's
compiled test binary keeps the package path. Put this artifact hash in the
controller slot only. The controller independently checks its compiled source
bindings, own executable hash, fixed target/machine/build, application pin and
public/receipt bindings. An arm64 cross-build is useful source evidence but this
native case admits the selected Server 2025 x64 target only. Never run the test
binary merely to check the build. Ordinary `go test` does not include the tag.

Pin exact installed service, retained manager, Node and Chromium binary hashes.
The manager binary must embed the selected actual clean VCS revision and
`localrmm/cmd/lan-manager` package metadata. Pin the complete compiled web inventory
and dependency inventory separately, and keep the production validator sources
in the application checkout. Dependency versions/resolution must match its
`web/package-lock.json`, including esbuild and Playwright's transitive packages.
No ambient `NODE_OPTIONS`, `NODE_PATH`, `ESBUILD_BINARY_PATH`, external browser
connection or dependency fallback is allowed. Native Python requires 3.12 or
newer with both `-I -B`; the browser's exact Node executable is separately pinned.

## Fill and seal the new strict plan

Start from `tests/windows_own_restart_native/plan.template.json`. It is deliberately
invalid: placeholder paths/hashes/IDs and zero validity times must never run.
Fill the current exact target identities/builds, existing private paths, all four
source bindings, artifact hashes, existing TLS origins and custody, selected
activated public identity, receipt/intent/public-file hashes, exact grant IDs,
retained manager process identity and distinct fresh approval references.

Use one new run ID of 8–64 letters/digits/underscore/hyphen, beginning with a
letter/digit, and an approved 4–60 minute UTC window. Allocate several minutes for
human login/transfers and two post-restart reports at the unchanged ordinary
one-minute cadence. Never shorten the runtime cadence or relax freshness after a
slow result. Approval references use the same bounded grammar. Plan source paths
are canonical local paths; Windows UNC/ADS/device aliases are refused before use.
Private workspaces must already exist with protective ownership/mode or ACLs.
The case creates only its own private evidence records and ephemeral private
pipes/browser context, never broadens a grant or host permission.

Seal the exact UTF-8 plan bytes by SHA256. Transfer only that approved public plan
through the approved path. To validate the schema and hash without any target
observation or application launch:

```sh
python -I -B /reviewed/harness/tests/windows_own_restart_native/run.py \
  --plan /private/plan.json --plan-sha256 <exact-plan-sha256> --check-plan
```

The gate rejects unknown keys, duplicate keys, invalid types, expired plans,
placeholder pins, changed sources, aliases/unsafe paths, cached/shadowed modules,
wrong platform/target and any presence of common CI variables, even `CI=false`.
No normal CI job runs the native entry point. Keep all plans/evidence/runtime
artifacts outside Git and don't paste private values into logs or chat.

## Human-coordinated native procedure, only after approval

1. **Start the Linux observer first.** On its actual interactive terminal:

   ```sh
   python -I -B /reviewed/harness/tests/windows_own_restart_native/run.py \
     --plan /private/plan.json --plan-sha256 <exact-plan-sha256> \
     --execute --role linux --target-id <selected-linux-target> \
     --approval-reference <linux-browser-approval> \
     --transfer-approval-reference <approved-public-transfers>
   ```

   The retained manager is independently verified. The pinned real Chromium opens
   a fresh isolated, sandboxed, nonpersistent context using existing system trust.
   A human signs in; the harness does not read or enter credentials. It does not
   import cookies, ignore TLS errors, attach to a browser or create an invitation.
   The fixed GETs must find the already activated selected identity and fresh
   grant-bound production inventory. Only a small validated baseline projection
   is saved as `<runId>-baseline.json`; its SHA256 is printed.

2. **Transfer that generated baseline once** to the exact `windowsBaseline` path.
   Compare the SHA256 against the Linux terminal. On the selected approved
   Windows terminal, use its pinned harness source:

   ```text
   python -I -B C:\reviewed\harness\tests\windows_own_restart_native\run.py --plan C:\private\plan.json --plan-sha256 <exact-plan-sha256> --execute --role windows --target-id <selected-windows-target> --approval-reference <own-restart-two-invocations-approval> --transfer-approval-reference <approved-public-transfers> --baseline-sha256 <Linux-generated-baseline-sha256>
   ```

   Review the displayed exact target and scope, then type the fixed confirmation
   phrase. The harness launches only its hash-pinned controller with exactly
   `-test.run=^TestOwnRestartNativeAcceptance$ -test.timeout=0`. The controller
   invokes the installed ordinary executable; it does not call a fixture backend
   or replace the public CLI with an internal function.

   The private controller plan is supplied through `TRACEBOLT_RESTART_PLAN`.
   `TRACEBOLT_RESTART_REPORT_HANDLE` and `TRACEBOLT_RESTART_CANCEL_HANDLE` are
   distinct inherited anonymous pipe handles with explicit private DACLs. They
   are cleared from child CLI inheritance. The finite pipe report, independently
   checked live, is authoritative; printed Go PASS or exit status is insufficient.
   Never invoke this controller directly or hand-edit a report as evidence.

3. **Transfer only the generated completion once**, if produced, to the exact
   `linuxCompletion` path. Compare its printed Windows SHA256, then paste that
   digest into the waiting Linux terminal. A digest is correlation metadata,
   never a manual success assertion. There is no supplied browser-result path.
   The still-live browser checks the boundary against its own baseline and waits
   for two fresh advancing samples before writing its result.

4. Review the create-only `<runId>-case.result.json` on Linux and its explicit
   omissions. A Windows native-subset completion alone is not manager acceptance.
   Any blocked, malformed, stale, canceled, late or unknown observation prevents a
   passing result. Preserve all started/intent/unknown records. Never delete or
   overwrite one to retry; a new run after uncertainty requires human read-only
   inspection, deliberate review and fresh external approval.

## Timing, freshness and uncertainty

All complete inventory DTOs are bounded in memory and checked by the real
production `validWindowsInventoryView`. The evidence includes only identity,
grant IDs, sequence, generation and original capture/receipt/server timestamps.
It exports no inventory rows. Selected identity, certificate validity and grants
are rechecked before/after each sample. Session loss, revoked/changed identity,
future/expired capture, stale original receipt, response delay, clock change or
stalled progression cannot become a pass. Repeated GETs and duplicate receipts do
not count. Sequence gaps are allowed; sequence equality/regression is not.

For baseline B and each advancing post-boundary sample A:

- A has a greater sequence, different generation and later Windows collectedAt
- A's original manager receivedAt is later than the previous sample's receivedAt,
  compared only within the same retained manager clock
- A's Windows collectedAt is strictly later than the new Windows process FILETIME
  **plus a fixed one-second safety margin**, covering the reviewed native clock
  drift and measurement bracket. The margin is predetermined, never relaxed
- Both post samples independently satisfy all production freshness relationships,
  bounded real browser/server skew and request-delay checks

The timestamp parsers retain up to nine RFC3339 fractional digits and all FILETIME
100-nanosecond ticks as integers/BigInt; no floating-point FILETIME conversion is
used. Manager receivedAt is never compared to Windows process creation to assert
a tight cross-host chronology. Normal wall/monotonic changes are bounded and
unexpected changes permanently fail closed. Earlier or pre-observation clock
manipulation is not attested. The case does not claim that a manager receipt
strictly postdates a cross-host completion timestamp; the established chronology
is the Windows capture/creation comparison and advancing manager-original receipts.

The Python supervisor never calls terminate/kill or uses a kill-on-close job on a
controller, service or CLI. It bounds stdout, stderr and report retention, discards
excess while continuing to drain, and independently observes controller exit.
Deadline, cancellation, pipe failure, output overflow, lost process observation or
broken notification permanently mark unknown and send only the private cancellation
signal. After a started native action, the controller remains responsible for its
lease, handles and drainage while an in-flight synchronous call returns. **There
is no hard wall-clock completion guarantee.** A late successful return cannot
turn unknown into PASS. No second invocation, retry, rollback or compensation is
started after cancellation/expiry/uncertainty. If observation is lost, require
human intervention and read-only inspection before any further lifecycle action.
The retained Linux manager is never killed on a browser failure. The isolated
browser closes through its pinned supported browser lifecycle; missing cleanup
observation also prevents acceptance.

## Explicit omissions and trust boundary

This case does not prove graceful worker/descendant drain, application flush,
native adverse cancellation timing, exact pending-body/signature retry retention,
discarded-memory semantics, local durable consume-once floors, original expiry
under an exercised in-flight request, bitwise private-state/key/ledger retention,
arbitrary administrator races, other-service actions, repair/upgrade/reset/
re-enrollment, reboot/OS persistence, dashboard rendering or full Windows parity.
A greater accepted sequence is not proof that a local counter never reset and
later caught up. `stateRetained:true` in CLI JSON is not independent evidence.

Public transferred files are correlation under external approval and trusted
custody. Hashes/parsers cannot prove that a privileged operator did not fabricate
bytes. The supported gate has no manual/fixture PASS route, no new signing
credential, no persistent access expansion and no claim of adversarially
unforgeable native attestation.
