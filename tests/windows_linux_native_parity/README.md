# Manual real Windows → Linux → browser parity subset

The explicitly versioned current-v2 route is documented in
[CURRENT_PROFILE.md](CURRENT_PROFILE.md). It supports fresh twenty-one-scope
consent v14/receipt12 and renewable TLS without changing historical v1 evidence.
Only portable/inert checks have run; native execution remains separately gated.

## Historical v1 route (kept fail-closed)

**Historical v1 compatibility block:** this v1 harness observes only the old
five-scope Setup baseline. Fresh Setup now selects the twelve-scope Read admin
profile, including personal user/domain/session and join metadata, with explicit
unchecked consent. An old five-scope approval or broad phase reference cannot
authorize that expanded profile. Native coordinator/Setup/browser entrypoints
therefore fail closed with `read_admin_native_gate_unavailable`, before host or
process work. There is no override. Portable contracts remain testable.

The steps below document the historical five-scope harness only; do not invoke
them for current Setup. A new native gate must bind full twelve-scope consent,
v3 receipt/all eleven extension grants, and fresh independent evidence for the
seven additional scopes, including complete service/software generations and
original partial/denied/unknown quality. This is missing native automation source
coverage, not a native test failure or a reason to skip ordinary feature CI.
Published historical evidence and release/download pins are unchanged.

This is **opt-in test source**, not a native acceptance report or permission to
operate a computer. It is off by default. Ordinary Validate runs only portable
contracts and injected adapter tests; no workflow starts this native harness.
Both native entrypoints reject CI flag presence, missing bindings, expired plans,
changed source or mismatched targets. The Python coordinator also requires
interactive stdin and isolated Python; its browser child instead requires a
private pipe carrying the exact canonical nonsecret spec.

The historical path uses the actual unsigned Setup and installed service, production
`cmd/lan-manager`, its durable stores, matching compiled dashboard, and a real
sandboxed Chromium session. There is no fixture manager, response routing, fake
clock, production bypass endpoint or credential shortcut. Missing capability is
blocked/unknown. Every report keeps `fullAcceptance: false`.

## What this subset establishes

After successful *automatic observations*, the finite browser report can establish:

- one fresh activated Windows identity tied to the selected machine's protected
  local identity and exact Setup/service bytes;
- advancing, fresh accepted inventory with separately grant-bound event headers,
  volumes, process metrics and network siblings, and default-off event/Update state;
- one task-owned synthetic Application event, its actual native message, real
  manager request/result, and exact plaintext rendering in the compiled dashboard;
- real cached WUA inspection and its quality/unknown-freshness/empty-state or row
  rendering, followed by observed independent grant withdrawal.

The historical five-scope baseline verifies fresh independent grant-bound siblings
only. It neither approves nor verifies current twelve-scope Read admin Setup.
Their native partial/denied/availability quality is preserved; complete or usable
rows for every baseline source are not established (`baseline_source_completeness`
is an explicit omission).

Zero cached rows can establish only cached-read and empty-state rendering.
`updatesRendering: empty_state_only` leaves row rendering unverified. It never
means current, patched, CVE-covered or compliant. Denied/unavailable/invalid/stale
native evidence does not pass a usable cached-result test.

The Windows runner observes SCM states, installed hashes, and both local preview
states around each supported grant command. A GUI exit, human statement, grant
command success or copied report alone cannot pass the browser path. Source tests
never produce native acceptance. The handoffs below carry public binding facts;
they are not manually authored PASS assertions or authorization tokens.

Excluded: policy writes/health incident timing, service-startup grant, destructive
fault preparation, other Windows services, OS reboot, watchdog/crash/replay proof,
revocation/removal/disposal, Windows 11/ARM64, upgrades, repair and full removal.
There are **no Windows upgrade/repair commands**. Health policies consume existing
accepted metadata but must be separately selected/approved; this baseline writes
none. No system service is stopped to manufacture a result.

## 1. Select targets and obtain authority outside this program

No target, network, credential or runtime artifact is supplied by this repository.
Choose a **fresh disposable Windows Server 2025 x64 VM with interactive desktop**,
a **separate Linux amd64 manager/browser host**, and a named disposal/certificate
custodian. Do not substitute the user's device or existing manager.

An already approved private route must connect both exact hosts and the two TLS
origins. Ordinary separate GitHub-hosted jobs do not provide it. This adapter
creates no VPN, relay, VNET, firewall rule, credential or persistent GitHub secret.
See GitHub's [private networking explanation](https://docs.github.com/en/actions/concepts/runners/private-networking).
A hosted-network adapter is a separate project.

Before native invocation, obtain action-time approval naming the exact target
IDs/machine identity hashes, final commit/tree, Setup/service/manager/dashboard/
browser bytes, private paths, both origins and TLS custodian, expiry and operations:

- `manager-browser`: start/stop only the isolated real manager; launch/close only
  its isolated browser; ordinary read-only observations; direct human login,
  invitation creation/download and exact fingerprint approval; selected synthetic
  event request after its real UI disclosure; two explicit public-file transfers.
- `setup` (historical only; blocked for current source): launch the exact GUI,
  human UAC/trust/five-scope/persistent-identity
  consent and hidden invitation entry, then stop/read only the fixed public
  identity artifacts/restart the owned Tracebolt service for target correlation.
- `event-fixture`: after the separate preparation approval below, format and write
  exactly one synthetic Application event under the named task-owned source.
- `event-enable`, `updates-enable`, `event-disable`, `updates-disable`: stop the
  owned Tracebolt service, preview both independent grants, execute only the named
  supported local operation, verify independence and restart the same service.

The plan's `approvalRef`, `--approval-reference`, and `--execute` only prevent
accidental/mismatched invocation. They do not authenticate an approver or establish
user permission. A target-wide kernel lock excludes concurrent harness instances;
create-only phase records prevent automatic retries. There is no reset/repair.
If permissions, trusted TLS or human handoff are missing, stop. Never install a CA,
change firewall/service permissions, accept a certificate warning or disable the
browser sandbox to get past a blocker.

## 2. Build and bind public artifacts before native approval

Use Python **3.12+ x64** with `-I -B`, Go **1.27.1** and Node **24**. The source
entrypoint must itself be obtained/checked from the reviewed commit. Local modules
are loaded from source bytes, with cache/package/extension shadowing refused.
All source/artifact paths reject symlinks/reparse points and untrusted write access.
Windows source bytes must preserve LF (for example `core.autocrlf=false`); Git
executable modes are verified on Linux and carried unchanged in the source
inventory, since NTFS modes do not represent Git executable bits.

Select the **final committed harness revision**, not a moving branch, the old
integration tree as a commit, a dirty snapshot or an older preview asset. Use the
existing `deploy/windows-setup/build-setup.py` or its exact-source Setup build CI.
Retain Setup.exe, service.exe, `setup-package-amd64.json` and `source-inputs.json`.
The adapter checks actual PE resources, exact embedded service/manifest bytes,
source commit and the complete builder-generated source-input inventory.

Prepare matching Linux artifacts in a separate clean checkout of that commit.
`ARTIFACTS`, `BUILD`, `SOURCE` and `RUNTIME` below are newly selected staging paths,
not shell variables containing secrets. Commands describe authorized preparation,
not instructions to run on an unapproved native target.

```sh
# From the clean BUILD checkout; the output directory is outside the checkout.
GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -buildvcs=true -mod=readonly \
  -o "$ARTIFACTS/lan-manager" ./cmd/lan-manager
npm --prefix "$BUILD/web" ci --no-audit --no-fund
npm --prefix "$BUILD/web" run build -- --outDir "$ARTIFACTS/web"
```

The manager must retain `path localrmm/cmd/lan-manager`, the exact VCS revision
and `vcs.modified=false` build metadata. `-buildvcs=false` is incompatible with
this harness. Keep generated web assets and dependencies outside the separate
immutable SOURCE snapshot. Verify build-checkout tracked files stayed unchanged.
These recipes bind reviewed inputs and selected output hashes; unsigned metadata
alone is not publisher authentication or a reproducible-build claim.

Create a separate browser dependency root from the exact `web/package.json` and
`web/package-lock.json`. A supported symlink-free preparation is:

```sh
npm --prefix "$RUNTIME" ci --offline --bin-links=false --ignore-scripts --no-audit --no-fund
```

Use the existing trusted npm cache. If absent, dropping `--offline` requires
separately approved preparation/network access; the native runner never installs
anything. `--bin-links=false` matters: ordinary `.bin` symlinks are rejected.
`--ignore-scripts` avoids lifecycle hooks; the locked `@esbuild/linux-x64` binary
works directly. Inventory the complete root including nested `node_modules`.
The 20,000-file/512-MiB total bound is finite. No ambient `NODE_OPTIONS`, proxy,
`ESBUILD_BINARY_PATH` or package lookup fallback is passed to the child.

Select actual Linux ELF64 amd64 Node and Chromium executables, never a shell
launcher/symlink which can choose different bytes. Their exact hashes are inputs. Node/Chromium have an explicit 512-MiB per-file
ceiling. The Python coordinator hashes them in 1-MiB chunks while retaining
only their ELF header; the browser child separately rechecks Chromium with a
bounded whole-file read (up to 512 MiB). The manager is bounded to 64 MiB.
Trusted OS/shared libraries, the installed browser resources, display/session and
working Chromium sandbox are existing host prerequisites. No tooling is installed
by this harness.

Export the public raw Git commit object outside SOURCE, then inventory SOURCE on
Linux. The utility executes no Git hook or subprocess. It recomputes Git blob/tree
hashes and requires the supplied commit object's tree to match. Runtime recomputes
the commit hash and tree again on both hosts.

```sh
git -C "$SOURCE" cat-file commit "$COMMIT" > "$ARTIFACTS/source.commit"
python3 -I -B "$SOURCE/tests/windows_linux_native_parity/inventory.py" \
  --source --root "$SOURCE" --commit-object "$ARTIFACTS/source.commit" \
  --output "$ARTIFACTS/source-inventory.json"
python3 -I -B "$SOURCE/tests/windows_linux_native_parity/inventory.py" \
  --root "$ARTIFACTS/web" --output "$ARTIFACTS/web-inventory.json"
python3 -I -B "$SOURCE/tests/windows_linux_native_parity/inventory.py" \
  --root "$RUNTIME" --output "$ARTIFACTS/browser-inventory.json"
```

Copy the exact source snapshot, public commit object and source inventory to
Windows through the already approved route. No credentials or private stores are
part of these artifact transfers.

## 3. Private material and fixture preparation

Read `docs/installation.md`, `deploy/lan.tls.example.json`,
`internal/lanconfig/config.go` and `internal/enrollmentconfig/config.go` first.
A custodian must already have provisioned protected TLS/issuer/operator material;
this harness generates/imports no credentials. The manager uses production flags:

```text
lan-manager --lan-config ABSOLUTE_PRIVATE_LAN_JSON --enrollment-config ABSOLUTE_PRIVATE_ENROLLMENT_JSON
```

LAN config is TLS only, `windowsInventoryEnabled: true`, exact private IPv4 listen
addresses and two approved HTTPS origins. Its only fields are those checked in
`linux_native.verify_config`; actions, alarm and other integration config fields
are rejected. Enrollment has a matching preprovided dedicated issuer, manager ID,
bootstrap CA and approved issuer/root fingerprints. Use `basic-readonly-v1` for
the ordinary Linux enrollment profile; Windows has its independent derived store.
The manager state is a separate existing empty private 0700 directory, not the
harness workspace. Key/auth files remain protected and are read only by production;
Python checks their metadata without copying their contents. Both Python and
Chromium must already trust the approved TLS path. No trust-store change occurs.

Each harness workspace must already be private (Linux owner-only 0700; Windows
current operator/SYSTEM/Administrators, with safe parent and inherited-child ACLs).
There are no other sessions/state to adopt. Workspaces and production state stay
separate. The plan contains public bindings and private paths, never passwords,
invitation secrets, key bytes, cookies or tokens.

For the synthetic event, obtain a **separate fixture preparation approval** for the
exact task source `TraceboltParity-RUN_ID`, Application channel, event ID 1–1000,
public built-in executable hash, one synthetic preparation record and disposal.
The documented [Windows eventcreate command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/eventcreate)
can prepare that unique source. For example, after approval in a local elevated
terminal (with a real selected run ID, no secrets in the description):

```text
C:\Windows\System32\eventcreate.exe /L APPLICATION /T INFORMATION /SO TraceboltParity-RUN_ID /ID 1 /D "Tracebolt fixture preparation only RUN_ID"
```

Use the actual OS-derived Windows directory; the example is not a target binding.
Verify the resulting task-owned registry source's `EventMessageFile`, resolve only
its `%SystemRoot%` reference, and put its actual absolute resource path/hash in the
plan. Do not assume resource formatting from that command's exit status. The
`event-fixture` phase loads only the pinned data/image resources, applies
`FormatMessageW` to the exact synthetic insertion in memory and requires exact
text equality before `ReportEventW`. It then writes one new synthetic event only
when the browser says ready. Production `EvtFormatMessage` and browser rendering
must independently return the declared exact SHA-256. CRLF is not trimmed or
normalized. If this built-in resource cannot render the exact declared string,
report blocked/unknown; do not rewrite the expectation or install another provider
silently. Actual native formatting remains unproved until the real run.

No source creation or registry write is hidden inside the baseline. No real
System event, unrelated Application event, event history or broad screenshot is
selected. Do not clear logs, alter WUA services/cache/policy, fetch updates,
download/install/reboot or prepare pressure/fault cases.

## 4. Fill and seal the plan

`plan.template.json` is deliberately invalid and cannot run. `contract.py` defines
the exact schema. Fill every path/hash/target/phase reference and a real 60–7200
second window. Machine hashes are SHA-256 of lowercase stripped MachineGuid
(Windows) or `/etc/machine-id` (Linux), never output as raw host identifiers.
`osBuild` is the exact Windows `CurrentBuildNumber` or Linux kernel release.
TLS pins use the exact certificate-file bytes; issuer fingerprint is SHA-256 of
DER, bootstrap CA/root pins are SHA-256 of the exact public PEM strings.
`messageSHA256` is SHA-256 UTF-8 of
`Tracebolt native parity synthetic Application event RUN_ID` with no newline.

Use one immutable plan on both targets. Keep it in private custody and independently
compare its SHA-256. Never edit it mid-run or use flags as approval proof. The
source/commit object, all artifact pins and target ID must match each invocation.
A read-only contract check does not contact either host:

```text
python -I -B tests/windows_linux_native_parity/run.py --check-plan --plan ABSOLUTE_PLAN --plan-sha256 EXACT_PLAN_SHA256
```

## 5. Execute the coordinated, human-secured path only after approval

Use the source-root entrypoint on the indicated target. Each command needs
`--execute --plan ABSOLUTE_PLAN --plan-sha256 EXACT_SHA --target-id EXACT_ID
--phase PHASE --approval-reference EXACT_PHASE_REF`. Interactive stdin and a
visible desktop are required for the coordinator; its browser child deliberately
uses noninteractive private canonical stdin. The Linux browser receives only a bounded nonsecret
spec over a private local pipe. Credentials never travel in argv/environment.

1. Start `manager-browser` on Linux. It launches the real manager, verifies trusted
   TLS and exact server leaf, then launches the exact real browser. Human signs in
   directly. Wait for the empty fresh enrollment list to be observed, then create
   one Windows invitation and click **Download bootstrap file** in the real UI.
   Only the validated public-only export is saved as `RUN_ID-public-bootstrap.json`
   in the Linux private workspace. Other/duplicate downloads fail closed.
2. Transfer that public file unchanged by the already approved private route to
   the Windows `publicBootstrap` plan path. Never copy the invitation into a file,
   chat, command or environment. Run Windows `setup`. Human selects that exact
   public export, reviews every trust/scope/service/identity acknowledgement,
   enters the invitation only in the hidden console, and separately approves the
   exact comparison fingerprint in the manager. The harness performs no secret
   entry, consent tick or dashboard approval.
3. After actual installed hash/SCM running observation, the approved Setup phase
   stops Tracebolt, checks retained public bootstrap/config/certificate/ready
   artifacts while stopped, writes `RUN_ID-windows-binding.json`, then restarts.
   Transfer only this tool-generated public binding file unchanged to the Linux
   private workspace; compare its printed public SHA-256 over the approved route.
   The observer requires its exact run/source/machine/artifact facts and actual
   backend device/certificate/invitation match before accepting identity.
4. Wait for `PARITY_BROWSER_BASELINE_OBSERVED`, then
   `PARITY_BROWSER_EVENT_ENABLE_READY`. Run Windows `event-fixture`, then
   `event-enable`. These are separate phases and approval references. Do not
   write the baseline synthetic event before the browser readiness time.
5. At `PARITY_BROWSER_EVENT_REQUEST_HANDOFF`, inspect the one exact synthetic row
   in the real Logs review, acknowledge the warning and click **Request messages
   once** yourself. The observer verifies the real create/query/result and exact
   rendered text; it never performs the content consent/write.
6. Follow the remaining one-time markers in order: `UPDATES_ENABLE_READY` →
   `updates-enable`; `EVENT_DISABLE_READY` → `event-disable`;
   `UPDATES_DISABLE_READY` → `updates-disable` (each full marker starts
   `PARITY_BROWSER_`). The runner previews both grants while stopped around each
   operation. Every accepted browser observation uses original fresh capture time
   and advancing real state. No report is synthesized to advance a phase.
7. The browser closes through supported Playwright cleanup, with explicit close
   proof. Linux stops its owned manager. Forced Node termination, absent close
   proof or uncertain cleanup remains unknown/manual intervention, never a clean
   pass. Windows service and identity remain; disposal/removal need their own
   later approval. No cleanup of production state is performed automatically.

If any phase fails, keep its create-only marker/result and all protected state.
Do not retry under a new run ID, alter receipts, edit consent sidecars, kill system
services or reset state to turn a failure into success. An interrupted Setup can
remain active and needs direct human cancellation/inspection. Clock rollback,
changed bindings, missing prior phase proof and an expired window fail closed.

## 6. Evidence and source validation

Only bounded finite result JSON and public artifact hashes are suitable for
review. The private plan, bootstrap and endpoint-binding files are runtime input
handoffs, not uploadable acceptance reports. Do not upload private config/keys,
SQLite/state, command transcripts, invitations, cookies, telemetry bodies, update
titles, event text, traces, screenshots, browser profiles or unreviewed OS errors.
The observer computes message equality in memory. No exporter accepts arbitrary
manual reports as full acceptance. Review the evidence audience/retention before
any upload; none is performed here.

Portable checks (ordinary CI; do not launch native adapters):

```sh
python3 -I -B -m unittest discover -s tests/windows_linux_native_parity -p 'test_*.py' -v
python3 -I -O -B -m unittest discover -s tests/windows_linux_native_parity -p 'test_*.py' -v
node --test tests/windows_linux_native_parity/browser.test.mjs
```

The Node tests bundle the actual production validators using the locked web
runtime. For a separately staged runtime set only the nonsecret source-test path
`TRACEBOLT_BROWSER_TEST_DEPENDENCIES`; it is never inherited by the native runner.
The tests use injected inert OS/process/page seams and cannot establish native
Windows event formatting, WUA, actual Setup, TLS topology or full acceptance.

Source map: `cmd/lan-manager/main.go`, `cmd/windows-service/main.go`,
`operation_windows.go`, `event_content_consent.go`, `updates_consent.go`,
`internal/windowsservice/service.go`, `internal/enrollmentclient/{bootstrap,handoff}.go`,
`deploy/windows-setup/{build-setup,pe_resources}.py`, and production
`web/src/windows-{inventory,event-content,updates}-*` validators/UI.
