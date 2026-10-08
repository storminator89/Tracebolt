# Separate fresh Windows ConPTY native test candidate

This is source-only opt-in test infrastructure, not a public installer, workflow
result, release gate override, deployment command or permission to run. No native
execution is established by portable tests or either-architecture cross-builds.
Existing base and expanded manual modes, consent meanings and reports are unchanged.
A distinct manual-only workflow candidate is included. The recorded native attempt
below failed; no accepted native subset has been established. There is no automatic
or reusable native trigger.

## Recorded native failure and diagnostics boundary

[Run 37725910252](https://github.com/storminator89/Tracebolt/actions/runs/37725910252)
at source `e4bc02d449b16b5a23fd9d8f32b34912a53a9fec` passed the approval and inert
checks, then failed native acceptance. Its finite report recorded native actions
attempted, but no synthetic input, receipt/grant verification, inventory frames,
owned-service stopped verification or disabled-state verification. These absent
observations do not establish the runtime cause or the resulting service state.
The verified historical report artifact SHA-256 is
`4f324ea407058bf9db74202f81a4b2cda9cc42e2da941aef17203121a0f5b7a2`.

The diagnostics-only candidate described below has not been run natively. Its
portable checks do not fix or identify the runtime failure, establish a successful
native subset, or authorize a new workflow dispatch or native operation.

## Distinct approval before any effect

The new exact profile is `fresh-read-conpty-v1`, TLS-only. It rejects old profiles,
old approval names, self-hosted or local contexts, mismatched source/test/service
hashes, wrong machine, different run/attempt, absent compiled SHA or expired grants.
It requires a GitHub-hosted Windows `workflow_dispatch` context for the named
repository and binds approval to the actual assigned machine hostname. Do not manufacture
that environment on a user's PC. Runner metadata is a launch boundary, not proof
that platform VM disposal happened; that result always remains unverified.

## One-run approval and test route

The owner selects **Manual disposable Windows fresh ConPTY acceptance**, supplies
the exact reviewed source SHA and `fresh-read-conpty-v1`, and explicitly approves
all eight disclosures below for one fresh assigned GitHub-hosted Windows 2025 VM
in the first attempt of that dispatched run. GitHub reruns retain old inputs, so
all attempts after 1 are rejected; another attempt requires a fresh explicit
workflow dispatch and approvals. No old approval or automatic source trigger can select it.
Publication of this source candidate does not itself authorize a dispatch.

The original dispatching actor and current triggering actor must both be the
verified repository owner `storminator89`. The job, launcher and Go admission
require the exact repository-owner and actor names, repository-owner ID and
actor ID `30489872`, and triggering-actor name. Missing facts, collaborators,
bots, another owner ID or reruns fail closed; repository write access alone is
not this owner's approval. GitHub exposes no separate triggering-actor ID in
its default context; first-attempt-only admission and both required names
retain the original actor-ID binding. These source checks do not replace any
separate action-time human approval required for native security or identity
operations, and no dispatch is authorized by publishing them. Old base and
expanded workflow approval contracts remain unchanged.

The first launcher phase validates those exact inputs and a clean checkout equal
to the dispatched SHA before further work. It then verifies the pinned Windows
Go toolchain, builds the ordinary service and separately tagged test from that
source, and rechecks source cleanliness. Within this already approved run, it
reads the actual machine/run/attempt and hashes both artifacts, and assigns one
14-minute deadline. Those observed facts narrow the existing owner-approved scope;
they never set a missing consent to true, select another machine/profile, or extend
an existing grant. Parent and child independently verify those exact bindings.

The route is `.github/workflows/windows-fresh-conpty-acceptance.yml` calling
`tests/windows_native_acceptance/run_fresh_conpty.py`. All native entry remains
behind the manual gate; neither workflow nor launcher is run by normal CI. A failed
or skipped test is not acceptance. The launcher retains only a strictly validated
finite reserialization of the new report, never the captured controller output.

All eight approvals are false unless the corresponding distinct value is exactly
`true`; consent must explicitly cover:

1. `SERVICES`: create the fresh fixed TraceboltWindowsAgent, stage it disabled,
   change only its verified configuration to automatic, and start it.
2. `IDENTITY`: create the fresh persistent endpoint key/identity and protected
   enrollment state, claim/activate against the local disposable fixture authority.
3. `APP_ACLS`: create only fresh app-owned Program Files/ProgramData parents,
   service/test executables, protected installer/runtime/four-extension stores and
   one `-acceptance-input` store containing public bootstrap only. No ancestor ACL
   repair, existing-object adoption or system trust/firewall change.
4. `FIVE_READ_SCOPES`: the exact ordered five scopes and complete notices in
   [fresh observation setup](windows-read-observation-setup.md): bounded inventory,
   Application/System event headers, caller-visible volume metadata/capacity,
   per-process CPU/working-set and numeric TCP/UDP endpoint metadata. No file/event
   message content, packet capture, process joins, remote actions or AI export.
5. `SYNTHETIC_CONSOLE`: create an isolated ConPTY/test child; feed only the fixture's
   locally generated one-time synthetic invitation from mutable memory through its
   real hidden console; perform bounded in-memory output/no-echo checks. This is
   neither a human entering a real invitation nor human manager approval.
6. `LOOPBACK_TLS`: temporary loopback fixture listeners/authority and native reports;
   never production Linux manager/ingress/dashboard. No HTTP fallback.
7. `STOP_OWNED_SERVICE`: after reaping the test child, inspect the exact protected
   fresh receipt and stop only that exact automatic service successor. Disabled
   staging is inspected without mutation. No foreign/partial ownership is adopted.
8. `RETAIN_FOR_VM_DISPOSAL`: retain all created service/files/identity/grants and
   require the platform's separately confirmed disposal of this exact disposable
   machine. No uninstall, recursive deletion, application cleanup or state reset
   is attempted or credited. An automatic service stopped by this test could start
   again on reboot; do not reuse/reboot the machine as an accepted installed host.

The last two are material new boundaries. Old `cleanup=true` means nothing here.
Unknown/partial ownership remains blocked and retained; it never gets a best-effort
stop/delete/configuration change. Successful subset evidence requires the exact
owned automatic service verified stopped. The report separately records
`ownedServiceStopped=true`, `serviceDisabled=false`, and
`automaticStartConfigurationRetained=true`; it never labels stopping as disabling.
A failed run that remains in disabled staging can separately record that observed
disabled state, but cannot pass the fresh subset. Disposal stays false/unverified.

## Source-only build boundary

`cmd/windows-service/fresh_*_windows_test.go` requires both Windows and the explicit
`tracebolt_fresh_native` build tag. The real `installReadObservation` and all of its
production dependencies are called unchanged. No shipping debug command, enrollment
input hook or installed test service is added. The separately built ordinary service
binary, not the test binary, runs under SCM. Test-only native support does read-only
limited-token inspection and closes its own provisioning read handles.

The tagged test binary's source binding is the linker symbol
`localrmm/cmd/windows-service.freshCompiledSource`; it is empty by default and then
fails closed. Safe cross-compilation examples (not execution or authorization):

    GOOS=windows GOARCH=amd64 go test -c -buildvcs=false -tags tracebolt_fresh_native -ldflags '-X localrmm/cmd/windows-service.freshCompiledSource=<reviewed-commit>' -o fresh.test.exe ./cmd/windows-service
    GOOS=windows GOARCH=amd64 go build -buildvcs=false -o service.exe ./cmd/windows-service

The launcher verifies the exact source and computes both binary hashes after the
approved build. Their bindings are checked independently by parent and child.
Changing the bound source, binaries, machine, run, attempt, deadline or scope
requires a newly approved run; a failed run cannot silently refresh them. Architecture support is only compilation until separately tested.

The approved-run launcher binds the following non-secret configuration: `TRACEBOLT_FRESH_PROFILE`, `SOURCE`,
`TEST_SHA256`, `SERVICE_SHA256`, `SERVICE_ARTIFACT`, `MACHINE`, `RUN_ID`, `ATTEMPT`,
`EXPIRES_UNIX` and `ROLE=controller`, all with the `TRACEBOLT_FRESH_` prefix. The eight
approval keys use `TRACEBOLT_FRESH_APPROVE_` plus the exact names above. Standard
GitHub runtime values must independently match. No invitation is accepted in any
argument, environment variable, file or transcript. The grant lasts at most fifteen
minutes, requires at least three minutes remaining when admitted, and reserves the
final two minutes for exact-owned stop/verification. It is never extended on retry.

An unauthorized tagged test skips before effects; a skip or process exit zero is
never native acceptance. Only the finite `passed_fresh_native_subset` report with
all required evidence can establish this subset, and none has yet been produced.

## Native execution design and finite evidence

The report requires five finite, string-valued diagnostic fields, including in
blocked and failed reports:

- `controllerStage`: `not_started`, `provisioning`, `fixture`, `bootstrap`,
  `launch`, `session`, `verify_completed`, `observe_inventory`, or `completed`.
  This identifies the last main-controller stage reached, not a successful
  completion of that stage. Cleanup does not replace it with a new stage.
- `sessionOutcome`: `not_run`, `invalid_steps`, `cancelled`, `output_rejected`,
  `output_read_failed`, `output_eof_missing`, `input_failed`, `approval_failed`,
  `child_unsuccessful`, `protocol_incomplete`, or `passed`.
- `outputRejection`: `none`, `output_limit`, `echo`, `escape_unsupported`,
  `csi_limit`, `csi_unsupported`, `csi_malformed`, `osc_limit`, `osc_malformed`,
  `osc_unsupported`, `post_input_title`, `carriage_return`, `text_unsupported`,
  `line_limit`, `protocol`, `incomplete`, or `state`. This is only the first
  guard rejection category. It never includes the offending byte, VT parameters,
  length, position, title, error text, or output. `none` means no guard rejection
  was recorded; it does not prove no echo or complete output. A category can
  identify a guard boundary, not the exact native sequence or root cause.
- `naturalChildExit`: `unknown`, `zero`, or `nonzero`. Only a child exit observed
  before controller cleanup may set the latter two values. A forced cleanup
  termination or later reaping cannot establish a natural exit. No raw exit code
  is retained.
- `coordinatorPhase`: `unknown`, or an existing production receipt phase:
  `install-started`, `claim-started`, `activation-started`, `grants-started`,
  `grants-incomplete`, `grants-verified`, `startup-transition-started`, or
  `configured`. The phase is copied only from already-required protected receipt
  inspections; these diagnostics add no runtime read or operation.

The defaults are respectively `not_started`, `not_run`, `none`, `unknown`, and
`unknown`. Without native actions attempted, all five must remain at these
defaults. A passing report additionally requires `completed`, `passed`, `none`,
`zero`, and `configured`, while
retaining every existing acceptance requirement. Finite nonpassing evidence is
allowed, including successful milestones followed by a later failure. These fields
never promote a failed report to a pass or replace ownership, approval, cleanup or
inventory evidence. Go and Python reject values outside these allowlists and
non-string diagnostic values; the launcher also rejects missing or extra report
fields before reserialization.

This is a diagnostics-only source change. It adds no production hook, invitation
input route, receipt recovery, retry, fallback, authorization, transcript, raw error
text, or telemetry export. Portable checks establish the finite reporting contract
only. They do not demonstrate a runtime fix, native execution, accepted Windows
installation, workflow dispatch, service operation or platform disposal.

- Parent revalidates the gate before effects, creates only fresh protected app
  resources, generates an ephemeral local peer and public bootstrap, and launches
  the exact hashed test executable directly. No shell or caller-wide inherited
  environment/handles. The child is created suspended and assigned to a
  kill-on-close job before it executes.
- Child independently verifies exact source/artifact/machine/run/deadline authority,
  then calls the actual production coordinator. Production disclosures, public
  trust display, `CONIN$`, console mode checks, key-event decoding and restoration
  are unchanged. No callback supplies invitation bytes directly to enrollment.
- Parent waits for the exact production hidden prompt, which is emitted only after
  hidden-mode verification and type-ahead flushing. It verifies receipt-bound
  stopped/disabled staging and absent grants before sending the synthetic input
  once. Fixture approval compares the public displayed fingerprint/comparison to
  its real pending claim, never a blindly copied fixture snapshot.
- Output is bounded to 64 KiB with a strict VT subset. Unsupported cursor editing,
  encoding, overflow, post-input title payloads, partial protocol, arbitrary read
  error or unproved EOF blocks acceptance without fallback. No transcript is
  retained/exported. A strict parser may reject real ConPTY rendering; only future
  native tests can establish compatibility. No source fixture is that proof.
- Success needs real completed protected v2 receipt, unchanged sender/four grant-ID
  digests, actual limited running service token, and positive v5 volume, CPU delta,
  working-set and peer TCP observations. Event-header successful-empty semantics
  remain explicit. No raw telemetry is exported.
- Child exit, drained EOF, console closure and exact-owned stopped/disabled service
  must all be proved. Cancellation terminates/reaps only the owned child job;
  ConPTY channels drain independently and bounded teardown errors fail the result.
  SCM service state is handled separately, after child reaping, under the distinct
  stop approval and original cleanup-time reserve. Completed automatic startup
  configuration is retained, never disabled. Partial state is retained. Hard runner
  termination or job cancellation may preempt cleanup; neither stopped state nor
  VM disposal can then be inferred.

`hiddenConsoleExercised` refers to the real native API path with `syntheticInput`.
`humanEntry` and `humanManagerApproval` remain false. Fresh production orchestration
is a separate top-level field in a new report schema; the old extension observation
still cannot claim it. `productionManagerExercised`, `productionIngressExercised`,
`sharedDashboardExercised`, reboot, native interruption acceptance, application
cleanup and VM disposal verification remain false. No real manager/public installer
or full Linux parity follows from this test.

Official API references:
- [CreatePseudoConsole](https://learn.microsoft.com/en-us/windows/console/createpseudoconsole)
- [Pseudoconsole session lifecycle](https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session)
- [Native console input API](https://learn.microsoft.com/en-us/windows/console/readconsoleinputex)
- [Environment block ordering](https://learn.microsoft.com/en-us/windows/win32/procthread/changing-environment-variables)

### Output rejection investigation boundary

The output categories add no accepted sequences and preserve the same 64 KiB
total, 4096-byte line, 64-byte CSI and 256-byte OSC bounds, echo matching, title
policy, clearing, fixed errors, prompt ordering and input/approval barriers. The
controller reads the category only after the serialized session returns. Existing
reports without this newly required field remain historical evidence and cannot
be reinterpreted as providing a category. In particular, the failed 4c88b1f run's
`output_rejected` does not establish which byte or sequence was rejected.

Microsoft documents ConPTY output as UTF-8 text interleaved with VT sequences:
[CreatePseudoConsole](https://learn.microsoft.com/en-us/windows/console/createpseudoconsole).
The [VT reference](https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences)
also documents cursor movement, erase, cursor blinking and extended colors that
this deliberately narrow guard does not accept. A valid Windows rendering
sequence can therefore be unsupported here. Public synthetic fixtures reproduce
that compatibility boundary, not the actual rejected native bytes. They provide
no basis for guessing an allowlist expansion or declaring the native failure fixed.
No additional native run is authorized by this diagnostic change.

### Exact ConPTY mode compatibility

The ordinary fixed-public-output [probe run 37749340509](https://github.com/storminator89/Tracebolt/actions/runs/37749340509)
on `f118d6a18591932065ff6cf3f4182351569ec2f6` observed all four exact mode
controls below, with no residual unknown. This proves a compatibility gap in
public ConPTY output, not the bytes rejected in the earlier native enrollment
run. The guard now accepts only CSI `?9001h`, `?9001l`, `?1004h`, and `?1004l`
in addition to its existing language. Parameter lists, leading-zero aliases,
other private modes, input event sequences and malformed lookalikes still fail.

These are input requests, not text, cursor movement or line editing:

- Microsoft's [Win32-input specification](https://github.com/microsoft/terminal/blob/main/doc/specs/%234999%20-%20Improved%20keyboard%20handling%20in%20Conpty.md)
  defines mode 9001 enable/disable and encoded key events. Its compatibility
  section explicitly expects clients without that capability to ignore the
  request. Microsoft's [plain-text input handling](https://github.com/microsoft/terminal/blob/main/src/terminal/adapter/InteractDispatch.cpp)
  synthesizes key events for such clients. This headless pipe client keeps its
  existing bounded plain ASCII synthetic invitation and carriage return; it
  does not implement or advertise Win32 key-event encoding.
- Microsoft's [mode definitions](https://github.com/microsoft/terminal/blob/main/src/terminal/adapter/DispatchTypes.hpp)
  identify 1004 as focus reporting, and its [input implementation](https://github.com/microsoft/terminal/blob/main/src/terminal/input/terminalInput.cpp)
  emits focus-in/out input only when handling a focus event with that mode
  enabled. This isolated pipe client has no UI focus events and emits no focus
  replies. The requests do not change the guard's visible text model.

The guard consumes these exact controls without resetting either echo matcher,
changing prompt readiness during partial sequences, or relaxing title, cursor,
line/total bounds, trust ordering or success/input barriers. No input encoding,
input writer, approval, permission, workflow or cleanup code changes. Portable
fixtures cover each sequence at every text position and sequence split before
and after input, concealed synthetic echoes, incomplete controls and malformed
lookalikes. This source fix is not native acceptance and authorizes no new run.

## Third-run early child exit and bounded failure diagnostics

[Run 37753015193](https://github.com/storminator89/Tracebolt/actions/runs/37753015193)
used exact source `24dd3cea9b28095c1b3f4731133238fdb003a5c2`. Its retained finite
artifact SHA-256 is
`d1acfbc5906287df6a5380e042126b61a59a8ce4e0cca76d37a73e56160b3df7`.
Approval and inert checks passed. The native report recorded controller stage
`session`, session outcome `protocol_incomplete`, output rejection `none`, natural
child exit `nonzero`, and coordinator phase `unknown`. No synthetic input,
receipt/grant verification, or inventory frames were observed. The owned child,
console and fixture were closed. Service stop/disabled state and platform VM
disposal remain unverified; retained state is not an accepted installation.

These facts do not locate the failed operation. The session returns
`protocol_incomplete` before testing process success when input or approval is
absent. On that path `outputRejection=none` means no incremental rejection was
recorded; it does not establish successful final protocol validation.
`coordinatorPhase=unknown` means no qualifying receipt observation was available,
not that a receipt or service was absent. The old child maps every caught failure
and recovered panic to the same nonzero status.

A source audit found all child admission environment keys and eight approvals
forwarded, exact matching child arguments, absolute artifact/bootstrap paths,
and KnownFolder-derived production layout. Parent provisioning creates the app
parents and executables, not the child installer/runtime/enrollment stores. No
source-proven missing environment value, working-directory dependency, or
preprovision collision was identified. The native step lasted 58 seconds including
build and admission, so ordinary exhaustion of the child's remaining-grant window
is not supported. None of these checks identifies the run's actual cause.

The subsequent diagnostics source candidate preserves the existing console-only
input and create-only coordinator operations. It annotates existing failure paths
with closed finite metadata and transports only approved failure-stage/category
pairs through fixed test-child exit statuses. The report retains only
`childFailureStage` and `childFailureCategory`. One atomic observation of the
existing waiter supplies those fields together with `naturalChildExit` before
forced teardown; termination imposed by cleanup cannot become a child diagnostic.
Unknown/unmapped statuses stay unknown. No console transcript,
raw error, raw process status, path, key, invitation, or additional native/protected
read is added to retained evidence. If a failed installation is followed by the
mandatory failed-receipt write, the first installation diagnosis is retained only
as metadata; the original write and public error remain unchanged. Diagnostic
metadata does not grant permission, retry an operation, weaken an admission rule, or establish cleanup or acceptance.

Portable fault-injection checks and Windows cross-compilation are source evidence
only. This candidate does not establish the third run's cause, authorize another
native dispatch, or establish a successful native subset.

## Read-only KnownFolder environment comparison

The fourth diagnostic run (`37758168998`) reached the strict root-syntax refusal
`service_layout_root` / `unsafe_path` after both KnownFolder APIs succeeded.
That locates the refusal, but does not identify the malformed root or prove why
it was malformed. No raw path is required to test the narrowed hypothesis.

Ordinary Windows service source CI now has a separate, opt-in, bounded probe.
It starts two fresh copies of the test executable, each limited to reading
`FOLDERID_ProgramFiles` and `FOLDERID_ProgramData` with `KF_FLAG_DONT_VERIFY`.
The baseline has only the existing child's three OS environment entries
(`SystemRoot`, `WINDIR`, `COMPUTERNAME`), a public probe role, and
`GOTRACEBACK=none`. It carries no native-gate metadata, authorization, bootstrap,
secret or caller environment. The comparison adds exactly `SystemDrive`, derived
from a strictly validated `GetSystemWindowsDirectory` result, rather than trusting
an inherited drive or substituting a KnownFolder root.

The valid parent roots remain private to memory; only their SHA-256 comparisons
travel to the owned children over an anonymous pipe. Children return canonical
finite categories (`valid`, `api_error`, `unsafe_root`, `unsafe_component`) and
parent-equality booleans. Child output is capped at 1 KiB, child lifetime at 10
seconds, and the wrapper retains at most 1 MiB of private test output before
printing only the finite summary. Raw output and errors are never replayed.

Interpretation: a valid parent, a baseline root refusal, and both comparison
roots strictly valid and identical to the parent would support the single-variable
explanation on that ordinary Windows host. A passing probe only means a complete
observation: it does not require or claim reproduction on every Windows image.
If the baseline already succeeds, or the addition fails to restore both roots,
the hypothesis remains unconfirmed. Windows cross-builds and portable parser
fixtures do not constitute a native observation. At the probe-only revision, the privileged child's allowlist, root checks,
trust/ownership checks, artifacts and pins were unchanged.
This probe neither installs nor controls services, creates keys/enrollment,
changes ACLs/settings, accesses network endpoints, nor runs the manual gate.

Microsoft documents the KnownFolder default paths using `SystemDrive`, the
read-only retrieval flags, and the shared Windows directory API:
- https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
- https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath
- https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/ne-shlobj_core-known_folder_flag
- https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemwindowsdirectoryw

### Observed result and narrow child-environment correction

Ordinary source run `37760619051` at commit
`5d48b2a56c0ada2008ec797b8a207d4cd6602afb` observed:
- Baseline ProgramFiles: `valid`, equal to parent.
- Baseline ProgramData: `unsafe_root`, not equal to parent.
- Adding only the API-derived SystemDrive: both roots `valid`, equal to parent.

This establishes the missing-variable behavior on that hosted Windows image.
The native test-child environment now adds only that proven `SystemDrive` value.
Both probe and builder reuse the identical pure strict directory validator;
`GetSystemWindowsDirectory` supplies the native value. An API error or invalid
result returns only the fixed admission error before child creation. Inherited
SystemDrive is never consulted, and ProgramData/ProgramFiles are not overridden.
All original forwarded entries and authorization bindings remain intact.

The pure builder is extracted into a test-only helper so ordinary portable tests
can assert the exact environment delta, reject malformed roots/NULs and verify
error non-disclosure. The production installer, KnownFolder resolution, strict
layout parser, executable ownership/trust, artifact pins, console input and
manual-gate approval requirements are unchanged. This source fix does not prove
that the complete privileged scenario succeeds, and does not authorize another
native run.
