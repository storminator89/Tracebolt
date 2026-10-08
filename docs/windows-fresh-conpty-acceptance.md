# Separate fresh Windows ConPTY native test candidate

This is source-only opt-in test infrastructure, not a public installer, workflow
result, release gate override, deployment command or permission to run. No native
execution is established by portable tests or either-architecture cross-builds.
Existing base and expanded manual modes, consent meanings and reports are unchanged.
A distinct manual-only workflow candidate is included; it has never been dispatched.
There is no automatic or reusable native trigger.

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
