# Fresh Windows observation setup: source-only coordinator

This is an isolated production-source candidate, not an available installation
command, release download, native acceptance result or permission to install.
The existing Windows commands and existing identities are unchanged. The separate
[Setup.exe preview](windows-setup-preview.md) now invokes this source entry point
through an explicit local wizard; it is unsigned and unreleased. There is no new
lifecycle CLI flag, automatic dashboard download pin, provenance assertion or
release-gate override. The exact distributed executable must satisfy the real
gates below before broader release.

## One explicit upfront read choice

`cmd/windows-service/installReadObservation` integrates the existing combined
`tracebolt.windows-capability-consent.v3` helper with fresh installation and
same-identity enrollment. It requires the exact ordered five-scope selection:

1. `windows-inventory-v1`: existing bounded machine/process/service/software,
   hostname/interface and system-metric inventory.
2. Application/System event headers under the existing event-health scope.
3. Caller-visible volume metadata.
4. Per-process CPU and working-set memory.
5. Numeric TCP/UDP endpoint metadata and API-snapshot owning PID.

One local acknowledgement covers the complete disclosure for these five scopes.
All five full privacy notices are emitted before native setup operations. For
explicit HTTP-test use, all five existing plaintext-risk notices are also
required and emitted; the bootstrap/identity transport must match. Production
TLS remains default. Acknowledgement does not replace hidden invitation entry or
the separate public fingerprint/comparison approval in the manager.

These are the currently implemented bounded READ contracts, not whole-machine
completeness or Linux feature parity. Existing v1-v5 frames, scope versions,
72 KiB frame budget, counters, original capture ages, exact retry bytes, operator
expiry and provider exclusions remain unchanged. There is no Windows Update/CVE,
remote SCM action, event-message content or external-AI authority in this choice.

## Reuse and durable ordering

The coordinator wraps the existing `setup` transaction rather than creating a
second installation framework. It reuses protected bootstrap validation,
create-only installer journal, native service adapters, runtime preparation,
hidden-console claim, `ResumeService`, activated handoff and existing local-grant
APIs. No new runtime sibling or enrollment/sender manifest field is introduced.

1. Require a fresh plan with no existing SCM service and fixed disabled startup.
2. Create the existing administrator-only installer store. Before SCM creation,
   durably write an intent containing the exact plan and combined acknowledgement.
3. Create the fixed service as `SERVICE_DISABLED`, retaining the limited
   LocalService account, individual SID, required privilege, image and path rules.
   Its distinct service receipt version 2 is not admitted by ordinary lifecycle
   functions. Old installations still use their unchanged version-1 automatic
   configuration and receipt bytes.
4. Persist the disabled receipt even for incomplete native creation. Require all
   four extension-store roots genuinely absent; any existing, denied or malformed
   store blocks fresh setup. Prepare runtime state using the existing transaction.
5. Persist the prepared installer receipt (outer version 2), then claim using the
   existing hidden input. No service start is requested. Resume only that committed
   identity to activation while repeatedly verifying receipt-bound stopped,
   disabled SCM state. Original expiry and enrollment session limits remain intact.
6. Record the exact activated sender binding, then a `grants-started` phase. Invoke
   `ConfigureWindowsCapabilities` once with all five approved scopes. Sequential
   writes retain their existing identity-bound protected state and locking.
7. Read back and verify all selected enabled grants without collecting telemetry;
   retain canonical SHA-256 digests including each original grant ID;
   revalidate the same sender identity and the owned disabled service. Durably
   record `grants-verified` and then `startup-transition-started`.
8. Change only that exact owned, stopped, disabled service to the ordinary
   automatic-start configuration. Verify the exact resulting configuration, save
   the ordinary service receipt inside the completed fresh installer receipt,
   and only then request the existing explicit Start operation.

Microsoft documents that `SERVICE_DISABLED` cannot be started and that attempted
`StartService` calls return `ERROR_SERVICE_DISABLED`; automatic startup is a
separate value. The source adapter reuses this OS-native boundary, instead of a
runtime marker whose absence could be confused with a legacy installation.
See [ChangeServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw).
Native behavior on the selected disposable machine still requires its own gate.
A trusted administrator deliberately changing SCM configuration is outside this
boundary; the coordinator rejects a changed configuration when it reinspects.

## Partial failure and reconciliation

No failed phase deletes a service/store, resets state, creates another identity,
extends an approval deadline, enables unselected scopes, adopts existing objects
or automatically retries a mutation. A fresh invocation cannot resume an existing
service. Unknown state remains for inspection.

- Before the startup transition, the newly owned service remains disabled. A
  failed grant retains `AppliedScopes` and `FailedScope` when the receipt update
  succeeds. The failed scope can have an indeterminate write. If that receipt
  update also fails, the durable `grants-started` record remains incomplete.
- `grants-verified` means local protected grants and identity were checked; it is
  not a native observation, manager receipt or dashboard acceptance result.
- A failed `ChangeServiceConfig` result, post-change inspection, receipt write or
  close can leave startup indeterminate. All grants must already have been
  verified and recorded before this transition is attempted. No success or
  service-start completion is inferred from the error.
- `ReconcileFreshReadSetup` is read-only. Given the original exact staged receipt,
  it identifies only the exact disabled binding or its exact ordinary automatic
  successor. Foreign image/configuration/SID/object bindings fail. This low-level inspector never writes
  a receipt, changes startup, retries grants, starts a service or authorizes recovery.
  The separate coordinator below uses its result with stronger retained evidence.
- If the automatic transition succeeded but the final receipt was not recorded,
  separate explicit reconciliation of protected phase history, original activated
  identity and all grants is still required. The source-only reconciliation adapter can finalize just the completion
  receipt after verifying that exact protected intent, original activated sender
  binding, all four unchanged grant digests and owned automatic SCM successor.
  It holds the protected installer-store lock and compares original bytes. It
  never replays installation, enrollment, grants, startup configuration or Start.
  Already-completed reconciliation is a verified no-write result. Disabled,
  missing, replaced or unknown state fails closed. No public recovery command
  is exposed. The old lifecycle CLI rejects unfinished v2 records.
- A completed setup returns the ordinary Start result: requested/asynchronous SCM
  state is not proof of an accepted report, startup after reboot, or first visible
  data. A start failure preserves the completed configuration and identity.

Installer receipt replacement compares the exact previously written protected
bytes under the existing installer-store lock. Canonical decoding rejects
unknown, duplicated and trailing fields. Legacy v1 records omit the new optional
field and retain their exact representation; no old receipt or grant is promoted.

## Evidence and outstanding release gates

Portable injected tests exercise consent and disclosures, disabled configuration,
owned/stopped checks, all phase failure boundaries, partial grants, identity/receipt
mismatch, digest-bound receipt-only finalization, read-only SCM reconciliation,
legacy decoding, cancellation and absence of
a public command. Windows amd64/arm64 cross-compilation only checks source builds.
Tests do not call native collection, SCM, credential or ACL operations.

Remaining gates include independent review of this exact composed source,
explicitly approved disposable native staging/enrollment/grant/transition testing,
real LocalService visibility and protected-store behavior, interrupted native
writes and transition reconciliation, hidden-console handling, Windows-to-real
Linux-manager/shared-dashboard evidence, reboot/shutdown behavior, supported
platform coverage and actual released-artifact/provenance/download verification.
The existing manual expanded-scope acceptance flow does not automatically prove
this fresh staged coordinator. Its separate approval remains necessary. No source
test, workflow result from another revision or fabricated receipt can release this
command. Existing Linux paths and Windows manual scope CLIs remain as documented.
