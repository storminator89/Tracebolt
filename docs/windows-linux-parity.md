# Windows / Linux feature parity roadmap

Source audit dated **10 October 2026**, baseline commit
`3ba4459a3151223ce98ac58c40471afa73576365`, tree
`310bd49647d1a7f4ce44e2295e33d6ec6bd69012`.
This document describes that baseline, not changes made after it.

The goal is equivalent useful operations in the **same Linux manager and shared
dashboard**, implemented with Windows-native sources and explicit permissions.
Removing platform checks or showing Linux panels on a Windows device is not
parity. Neither platform currently offers an unrestricted remote-management suite.

## Keep three evidence levels separate

1. **Implemented source:** collector, consent, protocol, manager and UI code may
   exist without a shipped or natively accepted endpoint feature. Synthetic tests
   and cross-builds establish only the behavior they exercise.
2. **Released bytes:** a Windows preview does not contain every later main-branch
   change. The selected packaged-Setup evidence in the
   [prerelease guide](windows-prerelease-install.md#selected-native-evidence)
   binds source `14719116bdb663d13e4bcaef434a4374a6265fe6`, tree
   `d2ec1451a0fb4332a48f0ee48b17c35eca807ad4`, and
   [run 38069058865, attempt 1](https://github.com/storminator89/Tracebolt/actions/runs/38069058865).
   Its accepted executables are unsigned. Use the actual release manifest for
   version, availability and asset hashes; this source audit did not reverify a
   live release. Earlier “no release” statements in historical status/install
   documents are not a live release lookup.
3. **Native acceptance:** that recorded gate covers four fresh hosted Windows
   Server 2025 x64 GUI cases, a loopback fixture manager and bounded install,
   cancellation, reporting and owned-service removal. It does not establish
   Windows 10/11, real human UAC/invitation handling, production Linux-manager
   interoperability, reboot, upgrade, full data removal or ARM64 runtime. The
   current audit baseline does not inherit exact-source native acceptance.

Linux is also bounded: [the installation runbook](installation.md) records the
rc.3 read-admin path and a specific Ubuntu TLS same-identity upgrade gate. Selected
APT installation and guided service-action setup are separately scoped source
candidates. They must not be presented as generally released Linux capabilities.

## Source-based parity matrix

“Implemented” below means baseline source, with the evidence limits above.
Priority P1 is the next useful product work; P2 depends on an earlier boundary;
P3 is a later extension. Lifecycle evidence is a parallel release gate.

| Area | Linux baseline | Windows baseline | Gap and priority |
| --- | --- | --- | --- |
| Fleet identity, telemetry, overview | Guided enrollment, nonroot sender, signed frames, stored observations and shared resource history | Implemented separate Windows inventory identity, protected state, LocalService sender, strict v1–v6 frame variants and shared overview/history | Preserve identity/replay boundaries. Prove real Windows → Linux manager → browser values and recovery on the exact new source. **Release gate** |
| CPU, RAM, storage | Linux metrics and separately granted complete visible mount generation | CPU/RAM/system-volume observations; optional caller-visible volume metadata and per-process CPU/working-set memory | Windows system CPU covers one processor group; quota-aware volume capacity is not physical-disk health. Add multi-group coverage only with truthful semantics. **P2** |
| Processes, services, installed software | Separate complete visible process/mount and package generations; systemd service/socket inventory | Bounded process/service/software rows with local filtering, sorting and pages; software is HKLM uninstall registrations only; separately granted service-startup metadata | Transport keeps at most 128 rows in each of process/service/software sections. UI paging is over this sample, not a full host generation. Complete Windows generations and per-user/Store software need new source/scope work. **P2** |
| Network | Interface identity and Linux socket inventory/optional socket-owner helper | Optional numeric TCP/UDP endpoints, state and API-snapshot owning PID; separate interface metadata | Preserve snapshot-only PID attribution. No traffic payloads, DNS discovery or stable process-owner inference. Existing source needs native end-to-end acceptance. **P2** |
| Logs and event messages | Separately granted service-journal content and retained browsing, exact service/date/severity/literal search and bounded continuation | Application/System event **headers** only: provider, event ID, level, timestamp, channel, record ID. Logs filters/pages only the latest accepted bounded sample | No formatted message, EventData/XML, older-event retrieval or content search. Add a separate, bounded message-content scope and real Logs view first; retained browsing follows. **P1** |
| Health, history and alarms | Contact, root-filesystem and selected systemd-service checks, incident workflows and separately configured delivery/investigation paths | Durable accepted-contact incident history; neutral system-volume readings and event-header sample counts | No Windows disk/service rule policy, event-derived alarm workflow, acknowledgment/maintenance or automatic notification path. Add Windows-specific rules without reusing Linux root or `.service` assumptions. **P1/P2** |
| Update inspection | Dpkg package facts, cached APT candidates and separately consented complete cached generation | No Windows Update inspection path; uninstall registrations are not update inventory | Add Windows-native read-only update applicability/provenance, installed/available state, age, partial/error/reboot semantics and Updates UI. Do not relabel APT records or equate KB presence with applicability. **P1/P2** |
| Vulnerability assessment | Linux package/source matching and bounded supported advisory coverage | No Windows-specific update/software/CVE matching or Security/CVE tab | Build only after trustworthy Windows product/build/update evidence and a reviewed advisory source; expose unsupported coverage explicitly. **P2** |
| Service actions | Default-off Linux `service.try-restart` workflow with reviewed target, signed permit, root helper, consume-once state and mutation fence; guided setup remains a source candidate | Local lifecycle for the fixed Tracebolt service only; no manager-driven target-service actions | Add a Windows exact-service action contract, separate privileged boundary and reviewed SCM semantics. Local installer Start/Stop is not remote remediation. **P2** |
| Update actions | Selected native APT candidate with exact preview/approval, bounded allowlist, separate command key and shared mutation fence; not released/natively accepted | None | After read-only discovery: exact native update selection/plan, explicit approval, durable one-use dispatch and truthful partial/reboot/intervention results. No automatic reboot or broad “install everything.” **P3** |
| Files | No general remote file-browser/upload/download/edit/delete feature | No general remote file-management feature; protected installation/state files are internal | This is a new cross-platform feature, not a missing Windows port. Start with explicitly selected read-only roots, handle-bound/reparse-safe traversal and bounded results before considering content transfer or writes. **P3** |
| AI and advanced diagnostics | Optional case analysis; separate default-off provider/device health-summary and service-journal AI scopes | Windows inventory is excluded from existing evidence export. WinDbg code is a pure contract/readiness foundation with no production caller or connected transport | Add typed Windows evidence/provider approval only after rule/evidence boundaries. Existing AI settings do not authorize Windows events, dumps or host tools. WinDbg remains a separate later product. **P2/P3** |
| Installation and lifecycle | Published pinned read-admin command, source service lifecycle and specific same-identity upgrade evidence; no universal reboot/auto-renewal promise | Fresh unsigned x64 GUI Setup with five-scope consent and owned-service removal; protected state/files remain afterward | Same-identity upgrades, interruption recovery, rollback policy, actual reboot/shutdown, supported desktop/ARM64 gates, signing/distribution and deliberate full removal remain separate work. **Parallel release gate** |

### Concrete source map

- Inventory and limits: [`windowsinventory/report.go`](../internal/windowsinventory/report.go),
  [`windowsmanaged/types.go`](../internal/windowsmanaged/types.go),
  [`windowsmanaged/service_startup_windows.go`](../internal/windowsmanaged/service_startup_windows.go),
  [`windowsprocessmetrics`](../internal/windowsprocessmetrics),
  [`windowsvolumes`](../internal/windowsvolumes), [`windowsnetwork`](../internal/windowsnetwork).
- Consent and frame boundaries:
  [`windows_capability_consent.go`](../internal/lanclient/windows_capability_consent.go),
  [`windows_event_consent.go`](../internal/lanclient/windows_event_consent.go),
  [`protocol.go`](../internal/lanstore/protocol.go),
  [`windows_inventory.go`](../internal/api/windows_inventory.go).
  Consent v4 allows a selected sixth startup-metadata scope; it does not change
  the existing five-scope Setup coordinator or old receipts.
- Shared platform routing and sample views: [`details.tsx`](../web/src/details.tsx),
  [`windows-inventory.tsx`](../web/src/windows-inventory.tsx),
  [`windows-inventory-tables.tsx`](../web/src/windows-inventory-tables.tsx),
  [`device-inventory.tsx`](../web/src/device-inventory.tsx).
- Logs: [`windowsevents/events.go`](../internal/windowsevents/events.go),
  [`windowsevents/source_windows.go`](../internal/windowsevents/source_windows.go),
  [`windowseventhealth/contract.go`](../internal/windowseventhealth/contract.go),
  [`windows-logs.tsx`](../web/src/windows-logs.tsx),
  [Linux retained browsing](retained-journal-browsing.md).
- Health: [`windowscontact/contact.go`](../internal/windowscontact/contact.go),
  [`api/windows_contact.go`](../internal/api/windows_contact.go),
  [`enrollmentstore/health.go`](../internal/enrollmentstore/health.go),
  [`health/health.go`](../internal/health/health.go),
  [Windows contact boundaries](windows-contact-history.md).
- Updates and actions: [`packagecollector/source_linux.go`](../internal/packagecollector/source_linux.go),
  [`cachedupdates/source_linux.go`](../internal/cachedupdates/source_linux.go),
  [`linuxcve/evaluate.go`](../internal/linuxcve/evaluate.go),
  [`actionhelper/backend.go`](../internal/actionhelper/backend.go),
  [`api/service_actions.go`](../internal/api/service_actions.go),
  [selected APT candidate](selected-package-updates-native.md),
  [guided service-action candidate](guided-service-action-setup.md).
- AI: [`analysis/packet.go`](../internal/analysis/packet.go) keeps `BuildPacket`
  limited to empty/basic-readonly provenance;
  [`analysis/health.go`](../internal/analysis/health.go) and
  [`analysis/journal.go`](../internal/analysis/journal.go) are separate scopes.
  [`windbgcontract/readiness.go`](../internal/windbgcontract/readiness.go) cannot
  report a connected implementation; see [WinDbg scope](windows-windbg-mcp-candidate.md).
- Setup/lifecycle: [`cmd/windows-service/setup_wizard.go`](../cmd/windows-service/setup_wizard.go),
  [`cmd/windows-service/read_setup.go`](../cmd/windows-service/read_setup.go),
  [`windowsservice/service.go`](../internal/windowsservice/service.go),
  [`windowsservice/removal.go`](../internal/windowsservice/removal.go),
  [retained-state semantics](windows-prerelease-install.md#cancellation-and-partial-state).

## First functional increment: useful event messages

Keep this smaller than a full Event Viewer or whole-history collection:

1. Introduce a separate default-off Windows event-message contract. Start with
   Application/System and bounded exact event identities. Read formatted text
   only after explicit local content/destination acknowledgement. Existing
   header grants, five-scope Setup receipts and pending v1–v6 bytes stay unchanged.
2. Implement and test the native adapter with strict native-buffer/output limits,
   handle cleanup, original record/provider/channel/time binding and finite
   denied, disappeared, unavailable, formatting-failed and truncated outcomes.
   Missing publisher resources must not become a fabricated successful message.
3. Add identity-bound content consent, bounded request/transport, strict manager
   admission and private operator retrieval. Preserve consume-once/retry/expiry
   truth; never place raw event text in diagnostics or generic AI evidence.
4. In the existing Windows Logs tab, show the message with source/time/quality
   and explicit unavailable states. Test EN/DE, long/untrusted text, access loss,
   navigation, refresh/cancel and late responses. Header search is not full-log
   search; retained event browsing needs its own continuation/loss contract.

An isolated native collector and contract are a useful **source foundation**,
but do not complete this user-visible increment until the consent, sender,
manager and UI paths are implemented and tested together. Publishing it or
performing host content reads needs the separately applicable approval/gate.

## Subsequent increments and completion gates

1. Windows health rules and read-only update inspection can proceed independently
   after their explicit contracts are reviewed. Keep unknown/partial/stale states
   visible and leave Linux health/AI admission untouched.
2. Add complete inventory generations and retained event navigation where bounded
   snapshots prevent useful investigation. Stable generation IDs, source-cursor
   loss and complete-versus-visible semantics are required before a “complete” UI.
3. Add selected remote SCM actions, then selected Windows Update actions, each
   with a separate least-privilege helper/policy, durable replay prevention,
   cross-operation mutation exclusion, exact review and post-action evidence.
4. Add narrowly approved Windows AI evidence. File-management and debugger
   integration remain separately designed features rather than shortcuts to
   arbitrary shell, memory access or remote control.
5. For every increment record the exact source and four distinct results:
   contract/fixture tests; native behavior under the intended granted identity;
   production manager/store/shared-browser integration; and installed-host
   lifecycle evidence. Include Windows amd64/arm64 cross-builds without calling
   them runtime acceptance. A release must bind its own tested bytes and must not
   silently migrate grants or reuse another revision's acceptance.

No item in this roadmap authorizes a native host read, service install/control,
credential creation, ACL change, provider call, release publication or deletion.
