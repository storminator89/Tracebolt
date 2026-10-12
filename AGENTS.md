# Tracebolt repository agents

For installation/deployment requests, read **[docs/installation.md](docs/installation.md)**
first, then the relevant `deploy/` templates and current CLI source. Treat this
file as navigation and project constraints, never as permission to act on a host.

**Fastest supported installation:** use the runbook's
[installation-agent fast path](docs/installation.md#fast-path-for-installation-agents).
Inspect the real target and existing state first; use the Linux Docker Compose
manager with approved protected configuration, then the verified dashboard Linux
read-admin command on a supported endpoint. Confirm authenticated login, service
state and fresh non-synthetic observations. The local demo is not deployment;
current Windows Read admin needs matching source artifacts and native acceptance.
Ask for required credential/trust, exposure and host-service approvals, and report
missing material rather than inventing credentials or weakening protection.

- Inspect the selected computer, OS/architecture, checkout/revision, existing work,
  toolchain, private paths and requested scope before changing anything. Preserve
  user edits. Do not assume the editing environment is the deployment server.
- Fresh same-key automatic certificate renewal is a TLS-only source candidate.
  Read `docs/automatic-certificate-renewal.md` before changing its policy, scheduler,
  immutable identity anchor or atomic credential manifest. Keep explicit unchecked
  local consent, original scopes/floors/ages, current-leaf expiry and final
  revocation checks; signed HTTP and optional native package actions are unsupported.
  Existing profiles are not adopted. Source fixtures do not authorize credentials,
  host installation, trust changes, native acceptance or a release.
- Current LAN paths: default manual-v1 with preprovided approved material, or
  explicitly configured guided-v2 with a dedicated protected client-auth issuer.
  Linux `enroll-agent` uses a hidden local terminal prompt and deliberate public
  fingerprint/comparison approval; Linux `lan-agent` supports one-shot or bounded
  foreground reporting. A Linux/systemd `agent-service` candidate adds read-only preflight and separately
  authorized install/restart/upgrade/uninstall; actual service acceptance is a
  manual disposable-VM gate. An unsigned Windows LAN preview is published; macOS LAN clients, verified boot
  persistence and automatic renewal are not shipped. Read `docs/windows-status.md`
  for the exact released source and remaining native gates. `make run` is the synthetic developer
  manager, not the LAN startup command.
- Obtain the required approval for deployment exposure, persistent credential or
  trust changes, firewall/global settings, service installation and destructive
  actions. Stop at missing credentials/authorization; explain the exact blocker.
  Never weaken TLS, file protection or firewall policy to make a test pass.
  Native enrollment creates persistent endpoint keys; obtain its required approval
  and hand secret invitation entry to the human/approved secure handoff. Do not
  pass invitation secrets through args, environment, URLs, files, chat or logs.
- Keep passwords, verifiers, private keys, cookies, raw telemetry and runtime state
  out of Git, logs, chat and artifacts. Use approved secure provisioning. Root CA
  private keys stay offline outside the explicitly authorized disposable HTTP setup
  helper, which creates a temporary root key in memory and never writes it. Only
  opt-in guided-v2 permits a dedicated client-auth intermediate signing key in
  protected manager custody. Public approval still
  requires independently verified identity/fingerprint and explicit authority.
- Expanded operational/package collection requires a fresh explicitly acknowledged
  profile and identity. Never relabel or reuse a basic/v2 ledger to grant it. For the
  fresh v3 HTTP background-service MVP read `docs/http-complete-first-start.md`.
  The current rc.3 complete-profile public command selects `--read-admin` and the
  validated ingress. One combined local scope approval configures inventory and
  the separate helpers; invitation input remains hidden and dashboard identity
  approval is still required. Basic/non-complete profiles retain pending-service.
  The recorded native Ubuntu TLS pass does not establish a user host or OS reboot.
- The separate hostname/interface-address extension stays off until explicit local
  consent under the existing stopped service identity. Use the documented preview,
  enable and disable commands; do not edit its sidecar or collect through the manager.
  Existing enrollment/counter state stays bound, and disabling does not refresh or
  erase retained metadata. See `docs/endpoint-identity-extension.md`.
- Optional on-demand journal content needs a compatible upgraded endpoint and a
  separate explicit local helper/content grant. Read `docs/linux-journal-helper.md`
  and `docs/journal-content-mvp.md` before proposing setup. The main agent must not
  become root or gain journal-group membership. Keep selected service allowlists,
  separate HTTP plaintext-content acknowledgement, durable consume-once floors,
  original expiry and operator-only content boundaries. Source/fixture checks do
  not authorize account, group, unit or socket changes or an actual journal read.
- Retained service-log browsing is a new create-only v4 local scope. Read
  `docs/retained-journal-browsing.md` before changing its policy, cursor protocol
  or installer integration. Never promote v1-v3 grants; the combined fresh admin
  approval must explicitly cover retained history. Keep consume-once and source
  cursor-loss truth, bounded pages, and external-AI separation.
- Complete visible process/mount generations are a separate default-off local
  extension under an existing activated v3 identity. Read
  `docs/complete-overview-extension.md` before opt-in. Keep the stopped-service
  identity guard, explicit full-scope disclosure, independent durable floors and
  original capture age. No automatic collection, re-enrollment, manager reset or
  host permission grant follows from a manager upgrade or schema initialization.
- Complete cached APT update rows are a separate default-off local scope;
  preview consent never authorizes the full generation. Before enabling or
  changing it, read `docs/complete-cached-updates-extension.md`. Preserve the
  independent durable floor, exact retry bytes, cached-only command policy,
  original metadata age and operator-only bounded paging. Fixture tests do not
  establish native Debian/Ubuntu or installed-service acceptance.
- For the fresh one-command read-admin profile, read
  `docs/read-admin-onboarding.md`. One explicit combined approval covers the
  supported read scopes/helper only; production HTTPS remains default and HTTP
  requires its full content-risk warning. Keep the main agent nonroot, retain
  started/completed phase evidence, and never adopt existing or pending journal
  state. Use only the verified rc.3 pin and matching manager source described there;
  older release commands are not compatible with the combined profile. Do not
  call fixture results native acceptance or execute any host grant without approval.
- For a completed read-admin v2 update, read `docs/read-admin-upgrade.md`. Use only
  the explicit verified coordinator; never substitute ordinary binary upgrade.
  Preserve original receipts, private state and same-scope grant bindings; require
  the separately approved native old-release-to-new-artifacts gate before release.
- For one-time existing-agent inventory consent, read
  `docs/guided-inventory-setup.md`. Its preview is nonmutating until explicit
  confirmation; existing identity-bound scope CLIs remain authoritative. Do not
  turn setup into a manager grant, journal recovery or host acceptance claim.
- Service-action setup is a create-only source candidate for one existing activated
  endpoint and one reviewed service. Read `docs/guided-service-action-setup.md`.
  Plan is read-only; manager/endpoint apply needs separate local approval. Never
  remove intent/fences or reinitialize missing used state. The old pinned release
  is incompatible; source fixtures do not authorize native setup or a target action.
- Selected native APT updates are a default-off source candidate, not released. Read
  `docs/selected-package-updates-native.md` and its native gate before setup. Source
  compilation and fake subprocess tests never authorize package installs, root
  helper grants or state reset. Keep exact signed plans, consume-once claims and
  the shared service/package mutation fence.
- Proactive AI diagnostics are a default-off manager-side scope. Read
  `docs/proactive-ai-diagnostics.md` before changing its admission or data flow. For
  optional restart-safe storage also read `docs/ai-settings-persistence.md`; never
  silently persist a provider/key/scope or bypass an unresolved storage fence.
  Preserve exact provider/device approval, claim-before-call deduplication and
  existing managed-evidence export blocks. Health-summary approval never permits
  raw logs, dump data, autonomous tools, shell commands or remediation. Fixtures
  do not authorize a real provider call, API-key entry or runtime scope grant.
- For the historical five-scope Windows observation coordinator, read
  `docs/windows-read-observation-setup.md`. Keep SCM disabled until activated
  identity and all exact grants are durably verified; retain indeterminate
  transitions for read-only reconciliation. The released five-scope preview exposes its GUI path; the current fresh GUI
  uses Read admin below. Existing service/grant receipts must not be promoted.
- The twenty-one-scope Windows Read admin source profile is the prominent fresh
  Setup choice; actual scope consent remains unchecked. Read
  `docs/windows-read-admin-setup.md`. Preserve legacy consent/receipt bytes and
  historical development interfaces, disabled fresh staging and exact identity/
  phase guards. There are no existing user installations: migration, binary
  upgrade and reconsent are not delivery gates for this fresh-install target.
  Provider-access proof, privilege expansion, event-content/cache grants and
  service control remain separate.
- Windows caller-visible volume metadata is a separate default-off local grant.
  Read `docs/windows-volume-inventory.md` before changing its consent, capacity
  semantics or v3 wire shape. Keep v1/event-v2 identities and bytes compatible;
  fresh combined approval is a reusable contract, not an automatic installer grant.
- Complete caller-visible Windows process snapshots are a separate default-off scope.
  Read `docs/windows-full-processes-contract.md` before consent, Toolhelp bounds,
  primary v4 used markers, generations or private paging changes. Snapshot PIDs
  never join retained metrics; old CPU/RAM remains separately consented and capped
  at 128. Cutoffs fail complete attempts, never promote prefixes. No process
  handles, paths, commands, owners, privileges or native acceptance follows.
- Windows per-process CPU and working-set memory is a separate default-off
  capability. Read `docs/windows-process-metrics.md` before changing consent,
  CPU accounting or wire v4. Preserve old grants, PID-creation attribution, exact
  retry, frame budget and provider exclusions; fixtures never grant host reads.
- Windows TCP/UDP endpoint metadata is a separate default-off local capability.
  Read `docs/windows-network-endpoints.md` before changing consent or wire v5.
  Keep earlier grants/frames unchanged, numeric addresses and API-snapshot PID
  attribution only, explicit HTTP disclosure, exact retry and private operator
  expiry. No DNS, process joins, traffic payloads or AI export; source fixtures
  never authorize a host network read or a service/security change.
- Windows adapter link/DNS/gateway context is a separate default-off local scope.
  Read `docs/windows-adapter-context.md` before changing native bounds, consent,
  wire v8 or its private Network view. Preserve all old grants/frames and the
  five-scope coordinator. No probes, DNS resolution, routes, traffic or privilege
  expansion; source fixtures never authorize host reads or grants.
- Windows caller-visible routes and raw interface counters are a separate default-off
  local generation. Read `docs/windows-network-context.md` before consent v10,
  receipt8/V6, primary v5 used-state, IP Helper tables or private Network changes.
  Keep ordinary v14 bytes/budgets, exact independent retries and original expiry.
  No cross-table index joins, rates, since-boot totals, probes, packets, MACs/GUIDs,
  privileged reads, host grants or native acceptance follows from source tests.
- Windows drive-letter mapping and storage-provider context are a separate default-off local scope.
  Read `docs/windows-storage-context.md` before fixed local roots/MSFT_PhysicalDisk,
  worker bounds, v13 transport or private Storage UI changes. No physical serials,
  SMART claims, guessed physical joins, remote reads, host grants or privileges.
- Windows aggregate storage I/O is a separate default-off local scope.
  Read `docs/windows-storage-io.md` before fixed PDH PhysicalDisk(_Total) counters,
  two-sample timing, isolated workers, consent v12/receipt10 or wire v16. Keep
  counter validity, finite nonnegative values and idle-latency suppression. No
  per-disk completeness, topology joins, SMART, health/AI/action authority, counter
  enablement, host grant or native acceptance follows from source fixtures.
- Windows CPU and memory context is a separate default-off local scope.
  Read `docs/windows-resource-context.md` before fixed processor/memory/pagefile
  sources, consent v11/receipt9 or private resource-context UI changes. Keep
  source-labeled processor counts, SMBIOS-installed versus OS-usable RAM and
  aggregate-only pagefile capacity/use distinct; no names/paths, paging-I/O,
  thrashing or health inference, CPU sampler change, host grant or native claim.
- Windows hardware and power context is a separate default-off local scope.
  Read `docs/windows-hardware-context.md` before fixed local WMI/power sources,
  isolated workers, identifying-serial consent, v12 wire or private Device UI.
  Preserve source-labeled chassis and BIOS serial meanings, unknown sentinels,
  independent source failures and old receipt bytes. No firmware writes, raw
  SMBIOS, UUID, license/recovery keys, host grants or native acceptance follows.
- Windows caller-visible sessions and local join context are a separate default-off
  local scope. Read `docs/windows-session-context.md` before changing fixed WTS/
  NetGetJoinInformation reads, worker bounds, consent, v11 wire or private UI.
  Personal labels require explicit disclosure. Unknown counts/denied fields are
  never empty/full-account assertions. No remote queries, impersonation, session
  actions, accounts, credentials or host permission follows from source tests.
- Windows Security Center antivirus and TPM presence/version are a separate default-off scope.
  Read `docs/windows-security-coverage.md` before fixed client WSC/TBS sources,
  worker bounds, wire v14, fresh fifteen-scope consent v8/receipt 6 or private UI.
  Server WSC is unsupported; unknowns never imply protection or TPM readiness.
  No reserved TPM fields, raw TPM commands, owner auth, BitLocker reads/keys,
  remediation paths, privileges or host acceptance follows from source tests.
- Windows Defender/Firewall posture is a separate default-off local scope.
  Read `docs/windows-security-posture.md` before changing fixed local WMI/COM
  reads, independent provider workers, consent, v10 wire or private Security UI.
  Denied/absent/passive sources never prove overall protection; Firewall reports
  local configuration, not effective policy or reachability. No scans, rules,
  credentials, remote queries, privileges or host permission follows from tests.
- Windows build/history/reboot context is a separate default-off local scope.
  Read `docs/windows-patch-context.md` before changing fixed registry/WUA sources,
  isolated-worker authority, consent or wire v9. Never read pending-file-operation
  values or infer current installation/compliance from retained history. Keep old
  grants/frames unchanged, unknown reboot sources and checked-source coverage.
  No host read, online scan, grant, install, reboot or security change is implied.
- Windows configured service startup metadata is a separate default-off local
  capability. Read `docs/windows-service-startup.md` before changing consent,
  aggregate native-buffer handling or wire v6. Preserve the original service-row
  digest/index binding, per-field unavailable states and old grants. The fresh
  five-scope coordinator remains unchanged; source fixtures never authorize a
  native configuration read, new persistent grant or service/security change.
- Bounded older Windows event search is a fresh default-off scope. Read
  `docs/windows-event-history-runtime.md` before changing its typed UTC search,
  receipt-linked selected-message followup, consume-once floor, session cache or
  fresh twenty-one-scope consent. Old twenty-scope and current-content v1 grants
  never promote. Preserve original search expiry, stable identity and final live
  credential/session guards; no arbitrary query, native grant or release follows.
- Selected Windows event messages and cached Windows Update inspection have
  separate default-off runtime/manager/UI source paths. Read
  `docs/windows-event-content-runtime.md`, `docs/windows-event-content-manager.md`,
  `docs/windows-event-content-wire.md`, `docs/windows-event-content-request.md`,
  `docs/windows-event-content.md`, `docs/windows-update-inspection.md` and
  `docs/windows-update-runtime.md` before changing them. Existing five-scope Setup or event-header grants authorize neither.
  Keep message content out of durable telemetry and AI/provider export; preserve
  exact selections, original expiry, session-bound ephemeral content and durable
  consume-once boundaries. Never reset missing used state or recapture lost results.
  Cached WUA inspection must remain offline and must not download, install,
  accept update terms, reboot, upgrade WUA or change service/network settings.
  Fixtures/cross-builds do not authorize native reads or create a local grant.
- Central managed MSI delivery is a fresh separate default-off source domain. Read
  `docs/windows-managed-msi-delivery.md` before changes. For fresh upload-once fleet
  v2 setup/registry/worklist also read `docs/windows-fleet-managed-msi.md`.
  Fresh reusable-v3 jobs additionally require `docs/windows-reusable-managed-msi.md`:
  also read `docs/windows-software-catalogue.md` for recent choices and same-content
  occurrence pins. Keep grant-wide sequences separate from readiness, exact reviewed retirement,
  original expiry, bounded custody/history and durable retired floors. Uncertainty
  blocks replacement; never claim verified publisher trust from reviewed evidence.
  Keep chunked private custody,
  separate delivery/install consent and keys, dedicated LocalSystem risk disclosure,
  original leaf/expiry checks, exact package/native review and one-attempt no-replay.
  Observation remains available; standalone deployment excludes other mutators.
  For fresh paired MSI/cached-WUA setup, read `docs/windows-coordinated-mutations.md`.
  Preserve the shared durable owner, exact participant roster and one-use native
  admission; no migration, TTL unlock, native retry or observer privilege follows.
  Never promote prepared-v1 or read permissions. Native setup/install acceptance
  remains separately approved and pending; see its manual acceptance plan.
- Prepared MSI installation is a separate fresh default-off one-attempt source
  domain. Read `docs/windows-prepared-msi-jobs.md` before changes. Preserve exact
  protected package custody, package-specific review/native acceptance, separate
  keys/grants/IPC/ledgers, unchecked named approval and durable no-replay. Never
  infer safety/offline behavior from a hash, widen WUA/observer privileges, accept
  caller paths/properties or imply cross-domain serialization. Source tests do not
  choose or run an installer or authorize host grants, keys or ACL changes.
- Selected cached Windows update jobs are a separate default-off source domain.
  Read `docs/windows-selected-update-jobs.md` before changing readiness, signed
  executor reports, manager enrollment transactions, consent, claim/attempt/result
  ledgers or Updates UI. Keep exact GUID/revision, explicit named approval,
  distinct manager/executor keys, original age and current-leaf/final guards.
  Never promote observation/service permissions, retry uncertainty, download,
  accept EULAs or reboot. Native elevated executor/provisioning remain inactive.
- Fresh background cached-update UTC scheduling requires
  `docs/windows-scheduled-background-updates.md`. Preserve standalone v2 and
  manual background v4 bytes; only fresh explicit v5 consent admits the combined
  profile. Keep original actor/window/lifetime, immutable outbox reconciliation,
  issuance-time fresh shared status and actual native-edge fencing. No native
  retry, refund, window extension, migration or host permission follows.
- Manual fleet groups and reviewed one-setting Windows health apply are manager-side
  organizational source features. Read `docs/fleet-groups-health.md`. Preserve
  private stable original identity bindings, current admission and exact revisions.
  Groups never grant scope or automatic inheritance; sequential writes stop on
  conflict/uncertainty and never retry an unconfirmed POST.
- Windows system-volume capacity health is a separate default-off manager policy.
  Read `docs/windows-capacity-health.md` before changing its thresholds or lifecycle.
  Preserve caller-quota semantics, advancing-source confirmation, durable floors,
  unknown evidence and explicit non-recovery policy closure. Never route it into
  Linux Health/AI/alarm admission or infer native scope/service-action permission.
- The Windows fleet incident inbox and operator acknowledgement are manager-only.
  Read `docs/windows-incident-inbox.md` before changing identity/domain keys, source
  deadlines or the enrollment-to-operator commit lease. Seen never means resolved;
  keep all v1 histories, Linux alarms and AI admission unchanged.
- Bounded Windows planned maintenance is separate manager-owned metadata. Read
  `docs/windows-maintenance.md`. Preserve original identity, revision, immutable
  end, current enrollment lease and final clock/session guards. It suppresses
  separately approved Windows notification dispatch, never incidents/evidence,
  source policies/history or host activity. Preserve in-flight result truth and
  consume queued/retry work without end-of-window backlog. Never join independent
  snapshots by mutable device ID.
- Windows incident notifications are separate default-off source policies. Read
  `docs/windows-notifications.md` before changing exact identity/domain keys,
  recipient-bound approval, atomic transition capture or the Windows claim adapter.
  Existing Linux recipient setup is not Windows data-sharing approval. Preserve
  old v1 ledgers, no-backfill, genuine recovery pairing, final enrollment/policy/
  time guards, durable uncertainty and the existing public HTTPS transport.
  Source fixtures never authorize a recipient, credentials or external delivery.
- Windows CPU and physical-RAM policies are independent default-off manager scopes.
  Read `docs/windows-resource-health.md` before changing their shared percentage
  engine, tagged storage, API or UI. Preserve disk v1 bytes, exact observed-group
  CPU and physical-memory semantics, independent opt-ins/floors, one coordinated
  source read, and unknown evidence. No host collection, AI or alarm grant follows.
- Windows machine-software change history is a separate explicit default-off scope.
  Read `docs/windows-software-history.md` before changing its consent, complete
  comparison, seven-day derived retention, shared reservation or private paging.
  Preserve exact post-grant identity/source generations, original before/after
  times, unavailable-field truth and visible whole-comparison gaps. No install
  times, upgrade/maliciousness inference, AI/export/actions or host grants follow.
- Selected-account HKCU/MSIX software is a separate default-off foreground source
  candidate. Read `docs/windows-selected-user-software.md` before consent, local
  identification-only IPC, account binding, primary v6 or private Software changes.
  The helper runs once in the selected normal user's own context; Setup never
  substitutes its elevated account or LocalService. No all-user enumeration,
  paths/commands, software actions, history comparison, persistent helper or AI
  export. Source tests and the prior 21-scope native harness do not establish this
  new source's native acceptance or authorize host grants.
- Complete Windows machine software generations require a separate default-off
  local scope. Read `docs/windows-full-software-contract.md` before changing its
  HKLM 32/64 source, consent, primary v3 marker, transport, store or UI. Preserve
  independent software/service floors and exact old primary bytes; old scopes
  never promote. Per-user, MSIX/Store, portable programs, paths and commands are
  excluded. Source fixtures never authorize native reads or host grants.
- Complete caller-visible Win32 service generations are a separate default-off
  local source extension. Read `docs/windows-full-services-contract.md` before
  consent, sender-state, native resume, chunk transport, store or UI changes.
  Preserve the mandatory primary used-marker, exact pending telemetry, independent
  generation floors, original age and all old grants. Drivers, ACL-invisible
  services, software, paths/accounts/configuration and AI export are excluded.
  Native/host grants and runtime acceptance require separate approval.
- Selected Windows service control is a separate default-off source candidate.
  Read `docs/windows-service-actions.md` and `docs/windows-action-provisioning.md` before broker, named-pipe, setup, permit,
  ledger or UI changes. Keep the distinct restricted service SID, key domain,
  protected broker/target ACLs, exact review, one-control semantics and immutable
  consumed state. Old read grants and Linux restart authority never promote.
  Source fixtures/cross-builds do not authorize native setup, ACLs or actions.
- Selected Windows service checks are a separate default-off manager policy.
  Read `docs/windows-service-health.md` before changing exact-name selection,
  discrete state evaluation, source admission, API or UI. Keep native
  `internal/windowsservice` lifecycle code separate from the manager-only
  `internal/windowsservicehealth` package. Missing/duplicate rows never prove down;
  preserve positive partial-row scope, original capture, authority and durable floors.
- Follow Go/Node versions and dependency locks in this revision. Validate commands
  against actual flags/config. Distinguish runtime tests from cross-builds, skipped
  container tests, and proposed functionality. Never invent install/enroll flags.
- Change only requested files; keep security boundaries and provenance intact.
  Run relevant checks and report exact revision, platform, pass/fail/skip and
  remaining gates. Do not claim a real deployment from local fixtures or CI.

Build/test entry points and safe operational boundaries are in the runbook;
component detail is in `docs/lan-runtime.md`, `docs/lan-agent.md`, `docs/docker.md`
and `tests/lanclient/README.md`. For service requests also read
`docs/linux-agent-service.md`; its candidate status does not authorize host changes.

## Separately approved service-log AI

`service-journal-ai-v1` is an explicit, default-off exception implemented only by
`internal/proactivejournal`, `analysis.AnalyzeJournal` and the journal-AI API.
Never infer its approval from local journal access or `health-summary-v1`.
Preserve exact provider/credential, manager, device/service, policy-generation,
window, acknowledgement and original-expiry bindings. Log-backed source/model
text stays memory-only; durable receipt/attempt metadata must contain no log or
model prose. The existing managed-profile `BuildPacket` exclusion remains intact.
See `docs/proactive-service-log-ai.md` for bounds and the native fixture boundary.
