# Windows Read admin setup

Current target: a fresh clean development installation. There are no existing
user installations; a published preview is not evidence of deployments. No
migration or existing-binary upgrade plan is required for this increment.

The fresh twenty-one-scope profile is available in unsigned x64
[preview.3](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.3).
Follow its [attached installation guide](https://github.com/storminator89/Tracebolt/releases/download/v0.1.0-windows-preview.3/windows-prerelease-install.md)
with matching reviewed manager/frontend source. Native acceptance covers only the
Server 2025 packaged-Setup install/remove, hidden-input cancellation and interrupted
transport subset. Complete provider access, real Linux-manager/shared-dashboard
interoperability and native restart/reboot remain unproved; see [Windows status](windows-status.md).
Publication does not authorize running an installer on any host.

The current dashboard offers the pinned Setup download and an optional local
file SHA-256 check **before** creating the ten-minute invitation. This checks
public executable bytes only; it uploads nothing, grants no scopes and does not
prove publisher trust or manager compatibility. Local collection approvals stay
unchecked in Setup. See the [installation audit and shorter workflow](windows-installation-audit.md).

## Fresh Read admin, seven readable groups

The prominent fresh Setup profile is **Read admin**, covering these twenty-one
scopes. Selecting that profile does not grant consent: the scope acknowledgement
starts unchecked. Personal user/domain/session labels, identifying chassis/BIOS serial metadata, local drive letters/volume GUIDs and storage-provider device identifiers/friendly labels, antivirus product names/status and TPM presence/version, local route metadata, interface aliases and raw traffic/error/discard counters, CPU models/source-labeled counts, installed SMBIOS RAM versus OS-usable RAM, current/limit and remaining commit capacity, aggregate pagefile allocated/in-use capacity, and aggregate local PerfDisk (_Total) throughput/operations/latency/queue lengths with the sample window are explicitly named. Bounded Application/System history
and selected historical messages have their own group and sensitive-content
warning; messages may contain credentials, personal information and other secrets.
The review starts with concise scope/requirement groups and offers the full
privacy notices as optional details. Back or choosing another bootstrap clears
all acknowledgements. HTTP-test requires its own unchecked plaintext-risk
acknowledgement for every selected scope. Service control stays separately
optional; the older five-scope internal compatibility path is not an extra
fresh-Setup choice or a required upgrade step.

| Group | Exact local scope | Source/coverage |
| --- | --- | --- |
| Device and activity | `windows-inventory-v1` | Existing bounded system, hostname/interface, process/service/software preview |
| Device and activity | `windows-application-system-event-headers-v1` | Application/System event headers, without messages |
| Device and activity | `windows-visible-volumes-v1` | Caller-visible volume metadata and capacity |
| Device and activity | `windows-process-metrics-v1` | Per-process CPU and working-set RAM, limited to 128 base-preview PIDs |
| Device and activity | `windows-complete-processes-v1` | [Complete caller-visible Toolhelp snapshot PID/parent PID/name/thread count](windows-full-processes-contract.md), independent of metrics |
| Network | `windows-network-endpoints-v1` | Numeric TCP/UDP endpoints and API-snapshot PID |
| Services and software | `windows-service-startup-v1` | Configured startup metadata for the bounded service rows |
| Services and software | `windows-complete-services-v1` | Complete bounded caller-visible Win32 service generations |
| Services and software | `windows-complete-machine-software-v1` | Complete bounded HKLM 32/64 uninstall-registration generations |
| Services and software | `windows-machine-software-history-v1` | Manager comparison of complete comparable HKLM generations for observed registration add/remove and field/version differences |
| Network | `windows-adapter-context-v1` | Adapter link state/speed, configured DNS and gateway addresses |
| Network | `windows-network-context-v1` | [Caller-visible route prefixes/next hops/index/metric/protocol/origin and interface aliases/raw octet/error/discard counters](windows-network-context.md), independent complete context without joins or rates |
| Updates and security | `windows-patch-context-v1` | Build labels, retained WUA history and fixed reboot indicators |
| Updates and security | `windows-security-posture-v1` | Independent Defender status and local Firewall profile configuration |
| Users and sessions | `windows-session-context-v1` | Caller-visible WTS sessions/personal labels and local join context |
| Device and activity | `windows-resource-context-v1` | [CPU model/architecture/source-labeled processor counts, installed SMBIOS RAM, OS-usable/available RAM, commit current/limit/remaining and aggregate pagefile allocated/in-use capacity](windows-resource-context.md); no names/paths or paging-I/O/health claims |
| Device and activity | `windows-hardware-context-v1` | Manufacturer/model, source-labeled chassis and BIOS serial, firmware and system battery/power |
| Storage | `windows-storage-context-v1` | Local drive-letter/volume-GUID mapping and fixed storage-provider identifiers, friendly labels, media/bus, size and provider health/status |
| Storage | `windows-storage-io-v1` | [Eight fixed local aggregate PerfDisk counters: read/write throughput, operations and latency, average/current queue lengths, with measured sample timing](windows-storage-io.md); no per-disk attribution or health verdict |
| Updates and security | `windows-security-coverage-v1` | [Security Center antivirus names/state/signatures on Windows clients; TPM presence/version](windows-security-coverage.md) |
| Event history and sensitive messages | `windows-application-system-event-history-v1` | [Bounded on-demand Application/System history, plus selected exact historical messages](windows-event-history-runtime.md); operator-only memory and original fifteen-minute expiry |

The authoritative fresh list (`WindowsReadAdminScopesV14`) and grouped requirement manifest are
`internal/lanclient/windows_read_admin_profile.go`. Coverage, exclusions and
bounded provider behavior remain the contracts in the individual scope guides.

Software-change history has a separate explicit scope and starts with a fresh
baseline after consent. Both compared generations must be complete under the
same exact current identity, HKLM source, software grant/revision and history
scope. It describes observed registration and field/version changes, never
actual install times, upgrade direction or application identity across reinstalls.
Retention ends seven days after the earlier original observation, with at most
1024 change rows / 1 MiB per device. Missing baselines, failed-capture gaps and
quota omissions remain visible. History supports operator-only search/paging;
no AI, export, health or action authority is granted. There are no new native
reads, provider prerequisites or privileges.

Read admin is not every possible Windows read feature. Selected sampled-event message
content and cached WUA update inspection remain independently consented. Fresh
v14 separately includes bounded historical searches and selected historical
messages, with explicit sensitive-content disclosure; see
[history runtime](windows-event-history-runtime.md). Service
control remains distinctly optional and separate; no action broker, service
allowlist, account change or AI/provider access is configured by this profile.

## Requirements are not access results

Setup requires the existing supported platform/package and fixed protected-path
preflight, a fresh inventory bootstrap, matching transport and a compatible
manager. Choose the public bootstrap from a regular file on a fixed or removable
local drive, up to 64 KiB. CD/DVD, network paths and reparse traversal are rejected;
copy the public file to an ordinary local folder such as Downloads first. This
does not import global certificate trust or carry the invitation secret.

The current **source candidate** can automatically select one public dashboard
bootstrap next to the Setup executable on a fixed or removable local drive. Save
the Setup and its downloaded `tracebolt-bootstrap-invite_<id>.json` together
before launching Setup. Only one correctly named candidate is considered; its
invitation ID must match the validated file. If multiple candidates exist, the
file is missing, invalid or inaccessible, choose the intended file manually.
Compare the selected invitation and trust values with the current manager
invitation; a selected file does not prove that it is current or unexpired.
All local approvals remain unchecked, and the hidden invitation prompt and manager
device approval remain separate. This convenience is not in published preview.3;
native packaged GUI acceptance is still required.

The current dashboard source also exposes existing pending Windows invitation
claims directly for review and provides separate organizational customer records.
The [customer and approval scope](customer-records.md) explains why these records
do not yet assign a customer to an enrollment or create a reusable installer.

The separate source-only package builder can also embed one validated public
invitation bootstrap into a newly built Setup using `--public-bootstrap <path>`.
The resulting executable selects that configuration for review without a
separate file on the endpoint. It is bound to the original single invitation:
building does not extend its deadline, create a customer or permit reuse. The
file must contain public configuration only; the secret still belongs solely in
the hidden prompt. All local consent and manager fingerprint approval remain
necessary. The build manifest records the public bootstrap digest and labels this
an unsigned, unpublished personalized source candidate. Build and fixture checks
are not packaged native installation acceptance. The published preview.3 and
current dashboard do not provide this personalized installer.

Its new bodyless public compatibility route is
`/v1/windows/read-admin-setup-capabilities-v10`, with exact contract
`fresh-twenty-one-read-admin-scopes-v1`. Historical v9/twenty-scope, v8/nineteen-scope and v7/eighteen-scope, v6/seventeen-scope, v5/sixteen-scope, v4/fifteen-scope,
v3/fourteen-scope and v2/thirteen-scope advertisements remain exact. The
historical twelve-scope route and
`fresh-twelve-read-admin-scopes-v1` response remain byte-for-byte unchanged. The old five-scope route and response remain
unchanged. An older/mismatched manager blocks before installation writes; no
invitation, credential or telemetry is sent in this check.

The grouped manifest names local system/process/volume APIs, Application/System
Event Log, SCM, HKLM 32/64 registration views, IP Helper, fixed registry/WUA COM,
Defender WMI, Firewall COM, WTS, NetGetJoinInformation, fixed local CIMV2
ComputerSystem/BIOS/SystemEnclosure queries, GetSystemPowerStatus, fixed local drive-root APIs and MSFT_PhysicalDisk, client Security Center COM and TPM Base Services, fixed Win32_Processor properties, GetPhysicallyInstalledSystemMemory, GetPerformanceInfo aggregate EnumPageFilesW, and eight fixed local PDH PhysicalDisk(_Total) counter prerequisites. This
increment does **not** query those providers during setup. Their availability is
`not_checked`; actual service-token access is `not_verified`. Administrator
access during installation could not establish LocalService readability anyway.
Providers may be absent, disabled or denied. Such sources stay unavailable or
unknown; no provider is installed or enabled, and no ACL, privilege, token,
account, firewall, network or Windows setting is changed to make a read succeed.

### Compatibility failures before installation

The current source checks manager compatibility before allocating the hidden
invitation console or creating application files, a service, keys or scope grants.
A failed check can mean a connection timeout, a TLS verification failure or an
unexpected response/contract. It does not by itself prove that the manager needs
an upgrade. Check connectivity **from the endpoint**, the selected origin and
approved CA, then compare the manager and Setup contracts. Reachability from the
operator's computer is not an endpoint connectivity test. Never bypass TLS or
change transport to get past this check.

The current source reports the proven pre-installation boundary explicitly and
keeps the general completion message phase-neutral. Failures after provisioning,
or without a proven phase, still require inspection of retained state; even a
compatibility error at that point cannot establish that nothing changed. The
wizard never retries or resets. These diagnostic changes are source-only and do
not alter previously published Setup executables. Source tests and a successful
public compatibility response do not establish native installation acceptance.

The main service keeps LocalService and its existing SID/privilege contract.
Defender passive/absent/denied and Firewall local configuration are not overall
protection or effective-policy proof. Retained update history is not current
patch compliance. Caller-visible sessions are not a complete user/account list. Installed SMBIOS RAM is not OS-usable RAM. Remaining commit capacity is limit minus current committed bytes from one valid source capture; aggregate pagefile capacity/use does not measure paging I/O, thrashing or health. This scope does not change the CPU utilization sampler.

## Fresh authority and receipts

Consent version `tracebolt.windows-capability-consent.v14` admits only the exact
ordered twenty-one-scope set, including separately acknowledged software-change
history and bounded Application/System history with selected sensitive messages.
Earlier v1-v13 retain their original scope sets and cannot authorize event history.
Fresh Read admin uses outer installer receipt 12. Historical v13 keeps its exact
twenty scopes and receipt 11; historical v12 keeps receipt 10; v11 keeps receipt 9; v10 keeps receipt 8; v9 keeps receipt 7; historical
v8 keeps receipt 6, v7 keeps receipt 5 and v6 keeps receipt 4. Historical v5 keeps
its exact twelve-scope set and outer receipt version 3. The existing five-scope
v3 consent continues to use outer receipt version 2 with exactly four extension
digests. V1 ordinary receipts and the old serialized forms are unchanged.

The same fresh transaction stages the owned service disabled, retains protected
intent/phase evidence, creates/activates the identity through hidden invitation
entry and separate manager fingerprint approval, and checks that every selected
extension root is genuinely absent. All twenty extension scope operations are then applied
through their existing protected consent APIs. Each operation rechecks the
original activated sender, unchanged protected phase receipt, and exact owned,
stopped, disabled service. Missing or changed authority stops the next operation.
All twenty enabled scope digests, including original grant IDs, must read back correctly
before the existing startup transition can begin. Software-change history reuses the software
protected store and irreversible primary used marker; event history adds its independent root, for nineteen
extension roots. Software-history enable rotates the software parent grant/revision
and the final software/history digests bind the same exact current consent.
Full process/service/software inspection
also validates the primary used marker and independent generation state.

Partial writes retain completed scopes and the potentially indeterminate failed
scope. There is no grant rollback, reset, adoption, automatic retry or identity
replacement. Startup transition/reconciliation keeps the existing exact-service,
original-identity, unchanged-grant and compare-old-receipt rules. Receipt-only
reconciliation can finalize a proved automatic successor; it does not install,
regrant, change startup or request Start. Fresh Setup never adopts an existing
service or partially used extension store.

## Preserved development reconsent interface (not a delivery gate)

The following already implemented interface is preserved for development
fixtures. There is no existing user installation to migrate, and it is not
required for fresh delivery. A compatible receipt-bound source binary supports:

- `windows-service --read-admin-preview`
- `windows-service --read-admin-enable --apply --twelve-read-admin-scopes`

An HTTP-test identity additionally requires `--insecure-http-test`. These are
source interfaces, not permission to run them. The owned activated inventory
service must already be stopped by its authorized operator. There is no automatic
Stop, Start, restart, binary replacement, enrollment, credential or privilege
operation in either command.

Preview validates the exact original installer receipt, current identity,
transport, each selected existing extension and the new manager contract. It
reports existing enabled/absent-or-disabled scope state and the static provider
requirements. It does not read provider data or create stores. A damaged, foreign
or partially used extension fails closed before any new grant is written.

Enable requires the new full disclosure and creates an independent
administrator-only `-read-admin-setup` phase store. It records the original
installer-receipt digest, sender binding, exact consent and original enabled
scope digests. Before and after every extension operation it verifies the owned
stopped service, unchanged original receipt/current identity, protected phase
bytes, and originally enabled grant digests. Existing enabled grants remain
unchanged; explicitly selected absent/disabled scopes may be enabled under their
existing APIs. Original sequence floors, pending bytes, capture ages and expiry
are not reset. Full-generation initialization retains its existing irreversible
primary markers. Completion records all eleven grant digests and leaves the
service stopped for a separate deliberate Start.

This is a one-time create-only transaction. Any existing reconsent store, complete
or incomplete, blocks replay. It is not a recovery/retry interface; do not delete
state to make it run again. Later individual disable/re-enable commands remain
separate explicit operations. Failure outputs contain finite status/scope results;
partial durable evidence stays for review even when its final write failed.

**The historical preview.1 executable cannot perform this path.** The current Windows
lifecycle has no verified binary-upgrade transaction. This increment therefore
does not provide a released-preview-to-current upgrade or tell an operator to
replace the receipt-bound image manually. Such a replacement can invalidate its
executable/configuration receipt and is not a supported shortcut. Existing hosts
without a compatible development binary remain refused by these preserved
interfaces. Original receipts are not rewritten. There are no existing user
installations to migrate; old-to-new binary upgrade or reconsent is not a release
or delivery gate for the current fresh-install target.

## Collection budget and truthful partial data

The foreground primary attempt retains its 20-second budget and 72 KiB frame.
Fresh storage-I/O wire v16 reserves a 26 KiB bounded base preview before
process/startup row binding; historical resource-context v15 keeps its 28 KiB
reservation. The [storage-I/O guide](windows-storage-io.md#worker-transport-and-privacy)
describes the independent 2 KiB envelope and unchanged composed frame bounds.
Pending retry bytes and independent complete generations remain unchanged.
The [resource-context guide](windows-resource-context.md#bounded-collection-and-transport)
documents the synthetic historical v14 maximum-composition fitting limitation
and why it is not native-reachability evidence.
Fresh odd sequences give the earlier-provider group first opportunity; fresh
even sequences collect the isolated context group, now including CPU/memory and aggregate storage I/O, first. Each
group rotates its leading source across successive turns. All optional providers
respect the existing three-second remaining primary-delivery reserve and a
maximum five-second parent budget, retaining any tighter native bounds. No cached-WUA
search is selected by this profile. Pending retry bytes do not collect or rotate.

A slow or skipped provider yields a finite current-grant unavailable/budget
envelope. Process and startup unavailable fields stay bound to the exact current
base PID/service rows. Repeated slow earlier providers no longer always take the first collection opportunity.
Latest failure reasons remain visible; the private view can show one separately
dated useful previous capture per independent context scope. Original generation,
grant, capture time and 24-hour expiry remain intact. Absent/replaced grants clear
that cache; row-bound process/startup observations are not carried forward. This
is per-scope retention, not per-field merging, and a partly useful new scope
snapshot replaces its predecessor as a whole. See
[context fairness and original freshness](windows-context-fairness.md).

The main/base and earlier native providers remain synchronous and cooperatively
bounded. The optional reserve is not a hard wall-clock guarantee against a
non-returning native API or arbitrary OS scheduling delay. The profile promises
explicit authorized coverage; unavailable providers are never reported as
healthy-empty or proof that protection, inventory or membership is complete.

Route/counter context and complete processes, services and software retain their independent bounded generations and
bursts after the primary attempt. They do not enlarge or precede the primary
frame's collection budget; they can extend the total foreground iteration. The
combined twelve-scope fixture checks both scheduling turns, primary/frame bounds,
truthful budget envelopes and later independent generation delivery. It is
synthetic source evidence only.

## Required native acceptance

Native acceptance remains deferred until the missing Admin-data features are
ready. Existing launch/aggregation guards stay closed: historical profile fixture
approvals cannot validate the current twenty-one-scope receipt12/v14 profile. No native controller was extended or run by this increment.

Before release, separately approve an exact-artifact disposable fresh-install
run covering TLS/HTTP disclosure, initially unchecked full consent, GUI
Back/Cancel/repeated-click flows, disabled staging, all twenty-one scopes and
actual unchanged LocalService readable/denied/absent providers. Include grant/
startup interruptions, original-age private data, and reboot/shutdown. Fixture
checks, cross-builds and hosted source/browser CI establish none of these native
results. Migration and existing-binary upgrade remain outside this target.

The new [storage context](windows-storage-context.md) displays provider health/status,
not SMART or physical-health proof. RAID/virtual/Storage Spaces visibility and
unknown sources stay explicit. [Aggregate storage I/O](windows-storage-io.md) is independently sampled; per-disk attribution, paging-I/O measurement and physical topology joins remain deferred.
