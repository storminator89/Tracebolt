# Windows Read admin setup: source candidate

Current target: a fresh clean development installation. There are no existing
user installations; a published preview is not evidence of deployments. No
migration or existing-binary upgrade plan is required for this increment.

This is a source-only increment on the existing Windows inventory identity. It
is not in the published Windows preview and has not passed native installation,
LocalService provider-access, reboot or GUI acceptance. It does not
change a download pin or authorize running an installer on any host.

## Fresh Read admin, six readable groups

The prominent fresh Setup profile is **Read admin**, covering these fifteen
scopes. Selecting that profile does not grant consent: the scope acknowledgement
starts unchecked. Personal user/domain/session labels, identifying chassis/BIOS serial metadata, local drive letters/volume GUIDs and storage-provider device identifiers/friendly labels, antivirus product names/status and TPM presence/version are explicitly named.
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
| Device and activity | `windows-process-metrics-v1` | Per-process CPU and working-set RAM |
| Network | `windows-network-endpoints-v1` | Numeric TCP/UDP endpoints and API-snapshot PID |
| Services and software | `windows-service-startup-v1` | Configured startup metadata for the bounded service rows |
| Services and software | `windows-complete-services-v1` | Complete bounded caller-visible Win32 service generations |
| Services and software | `windows-complete-machine-software-v1` | Complete bounded HKLM 32/64 uninstall-registration generations |
| Network | `windows-adapter-context-v1` | Adapter link state/speed, configured DNS and gateway addresses |
| Updates and security | `windows-patch-context-v1` | Build labels, retained WUA history and fixed reboot indicators |
| Updates and security | `windows-security-posture-v1` | Independent Defender status and local Firewall profile configuration |
| Users and sessions | `windows-session-context-v1` | Caller-visible WTS sessions/personal labels and local join context |
| Device and activity | `windows-hardware-context-v1` | Manufacturer/model, source-labeled chassis and BIOS serial, firmware and system battery/power |
| Storage | `windows-storage-context-v1` | Local drive-letter/volume-GUID mapping and fixed storage-provider identifiers, friendly labels, media/bus, size and provider health/status |
| Updates and security | `windows-security-coverage-v1` | [Security Center antivirus names/state/signatures on Windows clients; TPM presence/version](windows-security-coverage.md) |

The authoritative fresh list (`WindowsReadAdminScopesV8`) and grouped requirement manifest are
`internal/lanclient/windows_read_admin_profile.go`. Coverage, exclusions and
bounded provider behavior remain the contracts in the individual scope guides.
Read admin is not every possible Windows read feature. Selected event-message
content and cached WUA update inspection remain independently consented. Service
control remains distinctly optional and separate; no action broker, service
allowlist, account change or AI/provider access is configured by this profile.

## Requirements are not access results

Setup requires the existing supported platform/package and fixed protected-path
preflight, a fresh inventory bootstrap, matching transport and a compatible
manager. Its new bodyless public compatibility route is
`/v1/windows/read-admin-setup-capabilities-v4`, with exact contract
`fresh-fifteen-read-admin-scopes-v1`. The historical v3/fourteen-scope advertisement remains exact. The historical v2/thirteen-scope advertisement remains exact. The historical twelve-scope route and
`fresh-twelve-read-admin-scopes-v1` response remain byte-for-byte unchanged. The old five-scope route and response remain
unchanged. An older/mismatched manager blocks before installation writes; no
invitation, credential or telemetry is sent in this check.

The grouped manifest names local system/process/volume APIs, Application/System
Event Log, SCM, HKLM 32/64 registration views, IP Helper, fixed registry/WUA COM,
Defender WMI, Firewall COM, WTS, NetGetJoinInformation, fixed local CIMV2
ComputerSystem/BIOS/SystemEnclosure queries, GetSystemPowerStatus, fixed local drive-root APIs and MSFT_PhysicalDisk, client Security Center COM and TPM Base Services prerequisites. This
increment does **not** query those providers during setup. Their availability is
`not_checked`; actual service-token access is `not_verified`. Administrator
access during installation could not establish LocalService readability anyway.
Providers may be absent, disabled or denied. Such sources stay unavailable or
unknown; no provider is installed or enabled, and no ACL, privilege, token,
account, firewall, network or Windows setting is changed to make a read succeed.

The main service keeps LocalService and its existing SID/privilege contract.
Defender passive/absent/denied and Firewall local configuration are not overall
protection or effective-policy proof. Retained update history is not current
patch compliance. Caller-visible sessions are not a complete user/account list.

## Fresh authority and receipts

Consent version `tracebolt.windows-capability-consent.v8` admits only the exact
ordered fifteen-scope set, including Security Center antivirus and TPM metadata. Earlier v1-v7
retain their original scope sets and cannot authorize security coverage. Historical
v7 keeps outer receipt 5 and v6 keeps receipt 4; fresh Read admin uses outer installer receipt version 6. Historical v5 keeps
its exact twelve-scope set and outer receipt version 3. The existing five-scope
v3 consent continues to use outer receipt version 2 with exactly four extension
digests. V1 ordinary receipts and the old serialized forms are unchanged.

The same fresh transaction stages the owned service disabled, retains protected
intent/phase evidence, creates/activates the identity through hidden invitation
entry and separate manager fingerprint approval, and checks that every selected
extension root is genuinely absent. All thirteen extension grants are then applied
through their existing protected consent APIs. Each operation rechecks the
original activated sender, unchanged protected phase receipt, and exact owned,
stopped, disabled service. Missing or changed authority stops the next operation.
All thirteen enabled grant digests, including original grant IDs, must read back correctly
before the existing startup transition can begin. Full service/software inspection
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

**The old released executable cannot perform this path.** The current Windows
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
Fresh odd sequences give the earlier-provider group first opportunity; fresh
even sequences collect the isolated patch/Security/Sessions/Hardware group first. Each
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

Complete services and software retain their independent bounded generations and
bursts after the primary attempt. They do not enlarge or precede the primary
frame's collection budget; they can extend the total foreground iteration. The
combined twelve-scope fixture checks both scheduling turns, primary/frame bounds,
truthful budget envelopes and later independent generation delivery. It is
synthetic source evidence only.

## Required native acceptance

Native acceptance remains deferred until the missing Admin-data features are
ready. Existing launch/aggregation guards stay closed: historical five- or
twelve-scope fixture approvals cannot validate the thirteen-scope receipt4/v6
profile. No native controller was extended or run by this increment.

Before release, separately approve an exact-artifact disposable fresh-install
run covering TLS/HTTP disclosure, initially unchecked full consent, GUI
Back/Cancel/repeated-click flows, disabled staging, all thirteen scopes and
actual unchanged LocalService readable/denied/absent providers. Include grant/
startup interruptions, original-age private data, and reboot/shutdown. Fixture
checks, cross-builds and hosted source/browser CI establish none of these native
results. Migration and existing-binary upgrade remain outside this target.

The new [storage context](windows-storage-context.md) displays provider health/status,
not SMART or physical-health proof. RAID/virtual/Storage Spaces visibility and
unknown sources stay explicit. Throughput/latency and physical topology joins are deferred.
