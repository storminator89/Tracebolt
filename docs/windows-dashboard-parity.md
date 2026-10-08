# Windows feature and shared-dashboard parity checklist

The acceptance target is Windows capabilities inside the **same Tracebolt
manager and dashboard used for Linux**. A stdout report, standalone Windows page
or successful cross-build does not complete a feature. This checklist records the
explicit product requirement and the next implementation slice; unchecked items
are not shipped claims.

## Current evidence

- [x] Bounded native read-only Windows collector source and read-only CI: CPU
  interval (one processor group), RAM, system-volume disk, hostname, interface
  addresses, processes, services, software registry inventory and optional
  Application/System Event Log metadata.
- [x] Basic Windows enrollment/service/state source and fixtures, plus the
  separately approved fresh native subset recorded below. Portable source checks
  alone do not establish native acceptance.
- [x] Shared manager/store/dashboard-model fixtures admit Windows **basic** frames
  with explicit Windows/TLS compatibility and reject Linux managed-profile reuse.
- [x] Ordinary read-only prerequisite measurement exists. Source 5bd1340 observed
  the old ancestor-policy block; effective service-token access was unverified
  on that historical revision. The later fresh subset verifies a limited token.
- [x] Fresh native ConPTY subset on exact source
  `69fc69a9d20efb8f998898445246ff317d94ac57`: [run 37800284228](https://github.com/storminator89/Tracebolt/actions/runs/37800284228)
  reports `passed_fresh_native_subset`, with hidden synthetic console input,
  completed protected receipt/grants, limited service token, two inventory/extension
  frames and exact-owned service stop. This uses a loopback fixture peer.
- [ ] Remaining installed-host acceptance: outage/restart, interruption, reboot,
  upgrade/rollback and broader service lifecycle/cleanup scenarios. The successful
  subset retained automatic startup, service/app files, identity and grants;
  application cleanup and VM disposal were not verified.
- [ ] Real Windows endpoint → production Linux manager → shared browser dashboard
  acceptance. An in-memory native protocol peer does not satisfy this item.

The existing basic profile stays limited. A separate explicit
`windows-inventory-v1` source candidate now connects the richer report to the
ordinary sender and shared manager/UI; see
[Windows inventory dashboard](windows-inventory-dashboard.md).

## Inventory vertical slice: source implemented, fresh native subset passed

- [x] Windows-specific consent, strict bounded wire contract and explicit
  hostname/interface disclosure; no Linux profile or basic-ledger reuse.
- [x] Exact bootstrap/identity/platform scope and durable sender binding, TLS
  default and explicitly acknowledged HTTP-test compatibility.
- [x] One native collector adapter for CPU/RAM/system-disk and bounded process,
  service, software, hostname/interface sections with honest quality/counts.
- [x] Production manager validation, separate Windows enrollment store, fixed
  signed ingress and atomic frame/replay/history persistence.
- [x] Existing shared device Overview/resource charts and Inventory subviews,
  authenticated same-origin reads, EN/DE labels and bounded stale visibility.
- [x] Deterministic actual sender → signed ingress → durable manager → private
  operator view/history fixture with restart, exact retry and rejection checks.
- [x] DOM contract, consent, request interruption and cumulative freshness tests;
  additive invented Windows case prepared in the existing hosted LAN runner.
- [x] Hosted invented-data browser acceptance passed on source `69fc69a9d20efb8f998898445246ff317d94ac57`
  in [ordinary CI 37796325355](https://github.com/storminator89/Tracebolt/actions/runs/37796325355).
  This is synthetic shared-UI evidence, not real endpoint collection.
- [x] Separately approved fresh protected native subset on that same source;
  historical path-pinning, console and verification failures remain recorded in
  [the fresh native gate](windows-fresh-conpty-acceptance.md). No OS-root or
  ProgramData ACL widening was used.
- [ ] Actual Windows endpoint → production Linux manager → shared browser
  dashboard acceptance. The native loopback peer does not establish this path.
- [x] Separately consented bounded Application/System headers through sender/store and shared Health source; [source boundary](windows-event-health.md). Broader native-to-production-manager/browser acceptance remains pending.
- [x] Separately consented bounded caller-visible volume inventory, truthful quota/physical capacity, v3 sender/store and shared Storage source; [source boundary](windows-volume-inventory.md). Broader native-to-production-manager/browser acceptance remains pending.
- [x] Separately consented process CPU/working-set memory through v4 sender/store and the existing Processes table; [source boundary](windows-process-metrics.md). Broader native-to-production-manager/browser acceptance remains pending.
- [x] Separately consented bounded [service startup metadata](windows-service-startup.md) source through v6 sender/store and the existing Services table. Automatic/manual/disabled and delayed-auto quality are explicit; the original five-scope coordinator is unchanged. Native collection and exact-source hosted browser acceptance remain pending.
- [ ] Complete Windows event-derived alerts/health diagnostics and explicit AI evidence
  scope, followed by the remaining native capability parity below.

## Remaining parity work, each with UI acceptance

| Capability | Existing Windows foundation | Required next delivery and evidence |
| --- | --- | --- |
| CPU/RAM/disks/history | CPU/RAM/system-volume source connected through sender/store/shared charts; CPU limited to one processor group | Prove native end-to-end values; report multi-group limitation honestly; separately consented [caller-visible volume source](windows-volume-inventory.md) now connects through v3 sender/store/Storage UI; prove native quota/denied/no-drive-letter cases |
| Processes/services/software | Consent-bound bounded native/registry generations connected to shared dashboard source; shared Processes UI adds local name/PID filtering, numeric sorting and bounded pages | Exact-source hosted UI checks for the new controls and real endpoint-to-production-manager/browser acceptance; no `Win32_Product` repair side effects |
| Hostname/interfaces/connections | Explicit hostname/interface scope plus separately consented [TCP/UDP endpoint metadata](windows-network-endpoints.md), v5 sender/store and shared Network UI are implemented | Production-manager/browser acceptance; retain numeric addresses, API-snapshot PID attribution, explicit scope and partial/denied/freshness semantics; no traffic capture or stable process-owner claim |
| Logs and alarms | Opt-in Application/System headers persist through sender/store; shared [Logs sample browser](windows-logs-sample-browser.md) adds local filters/pages and refresh, with no messages/XML/EventData/security identities | Exact-source hosted UI checks for the new header browser and event-derived alerts; older event retrieval/content needs a separately consented bounded channel policy and access tests |
| Updates and CVEs | No Windows Update equivalent shipped | Native Windows update discovery/provenance and software matching, manager validation plus shared update/risk UI; separate approval for any remediation/installation |
| AI diagnostics | Manager feature exists; no Windows inventory end-to-end acceptance | Explicit Windows evidence/provider scope and shared diagnostics UI; preserve current export blocks, no raw event content/dumps or autonomous shell/actions |
| Service control/remediation | Local fixed SCM lifecycle candidate only | Reviewed exact-target Windows action/consent policy, durable consume-once requests and shared action UI; no arbitrary commands or automatic restart grants |
| Install/update/reboot | Source candidate/manual harness; no released Windows download path | Reviewed Windows artifact/provenance and simple approved installer/update flow, identity-preserving upgrade, genuine shutdown/reboot and rollback acceptance |

Every row needs four independently identified results: native collection under
its granted Windows identity, consent-bound transport and manager persistence,
shared dashboard behavior, and real endpoint acceptance. Source/fixture results
can advance implementation without being promoted into any of those native
claims. The goal is equivalent useful functionality with Windows-native APIs and
permissions; Linux-only package/journal/systemd assumptions must stay rejected.
