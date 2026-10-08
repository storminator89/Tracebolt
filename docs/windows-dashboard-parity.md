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
- [x] Basic Windows enrollment/service/state source and fixtures; native protected
  service acceptance is separately gated, not completed by source verification.
- [x] Shared manager/store/dashboard-model fixtures admit Windows **basic** frames
  with explicit Windows/TLS compatibility and reject Linux managed-profile reuse.
- [x] Ordinary read-only prerequisite measurement exists. Source 5bd1340 observed
  the old ancestor-policy block; effective service-token access stayed unverified.
- [ ] Approved real service install/claim/approval/reporting, state/ACL access,
  outage/restart retention, unrelated-service denial and owned cleanup pass on
  the corrected exact source.
- [ ] Real Windows endpoint → production Linux manager → shared browser dashboard
  acceptance. An in-memory native protocol peer does not satisfy this item.

The existing basic profile stays limited. A separate explicit
`windows-inventory-v1` source candidate now connects the richer report to the
ordinary sender and shared manager/UI; see
[Windows inventory dashboard](windows-inventory-dashboard.md).

## Inventory vertical slice: source implemented, native acceptance pending

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
- [ ] Observe the hosted browser case on exact composed source; local Chromium
  execution is blocked, so source/DOM tests are not screenshot acceptance.
- [ ] Native protected installation and actual Windows endpoint → Linux manager
  → shared dashboard. The separate native path-pinning prerequisite is still
  under correction; no root/ProgramData ACL widening is an acceptable shortcut.
- [x] Separately consented bounded Application/System headers through sender/store and shared Health source; [source boundary](windows-event-health.md). Native/browser acceptance remains pending.
- [x] Separately consented bounded caller-visible volume inventory, truthful quota/physical capacity, v3 sender/store and shared Storage source; [source boundary](windows-volume-inventory.md). Native/browser acceptance remains pending.
- [x] Separately consented process CPU/working-set memory through v4 sender/store and the existing Processes table; [source boundary](windows-process-metrics.md). Native/browser acceptance remains pending.
- [ ] Complete Windows event-derived alerts/health diagnostics and explicit AI evidence
  scope, followed by the remaining native capability parity below.

## Remaining parity work, each with UI acceptance

| Capability | Existing Windows foundation | Required next delivery and evidence |
| --- | --- | --- |
| CPU/RAM/disks/history | CPU/RAM/system-volume source connected through sender/store/shared charts; CPU limited to one processor group | Prove native end-to-end values; report multi-group limitation honestly; separately consented [caller-visible volume source](windows-volume-inventory.md) now connects through v3 sender/store/Storage UI; prove native quota/denied/no-drive-letter cases |
| Processes/services/software | Consent-bound bounded native/registry generations connected to shared dashboard source | Native installed-service and shared-browser acceptance; no `Win32_Product` repair side effects |
| Hostname/interfaces/connections | Explicit hostname/interface scope connected through identity/sender/manager/UI source | Native end-to-end acceptance; bounded Windows connection/owner metadata requires its own implemented API and permission evidence |
| Logs and alarms | Opt-in Application/System metadata only; no messages/XML/EventData/security identities | Persist bounded event metadata and surface event-derived alerts in shared UI; content retrieval is a separately consented, bounded Windows channel policy with redaction and access tests |
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
