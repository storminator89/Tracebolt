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

The basic service currently calls `collector.Snapshot`: it does not send the
richer `windowsinventory.Report` used by `cmd/windows-agent`. In particular,
interval CPU/process/service/software/network rows in stdout must not be described
as already connected to the service or dashboard.

## Next coherent implementation: inventory through the shared UI

Implement this source slice after the ancestor-policy correction is reviewed,
with native claims dependent on the approved service gate:

- [ ] Define a Windows-specific, explicit consent/profile and bounded wire schema
  for CPU/RAM/disk plus process, service and software inventory. Hostname/interface
  disclosure must be explicit. Do not relabel Windows as Linux
  `managed-operations-v3`, silently expand a basic identity, or imply consent from
  a manager upgrade. Profile names are implementation choices until committed.
- [ ] Bind the selected Windows scope through bootstrap, cryptographic proofs,
  issuer/claim platform admission and endpoint protected state. Preserve expiry,
  original identity/fences, revocation, wrong-profile rejection and TLS default.
- [ ] Wire the existing Windows collector into the ordinary service sender with
  bounded payloads, exact retry bytes, durable monotonic counters and distinct
  completeness/quality/truncation for every inventory generation.
- [ ] Add production Linux manager validation and persistence for that Windows
  wire contract. Reject forged platform/profile, duplicate/conflicting sequences,
  stale capture times, oversized rows and unconsented fields.
- [ ] Project Windows capabilities into the existing device details navigation:
  overview/metric charts, process rows, service rows, software rows and network
  identity where granted. Preserve stale/denied/partial/unavailable explanations,
  timestamps and limits; never fill missing observations with healthy defaults.
- [ ] Connect overview/history, alerts and health diagnostics to the actual stored
  Windows evidence. Existing Linux behavior and its release pin stay intact.
- [ ] Exercise real manager HTTP/operator APIs and shared UI using synthetic
  Windows fixtures; verify profile mismatch, denied/partial/stale data, restart
  retry, persisted receipts and EN/DE mobile/desktop layouts.
- [ ] Run the separately approved real Windows-to-Linux-manager/browser path on
  exact source. Verify the same device identity, fresh rows/charts and supported
  scope in the UI before calling this vertical slice complete.

## Remaining parity work, each with UI acceptance

| Capability | Existing Windows foundation | Required next delivery and evidence |
| --- | --- | --- |
| CPU/RAM/disks/history | RAM/system disk basic; interval CPU in stdout; CPU limited to one processor group | Wire real interval values into shared charts; report multi-group limitation honestly; add all-volume inventory with Windows semantics and native tests |
| Processes/services/software | Bounded read-only native/registry rows in stdout | Consent-bound generations, manager storage/query and existing dashboard tables; no `Win32_Product` repair side effects |
| Hostname/interfaces/connections | Hostname/interface addresses locally available | Explicit network scope through identity/sender/manager/UI; bounded Windows connection/owner metadata requires its own implemented API and permission evidence |
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
