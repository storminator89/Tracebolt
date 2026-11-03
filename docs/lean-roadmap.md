# Lean delivery roadmap

Baseline: `main` at `071ed51432395be62fa9c0a42ef914c500f80ddd`
(3 November 2026). This orders the next small epics; it does not replace the
[product scope](product-plan.md), [Linux priorities](roadmap.md),
[Windows priorities](windows-admin-roadmap.md) or individual scope contracts.
Only merged source at this baseline counts as existing; an issue or test
candidate alone does not prove completion.

## 1. Make capabilities and readiness clear

- **Existing:** [release/profile limits](../README.md#current-status), original
  observation times, explicit unavailable/partial states, Rust status diagnostics
  and a read-only [manager doctor](manager-initialization.md).
- **Next:** one compact capability/readiness view per device: exact profile and
  artifact, accepted-report age, granted versus available scopes, source coverage
  and remaining native/release gates. Start with the existing evidence, not a new
  readiness score.
- **Done when:** stale, missing, denied and unsupported evidence cannot appear
  ready; a running service or published package is never shown as native acceptance.

## 2. Unify Windows and Linux daily work

- **Existing:** [Linux Investigations](linux-health-checks.md#fleet-investigations)
  and a separate [Windows incident inbox](windows-incident-inbox.md), with their
  own incident, acknowledgement and maintenance contracts.
- **Next:** a read-only cross-platform work queue with platform/source filters,
  original event and latest evidence times, acknowledgement state and links to
  the existing device workflows. Keep source-specific identities and lifecycle.
- **Done when:** counts reconcile with each source; unavailable sources are not
  empty success; seen is not recovered. Opening a row grants or executes nothing.

## 3. Grow Rust Windows parity progressively

- **Documentation increment:** the [Windows agent scope comparison](windows-agent-parity.md)
  records Rust Basic's exact metric subset against all twenty-one Go Read admin
  scopes at its pinned source baseline. This adds no Rust collector or grant and
  does not establish native acceptance or feature parity.
- **Existing:** [Rust Basic](../rust/windows-agent/README.md) reports CPU, physical
  RAM, system-drive capacity and uptime. It is not the broader Go Read admin
  profile; automatic onboarding does not expand collection authority.
- **Next:** publish an honest per-scope parity list, then implement one bounded
  read-only scope at a time, beginning with process/service/machine-software
  inventory as separately reviewed increments. Keep Go Read admin available.
- **Done when, per increment:** consent, protected state, wire compatibility,
  bounded source coverage and unavailable states are tested. Record native
  evidence separately; never label an untested scope or the whole agent “parity”.

## 4. Add Linux CPU and RAM alerts

- **Existing:** [Linux Health](health-dashboard.md) shows resource readings;
  its durable checks cover contact, root filesystem and selected services.
  [Windows CPU/RAM policies](windows-resource-health.md) already exist separately.
- **Next:** independent, default-off Linux CPU and RAM policies over already
  authorized observations, with explicit measurement semantics, thresholds,
  confirmation duration, recovery hysteresis and existing incident history.
- **Done when:** advancing fresh samples are required; repeats, gaps and clock
  rollback cannot earn duration. Unknown evidence cannot recover an incident;
  acknowledgement, maintenance and policy removal keep their defined meanings.
  No new collection, notification or remediation authority follows.

## 5. Bring jobs into one place

- **Existing:** separately approved [Windows update jobs](windows-selected-update-jobs.md),
  [MSI worklists](windows-saved-msi-worklists.md) and controlled Linux
  [service](guided-service-action-setup.md)/[APT](selected-package-updates-native.md)
  source workflows, each with distinct authority and acceptance limits.
- **Next:** a read-only job center linking exact device, job purpose, review,
  approval, schedule and saved result. Keep each domain's ledgers and controls.
- **Done when:** queued, sent, executing, succeeded, failed, expired and uncertain
  are shown only when supported by that domain's evidence. Unknown outcomes
  cannot become success or trigger retries; viewing never issues a permit.

## 6. Make patch evidence easy to review

- **Implemented source increment:** a per-device [read-only patch evidence
  overview](patch-evidence-overview.md) for complete cached APT candidates and
  Windows cached results/history, with separate original times and source-view
  navigation. This is not a current patch-compliance verdict or native acceptance.
- **Existing:** Linux [cached APT/CVE review](linux-cve-warnings.md) and Windows
  [build/history/reboot context](windows-patch-context.md) plus separately granted
  [offline cached update inspection](windows-update-runtime.md).
- **Next:** one read-only patch overview with source/method, original scan/cache
  times, applicability limits, candidate counts and links to exact native views.
- **Done when:** missing or old metadata stays unknown/stale, retained history is
  not current installation proof, and a candidate/CVE match is not a compliance
  or exploitability verdict. No online scan, install or reboot is implied.

## 7. Finish case handoff and customer onboarding

- **Existing:** inventory CSV and bounded [support bundles](support-bundle.md);
  [customer records/assignments](customer-records.md) organize one manager.
  [Customer-bound onboarding](customer-device-onboarding.md) remains design and
  unexposed source candidates, not an available installer.
- **Next:** first an explicitly reviewed, allowlisted case-summary export with
  evidence references, original times, gaps and unresolved outcomes. Then a
  separate small onboarding slice linking an exact customer, pending device
  identity, deliberate approval and first fresh accepted report.
- **Done when:** export preserves existing managed-evidence/content exclusions
  and previews what leaves the system. Customer filters are never tenancy;
  profile links are not credentials, and pending approval is not an online device.

## Delivery rules

Work on one issue/epic at a time; parallel helpers stay within that same epic.
Split each epic into small, independently reviewable changes, with focused
unit/API/component regressions for the changed contract. No browser tests are
part of this roadmap's implementation work. Report unrun acceptance honestly;
omitting browser/native checks does not waive a release gate or prove readiness.

Keep identities, original evidence ages, consent, revocation, durable one-use
state and domain-specific permissions intact. No new paid service, host/security
change, broad rewrite, remote shell/desktop, automatic remediation or customer
tenancy is authorized by this plan. Publication and host/native acceptance remain
separate decisions.
