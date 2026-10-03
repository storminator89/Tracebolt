# Tracebolt — first product slice

Tracebolt is a development-stage endpoint diagnostics project. This document describes product scope and release gates, not a production-support guarantee.

## Product intent
A self-hosted endpoint diagnosis product for Windows, Linux and macOS. It combines trustworthy inventory and operational evidence with a clear investigation workflow. The first implementation is a local development prototype, not a production RMM or a substitute for tested endpoint management.

## Product requirements
- Windows, Linux and macOS are architectural targets. Native platform support requires acceptance testing.
- Premium, fast, restrained administration UI; useful information density, evidence beside conclusions and clear data-quality states.
- Security is a release criterion at every stage.
- Validate the initial product in an isolated development environment, then run native endpoint acceptance tests.

## First deliverable
- Runnable local management application and durable local data.
- Explicit synthetic cross-platform demonstration devices, cases and evidence.
- A limited real Linux sandbox collector, with unsupported or inaccessible readings reported honestly.
- Device search/filter/detail and an investigation flow through evidence and deterministic findings.
- Documented API and collector contracts, automated tests, security boundary review, browser screenshots.
- No autonomous actions, arbitrary remote shell, patch installation or cloud inference.

## Collector strategy
One Go agent with OS-specific adapters. Typed and bounded capabilities rather than caller-provided scripts. Fast health snapshots, slower operational checks and daily inventory. Preserve collection time, original source, version, coverage and errors. Device enrollment identity must not depend solely on hostname or hardware serial.

Windows sources: CIM/WMI selected fields, uninstall registry/Appx, Service Control Manager, native resource and Event Log APIs. Avoid Win32_Product queries because they can trigger MSI repair.
Linux sources: /proc, native filesystem/network interfaces, configured package databases, systemd/journald where supported and authorized.
macOS sources: native system/application inventory, launchd and scoped logging where permissions actually allow it. Never interpret a healthy on-demand job without a PID as a fault.

## Investigation scope
1. Unexpected service/background-process state.
2. Storage exhaustion or inability to write.
3. DNS/target-service reachability.

Separate observed facts, hypotheses, counter-evidence, missing data and suggested next tests. A model is optional and must demonstrate value against a deterministic baseline; no root-cause claims based solely on correlations.

## Verification boundaries

A Linux command sandbox is not a full Linux endpoint. Lack of systemd, journals, native network visibility or privileges must be reported as a capability limitation.

Cross-compilation and fixtures do not establish native OS support. Installation, background-service lifecycle, reboot, permissions, native logging and uninstall require real Windows, full Linux and Apple Silicon macOS acceptance testing. Test results must identify which checks actually ran and which remain unverified.

## Later release gates
- Per-endpoint authenticated identity, rotation and revocation.
- Operator authentication, explicit roles and protected audit trail.
- Bounded collection and offline buffering; transparent dropped data.
- Signed, manually controlled agent distribution before automatic updates.
- No endpoint credentials, shell or authority in the model runtime.
- Native OS tests and failure-path tests, separately reported per platform.
- Independent deployment review before any network-exposed pilot.

## Deferred
Patch installation/orchestration, interactive remote control, privileged remediation, general software deployment, customer multi-tenancy and billing. Consider MeshCentral only if remote access is concretely required; avoid a Tactical-derived commercial product without license review. osquery remains an optional later data source rather than an additional mandatory agent.

## Research anchors (reviewed 2026-10-03)
- https://www.ninjaone.com/docs/new-to-ninjaone/dashboards-navigation/software-inventory-endpoint-management/
- https://rmm.datto.com/help/en/Content/5AGENT/AgentFeatureComparison.htm
- https://www.action1.com/documentation/data-sources/
- https://www.action1.com/documentation/vulnerability-assessment/
- https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
- https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
- https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html

## Required next product capabilities

The initial target is a private LAN deployment with a central manager and manually installed, outbound-connecting agents. Loopback development guards must not be relaxed into LAN access: operator authentication, trusted TLS, approved per-device identities and per-request revocation checks are separate release gates.

Read-only missing-update assessment and vulnerability comparison are required roadmap capabilities. Installed inventory, offered updates and vendor-evidence CVE applicability are separate results. Every assessment needs source, coverage, freshness and an explicit unknown/partial state; no successful inventory scan or empty update list implies vulnerability-free status. Patch installation remains outside this detection milestone.

The OpenAI-compatible provider interface supports an explicitly chosen base URL, model and server-side key. Evidence preparation precedes inference. Recurring log review/dashboard alerting is a later, separately gated capability with approved sources and bounded collection/inference budgets, not a claim made by the current manual analysis prototype.

## Administration and monitoring direction

The first deployment is one environment, not a multi-customer MSP portal. The device workspace should progressively expose actual reachability and agent state, resource history, selected services/processes, network diagnostics, software changes, update/CVE assessments, relevant logs, evidence and case notes. Unsupported, denied and stale sources stay visible. These are phased requirements, not a statement that every collector is implemented.

Required interface behavior: English by default, with German available as a persisted preference. Source evidence and log/model text retain their original content. Favor short labels, accessible consistent icons and expandable detail over promotional copy or dense explanatory blocks.

Before expanding fleet scope, establish authenticated LAN transport, persistent bounded measurements, usable alert lifecycle and verified backup/restore. Multi-tenancy, complex technician roles and broad remote execution remain outside the initial environment.
