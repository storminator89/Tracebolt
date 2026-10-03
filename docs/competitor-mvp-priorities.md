# Competitor-informed MVP priorities

Reviewed 2026-10-03. This is a researched product backlog, not an implementation report or a feature-parity claim. Primary vendor documentation establishes documented behavior; no comparative product trial was conducted. Priorities, architecture, budgets and acceptance tests below are Tracebolt engineering recommendations, not vendor promises or delivery estimates. Scope: one private LAN environment, native Windows/Linux/macOS agents, a Docker or native manager, English-default/German UI, monitoring and diagnosis before remediation.

## Decision in brief

Build eight coherent capabilities, in this order: trustworthy device state; bounded resource history; a quiet alert lifecycle; inventory/change history; missing updates and evidence-backed CVEs; selected service/process and network diagnostics; bounded logs correlated into evidence; and optional evidence-first AI with portable case exports. Simple tags, profiles, search and filters support these capabilities rather than creating another management hierarchy.

The first four are the best benefit-to-complexity opportunities. Update/CVE assessment is mandatory despite its higher cost. Logs and AI should consume the same trustworthy evidence model; neither should become a shortcut around missing native collection or uncertain vulnerability matching.

## What current competitor sources actually establish

| Product and primary source | Documented useful behavior | Important qualification and Tracebolt implication |
|---|---|---|
| Datto [agent feature matrix](https://rmm.datto.com/help/en/Content/5AGENT/AgentFeatureComparison.htm) | CPU, memory, online status, process and ping monitors span Windows, macOS and Linux; hardware/software audits and change logs also span these platforms. | The matrix lists Event Log, Service, Software and Patch monitors for Windows only. A shared agent brand does not establish shared capability coverage. Distinguish software inventory from software monitoring. |
| Datto [audits](https://rmm.datto.com/help/en/Content/3NEWUI/Audits.htm) | Inventory auditing is documented separately from monitoring. | Separate slow inventory snapshots from current operational measurements. |
| Datto [monitors](https://rmm.datto.com/help/en/Content/3NEWUI/Monitors/Monitors.htm) | Duration criteria, auto-resolution, ping latency/loss, and alert rate limits are documented. Some rate limits disable a monitor. | Borrow explicit lifecycle and budgets, but keep loss/suppression visible. Do not copy automatic process/service remediation into a read-only product. |
| NinjaOne [condition types](https://www.ninjaone.com/docs/policies-and-conditions/conditions/policy-condition-types-explained/) | CPU, memory, device-down, disk space, network utilization, processes and uptime conditions; Windows services/events and macOS/Linux daemons. Disk exclusion controls differ by OS. | Shared high-level labels need OS-specific implementations and semantics. A listed condition is not proof of universal detection accuracy. |
| NinjaOne [condition configuration](https://www.ninjaone.com/docs/policies-and-conditions/conditions/ninjaone-policies-condition-configuration/) and [maintenance mode](https://www.ninjaone.com/docs/endpoint-management/maintenance-mode/) | Configurable conditions/severity/reset behavior and maintenance suppression. | Newer health-status enhancements have regional-rollout qualifications. Tracebolt should separately show observed health, acknowledgement and suppression. |
| Action1 [software inventory](https://www.action1.com/documentation/software-inventory/) | Central software inventory is a documented product capability. | Use inventory as the basis for change history and assessment, not as proof of vulnerability coverage. |
| Action1 [data sources](https://www.action1.com/documentation/data-sources/) and [snapshot alerting](https://www.action1.com/documentation/data-source-and-alerting/) | Structured data sources support reporting; stable object keys relate successive snapshots for created/modified/deleted alerts. | Custom data sources and custom reports are documented as Windows-only. Adopt stable typed records, not arbitrary PowerShell scripting. Partial snapshots must not manufacture removal events. |
| Action1 [vulnerability assessment](https://www.action1.com/documentation/vulnerability-assessment/) versus [vulnerability marketing](https://www.action1.com/vulnerability-management/) | Detailed assessment documentation names Windows/macOS and explicitly says Linux assessment is unsupported; the marketing page includes Linux. | **Unresolved primary-source contradiction, observed 2026-10-03.** Do not conclude either full Linux parity or definitive product-wide absence from these pages. Require version-specific vendor clarification or a trial before comparative claims. |

This is a selected evidence matrix, not a complete comparison. Blank or omitted functionality here means not evaluated. Competitor pricing, deployment scale, support quality and efficacy were not benchmarked.

## Eight actionable implementation priorities

Effort is relative: **S** = narrow bounded capability; **M** = collector/API/storage/UI integration; **L** = multiple platform or source adapters plus substantial validation. These are scope estimates, not calendar commitments. Risk describes correctness, security and operational risk. P0 means required foundation or required first-release scope, not that all P0 work can happen simultaneously.

### 1. P0 — Trustworthy availability and collector health

**Implement:** agent identity/version, last authenticated contact, server receipt time, endpoint observation time, boot identity where available, and per-capability states: fresh, stale, unknown, denied, unsupported and failed. Keep connectivity separate from CPU/service/update health. Show manager collection/ingestion health so a manager outage does not look like hundreds of independent endpoint failures. Start with server/workstation profiles and explicit device overrides.

**Why useful:** an administrator first needs to know whether the evidence is current and whether the endpoint or collection path stopped responding. This supports every later feature at modest complexity.

**Effort/risk:** S–M / low implementation risk, high consequence if state semantics are wrong.

**Objective acceptance:** stop agent transmission; last contact stops advancing and transitions at the configured grace period. Restart manager; timestamps and identity persist. Replay an old snapshot; it cannot refresh the observation age. Skew endpoint clock; server-derived liveness remains valid and skew is displayed. Disconnect one collector; other capability results remain usable. A revoked identity cannot upload. Never label a stale or never-run check healthy.

### 2. P0 — Useful resource history, not just current gauges

**Implement:** CPU, memory, per-volume free bytes/percent, uptime and a bounded top-process snapshot. Add network-byte rate only after counter reset handling. Preserve source-specific memory meanings. Use stable volume/interface identities, distinguish physical and virtual/removable mounts, and allow explicit exclusions. Start with a short local history and configurable retention; never bridge a missing interval with an invented line.

**Why useful:** resource pressure explains common slow-device and full-disk incidents without remote desktop. Per-volume history is more actionable than a fleet-average score.

**Effort/risk:** M / low–medium; denominator, counter reset and volume identity errors are the main risks.

**Objective acceptance:** controlled workload changes produce the expected series against native reference tools; restart or counter wrap never creates a negative/huge network rate; a disappearing mount does not become a zero-byte disk. Offline gaps remain visible. Retention and total disk budgets are enforced. One endpoint with many interfaces/mounts cannot exhaust storage. Process command lines/environment are excluded by default.

### 3. P0 — A quiet, understandable alert lifecycle

**Implement:** duration thresholds, recovery thresholds/hysteresis, deduplication by device/check/object, acknowledgement, resolution and timed maintenance. Begin with offline, sustained CPU/memory pressure, low storage and selected service failure. Maintenance suppresses notifications while preserving underlying observations. Use dashboard alerts before external delivery integrations. Add only two simple default profiles, server and workstation.

**Why useful:** a short actionable list beats constant transient warnings. Acknowledgement means someone saw the issue; recovery means evidence says it cleared.

**Effort/risk:** M / medium; lifecycle and outage amplification are more important than the number of rule types.

**Objective acceptance:** a short spike never alerts; a sustained breach opens exactly one incident; acknowledgement does not resolve it; recovery requires the configured stable interval. Maintenance expires at its stored time across a restart and shows a suppression badge. Manager downtime is presented as a shared collection issue rather than a fake endpoint recovery. Repeated identical events increment occurrence counts within configured budgets instead of creating an unbounded list. Rule edits retain an audit record and do not silently rewrite prior evidence.

### 4. P0 — Native inventory and a trustworthy change timeline

**Implement:** OS/build/architecture, selected hardware identifiers, installed package/application name/version/publisher/origin and collection scope. Diff comparable complete snapshots into install/remove/version-change records. Add device notes/tags and search by version, stale state, OS and affected package. Keep inventory identity separate from the authenticated endpoint identity.

**Why useful:** the timeline answers “what changed before this broke?” and creates the substrate for update/CVE assessment. This is more practical than a custom report designer.

**Effort/risk:** M / medium privacy and identity risk; comprehensive application discovery is not a small feature.

**Objective acceptance:** a version change produces one stable change event; duplicate replay produces none. A failed/truncated snapshot cannot imply every missing row was uninstalled. Machine and per-user applications remain distinguishable. Architecture, source package and repository origin are retained where relevant. Linux container scope cannot impersonate the host. Every record exposes source and observed time; synthetic demo records remain visibly separate from actual inventory.

### 5. P0 required scope — Missing updates, CVEs and activation state

**Implement:** three distinct results: installed scope; offered updates from the configured native source; evidence-supported vulnerability matches. Include feed freshness, coverage, vendor references, fix availability and reboot/activation status where justified. Follow [the detailed assessment plan](update-vulnerability-plan.md), including Debian/Ubuntu origins and native version comparators, Windows WUA/MSRC and scoped Apple advisory mappings. Run deterministic local matching against versioned server-side feed snapshots; refresh public advisory metadata without uploading endpoint inventories.

**Why useful:** missing updates and CVEs are a required product outcome. Broad catalog parity with commercial patch vendors is a continuing data-maintenance project, not a cheap API integration.

**Effort/risk:** L / high correctness and parser/security risk.

**Objective acceptance:** old upstream version with a distro-backported fix does not produce an unjustified vulnerable verdict; package-name collision or uncertain product mapping stays unknown/review. Offline/failed refresh preserves prior findings with freshness warnings. An empty offer list never yields “vulnerability-free.” A fixed package with an older running kernel remains distinguishable. Native update queries disclose permitted service/cache/network side effects and never install. Windows/macOS claims require actual native acceptance, not cross-compilation. No data available in the current sandbox is fabricated into a host inventory.

### 6. P1 — Selected service/process watches and targeted diagnostics

**Implement:** read-only expected-state watches for a few named services/daemons/processes, alongside bounded DNS and TCP checks for explicitly configured destinations. Record resolver, endpoint vantage point, target, resolved address, timeout and result. Optional ICMP comes later where permissions/support allow it; failed ping alone must not prove a service is unavailable. Begin with a device-level “check now” action executing a fixed typed check, not a supplied command.

**Why useful:** these checks directly support the first investigation cases: stopped background work and inability to reach a required service.

**Effort/risk:** M / medium; service semantics, privacy and server-side request forgery/network misuse need careful boundaries.

**Objective acceptance:** disabled/triggered/on-demand jobs do not alert solely because no PID exists; PID reuse cannot falsely identify the watched application. DNS failure, timeout and connection refusal remain distinct. Targets are allowlisted and resolved addresses revalidated; deny link-local metadata, unauthorized destinations and rebinding escapes. Bound attempts, wall time and bytes. The AI has no check-execution authority. No broad subnet scan, password collection, service start/stop or arbitrary shell is introduced.

### 7. P1 — Relevant native logs and correlated incident evidence

**Implement:** opt-in bounded event windows around incidents, initially selected Windows System/Application providers, named systemd units where journals exist, and narrowly selected macOS sources where allowed. Store structured original identifiers, source time, ingestion time, boot/context identity and any cursor. Correlate alerts, resource history, software changes and relevant logs in one timeline. Filters should prefer structured source/event fields over translated message text.

**Why useful:** diagnosis becomes inspectable, and evidence remains useful even if no model is configured. Avoid becoming a general SIEM or full-text log warehouse.

**Effort/risk:** L for all platforms; medium for one narrow adapter / high privacy and data-volume risk.

**Objective acceptance:** log flood/oversized event cannot exceed configured record/byte/runtime budgets; dropped/truncated counts remain visible. Rotation/bookmark invalidation creates an explicit gap. Partial channel denial stays partial even if another channel succeeds. Unicode, HTML and instruction-like log text render as inert data. Redaction is previewable and original access restricted. No blanket Security-log/full-filesystem ingestion or mandatory new log-forwarding service.

### 8. P1 — Evidence-first OpenAI-compatible diagnosis and portable cases

**Implement:** a configurable server-side provider base URL/model/key, disabled until configured; scoped evidence selection and preview; grounded hypotheses with evidence IDs, counter-evidence, unknowns and suggested next tests. Keep deterministic findings authoritative. Support a local-compatible provider as well as an explicitly selected remote endpoint. Provider compatibility needs a tested request/response subset, timeouts and response validation. Export a selected case as a reviewable JSON/text bundle with sources, timestamps and coverage; provide tested manager backup/restore independently of AI.

**Why useful:** combines observations into a readable investigation without pretending the model collected facts or established root cause. A portable evidence packet also supports human troubleshooting and recovery.

**Effort/risk:** M–L / high sensitive-data, hallucination and provider-boundary risk.

**Objective acceptance:** provider disabled/unreachable leaves monitoring and deterministic diagnosis functional. A malicious log cannot change the destination, reveal a key, run tools or alter assessment verdicts. All cited evidence IDs exist; unsupported root-cause assertions fail the evaluation. Measure diagnosis quality against the no-model baseline on labelled cases. Enforce evidence/token/cost budgets and cancellation. Exports omit secrets and include selected scope only. Restore into a clean environment and verify devices/history/configuration with secrets handled separately. No autonomous remediation or continuous cloud inference is implied.

## Automatic native-source strategy

The initial agent should require installation/enrollment, then gather the agreed native sources automatically on a bounded schedule. Users should not have to install several extra monitoring agents or author scripts to obtain baseline visibility. This is a product target subject to native acceptance, not an assertion that the adapters exist.

| Capability | Windows | Linux | macOS | Boundary |
|---|---|---|---|---|
| Operational measurements | Selected OS performance/resource APIs | `/proc`, filesystem and interface counters | Native host/process/filesystem APIs | Same normalized contract, source-specific semantics and coverage |
| Inventory | Selected CIM fields, uninstall registry, scoped Appx inventory | Existing package database plus exact distro/release/origin | Selected application metadata and OS/build identity | Never equate incomplete inventory with complete assessment |
| Service state | Service Control Manager selected services | Existing systemd via structured properties; unsupported otherwise | Scoped launchd labels/domains | Do not collapse all inactive states into failed |
| Logs | Local Event Log API with approved channels/filters | Existing journald where accessible; explicit selected fallback only | Existing authorized native logging sources | No permission escalation or extra service just to fill a tab |
| Updates | Configured WUA source and reviewed MSRC rules | Configured package metadata and vendor advisories | Native offered updates plus scoped Apple rules | Follow the assessment plan's side-effect and coverage contracts |

Native implementation anchors:

- [Microsoft Event Log queries](https://learn.microsoft.com/en-us/windows/win32/wes/querying-for-events) document batched reads, bookmarks and per-query statuses. Tolerating query errors can yield partial success; inspect statuses rather than declare the whole collection successful.
- [systemd's systemctl source manual](https://github.com/systemd/systemd/blob/main/man/systemctl.xml) documents structured properties and warns that possible states can evolve. Preserve unknown native states instead of forcing them into healthy/failed.
- [Apple's launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) distinguishes on-demand work from KeepAlive jobs. It is an archived conceptual source; validate current CLI/API output and permissions on each claimed macOS version.
- Existing [product plan](product-plan.md) defines the selected-source strategy and avoidance of `Win32_Product`; [update/CVE plan](update-vulnerability-plan.md) supplies platform-specific intelligence sources, comparators and acceptance fixtures. These plans are design inputs, not proof of implemented support.

Proposed starting collection classes: heartbeat and health roughly every minute; selected operational watches every few minutes; inventory daily and after an explicit refresh; incident logs on demand or a bounded enabled incident trigger. These are adjustable engineering defaults to benchmark, not accuracy guarantees. Add jitter, backoff, a concurrency cap and a bounded local queue. Collection time and ingestion time remain separate; retries are idempotent; data lost to a full queue is reported.

The manager can run natively or in Docker, but a manager container is not an endpoint agent and does not automatically see host logs/processes. Do not solve visibility by mounting the Docker socket or broad host filesystem. Use native outbound agents with approved identities over authenticated TLS; document manager backup volume and certificate lifecycle. Full Linux acceptance must include a real supported host, not only a minimal container.

## Keep the interface and operating model small

- One environment, one searchable device list, one alert list, and device detail tabs for actual implemented data. No empty future navigation, organizations/customers tree, billing or PSA layer.
- English is the default; German is a persisted UI preference. Translate labels, state explanations and dates/numbers consistently; retain original log, software and model evidence text. Test long German labels and keyboard/screen-reader use.
- First-level summaries show last contact, active issues, key resources and assessment coverage. Expand evidence and source detail rather than crowding the overview.
- Small explicit profiles/tags and overrides come first. Avoid hierarchical policy inheritance, arbitrary report builders and a plugin marketplace until concrete use cases justify them.
- A report should communicate scope and freshness next to counts. Never use a single green “secure” score to hide stale, denied or unassessed areas.

## Deliberately later

Remote desktop, unrestricted scripting, automatic service remediation, patch installation, software packaging, MDM enrollment, broad network/SNMP discovery, deep hardware/RAID catalogs, full SIEM collection, multi-customer tenancy, billing and complex technician roles add material authority, security and operating obligations. None is needed for the initial single-environment diagnosis workflow. Selected security-posture observations such as encryption/antivirus status may follow once their platform-specific meaning and permissions are validated; do not market them as EDR or compliance certification.

## Completion and publication discipline

A feature is complete only when its bounded collector, versioned contract, persistence, API, UI, failure paths and native acceptance agree. Record tested OS/build, adapter version, privilege level, data scope and actual outcomes. Fixtures prove logic; cross-builds prove compilation; browser screenshots prove presentation. None substitutes for native collection acceptance.

This document changed documentation only. It adds no runtime feature, install action, network deployment or external communication. Refresh competitor claims before product positioning; in particular, resolve Action1's Linux contradiction before any published comparative statement.
