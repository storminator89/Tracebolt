# Managed system data collection outline

## Scope and limitation

The user wants operational system data to arrive automatically after installation. The current transport proves only a bounded OS/build, CPU/RAM/root-filesystem/uptime observation. It does not collect the full categories below. This is a proposed compatibility and coverage contract for a later milestone, not an implemented feature list.

Keep the manual `tracebolt.support.v1` bundle identifier-minimizing. Introduce a separate versioned managed envelope and explicit profile for authenticated enrolled devices. The server-assigned identity remains authoritative; reported hostnames, hardware labels and addresses are untrusted operational attributes, not authentication keys.

## Typed sections

| Section | Intended bounded observations | Explicit exclusions or coverage limits |
| --- | --- | --- |
| Hardware and OS | OS edition/build/architecture, CPU model/core counts, physical RAM, vendor/model, firmware version, boot time; reported hostname if included by the managed profile | No product keys, passwords, tokens or environment dump; hardware serial/asset identifiers require a stated profile policy |
| Resources and drives | CPU/load, memory, local volumes/capacity/free space, filesystem status and selected health signals | No arbitrary user-supplied filesystem paths or personal file contents; SMART/privileged signals report denied/unsupported honestly |
| Network | Bounded interfaces, addresses, configured DNS and routes, link state and selected counters | No packet payload capture, connection content, credentials or broad active scanning |
| Services and selected processes | Native service state/start type and bounded process name/PID/resource summaries, with selected watches | No command-line arguments, environment variables, memory reads, executable uploads or arbitrary shell |
| Installed software | OS-native package/application identity, version, publisher/origin where known, architecture | Missing/untrusted package origin remains unknown; do not infer full inventory from one package manager |
| Offered updates | Native/cache-backed pending update evidence, source and freshness | No automatic patch installation; an unavailable/stale catalog is not zero missing updates |
| Vulnerability assessment | Evidence-backed package/version/source-to-advisory match with affected/fixed/unknown status | No name-only CVE verdict, no assumption that upstream version ignores distro backports, no complete-coverage claim from partial feeds |
| Relevant events | Allowlisted native event sources, event ID/provider/level/time/count and bounded selected diagnostics | Default excludes unrestricted raw messages/logs; secret redaction cannot guarantee arbitrary text is safe, and raw event text is not automatically shared with AI |
| Collector and agent health | Provider outcomes, permission errors, duration, truncation, build/schema/capability versions, service-reported state and last successful delivery | Collection validity, contact freshness and overall host health remain separate |

Each section needs a fixed schema, stable evidence IDs, collection time, provider/provenance, coverage limits, item/byte/time caps and an explicit state: collected, partial, denied, unsupported, error or not yet collected. Freshness is a separate dimension. A bounded/truncated list must say so; absent data never means zero problems.

## Field privacy and export defaults

A selected managed profile must disclose field-level collection, local/server retention and export policy. “System data” is not a blanket permission to inspect user activity. Candidate defaults below require installer/admin confirmation and platform verification:

| Field class | Managed collection default | Retention and AI export |
| --- | --- | --- |
| OS/build/architecture and numeric resource/capacity fields | On in the selected basic monitoring profile | Bounded metric history; only explicitly allowlisted case evidence may be exported on a separate Analyze action |
| Reported hostname and local interface/IP information | Declared fields in the selected managed/network profile; show them before approval | Latest bounded inventory/history only; excluded from AI by default |
| Service, process and application names/versions | Declared only when those sections are selected; bounded names and summaries | Treat as potentially activity-revealing; independent short retention and no automatic AI export |
| Serial numbers, MAC addresses, persistent hardware/asset IDs, account/user identifiers and full paths | Off by default; individually justified opt-in if later supported | Separate explicit retention and disclosure policy; excluded from default AI packets |
| Native event ID/provider/level/time/count | On only for allowlisted selected channels | Bounded event ring and explicit gap/truncation flags; metadata-only case evidence by default |
| Event message text, free-form OS error strings and diagnostic output | Off by default | No automatic capture/export; a later narrow opt-in needs its own privacy review and cannot promise perfect redaction |
| Passwords, tokens, private keys, product keys, environment/command-line dumps and personal file contents | Never part of these standard profiles | No telemetry retention or AI export |

Prefer fixed diagnostic reason codes such as `permission_denied`, `unsupported_platform`, `provider_unavailable`, `timed_out`, `truncated` and `parse_error`; localize the UI explanation from those codes. A raw native error can contain a path, account, host or secret and must not be copied into a reason field.

Adding a managed section must not expand model input automatically. Keep an independent AI-export allowlist and a destination-specific, user-visible preview/consent boundary. Central storage retention, on-device spool retention, case retention and optional model export are separate policies.

## Profile and transport evolution

Profiles select known providers and typed filters, not executable commands, scripts, URLs or free-form queries. The agent enforces a locally installed consent/capability ceiling and resource budget; a received profile cannot expand that ceiling. In HTTP test mode, unsigned server/profile responses are not trusted to authorize additional collection. Native queries use fixed field selections and typed filtering rather than concatenating remote strings into shell or WMI/query expressions. Proposed initial scheduling is resources every 30–60 seconds, slower inventory/network snapshots, and separately bounded update/advisory refresh. Exact cadence and resource budgets need platform measurements before becoming defaults.

Do not silently enlarge the existing 72 KiB v1 frame or its single-pending ledger. Define versioned streams/section snapshots with explicit per-section and total byte/item quotas, replay domains, atomic snapshot completion and bounded offline retention. Each multipart snapshot needs a scoped snapshot ID/generation, expected part count, bounded per-part digest/size and an atomic completion decision. A partial, truncated or missing inventory upload must not replace the last complete snapshot as if complete. Retain the last-good snapshot under its original time and independent retention limit while showing the current incomplete attempt separately. Preserve original timestamps and declare stale/partial data during outages.

Enforce quotas at both per-device/per-stream and global manager levels, plus a separate bounded agent spool. Bound concurrent incomplete snapshots and expire abandoned generations. A full global store must report capacity loss and preserve the last-good state rather than silently accepting an incomplete replacement. Exact numerical quotas and retention windows are implementation policy to benchmark and review, not yet established guarantees.

The manager stores contact history separately from observation time. Device health and alerts are derived only from rules with known evidence coverage. Missing collector permission, an expired identity, a stopped sender and an unhealthy measured service must not collapse into one green/red status.

## Platform acceptance

Linux, Windows and macOS require separate provider matrices and actual target execution. Prefer native APIs or explicitly bounded read-only adapters. The Linux sandbox's missing package/service databases remain unknown; it is not evidence that full Linux hosts lack those facilities. Installation/elevation, Windows service/registry/WMI/COM behavior, macOS permissions/signing/TCC, and restart/uninstall need explicit target acceptance before a platform is marked supported.

The administrator should see one operational setup flow and an honest coverage summary, not a list of guessed successful checks. Complete categories are an implementation roadmap with visible gaps, not a promise to collect every possible datum or any private content.
