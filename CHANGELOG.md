# Changelog

## 2026-10-07 — Scoped proactive diagnostics and Windows service source

- Add default-off background suggestions for newly opened, authorized Linux Health incidents. Require an explicit exact provider/model/device approval for the typed health-summary-v1 data scope. Keep raw logs, arbitrary context fetching, remediation and external AI-result notifications outside this increment. Persist bounded findings with original evidence times, consume-once claims and rate limits; revalidate authority and configuration before export and publication.
- Add explicit protected provider and scope persistence with original approval time, atomic writes and a pending-write fence. Save no previous memory-only configuration automatically. Key storage needs its own acknowledgement and the HTTPS operator profile; HTTP-test supports keyless loopback persistence. Provider/key changes invalidate scope, disable/forget are durable, and interrupted calls are not replayed. Protected files are not encryption or secure deletion.
- Add Windows-only protected SID/DACL/handle state, fixed LocalService SCM lifecycle, hidden console input and a guarded basic TLS setup/runtime command. Limit common enrollment admission to the existing Windows basic profile over TLS; preserve Linux profiles and reject cross-platform telemetry without changing replay floors. The new Windows CI covers injected source fixtures and builds only. Native state/service/console/enrollment and reboot still require a separately approved disposable test; no Windows installer release is claimed.
- Preserve the original Windows enrollment approval deadline while retrying recoverable session timeouts; real state, authority and expiry failures remain failures even if Stop races them. Require explicit LocalService read/traverse access for the protected executable and its ancestors before mutation. Expose only finite console/SCM diagnostic codes; this does not register an Event Log provider or establish actual service-token acceptance.
- Add an inactive WinDbg evidence/readiness contract and integration plan. It has no production caller, transport, debugger execution or AI export, and always reports that the connection is not implemented. Dump access and permissions are unchanged.
- Extend the existing LAN browser runner with one synthetic proactive settings/findings case, including saved-mode readback (21 cases total). No real provider, key, log export, endpoint grant, Windows installation or privileged ARM dispatch was performed by this source work. Verified rc.3 release assets and the accepted Linux upgrade path remain unchanged.

## 2026-10-07 — Windows read-only foundation and explicit ARM source acceptance

- Add a separate, opt-in Windows stdout collector for bounded native resource, hostname/interface, process, service and machine-software observations. Application/System event headers require a second explicit flag. No event messages, Security log, elevation, enrollment, service installation, sender or persistent state is introduced. A dedicated hosted Windows gate validates actual reads without exporting telemetry.
- Extend the existing manual read-admin workflow with native ARM64 fresh and source-built same-identity upgrade cases, plus cancellation and retained-journal cases. Bind the prior to exact 7b20 source and the candidate to the reviewed dispatched commit; independently verify native ELF, clean VCS metadata and artifact hashes. Require all three explicit approvals for every ARM case. Keep public release admission closed and historical rc.3 bytes/pins unchanged.
- Separate read-only host compatibility inspection from mandatory public release admission for the explicitly approved source harness. This does not add a public installer bypass flag or establish a published ARM release, physical Raspberry Pi, interrupted-upgrade recovery or reboot acceptance.
- Record that the 7b20 native ARM collector/fixture and manager-container TLS/HTTP jobs passed. Its separate service-action browser case reached HTTP 200 and the exact preview request, then failed while reading the response body; the historical subcause was not captured. Add fixed transport, size-bound and JSON-decoding stage labels while preserving all 83 assertions, response bounds, deadlines and action consent. No production correction is claimed for that failure.

## 2026-10-07 — Prepare Linux ARM64 parity and native CI

- Select architecture-bound read-admin, upgrade and socket-helper artifacts for 64-bit amd64 or ARM64 hosts. Reject 32-bit userland and cross-architecture upgrade inputs; retain the existing kernel, ownership, approval and private-state checks.
- Keep release runtime admission restricted to amd64. Historical published bootstraps, the verified rc.3 assets and the dashboard pin are unchanged. Raspberry Pi installation, privileged helper operation, upgrade and reboot still need their own approved native acceptance before an ARM64 release can be activated.
- Add a native Linux ARM64 collector smoke and installer/helper/parser fixture lane, including larger page sizes and foreign-package architecture fixtures. Run the existing disposable manager container lifecycle on both native amd64 and ARM64 runners with explicit host/image architecture checks and the original TLS/HTTP assertions.
- Preserve the accepted amd64 evening-update baseline: exact 3444 passed all 16 CI jobs and 124 browser cases, with three historical enrollment quarantines/skips retained. This separate source checkpoint does not require another user release build or change the accepted rc.3 upgrade instructions.

## 2026-10-07 — Align the hosted manager acceptance contracts

- Update the older v3 enrollment browser case to recognize the already verified rc.3 read-admin pin. Preserve its original consent, public checksum, hidden-secret and no-execution assertions.
- Select application setup controls by their exact accessible textbox/combobox names. The installed Playwright selector engine reproduces the old exact-label failure for nested select text and populated textarea labels. Retain target indexing, consent, request restrictions and every deadline; report only fixed allowlisted failure stages.
- Bind chart keyboard expectations to the exact fulfilled synthetic response rather than regenerating timestamps after the settling clock advances. A deterministic 500ms regression covers the mismatch, with narrower closed initial-stage labels. The prior coarse hosted failure does not establish which initial subassertion failed; rendered acceptance still needs the next run.
- This checkpoint changes tests and this record only. Production UI/API/collector/installer and resource-history delta behavior are byte-identical to b9d9; it does not require another agent release or native permission grant.


## 2026-10-07 — Coherent manager update and verified rc.3 commands

- Select the independently verified rc.3 bootstrap for the complete-profile dashboard command. The release remains bound to 405f source; its separate native Ubuntu TLS gate passed the rc.2 replacement, original identity/scopes/private-state checks, all six functions and cleanup. Update the current installation guides; the user's Debian/HTTP update and OS reboot remain separate acceptance.
- Refresh visible first-page inventory by validated complete generation without resetting selected source, submitted search, table DOM or scroll. Later pages and unsubmitted drafts pause visibly. Original timestamps, cursor expiry, backoff and access-loss clearing remain intact.
- Replace profile-only orange capability rows with neutral scope declarations and bounded actual collection/status evidence. Keep denied, failed, partial, stale and unknown outcomes explicit. Preserve original age and session deadlines across manual refresh; successful socket enumeration cannot imply confirmed owner provenance.
- Simplify the log service picker with a focused search, debounced retained-inventory reads, exact-unit keyboard selection and quieter disclosures. Preserve request-time content/plaintext consent and all capture/retention rules. Correct the hosted unit test's asynchronous review-readiness assertion without weakening its requested window or unchecked-consent checks.
- Add 24-hour CPU/RAM/root-filesystem minute history for newly accepted guided-agent observations. Keep gaps and original metric timestamps, exact replay/identity guards and bounded storage. Use 60-second visible reads and session-local deltas to reduce repeated full-history transfer; do not redraw unchanged expired slices. A controlled fixture measured 480,351-byte full history versus 979 bytes for two changed points and 320 bytes unchanged. No user-host resource measurement or new agent collection is claimed.
- Extend the existing hosted runner with application-settings, resource-history and capability cases (20 total) and first-page inventory continuity checks. All screenshots use disclosed synthetic fixtures; exact-revision hosted rendering remains the acceptance gate. Preserve the prior three quarantined cases, all individual assertions/deadlines, and native approval gates.


## 2026-10-07 — Persisted application-check setup candidate

- Add a compact administrator form for the existing HTTP/HTTPS (including verified leaf expiry), DNS and single-port TCP checks. Save typed targets as a disabled draft; review exact destinations/IPs and separately confirm manager-origin recurring checks before enabling. Editing consent, interrupted writes and stale revisions fail closed.
- Add explicit `manage_application_checks` permission for named operators, confidential settings reads, CSRF-protected bounded mutations and the existing shared-pilot administrator mapping. No account, grant, credential or real target is created by the source change.
- Persist manager/origin/profile-bound settings with protected atomic writes and a bounded secret-free audit envelope. Preserve explicit startup-file read-only precedence, sequential transport safeguards, cancellation/join and per-generation result separation. Browser toggles cannot bypass the existing completion-based cadence.
- Retain the read-only Overview status, with truthful disabled wording, cadence/freshness details and short reason help. Link administrators to the working Settings form; the pinned external guide is explicitly for startup-file configuration.
- Add mocked UI/API, injected worker/storage and exact intercepted hosted-browser cases. Local browser execution remains blocked before page creation by socket permissions; hosted geometry/native target acceptance and publication remain separate gates. This candidate does not alter the agent upgrade/release path, enable alarms or configure a user host.

## 2026-10-07 — rc.3 publication and public readback

- Publish v0.1.0-rc.3 from 405f57f after the manually approved native rc.2-to-source upgrade passed: changed artifacts, retained identity/scopes/private state, local approval and all six journal/socket/restart/revoke checks. This does not establish OS reboot or the user's Debian-host update.
- Capture the exact published bootstrap and pin the read-only hosted verifier to the rc.3 source, manifest, signature bundle and all twelve public asset hashes/sizes. Direct byte checks and release-archive reconstruction match the native-tested source; hosted keyless provenance/readback must pass before command activation. Historical published bootstraps remain unchanged.
- Keep dashboard activation separate from this metadata checkpoint. Require a rendered initial fleet identity before the synthetic age test submits its ordinary report, preserving original controls, assertions and deadlines. The prior boolean-only fixture error did not expose its cause; the competing read/write admission contract was reproduced separately.

## 2026-10-07 — Preserve stopped-unit upgrade restoration

- Keep successful reset of every loaded owned service mandatory, while accepting a failed reset only after a bounded non-loading query proves that systemd has unloaded the unit and renewed ownership, stopped-state and cgroup-drain checks succeed. Unloading already discards start-limit counters. Scope, capabilities, private state, rollback and original receipts remain unchanged.
- Preserve eight fixed restoration substeps in sanitized native failure evidence without exporting child errors, paths or private output. The original bb76 native upgrade failed at restore-runtime; its limited artifact does not prove which substep caused that historical failure. The corrected path still requires an actual old-release-to-new-artifact native pass before rc.3 publication.

## 2026-10-06 — Readable mobile investigation evidence

- Isolate the new investigation paragraphs from an older demo note grid, so mobile warning labels and original timestamps retain normal text flow. Add hosted checks for full paragraph width and non-overlapping label/time text.
- Update the real awaiting-agent browser contract to require the actual unavailable Health response, an unavailable case count and no successful empty-state claim. Keep its unknown-device and unavailable-metric assertions.
- The preceding 3f2 hosted run passed all new alarm, fleet and Investigations interaction cases; screenshot inspection nevertheless found the mobile text collision. The corrected rendering remains subject to the next hosted gate.
- Allow the existing aggregate Go job 60 minutes: its full serial race suite passed after 34m49s in 3f2, but the 40-minute job cap interrupted the following build. Keep all per-package deadlines, tests and assertions unchanged; later runtime steps still require the next complete run.

## 2026-10-06 — Read-only LAN health investigations

- Populate LAN Investigations from the existing durable Health incident history, with separate open, recovered and monitoring-stopped counts, original incident times, separately aged current checks and explicit undetermined cause. Keep acknowledgement distinct from recovery and leave the demo case/AI/note engine unchanged.
- Connect Overview counts and real device Health/history, details and exact-service logs. A logs link only selects the unit; existing capture permission and review remain required. Remove the misleading zero related-demo-case count on the Linux device overview.
- Add a bounded read-only operator API with live paging, strict input/output validation, session and enrolled-device rechecks, original certificate-expiry checks at output, and fail-closed source/storage/time behavior. No collection, case copy, health mutation, new permission, remediation or external request is introduced.
- Source/fixture validation is separate from hosted browser and native-host acceptance. This manager/frontend change does not update installed endpoints or establish a full health assessment or raw-evidence archive.
- Preserve exact browser assertions while centering measured alarm elements before full-visibility checks, addressing the observed subpixel nearest-scroll mismatch. Require a rendered fleet hostname/IP snapshot before testing logout, so the test proves private data was present before it is cleared. Neither correction changes production behavior, deadlines or retries.
- Add a hosted read-only Investigations case using explicitly invented intercepted DTOs, with separate real API/store proof. Archive two inspected, unedited synthetic fleet/log screenshots from their passing a6c8 scenarios, with exact source/run provenance and the overall browser-failure limit. New hosted acceptance remains pending.

## 2026-10-06 — Clear log capture windows and confirmed alarm readback

- Lead log selection with the exact observed service unit and a human-purpose label. Report aliases only when the observation says alias; do not infer a target, rewrite the selected name or broaden a grant. Empty complete captures now explain the exact unit, window and severity checks without confusing them with an empty text search.
- Add an explicit Last 15 min action that validates a fresh status response before changing only the draft window. Keep existing captured service/window, rows, search, paging and original retention distinct; reset safely if immutable query or authority context changes. Fetch logs still requires the existing exact request review and unchecked content acknowledgements. Move manager-reference-only refresh into Advanced.
- Refresh the read-only alarm delivery snapshot after a verified settings change or deliberate test response. Cancel older reads, preserve session and visibility guards, and retain previous counts with unknown status if the new read fails. No optimistic delivery result, automatic test or mutation replay is introduced.
- Correct the hosted fleet test to respect its actual unknown OS observation: Linux filtering must exclude that row, and unknown/all must restore it. Capture the actual mobile hostname/IP rows. Keep existing alarm-browser assertions and deadlines while adding closed stage and finite geometry diagnostics; the historical mobile failure is not claimed fixed. The separate overview response-body abort was not reproduced by the focused application tests, and its production code and browser assertions remain unchanged.
- The composed frontend suite passes 2,304 tests with unchanged deadlines, followed by TypeScript/production build and pure browser-contract checks. Hosted acceptance of the new log controls and alarm/mobile correction remains pending. The previous source checkpoint passed all non-browser CI jobs; its identified browser failures remain recorded.

## 2026-10-06 — Reported fleet identity and explicit alarm setup

- Show reported computer hostnames and interface-scoped IP addresses in the fleet table, with compact multiple-address counts, original freshness, truthful missing/denied/expired states and stable device-ID navigation. A bounded authenticated batch read covers the existing 25-record managed fleet limit without per-device HTTP requests or new collection authority. Encode once and recheck session and observation authority before returning those exact bytes.
- Add administrator alarm configuration for one generic public HTTPS webhook, with a protected write-only destination, explicit payload approval, revision-bound changes, enable/disable controls and a separately confirmed synthetic delivery test. Reuse the guarded outbox, DNS/address checks, bounded transport, uncertainty handling and deduplication. Named users need an explicit manage_alarms capability; command-line configuration keeps precedence. No destination, credential or actual delivery is configured by publishing this source.
- Add hosted fleet desktop/mobile acceptance and rendered alarm-settings acceptance using invented same-origin API responses. The latter proves the UI flow; separate API and fake-transport tests cover the backend. Preserve the device-tab metadata timing contract and the existing read-only alarm-status checks.
- The composed 2,284-test frontend suite, TypeScript/production build, affected backend race tests and 16 pure browser-fixture contracts pass locally. Component broad runs with existing dense-store time limits remain recorded as failed; the exact hosted aggregate and new rendered browser checks are separate pending gates. This checkpoint does not publish a new agent release, prove the coordinated rc.2 upgrade, enable automatic renewal or activate a webhook on a user host.

## 2026-10-06 — Coordinated same-profile read-admin upgrade candidate

- Add an explicit verified-release --action upgrade --upgrade-read-admin path for a completed read-admin v2 installation. It verifies the existing identity and receipts, stages trusted artifacts, holds the installer lock continuously, disables startup/admission and drains the agent plus both helper/socket pairs before replacement. The native installer borrows that exact lock and leaves the agent stopped until same-scope bindings and private-state preservation are verified.
- Preserve original receipts, device identity, consent/epoch and counters/floors. Record immutable update history with an explicit current executable binding; keep supported socket revocation valid afterward. Restore original enablement/activity after validation and disclose the owned systemd failed/start-limit reset. Failure containment attempts every independently proven participant, retains evidence and permits only bounded owned-public-artifact rollback; no private-state repair, reenrollment or new capability is introduced.
- Refuse ordinary installer upgrades of this full profile, which would otherwise invalidate hash-bound helpers. The old rc.2 bootstrap does not contain the new coordinated path; publishing this source is not an installed endpoint update or a new release activation.
- Extend the manually approved disposable native gate with a separate approved_read_admin_upgrade flag. The complete scenario verifies the immutable rc.2 artifact contract, installs it, observes the local upgrade approval, proves different current-source executable bytes and retained authority, then requires all six existing journal/socket/report/restart/revoke checks. Closed phase-only diagnostics preserve a failed upgrade without exporting child values. Actual native upgrade execution and release/public-byte verification remain pending.
- Correct the stale browser expectation that Details paused header polling, retaining the original bounded time windows and all sample-age, snapshot, disclosure and access-loss checks. Record requested certificate renewal/revocation, hostname/IP rows, alarm setup, LAN investigations and log alias/window usability as planned or in source development; these are not activated features in this checkpoint.

## 2026-10-06 — Correct fresh Debian process/update observations and device status refresh

- Treat Linux process comm values as bounded display names. Preserve kernel-thread slashes and literal backslashes through collection, strict wire/store validation and React rendering instead of incorrectly marking valid rows invalid. Numeric PID source selection, control/UTF-8/length limits and unknown/denied outcomes remain unchanged.
- Accept only three exact flat Debian installer/apt-listchanges configuration defaults after bounded grammar checks. Other Dir/RootDir redirects, includes, clear directives, block comments and unsupported forms remain rejected. The fixed cached-only APT commands, disabled writable caches, protected source checks and original metadata age remain unchanged; no APT refresh or package operation is added.
- Keep the device header current every 15 seconds on visible authenticated device tabs, using the existing bounded metadata GET. Shared request admission, original sample age, timeout/backoff, focus/session/device cancellation and selected forms/scroll remain. Paged inventory generations and journal snapshots are not re-fetched or renewed by a header check.
- Baseline regressions reproduce the three reported seams; focused source/wire/store/UI checks and the composed production build pass. The local full enrollmentstore race package exhausted its ten-minute package ceiling and is not a full-pass claim; exact hosted CI remains the broad gate. Installed rc.2 binaries still require a new verified agent release together with compatible manager/UI source. An existing full-update attempt retains its durable six-hour cadence; no ledger reset or host configuration edit is performed.

## 2026-10-06 — Activate verified rc.2 combined Linux read-admin installation

- Select the publicly verified rc.2 bootstrap through immutable publication commit 08c7f0ef3bb8c3f8941a071d885bdf550c7f72c5 and its exact SHA-256. Hosted run 37513100878 passed all 12 asset checks and source/workflow keyless provenance without executing Tracebolt.
- The complete Linux profile now copies one command selecting --read-admin and the validated public agent ingress. Its existing combined root-terminal approval covers the supported inventory, network, journal and socket-owner scopes, followed by hidden invitation entry and dashboard identity approval. Keep the terminal open until completion. Basic/non-complete profiles retain their ordinary mode; complete installations cannot silently fall back to a partial local command.
- Preserve clean-environment, fixed-URL/hash, terminal, fd handoff, cancellation and download guards. Synchronize exact UI, browser and inert shell contracts; no manager/API field can select executable trust or helper authority.
- Shorten the README and align fresh-install guides with the current release, native-source proof and prerequisites. The earlier c1cd TLS native run passed all scenarios, functional checks and cleanup on production-equivalent code. The user's Debian/HTTP installation, release-download runtime and OS reboot remain separate acceptance observations. No host setup or grant occurs when publishing or copying this command.

## 2026-10-06 — Pin rc.2 public release readback before installer activation

- Capture the exact published rc.2 bootstrap and all 12 public asset size/SHA-256 pins for source a6368b0202b1efecdb6214dc34c4302d239854f7. Public downloads match every pin; the bootstrap reconstructs exactly from that source and the published source archive matches all 1,550 Git blobs/executable modes.
- Move the existing read-only hosted verifier to explicit rc.2 context and require keyless provenance, the full manifest, both architectures' four programs and the source archive before a PASS result. No Tracebolt program or installer is executed by readback. Preserve historical rc.1 and pilot.2 bootstrap bytes.
- GitHub reports the prerelease as mutable; fixed source/hash/provenance checks remain mandatory. Strict hosted public readback is still pending, and the dashboard remains on its prior pin until that result is verified. No host configuration or new grant is performed by this preparation.

## 2026-10-06 — Settle initial journal-reader fixture effects before its single click

- Await the immediate mocked authentication/status render effects before opening the service picker in the independent primary-reader stream tests. A controlled delayed passive-effect schedule reproduces the earlier lost click; the same schedule passes after the fixture setup settles.
- Keep the original no-early-fetch, byte-limit, single-reader, disconnect/abort, identity and no-mutation assertions and all deadlines. Add explicit enabled-button and opened-dialog checks; click only once. All 33 independent UI checks pass.
- Production and native-acceptance bytes are unchanged from c1cd23a, whose approved TLS native run 37508637893 passed every scenario, all six functional checks and final cleanup. This test-only checkpoint does not claim another native run, OS reboot validation, or an already activated new release. Its exact hosted CI remains required.

## 2026-10-06 — Correct the final native journal-cleanup command stage

- Use the existing supported fixed-command-failed label when the native cleanup harness stops the owned journal helper and socket. The invented native-owned-helper-stop label was rejected by the production command adapter before execution, causing the final cleanup failure. Production command allowlists, ownership, drain and status checks are unchanged.
- Exercise the entire already-revoked cleanup branch with the real command wrapper and inert host/process adapters. Both journal stop commands must execute; either nonzero command still fails, and policy/tombstone bytes remain unchanged. The original label reproduces fixed-command-stage before executable inspection or process creation.
- The approved native run on 8707963 proved all six functional checks: installed owners, provenance, journal content, restart, revocation and no authority afterward. Its final cleanup still failed, so overall acceptance remains unpassed until the corrected complete scenario and full hosted checks succeed. This checkpoint changes tests only and performs no host action, dispatch or release activation.

## 2026-10-06 — Complete bounded readiness reads and owned helper shutdown

- Put complete Overview, endpoint identity, cached-update metadata and read-only system/socket pages through the same existing 750-ms single-reader gate. Keep active-operation limits, all mutation admission, client retry/deadline budgets and authority checks. Recheck original certificate/source/cursor expiry after waiting, commit and final response encoding; retain original collection/receipt times.
- A complete authenticated handler sequence now covers the native polling order, concurrent startup writes, periodic maintenance, refresh, three socket pages and journal creation/delivery/query. The unchanged baseline reproduces the omitted Overview/endpoint/page admission failures. Distinguish Overview and endpoint identity in fixed diagnostics; the historical 1abc readiness response identifies one of those two GETs, not an exact route.
- Treat only the helper's own coordinated cancellation as clean exit after worker shutdown. Failed helper shutdown is accepted only with full immutable receipt/unit ownership, terminal state, zero MainPID and repeated confirmed cgroup drain. Preserve failure history, disabled policy, floors, pending-state checks and all unrelated-error failures.
- Update the independent restart contract to include the already-approved reset operation, extending its existing intent/apply/completion failure tests. No assertion or timeout is removed.
- The 1abc native run failed during readiness before reaching the restart correction; its cleanup failure was recorded separately. Source reviews and inert end-to-end/race checks support this checkpoint, but full hosted and newly approved native acceptance remain required. No host action, grant, dispatch or release activation occurs on publication.

## 2026-10-06 — Restore the owned service's explicit maintenance restart budget

- A composed fresh read-admin installation starts the agent five times. The e45 native test reached its next explicit restart inside a 92-second execution window, against the unchanged systemd limit of five starts per 300 seconds. This reconstructs a guaranteed start-budget conflict; the failed run did not capture systemd's precise Result.
- Add one journaled Restart-only operation after stopping and validating the owned service: reset only its systemd failed status and start/restart counters, then start it. Installation, upgrade, uninstall, automatic crash recovery, identities and ledgers keep their existing behavior. The automatic five-starts-per-300-seconds limit stays unchanged; cleared systemd bookkeeping cannot be restored by rollback and is disclosed in the plan and native approval.
- Retain bounded existing CLI results and fixed unit status labels for failed restart, revoke and cleanup commands. Export only closed deduplicated diagnostics, never raw output or identities. The private source result remains 4 KiB and private log 1 MiB; the normalized closed diagnostic artifact is capped at 16 KiB.
- The previous approved native run proved installed TCP/UDP owners, v4 provenance and actual journal content; restart and revocation remain unpassed. Inert phase composition and reviewed adapter tests support this correction. Full hosted and newly approved native acceptance remain required; no user-host action, workflow dispatch or release activation occurs on publication.

## 2026-10-06 — Keep package and journal metadata readable through brief maintenance

- Reuse the existing store-global 750-ms single-reader admission gate for package metadata and both journal status reads. Short ordinary writes or maintenance can finish before the read; sustained contention and excess readers still fail busy. Keep the one-operation limit, existing channels, write/page admission and all client retry/deadline budgets unchanged.
- Recheck trusted time and identity after SQL admission and commit, preserve original capture/receipt/retention timestamps, and withhold expired output. Journal expiry crossed at commit is durably latched under the same held permit with at most one additional successful transaction; failed transactions are not retried. Per-read rollback and durable expiry are protected; a global cross-read journal clock floor is not introduced.
- Actual authenticated handler and store regressions prove brief maintenance now yields an unchanged accepted request/receipt, while sustained SQLite contention remains429. Focused race checks cover shared admission, cancellation, authority and expiry crossings. This corrects a demonstrated production discrepancy; the precise historical afec journal response and package lock owner remain unknown.
- Full hosted and approved fresh native acceptance remain required. This source checkpoint performs no user-host setup, new grant, workflow dispatch or release activation.

## 2026-10-06 — Honor native journal read backpressure and retain precise evidence

- Correct the native acceptance client to honor one exact documented GET storage_busy or journal_busy response with Retry-After: 2, within the existing five-second total deadline and 128-KiB response cap. Mutations remain single-shot; all log identity, content, time, restart and revocation assertions stay required.
- Exercise the actual journal handler with synthetic authenticated state: readiness, pending status, exact generation-bound delivery/query, device isolation and a real held SQLite writer. The busy response and unchanged receipt/expiry after release are reproduced; the historical afec native HTTP response is still unknown.
- Export at most eight distinct closed method/resource/status/failure/API-code tuples from bounded private test output, without raw paths, identifiers, bodies or errors. Successful native evidence contains no failure tuples.
- The preceding fresh native run proved installed TCP/UDP owners and v4 provenance; journal content, restart and revocation remain unpassed. Its separate ordinary positive-v3 package-read 429 failure also remains open. This checkpoint changes test code only and performs no user-host or release activation.

## 2026-10-06 — Correct native namespace traversal and retain independent checks

- Open only the fixed proc namespace parent with O_PATH instead of requesting directory listing access. Linux exposes that parent as 0511; keep the existing procfs/directory checks, fixed child opens, ptrace/nsfs/PIDFD verification, identity binding and unchanged helper capabilities. Generic process-directory enumeration is unchanged.
- Preserve a missing-owner failure while independently checking already-authorized journal content and an ownership-preflighted main-service restart. Keep every success requirement, skip grant-dependent revocation without owner proof, and preserve the primary failure through cleanup.
- Move the unchanged real transport/expiry smoke into its own ordinary CI job with the same pinned setup and verified dependencies. The backend retains its 40-minute ceiling; no test assertion or runtime deadline is raised. Hosted completion of both jobs remains required.
- Source review and bounded fixture checks support this correction; the next approved fresh native run must still prove actual owner capture, log content, restart and revocation. No user host or release activation is changed by publication.

## 2026-10-06 — Correct socket setup's offline validation arguments

- Remove the foreground-only --service-identity argument from socket setup's --validate-guided invocation. The actual subprocess still drops to the verified service UID/GID with no supplementary groups. Preserve the agent's argument guard, protected state checks, binary ownership, deadlines and failure containment. An actual CLI regression proves the old combination is rejected and the corrected combination reaches the local validator.
- Keep fixed per-mode socket setup failure labels for any remaining rejection, without exporting private CLI output. Preselect the supported fresh V2 profile in the manual test form; both specific approval checkboxes remain false and exact source binding stays mandatory.
- Cancellation and retained-journal native scenarios passed on the preceding source. This corrects a guaranteed blocker in the complete path; the next approved native run must establish full onboarding, owner/log evidence and restart acceptance.

## 2026-10-06 — Make the disposable TLS fixture verifiable across clients

- Give the test root and leaf certificates distinct fixed subjects. The previous empty names were accepted by Go but rejected as self-signed by Python/OpenSSL, blocking the real socket-manager capability check. Share the exact fixture generator with an offline TLS 1.3 handshake regression; wrong CA and hostname remain rejected. Production TLS, certificate verification and capability routes are unchanged.
- Refine only fixed browser diagnostic marks around the existing service-action refresh/preview checks. Every assertion, operation and deadline remains unchanged.
- The cancellation native scenario passed on the preceding source. Complete onboarding and helper/log/restart acceptance still require the corrected native run; no user host or release pin changes are included.

## 2026-10-06 — Preserve native setup and assertion failure categories

- Keep the coordinator's existing fixed failure reason in the sanitized native result across setup, interrupted enrollment, replay and helper maintenance. Retain the primary failure when cleanup also runs.
- For a failed native test, project only exact preselected static assertion labels from at most 1 MiB of private output. Export no raw logs, observed host values, secrets, paths or arbitrary error strings. Production source, native success requirements and approvals are unchanged.
- The approved disposable-parent preparation now permits the full cancellation scenario to pass. Complete and retained-journal scenarios still fail later; this diagnostic checkpoint does not claim their cause or successful fresh installation.

## 2026-10-06 — Prepare the approved disposable runner's installation parent

- Correct the fresh native test fixture for GitHub's intentionally world-writable /opt. After explicit source-bound approval, accept only a real root:root top-level directory in mode 0777 or 0755, tighten the same open inode to 0755 when needed, and verify its owner, mode and path identity. No recursive changes or ownership changes.
- Keep production installer checks unchanged. All three prior native scenarios identified the /opt preflight rejection; the updated manual workflow now discloses this extra disposable-VM preparation before approval. Complete fresh installation and later native checks remain pending.

## 2026-10-06 — Identify the failing installer preflight checkpoint

- Carry fixed, closed preflight categories through the existing installer failureStage and sanitized native acceptance result. Distinguish tool, directory, unit-parser, bootstrap, artifact, plan and transaction-begin checks without exporting host values or raw errors.
- Preserve all installer checks, commands, approval gates, cleanup and rollback behavior. The preceding absent-unit fix now passes the initial cancellation probe in all three hosted scenarios; the later installer blocker still needs the next native result.

## 2026-10-06 — Accept systemd's empty-array output for fresh helper units

- Correct fresh socket-helper preflight for systemd's omission of empty ExecStart and Listen arrays, even with --all. Permit only the corresponding omitted array for the fixed not-found, inactive helper unit; do not invent property values.
- Keep loaded-unit proof, required state/ownership fields, unknown/duplicate rejection, command bounds, approvals and installation behavior unchanged. Source-derived parser/preflight fixtures pass; the next approved native run must establish progress beyond the previously demonstrated pre-prompt rejection.

## 2026-10-06 — Explain native preflight rejection and observe primary browser reads

- Retain the failed fresh-V2 run as unpassed and add only closed initial-probe diagnostics: fixed rejection codes, an exit bucket and a scope-prompt boolean. Preserve native execution, approval guards and cancellation assertions; the underlying early failure is not yet established.
- Validate manual workflow inputs in an ordinary permission-free job and report fixed missing-approval/profile/source reasons. Keep exact source spelling and every privileged guard; never echo submitted input or private runtime logs.
- Observe the journal service-picker response through the application's existing bounded primary reader. Preserve the original HTTP/body/identity/consent checks and separate service/journal byte caps; the previous secondary browser-body read failed after HTTP200, with the exact cancellation cause still unproven.

## 2026-10-06 — Prepare one-command fresh read-admin V2 installation

- Compose the optional socket-owner helper and real sender/manager/UI provenance path with fresh read-admin V2 provisioning. Keep the main agent unprivileged; bind exact artifacts, activated identity, local approval and original source age. The combined approval explicitly includes the helper's broad CAP_SYS_PTRACE authority, which is not intrinsically limited to metadata by the OS.
- Build and verify four native release roles, require receiver-v4 support before grants, install create-only helper declarations, and retain exact state/sequence evidence through explicit revocation and drain. Align agent artifact checks with the installer's exact 0555 mode; the separate helper remains 0755.
- Replace the manual acceptance gate with explicit fresh-V2, CAP-risk and exact-source approval. The complete disposable scenario requires a real journal marker, controlled TCP/UDP owners, agent service restart and later ordinary reporting after revocation. Source/fixture checks are not native acceptance; no workflow dispatch, host grant, published installer activation or OS reboot is performed by this checkpoint.

## 2026-10-06 — Keep CVE paging controls readable on desktop

- Correct the CVE paging selector so later shared small-button styles cannot reduce its desktop height from 36px to 30px. Built-style checks reproduce the defect and verify 36px desktop controls, unchanged 42px mobile controls and unchanged unrelated small buttons.
- Add only fixed failure-stage labels to the new synthetic paging browser case. Preserve every existing assertion, request, guard and deadline; the original hosted assertion was sanitized, so full browser and screenshot acceptance remain required.

## 2026-10-06 — Prepare manual fresh read-admin systemd acceptance

- Add a manual, explicitly approved disposable-VM workflow for TLS by default or separately selected HTTP, covering fresh completion, enrollment cancellation and retained journal-phase refusal. Preserve selected-source checks, one local combined approval, nonroot sender identity and bounded sanitized evidence.
- Add inert selection, embedded-script and workflow-wrapper fixtures to ordinary validation. Default runs skip all privileged systemd gates; no native scenario, journal-content read, reboot, release provenance or published command activation is established by these source checks.

## 2026-10-06 — Browse every current CVE warning and mapped binary

- Add exact read-only, assessment-bound warning and binary detail pages with existing named-reader, Origin, CSRF and current-evidence checks. Keep completed totals, checkpoint bytes, revision and original assessment age unchanged.
- Reach omitted middle findings from check zero and page every eligible mapped binary without an unbounded response or retained result list. Preserve source/version mapping, deterministic comparison gaps and whole-check boundaries under existing time/comparison budgets.
- Add compact First/Previous/Next controls with bounded history, separate page counts, preserved evidence-age/session guards and no feed-write permission dependency. Strengthen page/global count validation against inconsistent responses.
- Cover full-set equality, more than 30 pages, over 128 binaries, byte limits, unknown comparisons, named-read access, long browsing, expiry and late responses with synthetic package/API/UI fixtures. Hosted browser and native deployed acceptance remain separate gates.
- Add a separate bounded hosted paging case while retaining all existing continuation and wider browser checks, including omitted-middle records, exact binary-version membership, source/session isolation and English desktop/German mobile capture requirements.
- Preserve the original [synthetic continuation previews from 81aae45](docs/ui-previews/81aae45/README.md), with immutable source/run/image provenance; these images predate full-detail paging and are not customer inventory.

## 2026-10-06 — Resume bounded CVE assessment after durable checkpoints

- Traverse source, advisory and installed version deterministically across bounded steps, retaining exact deduplicated progress/warning/vendor-gap totals without a growing seen-record map. Keep the three-second and 2,000-comparator limits, add a 4,000-visited-check limit, and preserve capped findings and binary details.
- Bind private four-slot restart-safe checkpoints to device, inventory sequence/full manifest/release, original feed identity/provenance and evaluator version. Persist before acknowledging advancement, recheck authority/current evidence around save, and fail closed on corrupt, unsafe or uncertain state. Public feed caches and endpoint consent/authority ledgers remain separate.
- Add v3 result continuation and view-v2 unavailable envelopes, bounded visible-view continuation with lifecycle cancellation, and handwritten restart/mid-record/>2,000-check, cache-failure, changed-binding and 1,396-row/six-warning/627-gap regressions. No new endpoint collection, inventory transmission, feed download, host operation or native deployment claim follows.
- Add one bounded synthetic hosted browser case for advancing, completed, blocked, changed and stale assessment state, with late-response isolation and desktop/mobile captures. Preserve every existing case and deadline; this adds no live inventory or vendor access.

## 2026-10-06 — Prepare one-confirmation fresh read-admin onboarding

- Add an explicit source-only fresh-install profile that combines the supported read scopes and bounded journal helper under one local content/HTTP disclosure and confirmation. Bind the exact bootstrap, manager ingress, installed identity and native complete-profile guard before progressing through existing consent adapters.
- Preserve started/completed phase evidence, reject existing or pending journal state, initialize fresh private replay floors as the ordinary agent and keep the main agent nonroot. Completion means local configuration only, not received reports, full socket-owner visibility, service actions or native reboot acceptance.
- Keep the published release and dashboard command pins unchanged. This candidate requires a new compatible release, verified public readback, deliberate command activation and separate native acceptance before it becomes a supported installation command.

## 2026-10-06 — Separate CVE processing progress from evidence gaps

- Keep the existing 2,000-comparison, three-second and response-size budgets while continuing assessment beyond display-only finding limits. Report all matched warning/version totals separately from the bounded visible details.
- Introduce v2 coverage counters for planned and completed source-version/advisory checks, genuine pending work, package eligibility gaps and deduplicated vendor-data reasons. Binary-detail truncation no longer labels completed assessments or unassessed-record totals as lower bounds.
- Preserve exact-release source mapping and Debian version comparison, shared-administrator feed writes and read-only assessment access. Add synthetic 1,396-package/six-warning/627-gap, real budget-cutoff and multi-page API regressions. Actual resumable processing remains a separate follow-on; no endpoint inventory is collected or sent to a vendor.

## 2026-10-06 — Read-only alarm delivery status in Settings

- Show existing retained provider-accepted, pending, failed, uncertain and dropped counts for authenticated LAN readers, with explicit provider-acceptance versus human-receipt limits. Settings performs only the existing status GET on entry or deliberate refresh; it cannot configure or send alarms.
- Label loading time as browser time because the API has no event/server timestamps. Failed refreshes preserve the original previous snapshot with unknown current status; access loss and suspension clear it and cancel late reads.
- Add hosted synthetic status/lifecycle and desktop/mobile capture coverage without configuring a destination, replaying events or performing a live delivery.

## 2026-10-06 — Align CVE controls with current session authority

- Show CVE feed sync/import controls only for an explicitly confirmed current shared-administrator session, matching the existing server capability. Named accounts retain read access; unknown authority fails closed. Recheck each write and discard stale selected-file state when the session changes, without expanding server permissions.
- Clarify the Journal picker action as "Refresh service list" / "Dienstliste aktualisieren" and correct current feature documentation while keeping source integration, opt-in configuration and native acceptance distinct.

## 2026-10-06 — Expose APT evidence identity and narrow picker diagnostics

- Show complete and transfer generation IDs/sequences, the transfer's original capture time and failed-attempt identity inside existing full-APT details. Preserve retained rows, source timestamps, request behavior and visible failure outcomes.
- Add fixed Journal picker test stages and bounded inventory HTTP status categories while preserving every existing body, consent, row and request-count assertion. The earlier intermittent browser failure remains unexplained; this adds diagnostic evidence rather than claiming a product correction.

## 2026-10-06 — Preserve Health drafts and show complete mobile check results

- Keep explicit service deselection and edits made during a pending Health save; ignore obsolete scope/revision completions instead of replacing the newer draft with saved values.
- Stack application results, certificate details and original observation age on narrow screens while retaining the desktop table and accessible header associations.
- Extend the existing hosted browser case with synthetic v1/v2 status and mobile/desktop checks; no real application target is configured or probed by those fixtures.

## 2026-10-06 — Bounded DNS and TCP observation source candidate

- Add strict opt-in v2 DNS-resolution and single-port TCP connection targets while preserving v1 HTTP/HTTPS configuration and status. Reuse exact-address policy, deadlines and manager-side freshness; TCP exchanges no application data.
- Extend the compact Overview panel with typed results and neutral certificate cells. Injected fixtures cover late completion, cancellation, connection cleanup and per-kind schemas; no real target, resolver/host configuration, network scan or deployment is performed.

## 2026-10-06 — Require service-identity setup evidence and application UI checks

- Keep production identity guards unchanged while testing fixture state independently of ambient runner groups; require a separate same-user, privilege-reduced CI read with all nine cases and seven actual public-reader evidence markers. Missing activation and ledgers must reach their state rejection, with no writes or manager requests.
- Add a hosted application-status UI case using explicit synthetic responses for retained HTTP/TLS expiry, original-age staleness, read errors and access loss. Preserve the existing browser cases, session defaults and launch settings; no real target is probed by this case.
- Preserve original desktop/mobile Logs captures from fully tested source71dc92c, with synthetic-data labels and exact artifact/image provenance.

## 2026-10-06 — Opt-in manager-side application observations

- Add a protected, default-off HTTP/HTTPS target list with explicit address binding, private-LAN/plaintext acknowledgement, bounded checks and verified leaf TLS expiry. Report only latest manager-side observations behind the read-only operator boundary and in a compact LAN Overview panel.
- Keep unknown/stale results honest and leave device health, alerts and existing device pages unchanged. Injected/local TLS fixtures do not establish real target reachability or native deployment; no target, host trust or network configuration is provisioned.

## 2026-10-05 — Inert selected-package plan and hook observation core

- Added a bounded canonical selected-upgrade description, original-age checks, exact binary/source/archive/index bindings and a pure APT v3 observation matcher. Strict fixtures cover malformed protocols, multiarch, repeated operations, stale or unknown evidence and archive mismatches.
- No package installer, native evidence collector, package-action permission, runtime integration or host change is enabled. Durable runner, authenticated native evidence, mandatory hook behavior and Debian/Ubuntu acceptance remain separate gates.

## Guided service-action setup source candidate

- Add explicit read-only manager/endpoint plans and one local digest-bound approval.
- Provision only a fresh fenced action domain for one activated endpoint and one reviewed service.
- Add source-only Docker/systemd adapters, locally custodied command keys, nonroot readiness and fault fixtures.
- Preserve legacy runtime bytes and refuse repair/reset of missing used action state.
- Native privileged acceptance and compatible release deployment remain separate gates.

## 2026-10-05 — Verify socket source disclosures

- Open the existing source-details disclosure in the browser check and verify its visible external-reachability limitation alongside the owner-attribution warning. Preserve all socket paging, field and expiry assertions; production copy and behavior are unchanged.

## Guided local inventory consent (source candidate)

- One local confirmation groups existing full process/mount and complete cached APT scopes, with separately selected optional hostname/interfaces. Installed capability checks, honest partial results and safe service-activity restoration preserve the existing consent authority. No host acceptance is claimed.

## 2026-10-05 — Align browser contracts with the reviewed device workspace

- Navigate complete and legacy inventory sources explicitly, preserving lazy-read, consent, cancellation, source-binding, count and expiry assertions after the Packages default and separated legacy views.
- Compare actual sample metrics using the displayed German fractional-number contract. Keep all browser case identities, evidence gates and deadlines unchanged; no production or fixture behavior changes.

## 2026-10-05 — Simplify Logs and align current device data

- Separate journal source selection, query controls, explicit capture review and results into a clearer workspace. Preserve original request/snapshot scope and timestamps, consent, bounded paging and no automatic capture; add desktop/mobile browser captures.
- Refresh visible focused Overview metadata every fifteen seconds, yielding to active API requests and preserving drafts, navigation, original sample age and honest stale states. Show supplied fractional CPU/RAM values without changing collection cadence or permissions.
- Default Inventory to complete Packages where supported and distinguish observed service enablement, socket-owner limitations and legacy previews. Align Security with current inventory/coverage instead of presenting unrelated legacy values as current findings.
- Add fixed approval-substage labels for the unresolved intermittent service-action browser failure; keep assertions, deadlines and privacy bounds unchanged.
- Preserve source/permission boundaries and add focused integration regressions. Local timing-limited component runs and unavailable local Chromium are recorded separately from exact hosted acceptance.

## 2026-10-05 — Fix journal rename verification and preserve early-abort evidence

- Accept the legitimate ctime change caused by atomic rename while retaining all other metadata, inode, content and stable-read checks.
- Add a read-only verifier for the exact original188 first-migration failure before policy writes. A separate digest-bound abort archives the verified pending gate and transaction, preserves the original grants and private state, and restores prior owned activity only after rechecks.
- Recognize only fully validated completed-abort archives for a later separately approved corrected grant. Add actual-filesystem and interruption/integration regressions; never reset or delete recovery evidence automatically.

## 2026-10-05 — Fix journal guide use of a real controlling terminal

- Open the controlling terminal without a seek requirement in the download bootstrap, guide check and explicit confirmation path, so genuine Linux root terminals are accepted.
- Keep root, TTY, immutable source, size/hash and exact confirmation guards; add controlling-PTY regressions. No grant or service action follows from downloading the corrected source.

## 2026-10-05 — Require explicit native IPC and service-action browser evidence

- Add a required Linux gate for thirteen exact Unix peer, response-writer and inherited-listener test events; skipped, failed or missing evidence cannot pass.
- Add four distinct real-browser service-action cases through named approval, actual API and transport handlers, a framed synthetic helper and fake executor. Keep fixture scope and unconfirmed delivery visible; preserve existing browser gates.
- Add adversarial evidence-checker tests and exact-source checks. This verification change does not provision runtime keys, grants, helper services or sockets and does not execute a real service action.

## 2026-10-05 — Connect the default-off controlled service action workflow

- Add named-operator preview and explicit approval for one locally allowlisted service try-restart, bound to durable manager jobs, signed permits, one-time agent delivery and independent root-helper admission.
- Keep ambiguous delivery and execution outcomes visible, preserve original expiry and replay floors, and expose bounded status without permits or credentials. UI availability remains an agent-reported hint; a completed systemctl operation does not prove a restart or service health.
- Add synthetic TLS/HTTP workflow and failure-path tests. Production provisioning, command keys, local grants, helper service/socket installation and native service acceptance remain separate unfinished gates; this source checkpoint performs none of them.

## 2026-10-05 — Add an explicit broad journal profile and guided migration

- Add a separately confirmed local profile for supported current and future system services, while each central Logs request still selects one exact service and retains its original scope, budget and replay guards.
- Report fresh permission-scope metadata and add a guided migration with installed-component compatibility checks and one digest-bound terminal confirmation. Older releases stop for an upgrade; no host upgrade, grant or log read is performed by publication.
- Prepare a command only after verifying all seven public source files against the exact immutable commit. Focused source/fixture checks do not establish installed-service or live-grant acceptance.

## 2026-10-05 — Add default-off external alarm delivery foundation

- Atomically capture exact new health transitions and bounded delivery intent, including transitions pruned from UI history. Preserve existing health behavior and authentication; add a read-only status endpoint.
- Add a single bounded injected worker and explicit protected public-HTTPS webhook opt-in, destination binding, no redirects/proxies, cooldown/backoff and honest accepted/failed/uncertain states. Never replay uncertain sends or broadcast old history.
- Cover failure, restart, capacity, recovery/maintenance, privacy and SSRF with deterministic fixtures. No recipient, credentials, live send, browser sender controls, SMTP, host change or installed-service acceptance is included.

## 2026-10-05 — Shorten primary device copy without hiding important state

- Use concise primary labels and remove repeated page subtitles. Keep interpretation notes in accessible disclosures while retaining original observation time, unknown/partial states and source facts in Details.
- Preserve established tab order, keyboard navigation, HTTP warnings, consent labels and the verified rc.1 download pin. Extend focused disclosure tests and the actual browser checks; exact composed hosted acceptance remains required.

## 2026-10-05 — Add optional named operator authority

- Preserve legacy shared login and existing administration. Add a strict protected, profile-bound v2 named-only configuration with stable actor IDs, explicit read/planning/execution/restart grants, no fallback and no credential provisioning. Configuration changes require manager restart and invalidate all sessions.
- Derive actor and capabilities exclusively on the server, retain login/hash/session/CSRF/logout boundaries, and add current-session capability admission for future typed action integration. Named accounts can read existing views and exact bounded query routes; existing administrative writes are not implicitly granted.
- Add a conditional username field, defensive session metadata validation and focused auth/config/API/UI regressions. No action endpoint, privileged helper, permit signer, service restart, package execution, host opt-in or installed-machine acceptance is provided.


Meaningful development checkpoints are recorded here. These are prototype milestones, not production releases.

## 2026-10-05 — Prepare bounded journal allowlist amendment and document the pilot plan

- Add a separately administered, add-only journal helper allowlist amendment with versioned local activation and durable generation reporting. Bind requests and results to the acknowledged generation, reject stale or mismatched work, and preserve endpoint identity, consume-once floors and original content expiry. No manager update or UI click grants local log access.
- Document the single-internal-customer delivery order: finish UI/logs, then external alarms, real approved service/APT actions, application checks and bounded diagnostic history. The controlled-action core remains inert and unintegrated; no service restart or package execution is exposed.
- Retain unmodified synthetic desktop/mobile browser previews from exact `ab5de596e79e92ad89376364953cd4cf9e78a016`, with viewport, source, workflow and image-hash evidence. Regenerate the exact-source Go vocabulary. Current rc.1 release/bootstrap pins stay fixed; source checks and screenshots do not establish host-helper amendment, installation or reboot acceptance.

## 2026-10-05 — Align browser evidence and improve Contact readability

- Keep provenance assertions intact after explicitly opening the new Details view. Require the exact seventh source-guidance journal case in the closed browser gate; the previous six cases, identity/privacy checks and deadlines remain mandatory.
- Stop the Contact summary value inheriting compact header-time styling. Keep card values at 22 px desktop / 18 px mobile, raise mobile supporting copy to 11 px, and add real-browser typography checks. Preserve the three-card layout; exact-source screenshot review remains required.

## 2026-10-05 — Focus device summaries and clarify Linux log sources

- Lead the device overview with compact Contact, Warnings and Updates cards plus resource observations. Keep unknown, stale, partial and original-age states explicit; move full source and identity facts into Details. Serialize cancellation-aware metadata summaries after identity readiness, without new polling or collection.
- Add a Linux log-source chooser that distinguishes existing service journal capture from unsupported broader sources. Supported service shortcuts only prepare a validated unit draft; content/HTTP acknowledgement and local helper grants still apply. Broader host, kernel, application-file and container-content sources remain design work.
- Add an inert controlled-action contract and durable consumption foundation with focused signature, policy, deadline, replay and storage regressions. No manager, agent, API, UI, helper or installer invokes it; it cannot start an action, restart a service or install an update. Production authority and execution remain separate work.
- Extend focused and browser regression coverage and regenerate the exact-source Go diagnostic vocabulary. Preserve the verified rc.1 release and bootstrap pins; exact combined hosted acceptance remains required.

## 2026-10-05 — Activate verified rc.1 downloads and simplify device diagnosis

- Select the verified `v0.1.0-rc.1` installer through its separate immutable bootstrap publication commit `458fc072a73946032446c0d9e63220ea29cca355`. The existing strict hosted check downloaded all ten assets, verified keyless source/workflow provenance and reproduced the exact bootstrap. Preserve the old release; installed-service, upgrade and OS reboot acceptance remain separate.
- Put current measurements before detailed identity and generation information, with expandable technical details. Add a service-table shortcut that opens Logs with that service selected while preserving separate content/HTTP confirmations and local permission requirements.
- Keep repeated tab selection and same-device metadata refresh from resetting the active draft. Add unit and hosted-browser checks for service handoff, interrupted navigation, inert unsupported service names and preserved capture boundaries; final combined hosted acceptance remains required.

## 2026-10-05 — Prepare independent verification of the published rc.1 release

- Capture the exact public `v0.1.0-rc.1` bootstrap built from `ccac65e7a61f0b5f0e325c3616a93273ab1e8eb1`. Its bytes match the reviewed source template and official release digests; preserve the previous pilot.2 bootstrap and dashboard selection.
- Point the existing read-only hosted verifier at all ten rc.1 assets and exact provenance pins. Retain its download, context, integrity and no-installer-execution guards; add release-selection and prior-bootstrap regressions. Independent public-byte verification must pass before dashboard activation. No installed-service or reboot acceptance is implied.

## 2026-10-05 — Observe journal acceptance through the primary response reader

- Replace the browser fixture’s secondary CDP body retrieval with an exact-route, 65,536-byte bounded observation of bytes consumed by the application’s original reader. Preserve response values, errors, cancellation and all HTTP, snapshot, paging, search, time and accepted-UI assertions.
- Add streamed, malformed, oversized, interrupted and duplicate-response regressions to the independent UI gate. Production code and acceptance deadlines remain unchanged; exact hosted Chromium acceptance is still required.

## 2026-10-05 — Bound system metadata waits and trace journal paging failures

- Give system metadata reads one store-global permit and a bounded 750 ms queued wait for the existing inventory admission slot. Preserve the active-operation ceiling, caller cancellation, explicit busy outcomes under sustained contention, and paging/write/maintenance limits. Deterministic contention fixtures cover the previously nonblocking read failure.
- Recheck trusted time after authority loading, commit and immediately before API output. Certificate expiry and original retention still clear observations, and clock rollback cannot revive them. Original capture/receipt times and sequence remain unchanged.
- Add fixed, bounded journal query lifecycle/substep diagnostics and stronger pagination/search fixtures without changing response-body, identity/digest/expiry assertions, retries or deadlines. Regenerate the exact-source Go vocabulary; composed hosted acceptance remains pending.

## 2026-10-05 — Preserve unassessed advisory records and narrow overview diagnostics

- Retain bounded tracker-style fixed-version tokens outside the strict comparison grammar as explicitly unassessed records. Never normalize or compare them or turn them into a warning/fixed conclusion; malformed types, control text, punctuation and oversized fields still reject the snapshot. Show a deduplicated unassessed-record count and coverage gaps even when no warning matches exist.
- Add privacy-bounded overview query phases, status/lifecycle events and DOM counts to locate the intermittent literal-search failure. Keep production behavior, response-body checks, paging/search/binding/age assertions, case identities and deadlines unchanged; strengthen the real-handler and hook search regressions.
- Regenerate the source-bound Go diagnostic vocabulary. Official-feed acceptance and exact composed hosted validation remain separate pending gates.

## 2026-10-05 — Locate official-feed parser rejections

- Add closed parser-stage codes and bounded counters to the opt-in official-feed smoke failure. Preserve every rejection condition, limit, ordinary error string and wrapped error classification. No source/package/CVE name, response value or decoder text is retained or exported.
- Add input-disclosure and rejection-contract regressions and regenerate the exact-source Go diagnostic vocabulary. This narrows the real-feed incompatibility; it does not claim a compatible feed or change acceptance.

## 2026-10-05 — Handle bounded larger official Debian feeds

- Respond to the measured 81,530,876-byte official feed with validated gzip transport/cache support and a separate 96 MiB decoded-JSON ceiling for the fixed official source. Compressed bytes and cached payloads retain their existing 32 MiB bound; manual imports retain their 32 MiB limit.
- Preserve fixed-origin HTTPS, finite deadlines, structural/record limits, gzip integrity and single-member checks, legacy cache compatibility, original age/provenance and atomic last-good retention. Add boundary, corruption and protected-cache restart regressions.
- Synthetic large-feed and focused race checks passed in the reviewed source; actual official response/schema compatibility still requires its exact hosted gate. Regenerate the source-bound Go diagnostic vocabulary.

## 2026-10-05 — Diagnose feed limits and align acceptance reads

- Add bounded numeric and fixed-enum feed-size diagnostics without raising limits, changing fetch behavior or exporting raw response content. Official-feed compatibility still requires the hosted check.
- Align the native acceptance client with the exact single-retry storage-busy GET contract, retaining its original five-second deadline and strict malformed-response rejection. Add fixed diagnostic categories; the historical generic operator-read failure does not establish its HTTP status.
- Check the journal reference accepted by the rendered UI after a successful protected read rather than re-reading its consumed body through browser instrumentation. Add streamed-body regressions for partial, malformed, invalid and interrupted responses. Production journal behavior, browser assertions and timeout budgets remain; regenerate the exact-source Go diagnostic vocabulary.

## 2026-10-05 — Add distribution CVE warnings and simplify admin diagnostics

- Add an explicit fixed-origin Debian security-data sync with a protected persistent last-good cache and local source-package/version assessment over complete DPKG inventory. Show published-fix CVE matches, advisory links, feed age and coverage gaps without uploading inventory. Ubuntu OSV bundle import remains a limited fallback; full official Ubuntu archive sync is not implemented.
- Keep health, update and certificate summaries visible while moving technical scope and provenance into accessible disclosures. Preserve critical stale, unknown, partial and revoked warnings and explicit operator actions.
- Fix package-panel admission contention by mounting only the selected package/update reader. Add a real React-to-Go regression for nonempty, zero and awaiting inventory plus mutually exclusive update sources. Preserve all browser assertions and timeout budgets.
- Add an independently reported hosted check of the fixed public Debian feed, with no endpoint data or raw-feed artifact. Native deployment and exact composed hosted acceptance remain separate gates; regenerate the source-bound Go failure vocabulary.

## 2026-10-05 — Narrow retained-package browser failure diagnostics

- Split device-navigation and package-source phases and attach the existing bounded failure observer to the retained-package scenario. Keep all original assertions, routes, timeouts and case identities. This improves diagnosis of the hosted failure; it does not establish its cause or change product behavior.

## 2026-10-05 — Add complete cached APT candidate generations

- Add a separate default-off full-row acknowledgement and independent cached-update replay/spool domain. Preserve the bounded preview grant, old dpkg wire/disk bytes and existing activation. Reuse the same durable transfer engine with fixed typed codecs rather than adding another state machine.
- Capture all known newer candidates before preview trimming, transfer immutable bounded chunks, and atomically promote only a fully validated generation. Unknown comparisons, holds, unsupported/missing sources and original cache age remain explicit; this performs no APT refresh, download, installation, CVE assessment or remote command.
- Add optional normalized manager storage, shared quota accounting, bounded cleanup, exact retry/restart/expiry recovery and authenticated generation-pinned paging/search. The Updates tab can traverse the entire known-candidate generation without an overall preview limit; each displayed page stays bounded to 100 rows.
- Add source, separate-consent, compatibility, transport, atomic-storage, cursor/retention, API/Go-DTO and bilingual UI fixtures. Real sender/ingress/store fixtures recover a lost acknowledgment across sender and manager restarts and page all 1,100 rows over TLS and signed HTTP; additional ingress fixtures exercise 1,201 rows, while UI fixtures traverse 1,213 rows and search beyond row 2,048. These are synthetic source checks, not populated native Debian/Ubuntu, installed-service or reboot acceptance. Exact-source hosted acceptance remains separate.

## 2026-10-05 — Add Linux health incidents and cached update visibility

- Add manager-side contact, root-filesystem and explicitly selected service checks from existing authenticated observations, with duration thresholds, recovery, acknowledgement, bounded maintenance and durable incident history. Unknown and stale data remain explicit; this does not add resource charts, notifications or repair actions.
- Add a default-off, explicitly consented Debian/Ubuntu cached-APT extension with authenticated transfer and an operator Packages panel. It performs no repository refresh or installation. Full-query totals accompany a bounded candidate preview; omitted rows are explicitly partial and complete candidate paging remains future work. Cache timestamps do not prove repository freshness or CVE coverage.
- Add focused collector, consent, transport, storage, API and UI regressions and deployment documentation. Regenerate the exact-source Go failure vocabulary. Combined-source and hosted acceptance are verified separately from isolated feature tests; native host activation remains a manual acceptance step.

## 2026-10-05 — Align the independent copied-command contract

- Update the independently held exact shell-text contract for the reviewed grouped prerequisite messages. Keep byte-for-byte comparison, all trust checks, and negative tampering cases. HTTP/TLS contract tests and shell syntax checks pass without executing installer commands.

## 2026-10-05 — Explain Linux installer prerequisites and outcomes

- Group missing initial command tools and show one manually reviewed prerequisite-package command. Keep the copied installer on one physical line, with the same immutable source/checksum pin, terminal handoff and no automatic package installation or privilege elevation.
- Extend the reusable bootstrap's early checks for native system tools, Python version, CA loading, foreground terminal and executable temporary staging. Add four progress phases and native installer guidance that distinguishes committed service startup, pending dashboard approval, first reporting and unresolved recovery without resetting retained identity.
- Add inert prerequisite/command checks and outcome regressions; regenerate the finite Go failure vocabulary from these exact sources without changing reporter policy. Scoped Python, frontend, Go and race checks pass. Hosted exact-source acceptance and manual VM/reboot observations remain separate. The published pilot.2 bootstrap, binaries and active release pin are unchanged; reusable-bootstrap/native improvements require a new independently verified immutable release before the dashboard distributes them.

## 2026-10-05 — Require initial package rows and localize browser failures

- Exact `e596b427` passed the two newly extended browser cases for coverage-busy recovery and device metadata refresh preserving Logs. Separate existing journal reference-refresh and v3 second-page checks failed; their broad stages did not establish a production cause. The other recorded cases passed, and the endpoint browser step did not run after the v3 failure.
- Require the first complete package page to contain exactly 100 rows and its expected first record before the independent baseline read and next-page click. Split both failing scenarios into precise phases while preserving every prior assertion, case identity and original timeout. This strengthens readiness but is not proof of the historical failure's cause.
- On failure only, record capped fixed route/method/phase/status categories and DOM booleans/counts, with a one-second renderer-inspection limit. Exclude raw URLs, identifiers, bodies, form values, exception text and credentials. Ten inert checks and source review validate this projection; application, fixtures, workflow gates and immutable pilot.2 assets remain unchanged. Exact-source hosted confirmation remains required.

## 2026-10-05 — Recover coverage reads and refresh device metadata in place

- Exact `5197056` completed all 13 CI jobs, including the full Go/race and positive native gates, with 110 required browser checks passing and three retained enrollment skips. Preserve that tested source as the preceding accepted checkpoint; this new UI follow-up requires its own full hosted run.
- Recover one qualified coverage `storage_busy` GET response inside the original controller, epoch, total deadline and freshness anchor. Clear obsolete counts while recovering, cancel late work on protected-scope changes, and keep catalog operations and mutations outside automatic replay.
- Add an explicit bounded device metadata refresh that preserves the selected same-device tab and existing Logs/inventory form instances. Authority, session and device failures clear stale state; ordinary failures stay visibly labeled without changing the original check time. No periodic polling or new collection grant is introduced.
- Extend two existing synthetic browser cases to verify actual coverage-busy recovery and metadata refresh while retaining Logs state. Preserve all 110 required case identities, three enrollment skips, five review lifecycle cycles, report schemas and artifact limits. Regenerate the finite Go diagnostic digest for the changed invented-data fixture only; backend runtime, workflow permissions and immutable pilot.2 assets/pin remain unchanged. Source and local checks do not establish a host upgrade or a newer binary release.

## 2026-10-04 — Reuse validated overview frames and copy one physical installer-command line

- Exact `f9aed37` completed 12 CI jobs and all 110 required browser checks; the Go aggregate identified `TestOverviewSharedBurstBudgetAndFairness` as its only failing root. An untouched local reproduction reached the unchanged 20-second burst deadline after 32 process operations. Profiling found redundant decoding and validation of already-validated chunk JSON; the hosted report itself did not expose the failed assertion.
- Retain private Work descriptors over immutable, fully validated pack bytes. Stage and reopen still validate untrusted frames and complete generations, and state/disk/lock verification, durable ordering, receipt/body binding and detached public Body copies remain. Reuse avoids repeated identical-row decoding during NextWork and acknowledgement without changing sender budgets or collection scope.
- Preserve the original 64/64 burst-operation assertions, all 9,000 process and 9,000 mount rows, and one capture. Three final measured race repetitions completed first bursts in approximately 15 seconds under the original 20-second limit. These machine-specific timings do not guarantee a result under arbitrary hosted contention; exact-source full CI remains required.
- Serialize the verified-download wrapper as one physical shell line using equivalent statement separators. Keep quoting, traps, fixed HTTPS source/hash, descriptor handoff and explicit public arguments intact; add independent exact HTTP/TLS syntax and no-newline checks. The source-owned pilot.2 pin and immutable release files remain unchanged, so this formatting fix does not distribute the newer journal/overview binaries or grant helper access.

## 2026-10-04 — Choose observed services and validate supported native retries

- Make Logs easier to request with a searchable selector backed by bounded, generation-pinned observed service pages, while retaining exact manual entry. Selecting an observed name never changes or proves the endpoint's separately granted local allowlist. Show empty, stale, denied and failed source states explicitly; no selection automatically captures content.
- Offer five-, fifteen-, thirty- and sixty-minute windows relative to the displayed checked UTC reference, with a nearby explicit refresh. Preserve typed drafts, acknowledgements and source age; clear private state on session, device and lifecycle boundaries. Extend the existing synthetic consent scenario and typed service fixture without removing prior assertions, cases or artifact limits.
- Repeated native CI classified a retryable HTTP sender outcome. Real-authority synthetic lost-response cases proved that the old first-Finished and single-step counter assumptions rejected supported retry recovery. Track every independent pending/acknowledged metric and system step, require exact replay flags, reject gaps/regressions/fatal/stale/malformed results, and bind final views to stopped durable counters.
- Keep all four required positive native samples, both transports, restart, original source-age and no-recapture checks under the existing contexts and time budgets. The underlying transport cause of the historical hosted failure remains unproven; this corrects the demonstrated acceptance-fixture assumptions without changing production sender behavior. The new exact-source native/browser/full regression run remains required; official pilot.2 assets and bootstrap pin are unchanged.

## 2026-10-04 — Keep expired inventory retries from recreating invalid generations

- Disposable-store fixtures reproduced a data-integrity failure after a lost Begin response, original transfer expiry and complete cleanup: retrying the same Begin could recreate an unbound generation and make later reads or reopening fail. The same cleanup prevented an authenticated pending Abort from reaching a terminal state.
- Reject expired or missing-bound-generation Begin retries before the ledger can create anything. Permit exact authenticated pending Abort after cleanup only for a missing generation at or after the original expiry. Preserve the full authority binding, durable floor, original start/receipt/expiry, prior completed generation and collection age.
- Add package, process and volume regressions covering reopen, wrong authority/binding, backward clock, revocation, rollback, previous-current preservation and higher-sequence continuation. The reviewed scoped race suite and vet pass. Regenerate only the finite Go diagnostic vocabulary for these exact source bytes; positive native/browser gates and time budgets remain unchanged.
- This prevents the reproduced path in an otherwise valid store. It does not repair an already-unreadable store and introduces no deletion, reset or state adoption. The preceding `04dc4808` repair passed 110 required browser checks with three retained enrollment skips and 12 CI jobs; its aggregate was still pending at this correction's preparation. Exact corrected-source full CI remains required, and official pilot.2 artifacts/pin remain unchanged.

## 2026-10-04 — Preserve Logs state across temporary interruptions

- A manual journal pilot configured its separate helper and returned a first captured result. Subsequent loss exposed two reproducible defects: a temporary authority-read failure erased accepted in-memory content, and a visible-window blur left the Logs view silently suspended. Retain cached bytes only across explicitly transient authority failures without returning them before fresh authorization; preserve original expiry and deletion on definitive invalidation.
- Make the paused state explicit after blur, clear private rows immediately, and offer a deliberate refresh of the original snapshot. Cancel stale work, prevent query replay, and retain the original lifetime across resume. Extend the existing browser lifecycle case with blur and refresh assertions; no case or privacy/expiry assertion is removed.
- The `fccc4b00` hosted run confirms the Docker fixture correction through an actual image build and both container profiles. It also exposed a UTC-default test timing failure and a native HTTP sender acknowledgement failure. Keep the native positive predicate and all time budgets intact; project only fixed sender categories and source-known Go package/root-test identities from private failure logs so the next run can identify a cause without exporting runtime output.
- Local source, fixture and composed checks are recorded separately from the required hosted rerun. The unresolved earlier Go aggregate failure remains open. Official pilot.2 assets and the active bootstrap pin remain unchanged and contain neither journal nor complete-overview features; this source repair is not a new verified binary release.

## 2026-10-04 — Recover bounded inventory metadata reads after admission contention

- Exact `9df28a6` passed the positive native complete-overview gate and frontend checks, but its first browser run recorded four endpoint failures and one overview visibility-restoration failure. Original reports did not capture the precise HTTP response; separate real-handler synthetic probes reproduced shared-slot `429 storage_busy` contention.
- Permit one fixed two-second retry only for exact busy metadata GET responses, retaining the original controller, protected epoch, total deadline and freshness anchor. Clear private data during interruption/recovery, expose retry progress, cancel delayed work on scope changes, and keep mutations/page operations outside automatic replay.
- Preserve every browser assertion and case identity. In the two visibility holds, deliver only an exact busy GET response so recovery can happen, continue holding the eventual successful response, and require rows to stay cleared. Diagnostics project only capped fixed route/status/code facts; no raw response or identity values are exported.
- The owner reports 1,095 frontend tests, type checking/build and focused independent reviews passing. Exact composed hosted confirmation remains pending. A separate Go aggregate failure on `9df28a6` remains under investigation; this UI correction does not resolve or weaken that gate. Preserve the helper recovery and Docker correction from immutable `fccc4b00`. These source checks do not establish hosted acceptance, actual host recovery or a new verified binary release.

## 2026-10-04 — Repair the pilot helper account command and preserve the failed attempt

- The observed helper apply stopped when the local useradd parser rejected the unsupported `CREATE_MAIL_SPOOL` override. Read-only inspection found no helper account or group creation; the protected attempt marker was retained and the existing agent was restarted. Remove only the unsupported override and report finite command-failure stages while preserving all setup guards.
- Add a separate, narrowly bounded marker-archive utility for that account-failure case. It verifies the original installation and absence of helper-side state, preserves the exact marker without clobbering, and never adopts/reset identities or applies setup. Human review and explicit local execution remain required; retrying the fresh setup is a separate step.
- Include the one missing public synthetic contract fixture in Docker's frontend stage. The original isolated stage reproduces the TypeScript failure; the single-file copy makes the build pass with identical production assets. Runtime image permissions, dependencies and application bytes are unchanged.
- Publish this small experimental recovery checkpoint for user feedback. All 73 inert helper/recovery tests pass and the source slices are reviewed. Actual marker archival, helper apply, source access and the full hosted rerun remain unverified. The preceding overview native gate passed, while its Docker/browser findings remain recorded and are not presented as a full CI pass.

## 2026-10-04 — Add complete visible process and mount generations

- Add a separately acknowledged, default-off extension for an existing activated v3 identity. Capture supported visible processes and mounted filesystems into bounded independent generations, preserving field failures, exact enumeration scope, durable counters and original capture/retention times. No command lines, environments or additional OS privilege are introduced.
- Atomically promote validated complete generations, retain an independently successful sibling across failures, and page/search by immutable generation. Put measured local filesystems before virtual mounts, preserve namespace/sandbox and capacity limitations, and use completed supported dpkg metadata for Software overview counts instead of the bounded preview.
- Keep metric and journal progress independent of overview delivery failures while retaining the shared transfer budget and trusted local-state guards. Source fixtures exercise real TLS and signed-HTTP sender/store admission, lost responses, restart, complete paging, revocation and trusted-clock/output boundaries without collecting host data.
- Add six synthetic browser cases and an explicitly enabled extension to the existing nonroot, group-clean Ubuntu native test. The native gate requires all prior opt-ins, actual positive process/mount pages, explicit stopped-agent consent and original-age retention after restart/disable. Its private evidence is checked using finite markers and counts; raw process, mount and identity values are not exported.
- The preceding `d3628dc` journal checkpoint passed all 13 CI jobs and 104 required browser cases, with three documented enrollment skips. This candidate passes 964 frontend tests, type checking/build and all-Go compile/vet; exact composed hosted native/browser/aggregate results remain pending. Existing 104 identities, three skips, five lifecycle cycles and immutable pilot.2 assets/pin are preserved.

## 2026-10-04 — Validate journal socket status using its unit type

- An actual read-only helper plan stopped at systemd status validation because the socket unit does not expose the service-only `MainPID` property. The service/agent status fields were valid, and the rejected plan did not proceed to setup.
- Require the exact property set for each fixed service or socket role and request empty properties explicitly. Preserve strict duplicate/unknown/missing-field rejection and all existing ownership, account, unit, consent and apply guards.
- Add inert parser and command fixtures for the real unit-property distinction. This changes only the setup script and tests; existing manager and agent binaries do not need rebuilding. A successful plan or source check does not substitute for the separate reviewed host apply and journal-access acceptance.

## 2026-10-04 — Match browser checks to journal controls and unassessed health

- The first journal checkpoint's browser report recorded 9/10 inherited HTTP-test cases and 1/6 new journal cases passing, with zero browser runtime errors. Five journal cases timed out in their shared capture setup; the endpoint target did not execute after the earlier failure. Those results remain failed/pending evidence, not complete acceptance.
- Use the severity control's exact combobox role/name and require the selected value. An inert check of the actual rendered component reproduced why the former exact label selector failed: its wrapping label text included every option. Add fixed setup-stage labels while retaining the request, coverage, paging, search, cancellation, expiry and private-content assertions.
- Match the two active LAN health checks to the reviewed `Not assessed` label and explicit no-assessment explanation. Preserve sandbox `Unknown` checks, the three quarantined enrollment bodies and all case identities, timeouts and required outcomes.
- This is a browser-harness correction only. Application, helper, installer and release bytes are unchanged; the exact-source hosted rerun must establish the result.

## 2026-10-04 — Connect bounded on-demand service logs

- Add explicit service/time/severity requests, one-time native claim/consumption, authenticated result transport and operator-only Logs pages. Results keep their original expiry, immutable snapshot identity and coverage; paging and literal search operate on captured content. Expiry, cancellation, revocation and restart loss never become healthy empty data.
- Keep journal access behind a separately acknowledged local content policy and dedicated least-privileged helper. The main agent retains its existing identity and group boundary. The create-only setup provides preview and a deliberate administrator apply; source and browser fixtures perform no helper installation, permission change or real journal read.
- Add six synthetic real-handler browser cases while preserving the previous 98 required cases, three named enrollment skips and five review lifecycle cycles. The journal source owner's 14-package combined race checks, all-Go compilation, 891 frontend tests/type checking/build and 21 inert setup tests passed. Exact composed-source hosted browser/native/aggregate acceptance remains pending.
- Correct the reusable release bootstrap's cleanup: the pinned verifier creates private state, so flat cleanup could mask an already committed installer's successful exit. Fixed-name descriptor-based cleanup preserves installer status and leaves unknown/protected entries alone. All 66 inert release fixtures pass; the original and corrected behavior were reproduced with the real offline verifier and an inert installer. The historical pilot.2 verifier remains bound to its original immutable bytes.
- The preceding `74a5236` download-command source completed all 13 CI jobs and 98 browser checks. Official pilot.2 assets and the active bootstrap pin remain unchanged and contain no journal feature; their known post-upgrade cleanup warning is not corrected by this source checkpoint. A fresh verified binary release and explicit host helper/content grant are still required for download-based journal use.

## 2026-10-04 — Pin the verified pilot.2 dashboard download

- The exact binary source `dbbcfe203` passed all 13 CI jobs and 98 required browser checks, with three existing enrollment skips. The official pilot.2 build/publication succeeded, and a separate read-only hosted check downloaded and verified all ten public assets, their keyless provenance and the generated bootstrap template.
- Publish the exact verified bootstrap in immutable commit `1011c6b8d38cf85d77a342addf0493cbe1f828ca`, then select that full commit and its SHA-256 in the source-owned dashboard pin. Keep the binary build commit distinct from the bootstrap publication commit; API responses, environment and storage cannot choose executable trust.
- Preserve exact manual fallback coverage and add activation-aware inert command assertions. All 832 frontend tests, type checking/build and seven command-contract tests pass with the real pin. Retain all 98 browser identities, three enrollment skips and five lifecycle cycles; exact hosted activation results remain pending.
- Download verification does not execute Tracebolt or install a service. A human still approves and runs the copied command; existing installations use the upgrade action without new enrollment, and host installation/restart/reboot observations remain separate.

## 2026-10-04 — Independently verify published Linux release bytes

- The actual `v0.1.0-pilot.2` candidate and publication jobs succeeded from source `dbbcfe203`. The release contains the exact ten expected assets with final version URLs; the earlier partial `v0.1.0-pilot.1` draft and tag remain retained.
- Add a separate read-only, ordinary-user GitHub check that downloads all ten fixed official assets, verifies their bounds and hashes, checks keyless provenance with the existing pinned verifier, and compares the bootstrap against the exact source template. It has no repository write, attestation grant, installer execution or user-host access.
- Export only the verified public bootstrap, manifest, signature bundle and closed verification result after success. Production download pins remain disabled until this independent public-byte gate completes; source checks and the earlier successful publication do not substitute for it.

## 2026-10-04 — Validate temporary GitHub draft asset URLs

- The first actual release candidate build and keyless verification passed on `79cef736`, but publication stopped after the first asset because GitHub returned a temporary draft URL instead of the final version URL. The existing `v0.1.0-pilot.1` tag and partial draft are retained for inspection; no release was published and no production download pin was activated.
- Bind draft asset URLs to the exact newly created draft's validated repository URL, while retaining exact names, sizes and SHA-256 checks. After publication, require the chosen version URL again for the release and every asset. A changed draft URL, unrelated repository, unexpected asset or uncertain mutation still stops publication.
- Add regression fixtures for the observed draft URL shape and rejected metadata/URL changes. All 48 inert release fixtures pass. This correction does not adopt, overwrite, delete or retry the retained partial release; a new selected version and actual workflow result remain required.

## 2026-10-04 — Prepare verified Linux release downloads

- Add a manually dispatched, exact-source Linux release build with keyless GitHub provenance for its strict artifact manifest. Keep ordinary jobs read-only; isolate the specifically approved attestation permissions to the candidate job and release write permission to the explicit fresh-version publish job.
- Reverify provenance, artifact bytes, repository identity, unchanged selected main source and absent version before publication. Refuse existing or uncertain release state without overwrite, deletion or automatic retries. No signing private key or repository-settings change is introduced.
- Add a fixed-origin, checksum-pinned bootstrap that verifies the complete official release before handing verified files to the existing installer. Preserve hidden terminal input, deliberate apply, identity retention and installer guards. Linux amd64 is the first runtime target; arm64 is only cross-built.
- Prepare the dashboard command selector with its source-owned production pin disabled. Until real release artifacts and the separately published bootstrap are verified, the existing manual installation command remains byte-for-byte selected.
- The composed source passes 43 inert release/wrapper fixtures and 831 frontend tests, type checking and build. These results do not establish an actual attested Tracebolt build, release publication, downloader installation or host reboot. Those gates remain open and require the exact selected source and official artifacts.

## 2026-10-04 — Add explicitly consented endpoint hostname and interface observations

- Add a separately versioned, bounded hostname/interface-address extension for the existing managed-v3 identity. Local preview/enable/disable requires the exact nonroot service identity, a stopped sender and explicit scope acknowledgement. Default collection stays off, and existing keys and counter domains are preserved.
- Admit typed optional frames and retain the endpoint attempt's original generation, collection time, receipt and expiry when ordinary reports omit it. Disable does not refresh old observations; failed or denied attempts do not become healthy last-good values.
- Show reported hostname separately from stable cryptographic identity, with independent per-interface IPv4/IPv6 coverage, permission gaps and original ages. Render values as inert text without primary-IP, external-reachability or remote-action claims. Auth, navigation and visibility changes clear protected data and cancel late reads.
- Keep the accepted 92 browser cases, three documented enrollment skips and five lifecycle cycles. Add six real-handler synthetic browser cases and a native opt-in consent/report/restart/disable gate. Its hosted process drops to the same existing nonroot UID/GID with no supplementary groups or capabilities; it creates no host account or persistent permission change. Success requires fixed complete evidence, and raw identity data stays out of CI output/artifacts.
- Source/component and inert gate checks passed; the new exact-source native/browser results and user opt-in remain separate pending acceptance. The preceding full-page checkpoint `a9a9d4e` completed all 13 CI jobs and focused pixel review. No release-download installer, broader diagnostic privilege or confirmed update/CVE coverage is added here.

## 2026-10-04 — Give device details a full page and simplify invitations

- Open device details in the available main-content width, with Back/Escape navigation, browser-history handling and focus return. Preserve protected-data concealment, keyed cancellation and late-response rejection across navigation and authentication changes.
- Show the invitation flow progressively while retaining explicit collection consent, hidden secret handling, public-command checks and deliberate fingerprint/comparison approval.
- Adapt the existing browser checks to page navigation and retain modal checks on keyboard help. All 92 case identities, three documented enrollment skips and five lifecycle cycles remain; two new invitation captures are taken before any secret exists.
- Add the ordered Linux pilot roadmap, distinguishing observed pilot behavior from planned identity metadata, verified release distribution, scoped diagnostics and update/CVE work. The owner's 722 component tests, type check and build pass; exact-source hosted browser acceptance remains required for this checkpoint.

## 2026-10-04 — Correct managed capability descriptions and source-archive permissions

- Describe managed inventory capabilities from the server's selected collection profile. Keep current coverage, failures and ages in their dedicated views, preserve denied states, and avoid treating supported inventory or service code as proof of successful collection, installation or reboot.
- Update the guided manager's capability limitations to reflect complete supported dpkg generations and paged services/sockets, while retaining the limits on remote actions, confirmed CVE/update authority and managed-inventory AI use.
- Create the v2/v3 first-start source archive under a scoped `umask 077`, preserving the existing refusal to overwrite an output file and the caller's shell settings. An inherited group-writable mode could otherwise make the installer correctly reject the archive before fetching bootstrap metadata.
- Retain all installer ownership and write-permission guards. This guide correction requires no binary rebuild.
- The preceding `1dadb7b` source passed all 13 hosted CI jobs, including positive native package/service/socket observations and 92 browser checks with three previously documented enrollment skips. Actual installed-service and reboot observations remain separate from these automated checks.

## 2026-10-04 — Correct capability-absence handling and match native bootstrap requests

- Handle the capability-query error before its byte count: the pinned Linux syscall wrapper returns-1 with the accepted no-attribute/unsupported errors. The old zero-count conjunction rejected ordinary no-capability executables. Inert private-file reproduction and regression tables cover the correction; actual capabilities, unrelated errors and all executable/path protection checks still reject.
- Match the native public-bootstrap contract in the browser test: explicitly require rejection of the authenticated cookie-bearing request, then verify the credential-free response, exact checksum and secret exclusion. No server guard is changed.
- Wait for committed drawer dismissal, locale selection and fresh pane state before the German mobile flow. Preserve its rows, viewport, keyboard focus and dismissal assertions; the prior broad failure did not prove a production navigation defect. All eight scenario identities remain mandatory.
- Hosted diagnostics identified complete package acknowledgement and socket coverage, but failed service coverage; the positive-data gate stayed red. This correction still needs the unchanged exact-source native/browser gates. No installed-service or reboot acceptance is claimed.

## 2026-10-04 — Efficient large-list test queries and bounded native diagnostics

- Scope the large service/socket traversal tests to semantic table cells instead of repeatedly computing every row's accessible name. Retain complete row ordering, pagination, visibility, request bounds and scope checks; strengthen exact socket endpoint/owner ordering. The owner's three full709-test runs pass with unchanged runtime assets and test timeouts.
- On a failed positive v3 native command, project only exact fixed test categories and allowlisted source-status enums from its private Go JSON. Limit file/record/projection sizes, reject duplicate JSON keys and special files, and never print raw output, stderr, paths, identifiers, counts or telemetry. The command still fails and all positive-data/success assertions remain mandatory.
- The first hosted v3 run passed707/709 UI tests, with a service-list timeout and a following socket assertion failure; the native positive-data command also failed before a bounded reason was available. No production cause is claimed yet. This test/workflow-only checkpoint requires a new exact-source native/browser result.

## 2026-10-04 — Fresh v3 Linux inventory and pending-service onboarding

- Add explicitly consented `managed-operations-v3` supported-dpkg generations, bounded chunk transfer and generation-pinned package pages, plus system-service and locally observed socket state with honest permission/source/attribution limits. Preserve basic/v2 identities and their narrower collection scopes.
- Add the secret-free dashboard installation command and checksum-bound public bootstrap fetch. A fresh explicitly selected pending service can retain its committed same-key claim while awaiting operator approval; collection and reporting start only after activation. Executables remain locally prepared and independently selected.
- Provide one fresh-start guide and dedicated complete-test Compose configuration. Build binaries/archive before inviting a device; retain old test state and use a new config/project/volume on the selected test ports. No automatic migration, identity reset or executable download is added.
- Retain released review-recovery, byte-limit, catalog and lifecycle regressions. Source/fixture checks and the owner's native TLS/HTTP approval/reporting/process-restart gate passed; this executor rejected package/service source prerequisites before collection, so positive v3 package/service observations require the hosted gate. New exact-source browser/container/native CI and actual installed-service/reboot acceptance remain separately reported.
- CVE authority and offered-update counts remain unknown. No APT action, remediation, network scanning, private telemetry upload or production-fleet claim is included.

## 2026-10-04 — Construct the exact review byte-limit fixture efficiently

- Replace repeated whole-document serialization for every removed ASCII padding byte with one initial measurement and bounded bulk trimming of the same rows. The existing exact65,536-byte acceptance and65,537-byte rejection assertions remain unchanged; add an explicit zero-remainder check.
- Preserve production source, default test timeout and all browser privacy/freshness assertions. The previous hosted run passed616/617 frontend tests but timed out constructing this boundary fixture before Chromium could start.
- The owner's corrected contract file passes10/10 and full frontend617/617, typecheck and production build pass. The affected test took2ms locally; exact-source hosted browser/CI acceptance is still pending.

## 2026-10-04 — Recover conditional review after transient read contention

- Exact-source browser diagnostics observed a restored review GET returning `429 storage_busy` while concurrent coverage loaded successfully. Private stale rows were cleared correctly; the missing fresh view was a read-admission recovery defect.
- Retry that exact review read once after two seconds, with visible English/German progress. Preserve the original cancellation controller, protected view epoch, freshness clock and ten-second total deadline; a second failure remains visible. Mutation requests never replay.
- Add deterministic backend admission/error-contract regressions and46 frontend retry/cancellation/error-classification cases. Owner617 component tests, typecheck and build passed; independent QA reran46 focused cases and security reviewed the exact overlay.
- Keep all18 conditional browser cases and five consecutive lifecycle cycles unchanged. Exact-source hosted acceptance for this correction is pending; service installation and real-device evidence remain separate.

## 2026-10-04 — Diagnose intermittent browser lifecycle revalidation

- Keep the successful `ed18d9a` acceptance and screenshot provenance intact. A later documentation-only run passed17/18 conditional cases and exposed an intermittent persisted-page lifecycle assertion on identical application and test code; no production root cause is established yet.
- Repeat that existing scenario for five consecutive suspension/restoration cycles and require every cycle to pass. All18 named scenarios, privacy/freshness assertions and failure exits remain mandatory; this is not retry-until-success or a new quarantine.
- Add fixed substage labels and capped request/status, whitelisted error-code and DOM-state counters. No response body, UI text, URL, device identifier, secret or telemetry value is exported. The formerly unbounded request-arrival wait now uses the normal assertion budget.
- Application behavior is unchanged. The diagnostic-only hosted result will determine whether request ordering, store admission or another path needs a focused correction.

## 2026-10-04 — Verified Linux inventory UI gallery

- Add four original, independently inspected synthetic screenshots for operational inventory, conditional review detail, offline catalog settings and the mobile package table, pinned to capture source `ed18d9a` with hashes and explicit fixture captions.
- Record18/18 new real-handler browser cases, plus the established40+6+10 and reduced enrollment10 passed/3 skipped scope. No browser runtime errors were reported.
- Retain unknown CVE/update authority, unverified catalog provenance, component/frame distinctions and service/telemetry boundaries. No real device data or credentials are published; prior screenshot galleries remain historical.

## 2026-10-04 — Keep CI evidence channels separate and reopen refreshed catalog controls

- Prepare locked Go dependencies before the dense race matrix and keep stderr in its own private file. The four exact cases, ten-minute budgets, process-exit checks and strict package/root/leaf completion requirements are unchanged. A real Go cold-cache reproduction showed how dependency messages could invalidate otherwise successful JSON evidence; the original private CI stream was not exported.
- Reopen the catalog-import disclosure after refreshed state recreates it, then require visible disabled replacement and an empty file selection. Retain real revision-conflict, lost committed response, single-write and storage assertions; all18 scenarios remain required.
- The first integrated run passed actual positive Ubuntu collection, Docker, native platform and inherited browser gates. Its new browser target passed16/18 and dense completion-evidence checks failed. These focused test/workflow corrections still require an exact-source hosted rerun; application and installer behavior are unchanged.

## 2026-10-04 — Bounded Linux operations, package observations and conditional review

### Added
- Explicitly consented fresh operational enrollment profiles, bounded Linux services/processes/interfaces/volumes/software/journal metadata, authenticated durable ingestion and per-section freshness/last-good views.
- Protected read-only release and dpkg package observations with selected source-version metadata, bounded counts and truthful unsupported/denied/partial states.
- Admin operational and Security panels, an explicitly imported unverified offline catalog, and bounded Debian-only conditional review candidates that retain observation/catalog lineage.
- A separately acknowledged managed setup selector, fresh HTTP inventory Compose profile and native background-service guide. Existing basic credentials/state are not adopted or relabelled; a new explicit profile/identity is required.
- A separate manual-only managed-service acceptance target requiring advancing observations after actual install/restart/upgrade. It is default-disabled and has not been executed by this checkpoint.
- Independent parser, consent, admission, replay, persistence, capacity, cancellation and stale-result regressions. A new authorized advisory scan records zero reached/imported findings and the existing unused OpenPGP module-only advisory for its exact frozen source.

### Boundaries and validation
- The composed source passes serial race checks with the one dense package matrix reserved for four mandatory isolated CI rows, plus vet/modules/build,571 UI tests and nine independent DOM checks. New exact-source browser, positive Ubuntu package and container gates remain separately tracked until actual completion.
- Confirmed CVE and offered-update counts remain unknown. Catalog declarations and version matches do not prove installed artifact origin, exploitability or update availability. Ubuntu packages are not reviewed against Debian rules.
- No raw journal bodies, arbitrary shell commands, update installation or automatic remediation are introduced. Operational labels remain private metadata. Basic identities are not silently upgraded into expanded consent.
- The corrected installed-service gate and three quarantined enrollment browser cases retain their existing explicit status. Cached-APT fixture-only work remains separate and is not enabled in this milestone.

## 2026-10-04 — Handle bracketed paste in the hidden enrollment prompt

- Recognize the terminal's standard bracketed-paste framing around one complete invitation. Keep input hidden and require an explicit Enter after the closing delimiter.
- Preserve the exact 43-character invitation format, bounded input, rejection of malformed framing/control characters and cancellation/terminal restoration. No argument, environment, file or visible-input fallback is added.
- Add inert pseudo-terminal regressions for wrapped paste, rejection, explicit-submit behavior and restored terminal settings. Focused normal/race/vet checks and the native client build pass; the specific real terminal still needs a successful retry to establish the user-facing outcome.
- Rebuild only `cmd/enroll-agent` for this change. The manager image, UI, credentials, bootstrap and existing enrollment state are unchanged; an expired invitation still requires the normal explicit recovery flow.

## 2026-10-04 — Manual disposable HTTP setup and Docker first start

- Add a default-plan-only Linux helper for a new fixed private HTTP-test configuration directory. Explicit apply requires a root controlling terminal, hidden confirmed disposable password input, and a selected private IPv4 address.
- Generate a dedicated short-lived client-auth issuer and password verifier without exporting secrets; reject existing destinations and preserve uncertain published state.
- Add a guided Compose command override and a concrete Docker build/start/enrollment guide. The current strict published schema selects `basic-readonly-v1`; no unpublished operational or package profile is enabled.
- Owner full Go tests and focused race/vet plus independent focused review pass. Actual helper apply, credential provisioning and the guided Docker first-start path still need host verification. Existing manager/UI behavior, installer diagnostics and the three quarantined enrollment browser cases retain their prior scope.

## 2026-10-03 — Preserve public installer path traversal under restrictive umask

- Set the intended mode through a verified descriptor only for newly created owned public binary/bootstrap directories; restrictive caller umasks no longer unintentionally remove traversal needed by the unprivileged enrollment child. Existing and private paths are not relaxed or adopted.
- Add inert restrictive-umask regressions and bounded fixed installer-stage diagnostics without exporting private terminal or runtime output.
- The initial installer source passed all ordinary CI jobs, but its separately approved fresh-VM installation attempt stopped in the `install_enroll` phase. Local regressions establish this directory-mode defect; only a new exact-source manual run can establish whether the hosted installation now completes.
- Independent focused race/vet and actual three-binary TLS/HTTP regressions pass. Installed-service lifecycle, true OS reboot and the three quarantined enrollment browser cases retain their distinct acceptance boundaries.

## 2026-10-03 — Linux/systemd installer candidate and opt-in acceptance gate

- Add a default-read-only fixed-path Linux installer with explicit install, restart, selected local artifact upgrade, uninstall and same-identity resume operations.
- Preserve dedicated numeric service identity, private sender state, selected-byte verification, bounded enrollment/rollback handling and terminal restoration. Retain identity/account on uninstall; no remote download, automatic updater or reset/purge path is added.
- Include independent source/inert-fixture regressions and a manual-dispatch-only fresh-Ubuntu acceptance harness. Ordinary push/PR tests skip its privileged account/service operations before effects.
- Actual install/reporting/restart/upgrade/uninstall acceptance remains pending until the approved exact-source manual job runs. A service restart does not establish true OS reboot persistence. Windows/macOS service installation, automatic renewal and real endpoint deployment remain open.
- Keep the three temporarily skipped enrollment browser cases explicit and independent of installer verification.

## 2026-10-03 — Explicit temporary enrollment browser quarantine

- Temporarily exclude exactly three named termination-dependent enrollment browser scenarios from the required gate. Each remains in source and is recorded as `SKIPPED` with a reason; the other ten enrollment cases and all existing 40 general/AI, 6 managed-preview and 10 operator-auth cases stay mandatory.
- Retain the reviewed response/UI synchronization correction and every original scenario body. `TRACEBOLT_REVIEW_QUARANTINED=1` restores all thirteen cases for a future exact-source acceptance run.
- The original guided candidate `d4a4856` passed 10/13 enrollment cases with zero runtime errors, plus all prior browser targets and six non-browser CI jobs. The three omitted cases have no successful hosted rerun yet. A reduced green gate must be reported as **10 passed, 3 skipped**; complete guided-enrollment browser acceptance remains open.
- Application behavior and backend/native security checks are unchanged. The new reduced hosted gate remains pending at this checkpoint; omitted cases remain an explicit acceptance gap.

## 2026-10-03 — Guided Linux enrollment and foreground reporting

### Added
- Explicit guided-v2 manager mode with protected preprovided client-auth intermediate custody, offline root key separation, strict public bootstrap, and durable proof/approval/issuance/activation/revocation.
- Conditional English/German enrollment UI, one-time secret display, public-only export, exact fingerprint/comparison consent, server-clock deadlines and safe suspended-page handling.
- Native Linux `enroll-agent` with hidden terminal invitation entry, strict trust display, preserved same-identity recovery and private-first sender handoff.
- Bounded serial foreground sender cadence/backoff retaining the exact pending-byte/sequence domain and exclusive lock during waits.
- Independent crypto/state/store/service/API/config/client/loop regressions, actual three-binary TLS/HTTP fixture acceptance, and a separate 13-case hosted enrollment browser target.

### Boundaries
- Manual-v1 remains the default; guided-v2 requires an empty legacy registry and does not automatically migrate identity or provision a CA.
- The ledger retains at most 25 records, including terminal states. No Windows/macOS LAN client, OS installer/service, reboot persistence, renewal or lost-key recovery is claimed.
- HTTP test remains explicitly unauthenticated plaintext. Invitations and activation responses are not made trustworthy by client possession proofs.
- Source/component and actual native fixture tests are distinct from exact hosted browser/container gates. New gallery captures remain pending until real rendering and pixel review; no secret/comparison values may be exported.

## 2026-10-03 — Defensive Ed25519 key policy and dependency notice

- Reject noncanonical, identity and non-prime-order Ed25519 public keys through a shared bounded policy used by certificate trust/approval and signed HTTP validation.
- Add a key/time check only after ordinary TLS chain and hostname verification; no trust bypass, automatic credential replacement or new enrollment surface is introduced.
- Pin `filippo.io/edwards25519` v1.2.0, preserve its upstream license in source and the runtime image, and verify exact notice bytes in both container lifecycle profiles.
- Independent review covers generated-key classification and normal real TLS compatibility, with zero reachable/imported-package advisory findings and the already documented unused OpenPGP module advisory.
- The immutable aggregate passed Go race/vet/module verification and build before publication. Exact-source native, browser and container CI are separate gates. This is defensive hardening, not a claim of a reproduced exploit through an existing deployment.

## 2026-10-03 — Verified bilingual viewport gallery and installation runbook

- Add a source-validated human/automation installation runbook and repository entry guide, with explicit credential/trust/deployment approval boundaries and supported-platform limits.
- Publish twelve original synthetic Chromium captures: English default inventory/investigation, German scrolled content, mobile device/AI views, consent and explicit HTTP-test login/awaiting states.
- Record exact capture source `b4a6f40`, CI run, viewport, per-image SHA-256 and independent pixel approval. No screenshot pixels were edited.
- The corrected source passed 40 general/AI/language/layout, 6 managed and 10 authenticated HTTP-test scenarios with zero runtime errors; actual Docker TLS/HTTP lifecycle and three native collector jobs also passed.
- Preserve explicit test-provider/no-real-analysis and plaintext-profile captions. No real endpoint data, key values or session material are included.
- Update scoped UI/LAN verification reports while keeping later Linux sender evidence separate from the capture source.

## 2026-10-03 — Native Linux one-shot LAN sender

### Added
- A separate foreground Linux sender using protected, preprovided configuration and approved client identity for default TLS/mTLS or explicit signed HTTP testing.
- Private single-writer durable state bound to profile, exact origin, certificate fingerprint and expected agent ID, preserving exact request bytes across uncertain responses and process restarts.
- Strict bounded receipt validation, stale-sample discard without sequence reuse, static diagnostics and privacy-safe availability counts.
- Actual two-binary manager/sender tests for both loopback profiles, restart/replay/revocation and isolated filesystem-state boundary regressions.

### Verification and limits
- Owner and independent review passed full Go race/vet/module verification and actual Linux manager/sender execution. Exact-source hosted CI remains a separate gate.
- No real LAN deployment or persistent credentials were created. Windows/macOS sender state/ACL protection, service installation, scheduling, offline history and production acceptance remain unimplemented.
- HTTP test traffic is readable and an impersonating server can forge an acknowledgement. It is not confidential or server-authenticated.

## 2026-10-03 — Contain accessible labels within the scrolling content pane

- Give the main content pane a positioned containing block so its visually hidden form labels cannot extend the outer document or scroll the topbar away.
- Retain all strict viewport, document-scroll and reachable-navigation browser assertions; add bounded geometry names to failures and scope the loading check to the application state.
- The preceding LAN checkpoint passed actual TLS/HTTP-test Docker lifecycle, all three native CLI jobs, 97 UI tests, six managed browser checks and ten authenticated HTTP-test browser checks. Four newly added scroll-shell checks exposed this layout defect; this checkpoint reruns the exact broader gates before updated gallery publication.

## 2026-10-03 — Authenticated LAN pilot, container packaging and bilingual interface

### Added
- Separate explicitly configured LAN manager with operator authentication, bounded sessions/CSRF, manual public-certificate approval, TLS/mTLS listener separation and durable replay/revocation state.
- A default-off, explicitly acknowledged HTTP test profile with signed telemetry, separate authentication/state and a persistent plaintext-risk warning.
- Optional nonroot, read-only Linux manager Docker image and Compose examples; hosted CI builds locally and tests TLS and HTTP-test container lifecycle without registry publication.
- English-default UI with a persisted German switch, authenticated session/logout flows and truthful awaiting-agent/source/platform states.
- Research-backed competitor priorities with objective acceptance criteria and explicit implementation gaps.

### Improved
- Viewport-bounded application shell: the content area scrolls while navigation remains within the viewport. New captures use actual viewport framing rather than long-document composites.
- Session revocation ordering, interrupted/logout UI handling and privacy-safe support-bundle/configuration boundaries.

### Verification and limits
- Frozen backend source, real loopback CLI fixtures, targeted security checks, UI types/build and 97 component/unit tests passed before publication. Exact-source browser and actual Docker lifecycle results are separate CI gates, pending for this new scope at publication.
- The current Linux advisory review reports zero reachable/imported-package findings and one unused OpenPGP advisory in a required module; see the scoped security report.
- No real LAN deployment, trusted browser certificate provisioning, installed/scheduled native sender, production audit/backup or fleet-scale assurance is claimed. HTTP testing remains deliberately insecure.
- Assessment remains an isolated synthetic foundation; this milestone does not expose real missing-update/CVE results. AI tests remain deterministic test-provider evidence, not real-model diagnostic validation.

## 2026-10-03 — Strict malformed-response transport regression

- Keep explicit rejection status, CORS and no-mutation assertions when the server closes a deliberately malformed HTTP request after returning its headers.
- Only the malformed-framing test tolerates reset/truncation after an allowed denial status; ordinary requests, missing or unexpected status, oversized bodies and timeouts still fail.
- Add five transport-reader regressions. The corrected test passed 500 repeated framing groups and the full 13-group boundary suite against the immutable assessment source. Application guards and source are unchanged.

## 2026-10-03 — Isolated read-only assessment foundation

### Added
- Bounded fixed-path Debian package inventory parsing, an injectable/native Debian version comparator, digest-pinned normalized synthetic advisory matching, and in-memory last-good result retention.
- Separate inventory, offered-update and CVE result types with nullable counts, source/coverage/freshness evidence, origin qualification and explicit unknown states.
- Independent contract tests, adversarial parser fixtures, safety checks, cross-build checks and short fuzz smoke coverage.
- A reviewed multi-platform implementation plan and updated product requirements.

### Verification
- Focused assessment race/vet and independent security-contract tests passed on the isolated source overlay.
- Full Go tests, Windows amd64/macOS arm64 test cross-compilation, and two bounded three-second fuzz smoke runs passed. Cross-compiled assessment tests were not executed on those target systems.

### Known limits
- Live advisory import, verified package-origin adapters, offered-update adapters, and UI/API integration remain unimplemented.
- This does not yet show real missing updates or CVEs in Tracebolt. All advisory fixtures are explicitly synthetic, and no real inventory or customer data is published.
- No LAN/authentication, Docker or new language-interface implementation is included in this foundation checkpoint.

## 2026-10-03 — Robust timestamp-based transport checks

- Give the deliberately aged test observation a 15-second admission margin, then wait against its actual timestamp and the server's configured expiry. The same freshness, replay and stale-state assertions remain in place.
- Report safe failure stages, top-level test names and source-line identifiers without exposing raw telemetry or request bodies.
- Run browser acceptance independently after frontend validation; backend/security jobs still contribute to the overall workflow result.
- Application source and security guards are unchanged.

## 2026-10-03 — Stable current-address browser assertion

- Identify the runtime-address row by its stable Manager label while retaining the exact custom-port assertion.
- No application behavior changed. The preceding run passed all eight AI test-provider scenarios and all six real managed-preview checks; this updates the remaining Settings test locator before a complete rerun.

## 2026-10-03 — Provider form readiness and native test isolation

### Fixed
- Provider settings become editable only after the fetched configuration is applied, preventing early edits from being overwritten. Inputs remain disabled during save.
- Form-validation tests wait for actual configuration readiness and cover the first editable state.
- Native agent smoke jobs keep all collector, bundle and agent tests while selecting only independent support-bundle contracts from the shared security-test package. Linux-only managed transport and AI/API checks still run in the full Linux job.
- Native smoke failure diagnostics expose only fixed package and top-level test names, never raw runtime samples.

### Verified locally
- 57 UI tests, nine independent UI regressions, type checking and production build passed.
- Actual Linux native test/build/CLI schema, cap and privacy checks passed. Hosted Windows/macOS and new browser results remain commit-specific CI gates.

## 2026-10-03 — Consent-based AI preview and local agent delivery

### Added
- Optional OpenAI-compatible provider configuration held in process memory, with explicit evidence-and-destination review before each analysis request.
- Bounded, validated AI suggestions with evidence citations, unconfirmed-cause labeling, cancellation and clear provider-error states. Automated validation uses only a deterministic local test provider, not a real model.
- A separate one-shot development agent and opt-in loopback telemetry preview, with awaiting/fresh/stale states, replay rejection, receipt provenance and no manager-side fallback sampling.
- Additive AI and transport security reviews, contracts, independent API regressions, and separate AI/managed browser scenarios.

### Improved
- Concise operational headings and current-address runtime information.
- Unknown collection times and awaiting samples remain visibly unknown rather than appearing as valid measurements.

### Verified prior milestone
- Source `2bccc168c6ef770484b1641bcaeabfe1d10270df` passed actual hosted Linux amd64, Windows amd64 and macOS arm64 read-only agent/runtime checks, plus 26 Chromium scenarios with zero runtime errors.

### Scope
- Provider tests use synthetic evidence and an explicitly labeled test provider. They do not establish diagnostic quality of a real model.
- Managed preview remains loopback-only, without enrolled sender identity, LAN transport, remote actions, service installation or production approval. Native hosted CLI smoke does not establish service, reboot or ordinary-user permission acceptance.
- New UI/browser outcomes are recorded for this checkpoint's exact CI commit; earlier browser passes do not cover these new features.

## 2026-10-03 — Native runtime CI and keyboard refinements

### Added
- Read-only agent runtime smoke jobs on standard hosted Linux amd64, Windows amd64 and macOS arm64 runners.
- Native package tests and actual executable/schema/privacy validation with required-field availability checks. Only pass/fail summaries and availability counts are logged; raw runtime samples are not uploaded.
- An additional independent dialog-shortcut regression and corresponding Chromium scenario.

### Fixed
- Global help/search shortcuts no longer open background views while a device dialog is active.
- Keyboard focus outlines use an opaque accent color.
- Screenshot capture waits for animations to complete and frames fixed dialogs at the viewport height.

### Verification boundaries
- Native hosted execution outcomes are recorded per exact CI commit. A configured job does not itself prove a platform passed.
- Hosted CLI checks do not establish service installation, reboot persistence, ordinary-user permission parity, macOS TCC behavior, signing, or production readiness.
- The earlier gallery remains tied to its actual source commit; refreshed captures follow the new browser run.

## 2026-10-03 — Verified browser gallery

### Added
- Eight actual synthetic-data screenshots covering inventory, device evidence and investigations across desktop/mobile and light/dark themes.
- A gallery with immutable source-commit association, CI run, capture time, viewports, and image SHA-256 hashes.

### Verified
- Hosted Chromium completed 25 real-manager scenarios with zero failures and zero uncaught runtime errors for source `594e88eee0e45060374a2c1049be711a96b58d37`.
- Coverage includes API loading/failure/retry, filters and sorting, source quality, dialogs and history, literal note rendering, write deduplication, persistence across manager restart, delayed-save navigation, malformed routes, and responsive layouts.
- The same commit's Go, UI, Linux CLI bundle-schema and HTTP boundary jobs passed.

### Scope
- Screenshots contain synthetic devices and cases. No live sandbox telemetry, database, or raw server log is published.
- These browser results do not imply native Windows/macOS agent acceptance or production deployment approval.

## 2026-10-03 — Investigation UI and bounded native preview

### Added
- React/TypeScript investigation UI with light/dark themes, responsive layouts, inventory search/filter/sort, saved views, CSV export, device evidence, and durable case workflows.
- Loading, error, stale-data and missing-data states, keyboard navigation, dialogs, and route history handling.
- Limited read-only Windows and macOS collector adapters with injected-provider tests and explicit target-acceptance limits.
- A versioned, validated stdout-only support-bundle export capped at 64 KiB.
- Independent HTTP boundary and support-bundle regression tests.
- Standard Linux CI for Go, UI types/tests/build, same-origin browser acceptance, and synthetic-only screenshot artifacts.

### Safety and correctness
- Formula-like CSV values are neutralized, note text is rendered literally, malformed routes are handled, and obsolete asynchronous case responses are guarded.
- Unknown or denied collection results remain explicit; valid metric quality never becomes a whole-device health claim.
- Disposable test state, screenshots of live local readings, raw logs, and support bundles are excluded from source publication.

### Known limits
- This is a local prototype with no authenticated fleet enrollment, remote actions, or production deployment approval.
- Native Windows/macOS target execution remains unverified; provider tests and cross-builds are not runtime acceptance.
- Browser acceptance is recorded in CI for each exact commit. Gallery images are added only after a real render is inspected.

## 2026-10-03 — Local diagnostics backend

### Added
- A loopback-only Go manager and JSON API.
- SQLite persistence for synthetic case notes and status changes.
- Seven clearly labeled synthetic Windows, Linux, and macOS devices with diagnostic evidence.
- Deterministic service, storage, and network investigation scenarios and read-only runbooks.
- A bounded, single-sample Linux collector plus explicit unsupported adapters for other platforms.
- API/collector/rule/persistence test coverage, build instructions, and least-privilege Linux CI.
- Product scope, API contract, platform limitations, and release gates.

### Known limits
- The browser UI is a separate upcoming checkpoint; no UI screenshot is claimed for this backend milestone.
- No operator authentication, enrolled endpoints, remote commands, privileged actions, or connected AI.
- Linux sandbox readings have incomplete host attribution. Cross-builds do not establish native Windows or macOS support.
- Local data is unencrypted and must stay private. Network exposure is unsupported.
