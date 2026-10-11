# Windows parity review status

Review snapshot: **11 October 2026, 00:46 UTC**. This page records subsequent source
and CI progress. The [parity matrix](windows-linux-parity.md) retains its historical
10 October baseline at `3ba4459a3151223ce98ac58c40471afa73576365`; its table is
not a current runtime-coverage claim.

## Reviewed source and CI

Commit links pin the reviewed heads. Each of PRs **#26–#33 has five tracked
exact-head CI workflows green**. These results apply only to the linked commits,
not later branch commits or this documentation-only refresh. Source/fixture checks,
browser scenarios and cross-builds prove only their exercised scope; they do not
establish release or native Windows-to-Linux installed-service acceptance.

| Review | Source or documentation scope | Exact reviewed head | CI at this snapshot |
| --- | --- | --- | --- |
| [#26](https://github.com/storminator89/Tracebolt/pull/26) | Windows parity foundations | [`83aa24f`](https://github.com/storminator89/Tracebolt/commit/83aa24f4cc00c03603c539972e0ed8dad38e563f) | 5/5 workflows green |
| [#27](https://github.com/storminator89/Tracebolt/pull/27) | Default-off cached Windows Update inspection and Updates UI | [`1b8c164`](https://github.com/storminator89/Tracebolt/commit/1b8c16402ec463c97630d1e08eca8129b8c79e63) | 5/5 workflows green |
| [#28](https://github.com/storminator89/Tracebolt/pull/28) | Default-off exact selected event messages and Logs UI | [`103e1d7`](https://github.com/storminator89/Tracebolt/commit/103e1d7100e9517d4072c8dcf441dce75e8f1983) | 5/5 workflows green |
| [#29](https://github.com/storminator89/Tracebolt/pull/29) | README, license and five genuine Windows screenshots with provenance | [`430f25b`](https://github.com/storminator89/Tracebolt/commit/430f25b48e6d9083ea94e8d8b6110afb4c7dbefd) | 5/5 workflows green |
| [#30](https://github.com/storminator89/Tracebolt/pull/30) | Test-performance work | [`9b9e629`](https://github.com/storminator89/Tracebolt/commit/9b9e6290d4fcf91d279c2b0fa7d6c2aaeae78830) | 5/5 workflows green |
| [#31](https://github.com/storminator89/Tracebolt/pull/31) | Default-off disk, CPU and physical-RAM health policies | [`72bfa0d`](https://github.com/storminator89/Tracebolt/commit/72bfa0dbe200a6c63d5deb1d46aaa3bb93b96ab6) | 5/5 workflows green |
| [#32](https://github.com/storminator89/Tracebolt/pull/32) | Default-off selected-service health policy | [`5aefcc5`](https://github.com/storminator89/Tracebolt/commit/5aefcc58ed6eceb31c22768bc37780e3d244a239) | 5/5 workflows green; enrollment coverage caveat below |
| [#33](https://github.com/storminator89/Tracebolt/pull/33) | Test-only restoration requiring all 13 original enrollment cases | [`fbdb00e`](https://github.com/storminator89/Tracebolt/commit/fbdb00e380794a4d0bcec0a662b5ad5a17607e09) | 5/5 workflows green; 13/13 original enrollment cases passed |

PR #32 [Validate run 38096891734](https://github.com/storminator89/Tracebolt/actions/runs/38096891734)
exercised merge checkout [`c9bbac8`](https://github.com/storminator89/Tracebolt/commit/c9bbac84ad227e51871f82e3e6cd6e28f3ea23e0),
exact tree `20fbd17f2b114b110e135566c4d7a63b9c5780b2`: **26 LAN browser cases
passed; enrollment had 10 passes and 3 quarantines**. Its green workflow must not
be read as all 13 enrollment cases passing.

PR #33 [Validate run 38098190228](https://github.com/storminator89/Tracebolt/actions/runs/38098190228),
[browser job 114349972686](https://github.com/storminator89/Tracebolt/actions/runs/38098190228/job/114349972686),
passed **all 13 original enrollment cases: 0 failed, 0 skipped, quarantines disabled**.
The checkout and report source is [`4fadd1a`](https://github.com/storminator89/Tracebolt/commit/4fadd1aa675ff89ccee0aef689af76407d59fc49),
tree `46795065ed01d0cf6aa86f7c4a2854203a8afdd2`, matching the listed head's tree.
This covers built React, real loopback HTTP handlers, a disposable database and
the native enrollment-client library. It does not establish actual CLI/telemetry,
installed-service, trusted-TLS browser or native Windows acceptance.

## Implementation and release boundaries

The #31/#32 health implementations are separately reviewed source; **PR #29's
documentation changes do not add that runtime implementation**. They evaluate
existing accepted inventory through independent opt-in manager policies. Disk is caller-visible, quota-aware
system-volume capacity; CPU covers the observed processor group; RAM describes
physical memory not immediately available. Selected-service checks require a
unique exact reported name: missing or duplicate rows stay unknown. These policies
add no host-read grant, service action, automatic notification or AI export.
See the pinned [percentage-health source](https://github.com/storminator89/Tracebolt/blob/72bfa0dbe200a6c63d5deb1d46aaa3bb93b96ab6/docs/windows-resource-health.md)
and [service-health source](https://github.com/storminator89/Tracebolt/blob/5aefcc58ed6eceb31c22768bc37780e3d244a239/docs/windows-service-health.md).

The published unsigned x64
[v0.1.0-windows-preview.1](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.1)
remains unchanged. It contains none of these later cached-Update, selected-message
or health-policy increments. Existing Setup receipts and manager upgrades do not
grant new endpoint scopes. The [preview status](windows-status.md) and
[installation evidence](windows-prerelease-install.md#selected-native-evidence)
retain their own exact-byte and limited hosted Windows Server 2025 boundaries.
The [five Windows screenshots and provenance](screenshots/2026-10-10-windows-parity/README.md)
are genuine dashboard captures using invented data, not native acceptance evidence.

## Remaining priorities

- **Native interoperability and lifecycle:** prove the exact new Windows source
  against the production Linux manager and shared browser, then separately cover
  installed-service behavior, interruption/recovery, upgrades, reboot, Windows
  10/11, ARM64 runtime and signing/distribution.
- **Retained event browsing:** older-event retrieval, bounded continuation,
  source-cursor loss and content search beyond exact selected messages.
- **Complete inventory generations:** bounded process/service/software samples
  and local UI paging do not establish complete host coverage.
- **Windows Update/CVE mapping:** cached inspection does not supply online
  discovery or trustworthy product/build/update/advisory matching; a KB alone
  does not establish applicability or vulnerability coverage.
- **Remote service and update actions:** separately reviewed exact-target plans,
  explicit approval, least-privilege execution, durable one-use boundaries and
  truthful partial/reboot outcomes. Local Tracebolt lifecycle is not remote SCM.
- **Separately authorized AI scope:** typed Windows evidence and explicit
  provider/data approval; existing AI settings do not authorize events or dumps.

These priorities follow the [subsequent source roadmap](https://github.com/storminator89/Tracebolt/blob/5aefcc58ed6eceb31c22768bc37780e3d244a239/docs/windows-linux-parity.md).
Neither platform has unrestricted remote shell or general file management.
Source progress and default-off policies must not be described as shipped or
natively accepted Windows/Linux parity.
