# First bounded native macOS evidence

The manually approved [run 38448470373](https://github.com/storminator89/Tracebolt/actions/runs/38448470373)
completed on 2026-10-13 with **failure on both architectures**. It established
partial collector execution and exposed two parser compatibility gaps. It did
not establish an installed agent, production log provider or macOS release.

## Exact source and evidence

- Commit: `25547945447be3189ff6b93f90fe2bb4efc22bdf`
- Tree: `9da9d5f731be4f60b7eac920eb04e90110e2b63b`
- Reviewed source SHA-256: `9fa2782325aea4b55dd29379e0cfad589437359da9d10e215e5ae7800e17012a`
- User-started `workflow_dispatch`, first attempt, both gates selected.
- Standard `macos-15` ARM64 and `macos-15-intel` X64 runners.
- Both ran macOS 15.7.9, build 24G830, Darwin 24.6.0, Go 1.27.1,
  Apple clang 17.0.0 and SDK 15.5.

Both metadata-only artifacts passed the closed schema, source-file hash and
commit/tree/digest checks. Each archive contained only its expected bounded JSON
report. Archive hashes matched GitHub's artifact metadata:

- [ARM64 artifact](https://github.com/storminator89/Tracebolt/actions/runs/38448470373/artifacts/11838608772):
  `cc1c3642f4b9b0f344475db3a0a396a3a18fe889c2c90edd3c464b52920ed8e6`
- [Intel artifact](https://github.com/storminator89/Tracebolt/actions/runs/38448470373/artifacts/11839162640):
  `e6ee3a2509faa7653bc9e576ac5849e07fc109a0a7e4b15b00a04337a9e71cb2`

Artifacts have 14-day retention and may require GitHub access. No raw provider
values or raw log output were uploaded. The source digest above describes that
immutable first run, not subsequent diagnostic changes.

## Inventory outcomes

The unchanged `macosinventory.CollectNative` actually ran **once per runner**.

| Source | ARM64 | Intel |
| --- | --- | --- |
| Hardware model/CPU counts/RAM capacity | Passed | Passed |
| Installer receipt identifiers | Passed, 38 rows | Passed, 37 rows |
| Process accounting labels/PIDs/parent PIDs | Passed, 435 rows | Passed, 465 rows |
| Passive IPv4 interface metadata | Rejected: `invalid_metadata` | Rejected: `invalid_metadata` |
| Passive IPv6 interface metadata | Rejected: `invalid_metadata` | Rejected: `invalid_metadata` |

These are caller-visible snapshots of disposable runners. Receipt identifiers
are not complete installed-application inventories. Process counts are samples,
not a promise that every privileged process is visible.

Both resulting partial snapshots validated and round-tripped. Collection took
54 ms on ARM64 and 118 ms on Intel; outer probe execution took 66 ms and 139 ms.
The probe exited 1 with no stderr and was reaped. Inner command byte counts,
timings and individual reap observations were not exposed by the collector and
remain unknown. The fixed time/size bounds remain configured limits rather
than measurements of each internal command.

The failure code establishes interface metadata rejection after successful
command capture. It does not identify the rejected token, line or validation
branch. Those values were not retained for review. No parser relaxation or
particular root cause follows from this report alone.

## Synthetic log outcomes

Each runner started one reviewed emitter. Its one-byte acknowledgement confirms
the three fixed emission calls, not their persistence or acceptance by the parser.

Only the first positive JSON query ran. Both queries exited 0 with zero stderr,
within bounds and without a timeout. ARM64 observed 3,454 output bytes in 908 ms;
Intel observed 3,463 bytes in 1,025 ms. These bytes were parsed in memory and were
not uploaded.

Each parser rejected `unsupported_schema` after one decoded object reached event
validation. The event counter increments before required-field, attribution,
unknown-key and type checks. Therefore **no accepted synthetic event or schema**
was established. Framing completion was false; field metadata was empty and
all content-observation booleans were unknown. The exact mismatch cannot be
recovered from these reports.

The NDJSON and negative-control queries were never started. There is no native
pass for their framing, field types, filtering or private-canary behavior. The
production log adapter remains unavailable.

## Cleanup and remaining limits

Both supervisors reaped all 16 of their direct children; the separate synthetic
emitter/query children were also reaped. Both task trees were removed. Native
supervisor elapsed time was 8,427 ms on ARM64 and 10,494 ms on Intel against the
configured 120-second budget. The synthetic OSLog entries were not erased;
normal retention and disposable VM disposal apply.

The existing runner identity was nonroot with matching real/effective IDs.
Administrative group membership was not queried, so ordinary non-admin
visibility remains unproved. No enrollment, keys, account, service, TCC or
permission change was part of this run. Actual endpoint/manager interoperability,
renewal, launchd lifecycle, reboot persistence and release acceptance remain
separate gates.

Next work is evidence-based source diagnosis with bounded, content-free rejection
categories. Unknown schemas continue to fail closed. A further native diagnostic
needs exact reviewed source, explicit execution scope and a deliberate new start;
this failed run is not automatically repeated.
