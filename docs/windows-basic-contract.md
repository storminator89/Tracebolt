# Windows Basic: inert contract foundation (TB-21 / #148)

**Not an enabled endpoint profile, new release, or completed authorization fix.**
`internal/windowsbasic` contains only a proposed minimal data contract and a
closed profile/route policy. No production component calls it. Existing Rust
Basic still enrolls under `windows-inventory-v1`; a small collector is not a
server-side restriction. Keep #148 open until the complete integration below is
implemented and accepted. The current Rust compatibility advertisement is not
changed to claim support for this foundation.

## Revalidated starting point

Baseline: main `f53f5cccd8c9613008bfecab5412475b872e0092`, 2026-10-31.

- Rust `src/protocol.rs` sends `tracebolt.agent-telemetry.windows.v1` with
  mandatory unavailable Windows inventory sections. `src/enrollment_wire.rs`
  binds `windows-inventory-v1`. These bytes remain unchanged here.
- `internal/rustcompat` and `internal/api/rust_basic_capabilities.go` advertise
  that same inventory domain. They do not enforce a Basic-only domain.
- `Material.WindowsStoreConfig`, `enrollment-windows.db` and the exact mode
  marker bind the existing Windows inventory identity. Reusing/relabeling that
  ledger as Basic would violate identity and consent preservation.
- The current ingress can parse Windows inventory frames v1-v16 and separately
  dispatch extended read/action protocols. Collector version or capability text
  must never select its authority.
- #128 and #147 remain dependencies. The #147 UI work is independent; this
  change edits none of its files. Open PR #178 contains UI work, not a new Basic
  server domain. No open Basic-domain implementation was found in the PR/branch
  review at this baseline.
- The latest published integrated test candidate observed in release metadata
  was `v0.1.0-integrated-rust-test.fb0a6dd3343d.41176813099`, source
  `fb0a6dd3343dca2feb3ea0b24f8251f116837b6b`. Its reported Rust ZIP digest was
  `sha256:9104838e1fa16c40914716af27996efdb9c873de40f5f0436c1aa86877b62bbc`.
  This is repository asset metadata, not a local download/hash verification or
  acceptance of those bytes. No asset or tag is modified here.

## Proposed minimal wire

- Collection profile: `windows-basic-metrics-v1`.
- Frame: `tracebolt.agent-telemetry.windows-basic.v1`.
- Exact telemetry route: `POST /v1/windows/basic/telemetry`, TLS only.
- At most 2,048 UTF-8 bytes, exactly seven case-sensitive JSON fields, no unknown
  or duplicate keys (including escaped duplicate names), no trailing JSON.
- `schemaVersion`, positive safe-integer `sequence`, canonical whole-second UTC
  `collectedAt`, and four required nullable scalar measurements:
  `cpuPercent`, `physicalMemoryPercent`, `systemVolumeUsedPercent`,
  `uptimeSeconds`.
- CPU means the processor group observed by `GetSystemTimes`; physical memory
  means `GlobalMemoryStatusEx`; system-volume capacity means caller-quota used
  percentage from `GetDiskFreeSpaceExW`. These are fixed contract semantics, not
  agent-selected source labels or a claim of whole-machine/all-volume coverage.
- Percentages are finite values in [0,100]. Sequence and uptime cannot exceed
  2^53-1. Null means unavailable, not zero or healthy. All-null measurements are
  a contact only, never evidence of host health.
- Capture age is at most two minutes, with at most thirty seconds future skew.
  `Decode` needs a valid server clock. This validation does not update freshness,
  authorize a credential, persist a report or advance a replay floor.
- No hostname, IP, software, processes, services, log content, action, free text,
  sender identity, agent version/type, capability or client-selected profile.

`ProfileAllowsRoute` is only a pure closed policy table. Its platform, transport
and collection-profile inputs must come from the server's immutable approved
identity, never a request claim. It permits only the exact proposed Basic tuple
and route; every other method, route and profile is denied. It is deliberately
**not** named or documented as credential authentication. Adding new inventory
routes cannot widen this equality-based policy.

## Required coherent runtime integration (not delivered here)

1. **Fresh independently configured domain.** Add an explicit default-off Basic
   switch, immutable create-only domain marker and separate bounded DB. Define
   initialization/crash/readback semantics before writes. Existing Linux,
   Windows inventory, macOS, mode markers, tombstones and used floors retain
   their exact bindings/bytes. No fallback, migration, auto-adoption or relabeling.
2. **Enrollment and compatibility together.** Admit the new platform/transport/
   profile only when its actual store, proof/intent/certificate binding and
   ingress exist. Give it unambiguous dedicated enrollment/bootstrap and public
   compatibility routing. Keep old Rust v1/Go inventory contracts compatible;
   advertise a new Basic capability version only for this real domain. Reject
   an incompatible manager before state/lock/key/CSR or installer mutation.
3. **Strict ingress and durable authority.** Bind the route to the new store;
   never dispatch it to the old Windows inventory handler. Before calling the
   path-only policy, require canonical Host/authority, RawPath/RequestURI/path,
   query/fragment absence, exact method/content framing and bounded headers/body;
   decoded path equality alone is insufficient. Require approved TLS trust and
   current leaf possession, then recheck original
   profile/platform identity, activation, revocation, expiry, live clock and
   replay floors in the final retaining transaction. Persist exact retry bytes
   and return original receipts without rejuvenating capture/receive age.
   Direct store calls require the same profile guard. Extended setup/read/action
   handlers must refuse Basic even if separately invoked or misconfigured.
4. **Rust state and local approval.** New config/enrollment/sender schema and
   fresh explicit Basic consent; no reuse of current inventory credentials,
   state, receipts or counters. Use only this scalar frame. Existing v1 retained
   state remains readable by its original version; incompatible versions stop,
   never delete or rewrite it. Basic-to-Read-admin means a new explicit enrollment
   and exact scope approval, not a capability toggle or in-place conversion.
5. **Projection, UI and release.** Derive Basic support from original server
   binding, not `agentVersion`, tags or telemetry capabilities. Show actual
   consent separately from support/evidence; unavailable stays unknown. Deny
   inventory/action entry points without hiding unresolved operations. Align
   download cards, manager/frontend/Rust manifests, required protocol, hashes
   and same-source artifact builds; publish new immutable bytes only after
   review and authorized release gates. Do not modify old assets/tags.
6. **Independent protocol/authorization review and evidence.** Review this new
   domain and its final transaction/mux boundaries independently before merge.
   Record exact final SHA/tree and artifact hashes, OS/architecture/profile and
   the tests actually run. Keep unit/policy, protocol fixture, cross-build,
   synthetic browser, native execution and real cross-platform E2E distinct.

## Acceptance matrix

| #148 criterion | Foundation evidence | Remaining evidence |
| --- | --- | --- |
| Basic accepts only advertised metrics; expanded routes fail server-side | Strict scalar parser; all current expanded agent-route families denied by pure policy | Authenticated final ingress/store negative tests, exact route/mux binding, no read/write effects |
| Existing Go profiles/wire remain compatible | No edits to existing runtime/Rust/Go contracts; regression checks reported per run | Final combined integration compatibility fixtures and artifact evidence |
| Spoofed version/type/capabilities never expand rights | Such fields fail the new parser; route policy takes no client metadata | Spoofing against actually enrolled Basic credential, immutable domain and final transaction |
| Basic-to-Read-admin needs fresh explicit scope approval and matching receipt/UI/authority | Inert profile is not admitted or falsely advertised; no transition exists here | New-domain enrollment, rejected in-place reuse, unchecked exact approval, UI/receipt matching |

### Negative matrix for the future actual ingress/store tests

Use an activated Basic credential and compare before/after durable state. Denial
must happen without invoking privileged helpers, enqueuing work, adopting a
grant, changing a replay floor or refreshing retained freshness. Include direct
store/configuration seams, not only HTTP routing:

- Old Windows telemetry v1-v16 with every optional extension, complete services,
  complete machine/selected-user software, full processes and network context.
- Event content/history capability, peek, claim, result and status.
- Selected service action capabilities, peek, claim and result.
- WUA poll/readiness/install/download/retirement/report; software-job poll,
  readiness/install/report; managed MSI poll/chunk/report.
- Linux telemetry, inventory, cached updates, overview, system metadata,
  journal and service-action routes; other-platform Basic/inventory routes.
- All old identities targeting the new Basic route; Basic identities targeting
  other stores; claimed inventory profile/version/type/capabilities; duplicate
  keys, extra sections, path aliases, query tricks and unrecognized routes.
- Missing/mismatched current leaf, revoked/expired/unactivated identities,
  activation/clock races, stale/future capture, reordered sequence, identical
  retry after restart and response loss, divergent same-sequence bytes, old
  receive/capture age, broken/missing used state and concurrent revocation.

The source tests in this change exercise the **pure policy and parser only**.
They are not the authenticated matrix above and do not establish native runtime
acceptance, a compatible new release, host setup or an expanded scope grant.

## Rollback

This foundation creates no runtime state. Removing it has no effect on existing
identities or reports. Future integrated rollback must disable only new Basic
admission, retain its original identity/tombstones/replay state and preserve all
old profile domains. Deleting used state or converting a ledger is not recovery.
