# Linux managed-preview transport: security review

Date: 2026-10-03. Scope: `internal/telemetry`, `cmd/dev-agent`, guarded development ingress, and the manager's explicit `--managed-preview` mode. This is a local one-shot development transport, not authenticated enrollment, a persistent agent, or production fleet management.

## Result

Source review, independent race tests and real local process/API checks pass. The reviewer independently ran two separate Linux dev-agent deliveries and verified default-off behavior, guard enforcement, replay rejection and timestamp expiry without manager fallback. The transport owner's real two-minute expiry artifact was also inspected. The exact-source managed-preview Chromium flow also passed 6/6 checks with zero runtime errors on `51c93f6f655102c25b25737c25da581b3ddd5c0f`. The associated corrected-selector general browser run passed 34/34 scenarios with zero runtime errors. [Exact CI run](https://github.com/storminator89/Tracebolt/actions/runs/37135116303). Later LAN authentication and mTLS changes are separate and are not covered by this gate.

## Verified protections and limits

- Ingress is disabled by default. The opt-in flag disables both startup and periodic manager-side sampling; the device begins unknown/awaiting, with null metrics and no fabricated last-seen time.
- The additional `dev-agent` command performs one explicitly requested delivery and exits. The existing `agent` remains stdout-only. There is no service installation, OS configuration change, persistent credential, background loop, remote control or shell capability.
- The sender accepts only canonical `http://127.0.0.1:PORT`, fixed request paths, no URL credentials/query, no DNS, no environment proxy and no redirects. A single bounded context covers session retrieval and delivery. Responses are capped at 16 KiB, headers at 8 KiB; total timeout is bounded to 100 ms–10 s.
- Ingress keeps the manager's exact Host/Origin, CSRF, content-type and loopback checks. These are not operator or sender authentication. Another local process can obtain the development session and submit a conforming bundle.
- The support-schema payload is capped at 64 KiB and requires exact fields, types and casing; duplicate/unknown/missing keys fail. Only the fixed Linux role and expected capability/evidence identities are accepted. No hostname, address, serial, account, process list, log, environment dump, or personal file content is intentionally collected. Free-text fields are not a general secret detector.
- Every timestamp must be present, internally ordered, no older than two minutes on receipt and no more than five seconds in the future. Both overall collection and generation timestamps must advance within a manager process. Rejection does not refresh receipt state.
- The receipt counter is not a sender identity. Replay memory is ephemeral and resets at restart; `managerStartedAt` distinguishes process epochs. An old still-fresh bundle may be accepted after a restart. This limitation is explicit.
- A sample becomes stale when the oldest included observation, overall collection time, or receipt ages out. Valid metric/evidence quality degrades to stale; unknown/denied stays unknown/denied. No self-collected replacement appears. Whole-device health remains unknown, and fresh telemetry does not claim that an exited sender is continuously online.
- Returned device snapshots are deep enough to prevent callers from mutating stored metric pointers or evidence arrays. Accepted-state replacement is atomic and rejected input leaves prior state unchanged.
- Linux kernel/filesystem readings retain sandbox scope limitations. No Windows/macOS transport or native acceptance is established.

## Independent execution evidence

- `go test -race ./... -count=1` and `go vet ./...`: passed on the integrated source, including the real TCP manager regression with an 11-second fake AI response.
- `tests/security/telemetry_boundary_test.go`: **five independent race-tested groups** passed for unknown startup, replay/identity rejection without refresh, oldest-field expiry, copy isolation, and literal target/redirect refusal.
- `tests/security/run_telemetry_boundary.py`: **seven real-API groups** passed using separately built manager, agent and dev-agent binaries with disposable databases:
  1. Default mode returns 404 for ingestion/status.
  2. Managed mode starts awaiting, with null metrics and no fallback sample.
  3. Missing write guard and oversized input are rejected.
  4. Two real separate one-shot Linux sender deliveries produce increasing receipts and explicitly unknown whole-device health.
  5. Exact replay returns 409 without refreshing receipt time.
  6. A mixed-age accepted sample ages out through the live API without any new post, timestamp refresh or fallback.
  7. Forged role metadata is rejected atomically.
- Inspected the transport owner's final real-process smoke report: all **14 listed checks** pass, `realExpiryObserved` and `sourceUnchangedDuringRun` are true, and the recorded source-file hashes match the reviewed tree. The sanitized report SHA-256 is `8a1461334b498b8dfc9c19af1b42a50cd7a726ace357569a8e6b738d35359779`. The recorded receipt and finish times span more than two minutes after the one-shot sender exited. This corroborates the expiry behavior without relying solely on injected clocks.
- Frontend typecheck/build and all **56 component/unit tests** passed independently. Zero/unset operational timestamps display unknown instead of a fabricated year-one date/age. Labels describe a local source rather than treating an awaiting placeholder as delivered telemetry.

A valid bundle and successful receipt do not prove machine identity or trustworthy authorship. Production transport requires separately reviewed authentication, enrollment/revocation, durable replay/audit controls, signing/distribution, availability limits and native lifecycle testing.

## Managed-preview browser evidence

The inspected pinned-source artifact confirms awaiting/unknown values without a year-one date, actual separate Linux sender delivery, UI values and provenance matching the manager, and real two-minute expiry with unchanged timestamps and stale/unknown presentation. All six checks passed. It explicitly records that telemetry was not exported and no screenshots of those real observations were captured. This does not establish Windows/macOS transport or production fleet support.
