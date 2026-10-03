# Linux loopback transport preview

This optional development mode tests a real, separate Linux collector process sending a bounded observation to the local manager. It is not authenticated enrollment, a persistent managed agent, or a production fleet transport. Keep the manager on its fixed loopback listener; never expose it through a reverse proxy or tunnel.

## Run the two processes

Build the UI and the manager using the normal project instructions. Build the additional, Linux-only one-shot sender:

```sh
go build -buildvcs=false -trimpath -o bin/dev-agent ./cmd/dev-agent
./bin/manager --managed-preview --port 8787 --db .local/transport-preview.db
```

In a second terminal in the same network namespace:

```sh
./bin/dev-agent --manager http://127.0.0.1:8787
```

The manager starts with an awaiting/unknown Linux role and no collected metrics. This mode disables both startup and periodic manager-side collection. The sender invokes the existing read-only Linux collector, obtains an ephemeral development CSRF session, sends one support-schema observation, prints a bounded receipt, and exits. It does not install a service, remain in the background, create an enrolled identity, or persist credentials. The normal `cmd/agent` command remains stdout-only.

The sender requires an explicit canonical `http://127.0.0.1:PORT` origin. Hostnames, remote IPs, IPv6, HTTPS, credentials, paths, query strings, redirects and environment proxies are unsupported and fail closed. The total session-plus-delivery timeout defaults to five seconds and is bounded to 100 ms–10 s. Session and receipt bodies are each capped at 16 KiB.

## What the UI and API represent

- The fixed role is `sandbox-local`, with source `sandbox`, platform `linux`, and overall health `unknown`. This is not a unique machine identifier.
- Seven synthetic demonstration devices remain separate and unchanged.
- `GET /api/dev/telemetry/status` reports `awaiting`, `fresh` or `stale`; separate `collectedAt` and `receivedAt`; a receipt count; and `managerStartedAt` identifying this in-memory manager epoch.
- `POST /api/dev/telemetry` is enabled only by the manager flag, with the existing exact Host/Origin, loopback peer, content-type and CSRF guards. These guards are not operator or sender authentication. Any local process able to obtain the development session can submit a conforming bundle.
- The regular device API adds a transport capability and `local-agent-transport` evidence. The evidence describes the receipt without claiming to authenticate the originating process. An actual separate-agent invocation is established by the smoke test, not by trusting a client-supplied label.
- Valid metric quality describes successful collection, not endpoint health. Missing fields are unknown/denied, never invented as zero. Unsupported systemd/service inventory, system logs and remote actions remain explicit.
- The Linux collector reads only bounded fixed OS/kernel sources. Kernel counters may describe a shared host; cgroup limits and physical-host attribution are not established.

## Freshness, schema and privacy

Payloads are limited to 65,536 bytes using `tracebolt.support.v1`. The parser rejects duplicate, unknown, missing, case-aliased and incorrectly typed fields, invalid metric values, unrecognized fixed-role labels, private identifier fields, synthetic observations, fake trend/case history and unsupported capability claims. The intended payload excludes hostnames, IPs, serials, accounts, process lists, logs, environment variables, personal file contents and credentials. Free-text OS/source descriptions are still system characteristics; this schema is not a general-purpose secret detector.

All observation timestamps must be present, at most two minutes old on receipt, no more than five seconds in the future, and consistently ordered. Within one manager process, collection and generation timestamps must both increase. Duplicate or out-of-order data is rejected without refreshing receipt time. The server's sequence is a receipt counter, not a sender sequence or authentication mechanism. Replay memory resets when the manager restarts; the public `managerStartedAt` changes so counters from separate runs are distinguishable.

Freshness expires when any included metric/evidence timestamp, overall collection time, or manager receipt ages beyond two minutes. The manager preserves the actual timestamps and degrades valid observations to stale without recollecting or substituting a fallback sample. A fresh observation never asserts that the exited one-shot agent remains continuously online.

## Verification

```sh
go test -race ./internal/telemetry ./cmd/dev-agent ./internal/api
python3 tests/security/run_transport_smoke.py --wait-stale \
  --report artifacts/review/transport-smoke.json
```

The default report contains validation results, count/state transitions and source, binary and observation-response hashes, without raw observations or receipt timestamps. An optional `--private-report /tmp/tracebolt-private.json` saves local proof outside the repository; never publish that file or real-sample screenshots.

The Python runner builds disposable binaries, starts a disposable database and loopback manager, invokes the actual separate Linux sender, checks transport and guard failures, and optionally waits for real timestamp expiry after sender exit. All subprocesses must run in the same execution/network namespace. The runner terminates its manager and removes its temporary state. It changes no OS/service configuration. Unit tests also cover manager-offline, total timeout, redirect/proxy rejection, malformed responses and mixed-age freshness.

Windows/macOS native acceptance, signed distribution, service lifecycle, remote networking, production authentication, enrollment/revocation, persistent agent identity, durable replay/audit controls and unattended monitoring remain outside this preview.
