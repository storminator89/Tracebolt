# Native LAN sender and foreground reporting

`cmd/lan-agent` is a foreground **Linux-only sender milestone**. It collects the existing bounded read-only observation and attempts one delivery. Optional `--foreground --interval 30s` schedules sequential bounded reports. The sender does not install a service, enroll a device, issue credentials, discover the network, download models or run arbitrary commands; guided enrollment is the separate `enroll-agent` command. Original `cmd/agent` remains stdout-only; `cmd/dev-agent` remains a localhost developer transport.

Controlled service actions are a separate default-off source feature: a complete-profile
foreground sender may run one independent action poll loop only when an existing
root-owned client grant, compatible root helper and manager action configuration
have been separately provisioned. The ordinary observation scheduler remains
read-only. The exclusive `--action-helper` mode is root-only and cannot be mixed
with sender flags; it installs or provisions nothing. See
[controlled-action helper](controlled-action-helper.md) and
[service-action workflow](service-action-workflow.md). Native host acceptance and
administrator authorization remain separate from these source checks.

Build: `go build -buildvcs=false -trimpath -o bin/lan-agent ./cmd/lan-agent`.

Run contract: `bin/lan-agent --config /absolute/path/agent.json`. The examples in `docs/examples/lan-agent.*.json` contain deliberately invalid placeholder IDs; replace them with the opaque ID returned by the administrator's manual certificate approval. No example contains a private key or usable password. These are configuration templates, not performed deployment steps.

## Preprovided configuration

The strict JSON schema discriminator is `tracebolt.lan-agent.v1`. Supply the exact manager **agent ingress origin**, approved `agentId`, client certificate/private-key file paths and private state directory. TLS is the default profile and requires an explicit server CA file with normal SAN/hostname verification. No ambient roots, environment proxy, redirect or automatic downgrade is used. Protected files follow the manager's private-file ownership/path policy. The command never puts private material in process arguments or emits it in JSON/logs.

HTTP test requires its own profile, explicit `insecureHTTPAcknowledged: true`, separate disposable client material and separate state. Only an Ed25519 client leaf directly issued by a configured manager root is supported. The sender signs the exact raw frame and locally configured origin; it does not learn a destination from server content. HTTP provides neither confidentiality nor server authentication. Network observers can read telemetry and an impersonating server can acknowledge/discard it. Use HTTPS for a trustworthy deployment.

Every DNS answer is vetted before a literal address is dialed. TLS permits explicitly configured private/loopback or ordinary global-unicast destinations with CA/hostname verification; special metadata, link-local, multicast, unspecified and transition ranges are rejected. HTTP test is restricted to loopback, RFC1918 and IPv6 ULA destinations. Public HTTP and carrier-grade/overlay HTTP address exceptions are not silently allowed.

## Exact delivery and restart behavior

The sender holds a private single-process state lock for the entire attempt. Its bounded state is tied to profile, exact origin, client certificate fingerprint and expected opaque agent ID. Changes to those listed binding fields cannot silently reuse that state or redirect pending observations. File paths and server-CA material are not themselves binding fields; a deliberate trust-anchor rotation still requires locally supplied protected configuration. An insecure/corrupt/incompatible state directory fails closed; it is not repaired by chmod or deletion of unrelated files.

Before transmission, sequence and exact request bytes are atomically persisted with file and directory synchronization. At most one pending frame of72KiB is retained in a state record of at most128KiB. A lost response leaves that frame intact. The next explicit invocation retries the same bytes, sequence and observation timestamps. A matching validated receipt clears the pending frame; a manager duplicate receipt keeps its original receipt age. Sequence is bounded to the manager's signed64-bit wire domain and is never reset or reused by acknowledgment/discard.

A pending sample older than the manager's2minute window is explicitly discarded while keeping its consumed sequence. The sender may then collect a genuinely new observation with a higher sequence. It never changes an old observation's timestamps to make delivery appear fresh. This is a bounded latest-sample buffer, not an offline history queue.

Request timeout is15seconds with5second dial/TLS/header bounds. CLI cancellation is propagated with a cooperative20second context budget. Synchronous local filesystem/fsync and stdout operations are not forcibly interrupted by that context; this is not a hard process wall-clock deadline. Default one-shot mode performs one network delivery attempt. Explicit foreground mode uses the bounded loop described in [agent-loop.md](agent-loop.md), retains its exclusive ledger lock through waits and gives each attempt its own cooperative budget. It is not an installed service. Failures print a fixed diagnostic and bounded JSON status; pending telemetry is never printed.

## Status and current evidence

Output `tracebolt.agent-run.v1` reports acknowledged/pending status, profile, sequence, duplicate/retry/stale-discard flags and percentage-field availability counts. Counts indicate collection coverage, not endpoint health. No raw readings, certificate/private key, hostname or IP is included in CLI status.

Focused tests use temporary loopback TLS and HTTP fixtures, normal ephemeral CA trust and actual built CLI subprocesses. They cover a committed manager observation followed by a lost response, exact retry from a new CLI process, receipt validation, destination changes, redirection refusal, cancellation and fresh collection after a stale pending sample. Manager restart/revocation is additionally exercised by the separate two-binary test package. Test completion evidence is recorded separately; compiling a test or cross-building a binary is not target execution.

Windows/macOS collectors exist, but LAN sender ACL/state protection and foreground/service lifecycle on those systems remain unimplemented. No installation, reboot, service recovery or uninstall acceptance is claimed. Bounded foreground scheduling/backoff is implemented. Longer offline history queues and OS service lifecycle remain separate work.


## Guided sender state requirement

`enroll-agent` emits `tracebolt.lan-agent.v2` with a separate state-binding domain.
Its private handoff initializes the exact sender counter ledger once before
publishing runnable configuration. Both one-shot and foreground v2 startup
require that existing bound ledger; missing paths, locks, ledger files, replaced
empty directories or a different binding cannot silently initialize a new
counter. Resumed enrollment uses a read-only existing-ledger validation under the
same exclusive lock and never removes sender-owned crash temporaries. Stop an
active foreground sender before revalidating its completed enrollment handoff.

Manual `tracebolt.lan-agent.v1` preserves its original fresh-state behavior. There
is no automatic migration between v1 and v2 bindings. A structurally valid older
backup cannot establish the latest sequence floor by itself; restoring a live
identity remains an explicit recovery operation, not a transparent reset.
