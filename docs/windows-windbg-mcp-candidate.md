# Optional WinDbg MCP dump evidence: source-contract candidate

Status: **source contract and synthetic tests only**, researched 2026-10-07.
This revision does not provide an operational WinDbg integration. It does not
install or discover WinDbg, launch a proxy, connect a session, execute debugger
commands, capture/read/upload dumps, call a model, or grant permissions.
`internal/windbgcontract` has no production callers or route. Its readiness
result always reports `ready: false` and `connectionImplemented: false`.

## Why this is useful

Recommended first scope: an operator selects an **existing dump** to investigate
an application crash, hang, or kernel crash. This can add call stacks, exception
and module information to a case that ordinary counters and event summaries
cannot explain. A later UI should show observations, hypotheses, counterevidence,
missing symbols/memory, and the exact evidence supporting each hypothesis.

It does not replace normal health monitoring, establish current machine state,
or guarantee a root cause. A dump is a historical snapshot. Missing or mismatched
symbols and missing minidump memory limit what can be concluded. A single hang
dump may show a wait without proving a deadlock or how it developed. Microsoft
explains the symbol and minidump limits in
[Analyzing a user-mode dump](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/analyzing-a-user-mode-dump-file).

## Verified Microsoft contract and limits

- MCP is included starting with **WinDbg 1.2610.1001.0**. The supported clients
  are VS Code with GitHub Copilot and GitHub Copilot CLI. Other clients are
  custom, best-effort integrations, so Tracebolt must not imply Microsoft support.
- Setup requires permission for the target and data, the selected client, and its
  model service. An administrator's restricted-mode policy can disable MCP.
  Registering the server and starting its service are distinct from attaching a
  target. Follow [Microsoft's setup instructions](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/set-up-windbg-mcp).
- The client talks stdio MCP to `DbgX.Mcp.Proxy.exe`, which talks to one WinDbg
  session over a local per-process named pipe. Only one active MCP client is
  allowed per session. `list_sessions`, `connect_session`, and
  `disconnect_session` are documented connection tools. The consulted pages do
  not provide a complete stable schema for every debugger tool.
- Full Secure Mode requires starting MCP before connecting the target. Starting
  later yields partial mode. Secure Mode stays active until WinDbg restarts.
  XPIA output protection requires permitted MCP sampling; unavailable
  classification fails protected operations without returning output. Neither
  protection should be disabled as a compatibility workaround.
- Local debugger transport does **not** mean data stays local: the client can
  send debugging context to its model service. Sampling classification is also
  model use. Diagnostic logs can contain target data. See the
  [WinDbg MCP overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-mcp-overview).
- The general [WinDbg installation page](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)
  lists Windows 11, Windows 10 version 1607 or later, and x64/ARM64 hosts. That
  is a general prerequisite, not evidence that this candidate runs on every such
  host. Windows Server MCP deployment is not established by those requirements.
- [Copilot CLI](https://docs.github.com/en/copilot/concepts/copilot-surfaces/copilot-cli)
  is available with Copilot plans and may require organization policy enablement.
  An own Tracebolt client/model path would need separate compatibility and terms
  review; it is not the supported Copilot workflow. This candidate does not
  establish redistribution rights. Keep WinDbg as a separately installed
  prerequisite; do not bundle Microsoft binaries or claim included model usage.

The [announcement](https://devblogs.microsoft.com/performance-diagnostics/introducing-windbg-mcp-debug-with-natural-language-grounded-in-evidence/)
provides the launch context. Manual supported-client proxy configuration and
sampling/elevation troubleshooting are documented in
[Microsoft's troubleshooting guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/troubleshoot-windbg-mcp-setup-connection-issues).
Use the proxy path supplied by the installed WinDbg configuration, not a guessed
path or a similarly named third-party package. Never automatically disconnect
another user's/client's session to acquire it.

## Intended architecture, not implemented runtime behavior

1. Keep the Windows LocalService agent at its existing low privilege. Do not add
   SeDebugPrivilege, process-memory access, arbitrary shell, a remote-debug port,
   or a WinDbg dependency to the enrollment/SCM service.
2. Use a separate, interactive, least-privilege Windows analysis companion. Its
   future trusted local probe should check the signed installed proxy/version,
   administrator policy, client sampling capability, intended session and target,
   Secure Mode, and XPIA without weakening protections. Failure stays unavailable.
3. First operator flow: choose an existing local dump; disclose that memory,
   source, symbols, usernames/paths, and logs may be sensitive; select the model
   destination; approve that exact data use. A local-model option must also
   implement sampling and be tested; selecting a local model is no compatibility
   guarantee. XPIA sampling must not silently send data to another provider.
4. Start with a fixed reviewed diagnostic plan, per-session time/output budgets,
   explicit session identity, audit records, and an exclusive connection. Derive
   actual MCP tool mappings from the authorized installed server's negotiated
   tools/capabilities. Pin/review schema changes; do not assume fixture command
   strings are real MCP tool names or safe command-dispatch policy.
5. Preserve target hash/identity, original dump capture time (or unknown), analysis
   time, version, symbol quality, command, output hash, evidence IDs, and synthetic
   provenance. Hashes are integrity references, not authenticity or consent.
6. Keep raw evidence local by default. A later export boundary must separately
   authorize the data/source and exact model destination, minimize/redact, and
   bind the grant to the selected dump/session and expiry. Redaction cannot prove
   absence of secrets. Transport encryption alone cannot provide that permission.
7. Feed an explicitly approved, bounded evidence packet into a separate AI scope
   only after that boundary exists. Cite known evidence IDs, retain assumptions
   and gaps, and treat every output as untrusted data rather than instructions.
   This source is deliberately absent from the existing analysis allowlists,
   including health-summary-v1; existing local-AI setup is not a dump-data grant.

Proactive assistance may suggest investigating a crash/hang when already
approved telemetry supports it. That suggestion does not authorize installing a
debugger, collecting a dump, attaching to a process, launching MCP, uploading
memory, or creating persistent access. Future live debugging, TTD capture,
process control, new extensions/scripts, memory writes, shell/file operations,
and remote debugging need a separately reviewed workflow and explicit approval
for the concrete action and its impact.

Even Microsoft's [noninvasive user-mode debugging](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/noninvasive-debugging--user-mode-)
suspends the target threads. It is not impact-free. Examining an existing dump
avoids attaching to that running application, but parsing data/extensions can
still affect the analysis host. Secure Mode is not a read-only sandbox or an
extension trust guarantee. The older
[general Secure Mode restrictions](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/features-of-secure-mode)
and newer MCP startup flow must be checked on the concrete release; if target
opening or symbols are blocked, stop rather than disabling protection.

## What this source slice actually implements

- `Assess`: pure evaluation of supplied observations. The zero value is disabled.
  Missing/unsupported host, version, proxy identity, policy, session, existing
  dump, full Secure Mode, XPIA, or sampling gives explicit blockers. Even a
  perfect fixture requires an unimplemented transport and native verification.
  No observation is collected here, and caller-supplied booleans are not grants.
- `Validate`: a typed local evidence contract, separate from MCP wire messages
  and `analysis.Packet`. It bounds records, output and encoded bundle size;
  validates IDs, dump kind, timestamps, hashes and symbol status; rejects duplicate
  IDs and arbitrary/compound command labels; and preserves unknown capture time,
  incomplete symbols, original content and the synthetic label. Errors do not
  reflect supplied target data.
- The five exact command labels (`!analyze -v`, `!analyze -hang`, `~* kb`, `lm`,
  `kv`) are fixture labels only. Nothing dispatches them. They neither make a
  live target safe nor authorize indirect extension behavior. The hang option's
  behavior is described in [!analyze](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-analyze).
- Validation always labels output untrusted, AI export disallowed, and root cause
  unconfirmed. It verifies structure/integrity only, not whether evidence is true,
  an output is prompt-injection-free, or a hypothesis follows from that evidence.

No installer flag, enrollment profile, service permission, endpoint route,
existing AI filter, model configuration, dependency, UI, or release claim changes.

## Required acceptance gates before any usable integration

- Authorized disposable Windows host with the pinned WinDbg release and an
  approved client/model. Verify licensing/setup, standard-user startup, signed
  proxy discovery, real MCP negotiation and tool schemas. Cross-compilation does
  not satisfy this gate.
- Verify full Secure Mode before target opening, approved symbol loading, XPIA
  and sampling including failure/blocked-output paths. Never resend XPIA-blocked
  output through another route. Check denied policy and elevated-session failure.
- Use synthetic known crash/hang dumps with symbols. Verify provenance, wrong
  target/session prevention, single-client contention, disconnect/cancel,
  deadlines, partial output, missing memory/symbols, version changes and no
  command chaining or unexpected extension/network behavior.
- Build and independently review the local permission, protected storage,
  retention, redaction, provider/sampling destination and consume-once request
  boundary before adding any production caller or AI export.
- Separately authorize and test any future dump capture, live attach, privileges,
  service wiring or deployment. The implementation request for this candidate
  does not grant those actions.

### Safe source checks

`go test -race -count=1 ./internal/windbgcontract`

`go vet ./internal/windbgcontract`

`CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -c -o /tmp/windbg-contract-amd64.test.exe ./internal/windbgcontract`

Repeat the compile for ARM64. The test binaries are compile artifacts only and
must not be described as Windows execution or integration acceptance.
