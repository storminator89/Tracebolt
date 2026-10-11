# Windows Users / Sessions context

Source candidate, 11 October 2026. A private Users / Sessions view reports the
Windows sessions visible to the existing service caller and this computer's
local domain/workgroup join context. It is not a full user/account inventory,
logon history, directory inventory or proof of a domain connection. Native
acceptance and the published Windows preview remain unchanged.

## Explicit local consent

`windows-session-context-v1` is a separate default-off scope. For an existing
activated, receipt-owned inventory service, stopped by its authorized operator:

- `windows-service --session-context-preview`
- `windows-service --session-context-enable --apply --user-session-join-metadata`
- `windows-service --session-context-disable --apply`

The complete disclosure explicitly calls user, domain and session labels
personal metadata. It must finish before dispatch; an HTTP-test identity also
requires `--insecure-http-test` and its separate plaintext warning. A protected
create-only `-session-context` sibling binds the exact new grant to the existing
sender identity. The sender lock spans configuration. Missing used state and
foreign/unsafe state fail closed. Disable preserves state; explicit re-enable
creates a new grant. No older grant, five-scope Setup receipt, account or service
is promoted, reset, restarted or modified by this new scope. Source commands
are not permission to execute them on a host.

## Fixed local sources and exact bounds

The WTS worker calls only `WTSEnumerateSessionsW` with
`WTS_CURRENT_SERVER_HANDLE`, Reserved=0 and Version=1. The returned count is
checked before traversal: above 4096 is unavailable/bounds, never a complete
empty list. At most 4096 numeric session IDs/states are traversed and sorted;
duplicate IDs invalidate the result. At most 32 lowest-ID rows are retained.
Station-name pointers are never read. Only retained IDs are queried through
`WTSQuerySessionInformationW` for `WTSUserName`, `WTSDomainName` and
`WTSClientProtocolType`. No remote server handle is accepted or opened.

Each row has a session ID, user/domain labels when permitted, WTS connection
state, and Console/RDP/unknown protocol. Empty labels are distinct from denied
or unavailable labels. A service/listener session can appear; a row does not
prove a logged-on interactive user. The WTS `idle` connection-state enum is not
an activity/idle-time measurement. No client name/IP, SID, token, credential,
command line, logon time, history, input/keystroke or activity counter is read.
User/domain labels are at most 64 UTF-16 units each. Returned byte lengths are
checked before copying; odd, unterminated, control-bearing or malformed UTF-16
is unavailable, never silently repaired. Protocol admits only the documented
0 (console) and 2 (RDP); unfamiliar values remain unknown.

The independent join worker calls `NetGetJoinInformation` with NULL server.
It returns only unjoined/workgroup/domain/unknown and a bounded name when
available. The allocated buffer is sized with `NetApiBufferSize`, capped at
514 bytes before copying, decoded with at most 256 UTF-16 units, and freed with
`NetApiBufferFree`. A known join type can coexist with an unavailable name;
unknown/denied never becomes unjoined. This does not query Active Directory,
Microsoft Entra ID, trust health, groups, accounts or remote connectivity.

Windows allocates these native API buffers before returning and offers no
pre-allocation limit parameter. The source bounds its own traversal, copies,
retained rows and child lifetime; it does not claim a cap on Windows/provider
internal allocations. Every returned allocation is freed on success and error.
Observed count means the count returned by that caller's successful WTS call,
not all sessions or users on the host. Retained and truncated counts stay exact;
unavailable enumeration has unknown counts, not zero assertions. Field/query
races are partial metadata, not an atomic logon snapshot.

Primary references:

- [WTSEnumerateSessionsW and query permissions](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsw)
- [WTSQuerySessionInformationW and returned byte counts](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw)
- [WTS information classes and protocol values](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_info_class)
- [WTS session structure](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wts_session_infow)
- [NetGetJoinInformation local semantics](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetjoininformation)
- [Network API buffer sizes](https://learn.microsoft.com/en-us/windows/win32/api/lmapibuf/nf-lmapibuf-netapibuffersize)

## Isolation, transport and private lifetime

WTS and join each run in a fixed private mode of the current protected
executable. Each child authenticates the restricted service identity, live SCM
parent, creation time, executable hash, activated material/ready receipt and
exact new grant before and after capture. No path, executable, query, server,
credential or grant is trusted from IPC. There is no impersonation, elevation,
permission adjustment, session disconnect/logoff, account change or native
service action. LocalService denial is an honest unknown result.

Each owned worker is killed and synchronously reaped after at most two seconds,
with a 100 ms inherited-pipe wait bound and the existing independent 20-second
parent-loss watchdog. One provider's timeout cannot erase the other result.
The combined source receives at most five seconds. Co-enabled cached updates,
patch context and Security retain bounded budgets and the shared three-second
primary-delivery reserve inside the unchanged outer attempt. A depleted optional
budget yields a finite unavailable result; no native goroutine is abandoned.

The canonical worker request is at most 1 KiB; the snapshot at most 24 KiB.
Signed transport `tracebolt.agent-telemetry.windows.v11` requires the separate
`windowsSessionContext` section; v1–v10 and their original bytes remain unchanged
when absent. Every sibling keeps a distinct grant. Sections share the exact base
generation and conservative original capture, not an atomic read timestamp.
Fitting drops whole optional rows, preserving base/self rows, source authority,
original age and observed/retained/truncated counts inside the 72 KiB frame.

Activated material and exact consent are rechecked before read, after capture,
before staging and before send/retry. Retry preserves exact wire bytes and age;
replacement/revocation suppresses old pending personal metadata. The durable
capture floor also protects later scope-absent frames. Only authenticated private
Windows inventory projection exposes `sessionContext`, with current identity,
revocation, staleness and 24-hour privacy expiry. It is absent from basic/public
observation, AI/provider inputs, health policies, exports, notifications and
alarms. The EN/DE UI has compact membership/session rows and collapsed source
scope/count details, with no session action or remote-desktop integration.

## Verification boundary

Essential portable fixtures cover canonical model and native parsers, consent,
current material, authenticated worker revalidation and kill/reap, source-driven
sender-to-manager TLS ingress and signed HTTP-test handlers, exact retry/restart,
original expiry, old-wire rejection and private UI lifetime/navigation. Transport
handler fixtures are not a real socket/TLS handshake. Windows amd64/arm64 builds
establish compilation only. The existing hosted inventory browser flow now navigates Users / Sessions,
opens source details, verifies remount clearing and requires eight exact-source
EN/DE desktop/mobile summary/detail captures. Actual hosted pixel review remains
a publication gate; local Chromium socket creation is unavailable.

Separately authorized disposable Windows acceptance must establish actual
LocalService session visibility and denied labels, Console/RDP/disconnected and
listener rows, domain/workgroup/unjoined results, native bounds/timeouts and
revocation/replacement through the manager/browser. Source fixtures authorize
no host read, grant, installation, credential, session/account or permission
change. Integrated remote desktop and account administration remain deferred.
