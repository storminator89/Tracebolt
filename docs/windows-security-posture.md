# Windows security posture

Source candidate, 11 October 2026. A compact private Security view reports two
independent local sources: Microsoft Defender status and Windows Firewall local
profile configuration. It does not determine whether a device is protected,
compliant, reachable, or using another antivirus. Native acceptance and the
published Windows preview are unchanged.

## Separate local approval

`windows-security-posture-v1` is default-off and independent of every earlier
Windows scope and the five-scope Setup coordinator. For an existing activated,
receipt-owned inventory service, stopped by its authorized operator:

- `windows-service --security-posture-preview`
- `windows-service --security-posture-enable --apply --defender-firewall-posture`
- `windows-service --security-posture-disable --apply`

These source interfaces are not permission to execute the commands. Enable and
preview must finish the complete local-source disclosure before dispatch. An
HTTP-test identity also requires `--insecure-http-test` and the separate plaintext
warning. Production remains HTTPS. A protected create-only `-security-posture`
sibling binds the exact grant to the existing sender identity. The existing
sender lock spans configuration. Missing used records and foreign/unsafe state
fail closed. Disable preserves state; explicit re-enable creates a new grant.
There is no migration, existing-grant promotion, service restart, identity reset,
ACL change or privilege expansion.

## Fixed, bounded sources

Defender uses local COM `SWbemLocator` with server `.` and the fixed namespace
`Root\Microsoft\Windows\Defender`. A single forward-only, semisynchronous query
selects only these properties from `MSFT_MpComputerStatus`:

- `AMRunningMode`
- `AMServiceEnabled`, `AntivirusEnabled`, `RealTimeProtectionEnabled`
- `AntivirusSignatureVersion`, `AntivirusSignatureAge`

The caller supplies no server, namespace, WQL, credentials or impersonation
settings. Enumeration accepts exactly one instance, reading at most two to
check multiplicity. No `SELECT *`, WMI methods, process/path data, threat history,
scans, updates, downloads, remote queries or provider error prose is requested.
Only fixed-size variants are admitted. BSTR length is checked before copying;
mode is at most 32 UTF-16 units and version at most 64 ASCII units. Signature
version accepts only 2–4 decimal components. Signature age is a reported day
count, never a freshness/compliance verdict; sentinel values 65535 and above
remain unknown. Known mode strings map to normal, passive (including SxS passive)
and EDR block. Any unfamiliar mode remains unknown, without inferring a mode
from false flags. Absent/unsupported sources and partial metadata stay unknown rather than
becoming disabled protection. A directly returned access-denied HRESULT is
reported as denied; opaque COM dispatch failures remain unavailable because
provider exception prose is not requested or retained.

Firewall uses fixed local `CLSID_NetFwPolicy2` and only the getters
`CurrentProfileTypes` and `FirewallEnabled` for each of Domain, Private and Public.
A bitmask can contain several active profiles. Each individual profile has an
independent active and locally configured on/off/unknown state. Microsoft notes
that the effective policy may differ because of Group Policy. No rule list,
program/interface paths, exclusions, traffic probes, policy writes or changes
are accessed. An inaccessible provider never becomes a disabled firewall.

Microsoft primary references:

- [Defender status class](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpcomputerstatus)
- [Defender running modes](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows)
- [SWbemLocator.ConnectServer](https://learn.microsoft.com/en-us/windows/win32/wmisdk/swbemlocator-connectserver)
- [SWbemServices.ExecQuery](https://learn.microsoft.com/en-us/windows/win32/wmisdk/swbemservices-execquery)
- [FirewallEnabled local-state limitation](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_firewallenabled)
- [CurrentProfileTypes bitmask](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_currentprofiletypes)

## Isolation, transport and private view

Each provider has a separate fixed internal worker mode in the current protected
executable. Both independently authenticate the existing restricted service
identity, actual live SCM parent, creation time, executable hash, activated
configuration/certificate/ready receipt and exact new consent before and after
capture. COM activation uses a locked OS thread, High/System integrity and no
thread impersonation. It never elevates, changes authentication settings or
weakens provider access controls. LocalService denial is an honest result.

The parent kills and synchronously reaps each provider child after at most two
seconds, with a 100 ms inherited-pipe wait bound and the existing independent
20-second parent-loss watchdog. A failed or timed-out Defender child leaves the
Firewall result useful, and vice versa. The combined reader receives at most
five seconds; cached update and patch workers also receive bounded budgets when
co-enabled, retaining the existing three-second primary-delivery reserve and
20-second outer attempt. Provider-service internal work/memory is outside the
owned child-process boundary. There are no abandoned native-read goroutines.

Worker input is the bounded 1 KiB canonical binding/grant/generation/capture
request, never a path, credential, query, configurable executable or environment.
The combined snapshot is at most 4 KiB. Wire
`tracebolt.agent-telemetry.windows.v10` requires its separately granted
`windowsSecurityPosture` section; v1–v9 and pending retry bytes are unchanged
without it. Every sibling retains its own grant. Source sections use the exact
base generation and conservative original capture time; they are not an atomic
snapshot. Fitting preserves base rows, protected self metrics, source quality,
original capture/grant/counts and the 72 KiB frame limit, dropping complete
optional rows where required.

The sender revalidates the activated identity and exact grant before capture,
after capture and before send/retry. Revoked/replaced grant data cannot retry.
Pending retries preserve exact bytes and source age. The durable capture floor
also protects subsequent scope-absent frames. Only the authenticated operator
Windows inventory view returns `securityPosture`; revocation, current identity,
staleness and 24-hour privacy expiry apply. This metadata is not added to basic
or public observation, AI/provider packets, health policies, alarms, exports or
notifications. EN/DE Security shows compact source rows, original capture and
collapsed source detail. There is no global green protection/compliance badge.

## Verification boundary

Portable fixtures exercise canonical bounds/unknowns, independent provider
failures, grant create-only semantics and disclosure, fixed authenticated child
lifecycle/kill/reap, exact retry/restart, TLS/HTTP-test transport, old-wire rejection,
private view age/revocation and co-enabled primary-send budgets. Windows builds
are compilation only. Hosted browser fixtures render synthetic source-bound
results; they do not prove native collection or installed service acceptance.

A separately authorized disposable Windows gate must establish actual
LocalService provider visibility, current Windows variants and passive/absent
Defender behavior, local Firewall profile semantics, provider timeout behavior,
protected consent revocation/replacement and native-to-manager-to-browser flow.
This increment authorizes no host reads, grants, installation, scans, updates,
firewall changes or remediation. TPM, Secure Boot and BitLocker remain deferred
roadmap scopes; recovery keys are outside this design.
