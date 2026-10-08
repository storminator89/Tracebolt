# Windows service startup metadata

This is a bounded, source-only end-to-end candidate for the existing Windows
Services table. It adds configured startup mode to the ordinary signed sender,
durable manager and authenticated operator view. It is not complete service
inventory, a remote action, a released installer or a native acceptance result.

## One explicit additional scope

The existing base disclosure enumerates service names, display names, states and
PIDs. It does not cover startup configuration. None of the existing five scopes
or their receipts authorizes this new read.

`windows-service-startup-v1` is one coherent, default-off capability for bounded
startup metadata. The new combined consent v4 can select it explicitly alongside
the existing independently selected scopes. Consent v1-v3 keeps its exact earlier
meaning. The fresh five-scope coordinator still requires its original v3
selection; it does not acquire a sixth scope. A manager/agent upgrade does not
write a grant, migrate a receipt, reset a ledger or enable capture.

The source lifecycle entry points are:

- `windows-service --service-startup-preview`
- `windows-service --service-startup-enable --apply --service-startup-metadata`
- `windows-service --service-startup-disable --apply`

These are source command descriptions, not authorization to execute them. The
owned service must already be stopped, and its activated Windows inventory
identity must match. Enable prints the complete startup disclosure before a
protected write. Explicit HTTP-test use also requires the existing
`--insecure-http-test` choice and the new plaintext startup-metadata warning;
production TLS remains default.

The grant lives in a separate protected create-only sibling, bound to the same
sender. Preview never creates state. Missing records in a used store, unsafe
paths, denial, foreign identity and partial writes fail closed. Disable preserves
the record; a later explicit re-enable gets a new grant ID. Existing sender and
enrollment manifests, identity, counters and other grants are unchanged. No
operation changes an observed service or its access rights.

## Exactly what is read

Only names already retained in the final bounded base service snapshot are
queried, at most 128. There is no additional enumeration, remote machine name,
registry traversal, shell, privilege adjustment or background subscription.
The adapter opens the local SCM with `SC_MANAGER_CONNECT`, then each existing
service with only `SERVICE_QUERY_CONFIG`. It never requests change-config,
start/stop, security-descriptor or all-access rights. Each service handle closes
synchronously before the next row. The existing service name, display name,
state, PID, counts and partial/denied status remain unchanged.

The retained fields are:

- Configured mode: automatic, manual or disabled.
- Delayed-auto Boolean, only when automatic mode was observed and its separate
  native query succeeded.
- Independent finite quality for mode and delayed status. Denied, unavailable
  and unknown values are never replaced by manual, disabled or false. A known
  manual/disabled mode has no applicable delayed-auto value.

Unknown native mode values and unexpected service kinds are withheld. Access
denial leaves the base service row visible with a denied startup cell. A removed
service, unsupported query, failed read or exhausted cooperative budget leaves
the corresponding value unavailable. There is a five-second cooperative budget,
checked between calls and rows. An already-running synchronous native call
cannot be forcibly canceled; no goroutine abandons it.

### Aggregate native-buffer boundary

Windows `QueryServiceConfigW` supplies an aggregate configuration buffer, not a
scalar-only start-type API. That buffer necessarily includes other configuration
bytes. The adapter uses a fixed maximum 8 KiB temporary buffer, reads only typed
numeric startup mode (and service type as a local Win32 guard), never follows its
path, account, dependency or display-name pointers, and clears the buffer before
returning. Those aggregate bytes are never modeled, persisted, logged, encoded
or transmitted. No password or security-descriptor API is called.

`QueryServiceConfig2W` is limited to
`SERVICE_CONFIG_DELAYED_AUTO_START_INFO`, and only for an observed automatic
mode. It does not query descriptions, triggers, failure actions, privileges,
security identifiers or launch protection. See Microsoft's
[configuration read contract](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw),
[optional configuration API](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w)
and [delayed-auto semantics](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info).

Startup configuration and runtime state are separate observations. These reads
are not atomic with enumeration, and Windows service names are not immutable
instance identities. A service may change or be recreated during capture.
Automatic does not prove a successful boot start; manual does not exclude
trigger-based start. Trigger configuration is not collected. PID is still the
original enumeration value and is never used for a new process join.

## Frame, binding and exact retries

The base `tracebolt.windows-inventory.v1` service rows stay unchanged. A new
`tracebolt.agent-telemetry.windows.v6` frame requires its independently consented
`windowsServiceStartup` sibling. Without startup scope, the original v1-v5
schema/consent selection remains compatible and existing persisted retry bytes
remain valid and unchanged. For the same collector input, leaving startup absent
does not add this sibling or change the startup-free encoding. The separate
OS-provenance correction in this checkpoint restores already-approved evidence
to newly generated observations; it does not promise byte-identical new frames
to older software that dropped those fields. Existing extension combinations stay optional
and independently authorized.

The startup snapshot is `tracebolt.windows-service-startup.v1`. It binds the
grant ID, base generation, original collection time and SHA-256 of the exact
canonical final base service-row array. Startup rows reference original array
ordinals, before UI sorting or paging. The digest includes name, display name,
state and PID, preventing a different ordering or trimmed base from relabeling a
reading. Duplicate base rows are not merged. Sender, ingress, store and browser
must validate the same binding before use.

At most 128 startup rows and 16 KiB are retained. `requestedCount` is the exact
number of retained base rows offered to the startup adapter; it is not the total
host service count or a count of successful reads. Indices are unique, ordered
and in range. Deterministic trimming keeps the original requested count, digest,
grant, generation and capture time. The whole frame remains at most 72 KiB;
extension rows can be trimmed, but base row order is not changed after binding.

Consent is checked before capture, after capture and immediately before send.
Disable or grant replacement suppresses affected pending bytes without resetting
sequence state. Retries and restart use the exact already-protected pending
frame, never recollect or relabel rows. A new base generation must advance beyond
the preceding startup capture even if the next report omits startup scope.
Strict validation rejects unknown/duplicate fields, contradictory quality,
out-of-range indices, wrong count/digest/generation/grant and invalid capture age.

The durable manager retains the accepted frame through its existing atomic path.
The same-origin operator inventory view includes an optional `serviceStartup`
member. Its original capture and accepted receipt are preserved. Identity
revocation/expiry and the existing 24-hour base privacy envelope hide it;
independent startup age can also hide it. No startup data enters basic telemetry,
Linux profiles, AI packets, provider evidence or action permissions.

## Existing Services UI

The existing EN/DE Services table adds a Startup mode / Starttyp column, localized
search and mode sorting within the admitted bounded snapshot. It keeps its
25-row local pages, original service display names, state and PID. Missing,
denied, unknown, unavailable, trimmed and stale metadata remain explicit.
Automatic with unavailable delayed status is not labeled ordinary undelayed
automatic. Search, sorting, pagination and refresh do not collect new data or
change a grant.

The resource's session, navigation, visibility, timeout and trusted-age checks
apply to the new sibling. New generations clear table controls as before.
Sorting never substitutes the sorted row index for the original snapshot index.
The current bounded-service notice must describe the optional startup scope
instead of claiming startup mode is never collected. No new action button,
permission toggle or separate startup page is introduced.

## Verification and future native gate

The source gate uses only invented data and injected native API functions. It
must cover all startup modes, false/true/unknown delayed status, mode-vs-delay
contradictions, access denial, disappeared services, buffer limits, cancellation,
handle closure and excluded-pointer sentinels. Unknown pointers must never be
dereferenced, and temporary buffers must be cleared even on failure.

Portable integration must exercise the actual sender, signed TLS and HTTP-test
ingress, atomic durable store and authenticated view with an in-memory fixture
grant. Cover all independent extension combinations, exact lost-response retry,
restart, disabled/replaced scope, capture floors, old version compatibility,
base trimming/reordering, duplicate rows, byte limits and private-data expiry.
Cross-language vectors must include HTML-sensitive and Unicode service names.
DOM tests cover both languages, sorting/search/paging, original-index binding,
all unavailable states, interruption and expiry. Windows amd64/arm64 source
builds are compilation evidence only. Browser acceptance is separate.

The existing hosted service/software phase also has invented positive startup
rows and exact display/search/sort assertions. It adds no virtual-clock movement,
phase name, request route or session allowance. The existing composed 617-second
fixed clock advances remain inside the same 1,200-second synthetic session, and
the request-time browser-clock sampling is unchanged. Pure fixture checks do not
establish browser layout or native acceptance.

Before native acceptance, choose the exact reviewed source/artifact and obtain
explicit authority for the new read scope on one disposable Windows environment.
A first read-only smoke can query pre-existing services under the approved token,
keep all rows in memory and emit only finite pass/fail/coverage facts. It must not
create services, change startup settings, loosen ACLs or invent unavailable mode
coverage just to pass. Ordinary hosted-runner results do not establish the
installed LocalService path.

The subsequent installed-service gate needs its own approval for the new local
grant and any required lifecycle action. Preserve the identity and five existing
grants; verify actual limited-token visibility/denial, repeated captures,
disable/re-enable and exact retries into a real Linux manager and the shared UI.
Automatic/manual/disabled/delayed and denial cases absent from the selected
machine remain explicitly unproven until an independently approved fixture
environment can exercise them. A prior five-scope native pass does not cover
this capability. No test in this source candidate executes this future gate.
