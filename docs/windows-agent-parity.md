# Windows agent scope comparison

Source baseline: `main` at
`8e35299a13cf634e5e0924c3749e9d5e992174ea` (3 November 2026).
This is a documentation-only comparison of **Rust Basic** and **Go Read admin**
at that revision. It adds no collector, scope, installer behavior or authority.
It does not describe every immutable package available from the release list.
Use the selected package's exact source, manifest and acceptance record with its
matching manager/frontend; see the [Rust candidate guide](integrated-test-candidate.md)
and [Go Windows status](windows-status.md).

## Read the states separately

- **Implemented source** identifies code that exists at this baseline. A source
  implementation can still return unknown, unavailable, denied or partial data.
- **Local scope** identifies collection consent and its protected identity/state
  contract. A manager view, installation profile or group membership grants none
  of these scopes automatically.
- **Native evidence** applies only to the exact tested artifact, OS, account,
  provider and workflow. A source test, cross-build or published ZIP is not native
  acceptance. A running service is not a fresh accepted report.

Rust Basic still uses the broader `windows-inventory-v1` manager identity and the
existing Windows telemetry route. It has **no distinct basic-only server-side
authorization domain**. Its smaller collector does not narrow that server
identity or authorize a future collector expansion. Automatic registration
retains deliberate manager identity/fingerprint approval. See the
[onboarding contract](windows-rust-onboarding.md).

## Basic observations available in Rust source

The [native adapter](../rust/windows-agent/src/native.rs) implements these four
observations. The [frame builder](../rust/windows-agent/src/protocol.rs) supplies
the original collection time and keeps whole-device status `unknown`.

| Observation | Rust source and meaning | Coverage limit |
| --- | --- | --- |
| CPU utilization | Two `GetSystemTimes` samples, separated by 500 ms | Observed processor group only; no whole-machine multi-group claim, process CPU or CPU model/count inventory |
| Physical RAM utilization | Used percentage from `GlobalMemoryStatusEx` total and available physical bytes | No installed SMBIOS RAM, commit/pagefile context or per-process working set |
| System-volume capacity usage | `GetDiskFreeSpaceExW` for the fixed local system drive, using caller-available and caller-total bytes | Caller-quota semantics; no complete volume list, physical-disk attribution, storage health or I/O rates |
| Uptime | `GetTickCount64`, formatted as whole seconds | No boot-event history, reboot-cause diagnosis or persistence acceptance |

Failed/invalid CPU, RAM or capacity samples serialize as a null value with
`quality: unknown`; they never become zero utilization. Fixed wire labels such
as `Local Windows` and `Windows` are not a collected hostname or detailed OS/build
inventory. Neither these observations nor transport success establish a healthy
device or full Go parity.

Even the overlapping metrics do not promise identical measurement behavior:
the [Go inventory CPU provider](../internal/windowsinventory/collect_windows.go)
refuses a processor-group count other than one, while Rust reports its observed
group without that gate. Go uses a [250 ms sample interval](../internal/windowsinventory/report.go)
versus Rust's 500 ms. Each adapter retains its own quality semantics; the common
Windows API name alone does not establish metric parity.

## Exact Go Read admin scope matrix

The authoritative Go source list is
[`WindowsReadAdminScopesV14`](../internal/lanclient/windows_read_admin_profile.go),
with fresh consent version `tracebolt.windows-capability-consent.v14`.
The [setup guide](windows-read-admin-setup.md#fresh-read-admin-seven-readable-groups)
explains its twenty-one scopes and unchecked combined approval. **Go source**
below describes that approved profile's contract, not guaranteed provider access
or a blanket native-success claim.

In the Rust column, **Not collected** means the current Rust collector/frame
does not provide this scope's observations. It does not mean a disabled source
can be enabled by checking a manager option.

| Exact local scope | Go Read admin source coverage | Rust Basic source |
| --- | --- | --- |
| `windows-inventory-v1` | Base observations plus bounded system/hostname/interface/process/service/software preview | Basic metrics/uptime subset only; all five inventory sections explicitly unavailable |
| `windows-application-system-event-headers-v1` | [Bounded Application/System event headers](windows-logs-sample-browser.md), without messages | Not collected |
| `windows-visible-volumes-v1` | [Caller-visible volume metadata and capacity](windows-volume-inventory.md) | Not collected; one system-drive capacity metric is not this scope |
| `windows-process-metrics-v1` | [CPU and working-set RAM for up to 128 base-preview PIDs](windows-process-metrics.md) | Not collected |
| `windows-complete-processes-v1` | [Complete caller-visible Toolhelp PID/parent/name/thread-count generations](windows-full-processes-contract.md), independent of process metrics | Not collected |
| `windows-network-endpoints-v1` | [Numeric TCP/UDP endpoints and API-snapshot PID](windows-network-endpoints.md) | Not collected |
| `windows-service-startup-v1` | [Configured startup metadata for bounded service rows](windows-service-startup.md) | Not collected |
| `windows-complete-services-v1` | [Complete caller-visible Win32 service generations](windows-full-services-contract.md), excluding drivers and invisible rows | Not collected |
| `windows-complete-machine-software-v1` | [Complete bounded HKLM 32/64 uninstall-registration generations](windows-full-software-contract.md), excluding per-user/Store/portable software | Not collected |
| `windows-machine-software-history-v1` | [Manager comparison of comparable complete HKLM generations](windows-software-history.md); observed changes, not installation times or upgrade proof | Not collected; Rust supplies no complete software baseline |
| `windows-adapter-context-v1` | [Link state/speed and configured DNS/gateway addresses](windows-adapter-context.md), without probes or DNS resolution | Not collected |
| `windows-network-context-v1` | [Caller-visible routes, interface aliases and raw counters](windows-network-context.md), without joins or inferred rates | Not collected |
| `windows-patch-context-v1` | [Build labels, retained WUA history and fixed reboot indicators](windows-patch-context.md), without current patch-compliance proof | Not collected |
| `windows-security-posture-v1` | [Independent Defender status and local Firewall profile configuration](windows-security-posture.md), without effective-protection proof | Not collected |
| `windows-session-context-v1` | [Caller-visible WTS sessions and local join context](windows-session-context.md), without complete account enumeration | Not collected |
| `windows-resource-context-v1` | [CPU model/count context, SMBIOS versus OS RAM, commit and aggregate pagefile capacity](windows-resource-context.md) | Not collected; aggregate CPU/RAM percentages do not supply this context |
| `windows-hardware-context-v1` | [Manufacturer/model, source-labeled chassis/BIOS serials, firmware and power/battery](windows-hardware-context.md) | Not collected |
| `windows-storage-context-v1` | [Local drive-letter/volume-GUID mappings and bounded storage-provider context](windows-storage-context.md), without guessed physical joins | Not collected |
| `windows-storage-io-v1` | [Eight fixed aggregate PerfDisk counters and their sample window](windows-storage-io.md), without per-disk attribution or health verdict | Not collected |
| `windows-security-coverage-v1` | [Client Security Center antivirus metadata and TPM presence/version](windows-security-coverage.md); provider/platform limits remain explicit | Not collected |
| `windows-application-system-event-history-v1` | [Bounded on-demand Application/System history and selected historical messages](windows-event-history-runtime.md), with separate sensitive-content disclosure | Not collected |

### Unavailable inventory is not an empty machine

Rust's `tracebolt.agent-telemetry.windows.v1` frame contains a
`tracebolt.windows-inventory.v1` envelope. Its `hostname`, `processes`, `services`,
`software` and `network` sections all use `quality: unavailable`, empty `rows`,
`countExact: false` and `complete: false`. The reported zero `observedCount`
therefore cannot prove that the device has no processes, services or software.
No complete inventory generation or any of the other scope extensions above is
emitted by the current Rust frame builder.

## Outside this twenty-one-scope comparison

Go Read admin is itself a bounded profile. Independently consented
[offline cached WUA inspection](windows-update-runtime.md),
[selected sampled-event messages](windows-event-content-runtime.md) and
[selected-account HKCU/MSIX software](windows-selected-user-software.md) are
separate contracts, not implicit Read admin or Rust coverage. Selected
[service control](windows-service-actions.md),
[MSI work](windows-multi-package-msi-catalogue.md) and
[Windows Update operations](windows-selected-update-setup.md) require their own
authority, protected state, review and native gates. Rust Basic implements none
of those collection/action workflows. Manager-side health policies, incident
views or diagnostics over existing observations do not add endpoint collection.

## What the existing tests establish

- [`invalid_metrics_are_unknown_and_inventory_is_not_claimed_complete`](../rust/windows-agent/tests/contracts.rs)
  checks invalid metric handling and explicitly checks the hostname section's
  unavailable/noncomplete state. The identical five-section shape above is also
  visible in the frame builder and the
  [invented wire fixture](../tests/rustagent/fixture.json); this is not five
  separately exercised native inventory collectors.
- [`TestRustFrameAcceptedByManager`](../tests/rustagent/protocol_test.go)
  passes that invented Rust fixture through the actual Go inventory/observation
  and ingress validators, checks noncomplete inventory and rejects a stale frame.
  It proves compatibility for that frame, not native source access or authority
  for a broader Rust scope.
- [Go profile tests](../internal/lanclient/windows_read_admin_profile_test.go)
  and the [v14 history test](../internal/lanclient/windows_event_history_setup_test.go)
  cover the corresponding source consent boundaries, including that old consent
  cannot become the new history grant. They do not prove LocalService can read
  every provider on a target machine.
- The [Rust workflow](../.github/workflows/windows-rust.yml) defines separate
  source checks, matching-package builds and disposable Windows Server 2025
  installed-service acceptance against a protocol fixture. A workflow definition
  is not a successful run. Use the chosen artifact's exact run/manifest to learn
  what passed. It does not establish Windows 10/11, OS reboot, complete provider
  access or real shared Linux-manager/dashboard interoperability.

No fresh native or browser acceptance is recorded by this documentation change.
The [Rust candidate gates](integrated-test-candidate.md#evidence-and-remaining-gates),
[installer preflight limits](rust-installer-preflight.md) and
[Go native evidence](windows-status.md) remain separate.

## How to add the next Rust scope

The [lean roadmap](lean-roadmap.md#3-grow-rust-windows-parity-progressively)
places process, service and machine-software inventory in separately reviewed
increments. No one of them is implemented by this matrix. Each increment needs:

1. An exact data/source/coverage contract with explicit missing, denied, partial
   and bounded outcomes; a prefix must not become a complete generation.
2. A deliberate local consent and protected-state design bound to the original
   identity. The broad existing manager identity and Basic acknowledgement must
   not silently expand collection. Separately review manager-side authority and
   admission constraints; client consent alone cannot narrow the current broader
   server identity. Preserve prior grant and wire compatibility.
3. Bounded native collection, strict framing, exact pending retries and durable
   sequence/generation floors, with revocation, expiry and original-age handling.
4. Focused source/manager regressions followed by separately recorded native
   evidence on the exact account, OS and artifacts before any release claim.

Keep Go Read admin available while each new Rust scope earns its own evidence.
Do not label the entire Rust agent "parity" after one scope passes.
