# Manually selected interface diagnostic probe

Source-only test adapter, disabled by default. This is not an endpoint command,
profile, consent, enrollment or new provider. It requires both Darwin and the
explicit `tracebolt_interface_diagnostics` build tag; ordinary endpoint builds
contain no diagnostic native bridge. Main also refuses a missing exact manual
selector, unsupported architecture, wrong pinned Go version, mismatched hosted
runner markers, repeat attempt, or missing/mismatched source/commit markers.
Those markers are accident guards. The Python supervisor is responsible for
exact-source admission and rechecking reviewed source and executable custody.

The only provider reads are the existing runner's fixed
`/sbin/ifconfig -a inet` and `/sbin/ifconfig -a inet6`, once each. There is no full
`CollectNative`, hardware/receipt/process call, alternate format, retry, shell,
discovery, global callback or native value publication. Each successful command
is parsed exactly once by `ParseInterfacesWithDiagnostic`, then separately
validated in a synthetic in-memory envelope with all other sources unavailable.
The envelope never creates a grant or identity. Raw byte buffers are cleared
after use; parsed values are not retained in reports or written to disk.

The production `runFixedCommand` is unchanged: one-second command budget,
200-ms pipe wait, fixed environment and `/` cwd, no stdin, bounded combined
stdout/stderr, stderr-content rejection, cancellation and direct wait/reap. A
plain command failure still allows the other family once. Parent cancellation
prevents further commands and preserves completed sibling evidence.

The dedicated closed `tracebolt.macos-native-interface-diagnostics.v1` schema
has exactly two ordered families. It emits fixed IDs, declared limits, one-call
counts, finite command outcome/parser code/validation result and pass booleans.
It includes no interface name, address, prefix, MTU/flags, raw/error text, line
number, input hash or native value count. Unknown enums are rejected. Inner
reports are bounded to 16 KiB. A useful diagnostic failure remains a failed
family and failed gate, never native acceptance. Go and Python independently
validate the projection, and Python rejects unknown or duplicate JSON fields.

The unchanged runner does not expose per-command byte counts, elapsed time,
exit code, child start or child reap. All six fields remain null and
`commandMetricsAvailable=false`; an outer reaped probe is not independent proof
of every internal child. The supervisor observes and cleans its own direct
children using its existing bounded control flow.

Gate I may be selected only in a newly reviewed, explicitly approved manual
run. Gate A and Gate I are mutually exclusive. Independently selected Gate B
retains its separate write/read scope and does not become authorized by I.
Source tests and Darwin cross-compiles never authorize native execution,
workflow dispatch, publication, credentials, privilege/TCC changes or release.

Tests use in-memory synthetic inputs, injected runners and static build-tag
inspection. Run unit tests with and without `-tags=tracebolt_interface_diagnostics`;
Darwin compilation is compile-only. Never invoke the native selector as a test.

See the focused [Gate I review and scope disclosure](../../../docs/macos-interface-diagnostics.md)
for the outer-v2 report, preparation, public metadata and exact future manual
inputs. The shared native-acceptance document distinguishes A/B/I selection,
the separately reviewed log-v2 result and the assembled outer-v2 report.
