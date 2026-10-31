# Rust caller-visible service status: inert collector port

This source candidate ports the bounded Go basic-inventory SCM service-status
collector to Rust. **It is not active functionality of the installed Rust agent,
not Read admin parity, not complete service generations, and not native
acceptance.** `src/inventory_services.rs` is compiled only under `#[cfg(test)]`.
The production execution paths, Basic configuration/consent, enrollment, wire frames,
installer, sender state and manager authority are unchanged. No source test
creates a service, grant, key or persistent endpoint identity.

## Implemented source behavior

- Fixed local `OpenSCManagerW` with `SC_MANAGER_ENUMERATE_SERVICE`, followed by
  exactly one `EnumServicesStatusExW` read for Win32 services in all states.
  No driver enumeration, service handles, startup/configuration reads, controls,
  shell commands, remote queries, privilege changes or host security changes.
- One aligned initialized 256 KiB buffer; at most 2,048 native rows. Invalid
  counts fail unavailable. Names/display names must point inside the original
  arena after its row table, be aligned, terminate within 256 UTF-16 units and
  satisfy the unchanged Go managed wire's 256 UTF-8 byte/text restrictions.
  Malformed UTF-16 is rejected, never replaced lossily. Decoder reads bounded
  byte slices, not returned native pointers.
- Seven discrete states; PID copied only for running, continue-pending,
  pause-pending and paused. Other states carry the existing v1 numeric zero
  sentinel, not an asserted transition-state PID.
- Deterministic sorting, at most 128 transport rows and a 32 KiB section budget
  including Go's HTML-escaping expansion when it re-encodes accepted snapshots.
  Trims retain the pre-trim observed count and source exactness, clear complete
  and explicitly mark truncation/partial. `ERROR_MORE_DATA` remains partial and
  count-inexact, including a zero-row prefix. Access denied, unavailable and
  successful empty caller-visible enumeration remain distinct.
- Names/status/PID cover only the caller-visible Win32 API scope. Windows may
  silently omit services lacking QUERY_STATUS access; healthy/complete never
  means every service on the host. No paths, accounts, software, logs or actions.

The source/native and wire limits correspond to `internal/windowsinventory` and
`internal/windowsmanaged`, respectively. This is a single bounded preview, not
`internal/windowsfullservices`' independent resumable complete generation.
The 32 KiB section budget is not a whole-frame budget; a future authorized
adapter must enforce the unchanged 48 KiB snapshot ceiling across all sections.

Microsoft documents the
[SCM enumeration contract](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw),
[returned layout and name limits](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-enum_service_status_processw),
and [state-dependent PID validity](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process).

## Required integration gates

Do not connect this module to `native::collect`, `Sample`, the sender, service
runtime or installer under the Rust Basic profile. A future integration requires
fresh explicit local service-inventory consent and independently authenticated,
immutable server inventory authority, distinct from Basic. Existing ledgers or
certificates must not be relabeled/promoted. The inert `internal/windowsbasic`
profile foundation itself does not provide active enrollment or grant delivery.
Integration requires an independent security review of identity/profile admission,
consent/ledger binding, aggregate frame limits, exact retries and all unchanged
Basic behavior. This port does not implement that authority or UI/CLI integration.

Unit tests use only invented in-memory native-shaped buffers. An exact Rust
section fixture is also decoded by the real Go managed snapshot validator.
Windows-only tests assert SDK ABI size/alignment/field offsets and compile the real native
adapter without calling it. Linux tests do not establish Windows compilation,
LocalService visibility, real SCM behavior, installation, reboot persistence,
fresh accepted reports or shared-manager/dashboard interoperability. Those
require their separately approved Windows/source and native acceptance gates.
