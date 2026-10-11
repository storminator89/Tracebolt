# Windows adapter link, DNS and gateway context

This source candidate fills the existing Network tab with native adapter
operational state, transmit/receive link speeds and configured numeric DNS-server
and gateway addresses. These are configuration/snapshot values, not measured
throughput, Internet reachability, DNS resolution, route selection or traffic
counters. Windows runtime acceptance and release publication remain separate.

## Independent local consent

`windows-adapter-context-v1` is default off. Base inventory, network endpoints,
the five-scope setup coordinator and every existing receipt remain unchanged.
A manager or agent upgrade never creates this grant. An already activated,
receipt-owned Windows inventory service must be stopped before using:

- `windows-service --adapter-context-preview`
- `windows-service --adapter-context-enable --apply --adapter-link-dns-gateways`
- `windows-service --adapter-context-disable --apply`

Enable prints the new scope disclosure completely before dispatch. The explicit
HTTP-test path additionally requires the matching `--insecure-http-test` flag and
its plaintext warning; production remains HTTPS. These are command descriptions,
not authorization to run them on a host.

The protected `-adapter-context` sibling is identity-bound and create-only.
Preview never writes. Missing records in a used store, foreign identity, unsafe
paths, permission denial and failed writes fail closed. Disable retains the
record; re-enable generates a fresh grant ID. The sender lock is held through
configuration. No existing manifest, counter, identity or scope is reset. No
service restart, permission change or automatic host action occurs.

## Local native collection and limits

One synchronous `GetAdaptersAddresses(AF_UNSPEC)` call uses one aligned 1 MiB
buffer. There is no source-controlled allocation loop or unbounded retry.
`ERROR_NO_DATA` is an observed empty result; overflow and failures are unavailable,
access denial is denied, and unsupported platforms are explicit. A five-second
cooperative budget applies between bounded parsing steps; an in-flight native
call cannot be forcibly canceled.

The call skips unicast, anycast and multicast address lists, requests gateways,
and includes IP-bound interfaces without assigned addresses so down adapters can
remain visible. It does not request all network compartments. Software loopback
is excluded. At most 128 native adapter nodes and 512 address nodes are inspected.
At most 32 adapter rows, 8 DNS addresses and 8 gateway addresses per row, and
16 KiB are retained. Counts describe usable adapter rows; incomplete coverage is
a lower bound. Per-list partial status survives invalid pointers or truncation.
Known empty lists remain different from unavailable lists.

The decoder checks native record lengths, pointer range/alignment, cycles,
UTF-16 name bounds, socket lengths and IP family before reading selected bytes.
The supported Windows amd64/arm64 ABI offsets are compile-time checked against
`x/sys/windows`. Friendly names are limited to 96 UTF-8 bytes. IPv6 scope IDs are
numeric and preserved. IPv4/IPv6 indices are temporary capture-time identifiers,
not stable adapter identities; no old address snapshot is joined to these rows.

Operational state is taken directly from `OperStatus`, including down, testing,
dormant, not-present, lower-layer-down and unknown. It is never inferred from an
address. Directional native link speeds are independent; zero, sentinel or
unsafe-to-represent values are unknown rather than zero throughput. Missing
optional native fields are unavailable. DNS/gateway lists are sorted for stable
bounded retention; their order does not describe resolver or route preference.

IP Helper returns an aggregate allocation that also contains excluded metadata.
Only interface indices, friendly name, operational state, directional link
speeds and DNS/gateway socket lists are decoded. MAC addresses, suffixes,
descriptions, DHCP/WINS servers, GUIDs, credentials and excluded pointers are
never modeled or followed. The temporary allocation is cleared on return.
There is no shell, DNS lookup, probe, packet capture, remote call, route read,
privilege adjustment, network configuration or control action.

Microsoft contracts: [adapter fields and versions](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh),
[bounded API and flags](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses),
[gateway list](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_gateway_address_lh).

## Shared transport and operator UI

`tracebolt.agent-telemetry.windows.v8` requires a separately consented
`windowsAdapterContext` sibling. Every earlier v1-v7 frame retains its old shape
when this scope is absent, including exact protected pending retry bytes. All
older extensions remain optional and independently selected. A different visible
scope cannot reuse the adapter grant ID.

The snapshot uses the base reporting-window start as its conservative capture
age; reads within that window are not atomic. The generation and original capture
must match the base. This preserves the durable monotonic capture floor through
later scope-absent reports. The whole frame stays within 72 KiB. Fitting removes
complete optional rows deterministically without changing original counts,
quality, grant, generation or age; it never changes the bound base row arrays.

Consent is checked before capture, after capture and immediately before send.
Revoked or replaced grants suppress old pending data. Retry/restart uses the
original pending bytes and manager receipt, with no recapture or refreshed age.
The authenticated manager stores the frame atomically through the existing path
and exposes `adapterContext` only in the private operator inventory view. Current
identity authority, stale status and the original 24-hour privacy envelope apply.
No adapter context enters basic observations, AI/provider exports, Linux profiles,
health policy or action authorization.

The existing Network tab adds a compact EN/DE adapter table. Link state and
separate transmit/receive speeds are directly visible; each row offers DNS and
gateway details on demand. Existing endpoint rows remain in the same section.
No new dashboard card, setup toggle or long inline explainer is added.

## Verification and remaining gate

Portable fixtures cover native buffer decoding, down/unknown states, directional
speeds, scoped IPv6, pointer/cycle/bounds failures and excluded-pointer sentinels;
consent default-off/create-only/disable; both signed HTTP-test and verified-chain
TLS ingress admission; exact retry/restart, authority and expiry; and compact UI
validation/lifecycle behavior. Cross-builds are compilation evidence only.

A separately authorized disposable Windows acceptance must establish actual
ordinary LocalService visibility, link-state/speed behavior, DNS/gateway coverage,
protected sibling ACLs, stopped-service consent, disable/re-enable and actual
Windows-to-Linux-manager-to-browser operation. Tests must not enable adapters,
change DNS/routes, loosen ACLs or create missing native cases merely to pass.
Route tables and raw byte/error/discard counters now have a [separate explicit
source scope](windows-network-context.md). Packet traffic remains excluded.
