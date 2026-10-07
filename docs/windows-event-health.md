# Windows event headers in shared Health

This is a source candidate, not native Windows acceptance. It adds a default-off
`windows-application-system-event-headers-v1` extension to an already activated
`windows-inventory-v1` identity. Inventory consent alone never reads events.
No identity, enrollment domain, existing store manifest or sender floor is reset.
The matching updated manager/dashboard must be deployed before explicit enable;
old managers reject the new frame. Do not downgrade a sender with a pending v2
frame or reset its ledger to bypass incompatibility.

## Explicit local scope

The stopped, owned service can preview the independent scope using
`windows-service --events-preview`. Enabling source uses
`--events-enable --apply --application-system-event-headers`; disabling source
uses `--events-disable --apply`. Each HTTP-test operation additionally requires
`--insecure-http-test`; the existing plaintext transport warning is printed.
These are source commands only. No installed service, native event read, ACL
change or consent activation was performed by the fixture tests.

Enable requires an activated matching Windows inventory handoff and the existing
sender's exclusive inspection lock. A separate protected sibling store of the
runtime root binds the exact scope/version to the original sender binding
(manager origin, identity, certificate and transport). It does not expand the
old root/enrollment/sender allowlists. Existing or incomplete unsafe state is
never adopted or repaired. Repeated enable preserves a live grant; re-enable
after disable obtains a new grant ID. Disable retains its record. Missing,
foreign, malformed or unreadable consent disables collection, never enables it.

The exported local configuration function can be reused by a future combined
Windows installer after activation, under its explicit combined consent. This
candidate does not add an automatic installation-time or manager-side grant.
Native protected sibling-store and stopped-service acceptance remain required.

## Bounded wire and persistence

Only Application and System are queried, at most 16 headers each using the
existing bounded native reader. Only provider, 16-bit event ID, 8-bit level,
record ID, timestamp and fixed channel are admitted. Record IDs are decimal
strings to preserve the full uint64 range in JavaScript. No messages, XML,
EventData, Security log, account identifiers, custom query or shell is added.

The independent strict snapshot has a 6 KiB encoded limit. Deterministic row
omission retains observed counts and marks truncation; original event capture
and event timestamps remain unchanged. The whole existing telemetry frame still
has its 72 KiB limit. Unknown members, duplicate keys, noncanonical encodings,
wrong channels, quality/count contradictions and mismatched generations fail
closed. Scope and grant IDs are required. The sender emits Windows telemetry
v2 only with explicit event scope; v1 remains unchanged when disabled.

The existing signed Windows route, enrollment identity, replay checks, atomic
manager persistence and authenticated same-origin operator API are reused.
Exact pending retries preserve all original bytes/timestamps across restart.
Revoked or replaced local consent prevents sending an event-bearing pending
frame; discarding it preserves sequence floors. Consent is rechecked after
collection and before transmission while the sender ownership lock excludes
configuration. Manager revocation hides retained private rows. Disabling the
extension replaces the latest event view after the next accepted v1 report;
it does not retroactively erase retained telemetry or confer remote deletion.

## Minimal shared UI

The same Windows device Health tab shows each channel's observation quality,
counts of error/warning headers within the bounded displayed sample, and optional
header details. It does not turn a sample into an all-device health verdict.
An empty successful query remains an observation, not healthy zero. Denied,
unavailable, unconfigured and stale samples are explicit. Header timestamps may
be older than their capture; no complete time-window coverage is claimed.
Unknown/reserved event levels are shown as unknown.

Event capture and manager receipt freshness are retained; samples become stale
after two minutes and private rows disappear after 24 hours. Existing clock,
timeout, session loss, blur, navigation and request interruption protections
clear event data alongside inventory. EN/DE labels reuse the shared layout.
No event values are inserted into basic observation evidence or model/provider
exports. AI evidence approval, log content, remediation and native execution
remain separate work.

## Evidence boundary

Portable contract/consent fixtures and actual synthetic sender → signed ingress
→ durable store → authenticated operator tests cover old-profile compatibility,
restart/exact retry, scope/quality rejection, local revocation and expiry.
Browser DOM tests and TypeScript/build checks are source evidence; neither
screenshots nor native installed-service/Windows-to-Linux production acceptance
are implied. Do not dispatch the native workflow or alter host security policy
without the separately required authorization and exact-source prerequisites.
