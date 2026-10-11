# Windows hostname and IP addresses in the fleet

The source dashboard displays and searches Windows hostname and numeric IPv4/IPv6
interface addresses already present in the accepted `windows-inventory-v1` frame.
It does not collect again, enable a capability, grant access or change the endpoint.
The published Windows preview is not rebuilt by this manager/UI change.

## Operator display contract

`GET /api/fleet/identities` returns `tracebolt.fleet-identities.v2`. It combines at
most one bounded read from each configured enrollment authority, retaining the
existing 25-record and read-admission limit per store: at most 50 combined records
and a response strictly below 512 KiB including its newline. An over-budget or
invalid response fails closed. Duplicate device IDs across authorities are rejected.
The existing `/api/fleet/endpoint-identities` v1 route, its 25-record/256-KiB limits
and Linux endpoint-identity consent and validation remain unchanged.

Each Windows item has its own `tracebolt.windows-fleet-identity-view.v1` schema.
Its latest projection contains only the original hostname and interface sections,
original generation/capture timestamp, and their exact native source, scope,
quality, counts, completeness and truncation. It does not include processes,
software, services, sockets or event content. Missing or denied hostname data
stays unavailable; partial address rows remain useful and visibly partial.
Windows interface metadata does not establish up/down state, a primary address,
DNS identity or reachability. Addresses are inert display/copy/search text.

Sequence and receipt are the original accepted values. The visible lifetime ends
at the earlier of the original capture plus 24 hours and certificate expiry.
Capture or receipt older than 120 seconds is stale; future captures within the
existing allowed skew remain stale. Revoked authorities emit no identity values.
Both authority clocks and the authenticated operator session are rechecked before
output; the same encoded bytes are bounded and checked immediately before write.

The browser uses the existing session-bound fleet reader, abort/deadline and
navigation rules. Original age and expiry keep advancing while values are shown;
logout, invalid refreshes and late responses cannot restore private values.
Hostname/address search does not change `Device`, routing IDs, CSV data or AI
packets. No new durable collection or database schema is introduced.

## Verification boundary

Focused store/API tests cover saved-frame preservation, duplicate receipt,
authority/retention expiry, cancellation, bounded admission and mixed-authority
HTTP output. A synthetic production-handler JSON fixture is consumed by the
frontend validator. UI tests cover unavailable/partial dual-stack metadata,
search, inert text, original expiry and session replacement/logout.
These fixtures and the production web build are source acceptance, not native
Windows collection, deployment or browser screenshot acceptance.
