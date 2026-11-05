# Explicit named customer reads (TB-06 slice)

Status: optional source capability, not completion of
[TB-06 / #133](https://github.com/storminator89/Tracebolt/issues/133).
This implements the separately approved product decision to let a named account
read customer records and Windows organizational assignments **only when the
protected startup configuration explicitly grants `read_customers`**.

## Exact authority

Every named account still needs its independent `read` grant. Ordinary `read`,
all existing maintenance grants and `manage_sessions`, individually or together,
do not imply `read_customers`. No role, wildcard, customer membership or UI field
can create this permission. Existing configurations, accounts and live sessions
receive no automatic additional access. The file loader accepts the optional
literal capability but does not write configuration or provision credentials.
Changing a configured grant still requires separately authorized protected-file
administration and a manager restart; sessions remain memory-only.

The new capability admits exactly:

| Method / route | Existing data returned |
| --- | --- |
| `GET /api/customers` | Manager-bound bounded customer IDs, names and revisions |
| `GET /api/customer-windows-assignments` | The same catalog plus currently admitted Windows device IDs, original identity bindings, customer associations, unavailable-assignment count and original bounded view lifetime |

Both are whole-manager organizational views, **not customer-scoped isolation**.
The grant exposes every currently admitted row in those existing bounded
projections. It does not filter by an operator's customer, change any enrollment
authority or authorize reading new endpoint data. A recipient able to read a
value can copy it; there is no new server export route or AI/export permission.

There is no customer-detail GET or supported HEAD route. Customer creation,
renaming, assignment, deletion and every other non-GET remain denied to named
accounts, even with every configured capability. Existing shared-administrator
read/write behavior stays unchanged. Enrollment, trust, provider settings,
endpoint scope, native actions and account/grant editing remain independent.

## Admission, identity and revocation

The handlers check the actual server-held session and exact capability before
source/store access. The brief session capability admission is released before
source/store I/O, so logout is not held behind a read waiting for a source.
Current session/context checks before output still suppress a revoked or expired
response. Grant sets are immutable within that manager process; copied browser
metadata cannot authorize a request.

All existing transport/Host/canonical-path, issuer/manager binding, source
identity exclusion, original enrollment, current-leaf/authority lifetime and
monotonic-clock checks remain in the same handlers. The separately acknowledged
HTTP-test profile remains plaintext and does not make these customer views
confidential. Old assignments never move
to a replacement enrollment with the same device ID. No stored record, original
age, revision, receipt, replay or revocation floor is reset or migrated.

Successful reads have the actual immutable named actor in their server session;
these read views do **not** add a durable per-read audit record. No administrative
write becomes named or gains an audit actor through this slice. Full #133
administration and its durable-actor acceptance criteria remain open.

## Browser and verification boundary

The browser mounts both customer readers only after confirmed explicit session
metadata establishes shared administration or the named `read_customers` grant.
Named views have no create/edit/assignment controls, and their mutation callbacks
also reject read-only mode. The server remains authoritative even for a direct
request or a modified browser. Existing expiry/navigation/access-loss cleanup
and explicit GET refresh are retained; there is no automatic POST or retry.

Source/real-loopback TLS tests cover two distinct granted named actors, ordinary
read and all prior grants denied, anonymous denial, forged authority, all write
methods denied, unchanged records, current actor metadata, revocation during
reads and issuer expiry. Auth/config tests cover explicit parsing, independent
bits, duplicate/unknown grants, defensive snapshots and logout. Browser unit
tests cover strict metadata, no mount without the grant, read-only controls and
GET-only refresh. These are synthetic source/browser fixtures, not live account
provisioning, a customer deployment, native endpoint acceptance or a full
security audit. Report exact executed checks with the final revision.
