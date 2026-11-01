# Customer records and device approvals

Current source adds a customer catalog to the LAN Devices
setup area. Customers are organizational records, not tenants: they do not
isolate access, grant collection or identify an installer.
Existing fleet groups and enrollment identities are unchanged. This is a first
step toward customer-bound onboarding, not a Datto-style site installer.

An explicitly authenticated shared administrator may create or rename up to
25 records. A record has a server-generated `customer_` ID and a revision;
names are 1–80 UTF-8 bytes without leading/trailing whitespace or control
characters. IDs are not reused, and deletion is not provided. Named operators
may read the existing whole-manager catalog and Windows assignments only with
the separately explicit [`read_customers` grant](named-customer-read.md); they
cannot create, rename or assign records. The private API checks the manager binding
and current issuer, same-origin/CSRF for writes, exact expected revision and a
live operator lease again before commit. Corrupt data and unavailable manager
binding fail closed. A conflict or unconfirmed POST requires a fresh GET and
another deliberate action; the UI never automatically retries a write.
The catalog is bound to the original manager instance, origin, transport profile
and issuer fingerprint. A different binding has its own catalog; records are not
automatically migrated when the manager or issuer changes.

The private endpoints are `GET /api/customers`, `POST /api/customers` with
`name` and `expectedRevision: 0`, and `POST /api/customers/{id}` with `name`
and its current `expectedRevision`. A catalog response has schema
`tracebolt.customers.v1` and public-to-the-operator IDs, names and revisions.
These endpoints do not allocate invitations, keys, installers or grants.

## Customer separation requires separate manager instances

Customer records, assignments and any display filters organize one manager's
workspace. They are not authorization inputs for customer-scoped API reads,
CSV export, collection or actions. Existing server permissions and each
endpoint's explicit local grants still govern those operations. Selecting one
customer does not hide another customer's data from an otherwise authorized
operator. This catalog has no customer login, membership or tenant boundary.
A Windows identity assignment is not an enrollment grant.

For confidential customer boundaries, use separately configured and protected
manager instances, not one shared manager with a customer filter. Follow the
[installation runbook](installation.md) independently for each instance:

- Use distinct manager identities and operator/agent origins, with independently
  approved TLS identities and client-auth trust/issuer material. Do not configure
  one instance to trust another customer's endpoint issuer or reuse its private
  keys, endpoint credentials, invitations or local enrollment state.
- Keep operator authentication, sessions, API/provider credentials and optional
  delivery destinations separate. A customer ID or hostname is not a credential.
  No user, role or approval transfers by matching a name between instances.
- Use separate protected configuration/state directories, databases and deployment
  volumes. For Compose, distinct project/volume names and bind paths must resolve
  to different storage. Changing a customer label does not separate them. Host/
  container access controls and reviewed exposure remain necessary. Never mount
  or copy another instance's live state.
- Retain separate protected backup sets with their own access controls and keys;
  do not merge customer archives or restore A's state as B's manager. Preserve
  original identities, revocation and consumed-state floors. Restore is not
  permission to reset or resurrect authority. Follow the runbook's stopped-manager
  backup/restore procedure and its acceptance requirements.
- Verify each approved deployment independently: exact TLS origin, pre-login
  denial, intended operator access, matching endpoint identity and fresh accepted
  reports. Only after separate authorization, test cross-instance denial using
  disposable identities, never real customer keys or copied production databases.

This is a deployment separation model, not an automated multi-instance installer
or proof of hostile-tenant isolation. Two instances on one host do not isolate
against that host's administrator; use separate hosts/VMs when that is the required
trust boundary. A bounded [organizational-boundary acceptance regression](customer-organization-acceptance.md)
checks two separate Linux manager processes with disposable identities, trust,
state and backup copies, plus unchanged API/CSV permissions. That is not a real
customer deployment, general backup/restore or production-hardening result.
Deployment and credential/trust changes still need their own approval.

## Organizational assignment of activated Windows identities

The current source additionally lets a shared administrator explicitly assign an
already activated, currently admitted Windows identity to one customer. This is
organizational metadata after activation, not a pending-device approval, customer
isolation, scope grant or installer binding. The UI displays the complete opaque
identity digest and requires an initially unchecked confirmation of the selected
customer and identity. It reports unavailable retained assignments separately;
it does not infer names or membership from an absent source.

The manager binds the record to the original manager/transport/profile,
invitation, device ID and original issued certificate, not a mutable hostname or
renewed leaf. A valid same-identity leaf renewal preserves the record; revoked,
expired, unavailable or replaced identities cannot inherit its display. The
create-only record cannot be changed or deleted by this workflow. Up to 100
records, including unavailable historical ones, are retained; exhaustion blocks
new assignments. Customer renames do not change the chosen customer ID. There is
no implicit re-enrollment or reassignment.

Each customer keeps a count updated in the same operator transaction as a new
assignment. A missing assignment/table after use is rejected when this count no
longer matches the retained rows. This detects that limited loss condition; it
does not authenticate row contents or detect a complete backup rollback or a
coordinated change to rows and count. After the first assignment, older manager
binaries that do not understand the count reject the changed customer record;
do not downgrade them onto this store. Source checks are not an upgrade or
backup/restore acceptance.

Private `GET /api/customer-windows-assignments` returns bounded customers,
currently admitted Windows identities, their assignments and the count of
unavailable retained records. The view has a manager-clock `validUntil`, at most
30 seconds and no later than relevant issuer/current-credential expiry. The UI
clears stale views and confirmations. The reviewed `POST` requires the exact
customer ID and revision, device ID, original identity digest and explicit
acknowledgement. A fresh enrollment authority lease is held while the operator
transaction checks that customer revision and commits; the live session, current
authority and clock are rechecked. The result can be uncertain if the response
or outer authority check fails after the operator commit. No mutation is
automatically retried. During the current browser page session, an unconfirmed
request blocks further assignments until a GET shows that exact original identity
assigned; an unassigned read is not proof a delayed request failed. This UI fence
is memory-only and does not survive reload or a different operator/browser; a
durable server-side reconciliation protocol remains necessary.

The Windows setup area separately shows current existing invitation claims
awaiting review. Opening a row reuses the existing comparison dialog: review the
complete device-key fingerprint and comparison value independently and explicitly
approve the exact revision. Expired or unavailable state must not be presented
as a live approval. Existing claims contain no verified customer or device name;
the UI does not invent either. The list applies only to the selected Windows
enrollment authority, not all platforms or customers.
If an approval or termination POST is interrupted, the current browser process
fences further actions for the same manager, invitation and original claim until
a later valid read shows a matching advanced approval or terminal state. An
unchanged pending read is not proof that the interrupted POST failed. This fence
survives closing the dialog and SPA navigation, but not browser reload or process
restart; it is not a durable server-side no-replay guarantee.

The required next enrollment contract must bind a new device's signed claim to an exact
customer and manager, limit unauthenticated requests, and atomically bind the
approved original identity and customer. The proposed end-to-end lifecycle and
its outstanding gates are described in [customer device onboarding](customer-device-onboarding.md).
Separate source packages now exercise proof verification, challenge consumption
and pending storage together in fixtures, but they are not connected to the
running manager, approval or an installer. Until those parts exist this catalog cannot be used
for customer-specific device approval, access isolation, reusable download links
or PowerShell installation. The published preview and running managers do not
automatically contain these source changes. Native installation, real customer
enrollment and production release are not established by source fixtures.
