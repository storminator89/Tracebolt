# Inventory and Security source presentation

The device Security tab uses the same current Linux CVE assessment reader as the
CVE tab. Its dpkg row count comes from the validated complete package manifest
used by that assessment, not from a page length, pending transfer or the older
operational preview. Original inventory age, feed age, limited coverage and
stale/unavailable outcomes remain visible. Missing evidence is never a successful
zero or a healthy-device conclusion.

Packages and Updates are direct navigation targets. Inventory opens Packages by
default; an explicit source selection mounts only that reader. The legacy bounded
preview is behind a closed disclosure. It no longer starts a simultaneous full
package-summary read. Security's legacy coverage and v2 package metadata remain
available through an explicit diagnostic-source selector. Only one of the current
CVE, legacy coverage or v2 metadata readers is mounted at once. Closing that
selector's disclosure returns to the current CVE reader. No polling is added.

## Coverage remains source-specific

- Packages: received complete dpkg generation and original capture time. This is
  not a complete inventory of Snap, Flatpak or manually installed software.
- Updates: complete known cached APT candidate rows, or an explicitly selected
  bounded preview. Metadata age, comparison gaps and missing scope are independent
  of package inventory and CVE findings. Reading does not refresh APT metadata or
  install anything.
- CVE: current complete package generation checked against loaded supported
  distribution records. Published fix versions do not establish installable update
  candidates, reachability or exploitability.
- Processes and mounts: complete generations require the separate existing local
  opt-in. A missing generation does not mean zero processes or mounts. Successful
  enumeration remains bounded by the agent's Linux namespaces and field access.
- Connections: all received socket rows can be present while PID/process owner
  attribution is denied or unavailable. The UI preserves both outcomes; the owner
  failure does not erase or invalidate received connection rows. No privilege is
  inferred from an operator's manager login.
- Legacy operational evidence: bounded samples, their own capture times and
  legacy profile. They cannot replace complete counts or override current CVE and
  update views. Offline catalog gaps refer only to that older diagnostic source.

## Remaining administration gap

A one-time, explicitly reviewed full administration profile is not implemented by
this presentation change. Today complete process/mount capture, cached-update
preview, complete cached-update capture, hostname/interface metadata, journal
content and controlled service actions have separate local consent/helper
boundaries. Upgrading the manager or clicking a view must not silently enable any
of them, convert an existing profile, re-enroll an endpoint, grant groups or root,
change the service sandbox, or retry a denied owner read with extra privilege.

A future unified setup flow needs one reviewable disclosure of the exact scopes,
identity/destination binding, transport risks, cadence/retention and helper
permissions, followed by explicit administrator approval. It must preserve
per-scope disable, durable sequence floors, existing identity and original age,
and report partial setup without treating it as a complete grant. That is a
separate implementation and host-acceptance task. Existing instructions remain
in [complete overview](complete-overview-extension.md),
[complete cached updates](complete-cached-updates-extension.md),
[endpoint identity](endpoint-identity-extension.md) and
[journal content](journal-content-mvp.md).

## Verification scope

UI fixtures cover the reported 1,396 complete dpkg rows and six warnings, no
legacy blanket claims on the primary view, unavailable/stale evidence, lazy and
mutually exclusive sources, cancellation/session replacement, source-specific
counts, and 14 complete socket rows with denied owner attribution. Fixtures and
browser presentation checks do not establish the user's endpoint consent state,
actual field permissions, service acceptance or reboot behavior.
